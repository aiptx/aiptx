"""
AIPT Progress Tracker - Track and report progress

Provides progress tracking with:
- Percentage progress
- ETA calculation
- Event callbacks
- Logging integration
"""
from __future__ import annotations

import time
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


# Type alias for progress callback
ProgressCallback = Callable[[float, str, Dict[str, Any]], None]


@dataclass
class ProgressEvent:
    """A progress event"""
    timestamp: str
    progress: float  # 0.0 to 1.0
    message: str
    phase: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PhaseProgress:
    """Progress within a phase"""
    name: str
    total_steps: int
    completed_steps: int = 0
    current_step: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    @property
    def progress(self) -> float:
        if self.total_steps == 0:
            return 0.0
        return self.completed_steps / self.total_steps

    @property
    def is_complete(self) -> bool:
        return self.completed_steps >= self.total_steps


class ProgressTracker:
    """
    Track and report progress for long-running operations.

    Example:
        tracker = ProgressTracker(
            total_phases=4,
            on_progress=lambda p, m, d: print(f"{p*100:.1f}% - {m}")
        )

        tracker.start_phase("recon", total_steps=10)
        for i in range(10):
            tracker.update_step(f"Scanning target {i}")
        tracker.complete_phase()

        print(f"ETA: {tracker.eta}")
    """

    def __init__(
        self,
        total_phases: int = 1,
        on_progress: Optional[ProgressCallback] = None,
        on_phase_start: Optional[Callable[[str], None]] = None,
        on_phase_complete: Optional[Callable[[str, float], None]] = None,
    ):
        self.total_phases = total_phases
        self.on_progress = on_progress
        self.on_phase_start = on_phase_start
        self.on_phase_complete = on_phase_complete

        self.phases: Dict[str, PhaseProgress] = {}
        self.phase_order: List[str] = []
        self.events: List[ProgressEvent] = []

        self._current_phase: Optional[str] = None
        self._start_time: Optional[float] = None
        self._completed_phases: int = 0

    @property
    def progress(self) -> float:
        """Overall progress (0.0 to 1.0)"""
        if not self.phases:
            return 0.0

        # Weight each phase equally
        phase_weight = 1.0 / max(self.total_phases, len(self.phases))
        total_progress = 0.0

        for phase_name in self.phase_order:
            phase = self.phases[phase_name]
            if phase.is_complete:
                total_progress += phase_weight
            else:
                total_progress += phase_weight * phase.progress

        return min(total_progress, 1.0)

    @property
    def eta(self) -> Optional[timedelta]:
        """Estimated time remaining"""
        if not self._start_time or self.progress == 0:
            return None

        elapsed = time.time() - self._start_time
        if self.progress >= 1.0:
            return timedelta(seconds=0)

        estimated_total = elapsed / self.progress
        remaining = estimated_total - elapsed
        return timedelta(seconds=int(remaining))

    @property
    def elapsed(self) -> timedelta:
        """Elapsed time"""
        if not self._start_time:
            return timedelta(seconds=0)
        return timedelta(seconds=int(time.time() - self._start_time))

    @property
    def current_phase(self) -> Optional[PhaseProgress]:
        """Get current phase"""
        if self._current_phase:
            return self.phases.get(self._current_phase)
        return None

    def start(self) -> None:
        """Start tracking"""
        self._start_time = time.time()
        self._emit_progress("Started tracking")

    def start_phase(
        self,
        name: str,
        total_steps: int = 1,
        description: str = "",
    ) -> None:
        """Start a new phase"""
        self._current_phase = name

        phase = PhaseProgress(
            name=name,
            total_steps=total_steps,
            started_at=datetime.now().isoformat(),
        )
        self.phases[name] = phase

        if name not in self.phase_order:
            self.phase_order.append(name)

        if self.on_phase_start:
            self.on_phase_start(name)

        self._emit_progress(f"Started phase: {name}", phase=name)
        logger.info(f"Phase started: {name} ({total_steps} steps)")

    def update_step(
        self,
        step_description: str = "",
        increment: int = 1,
    ) -> None:
        """Update progress within current phase"""
        if not self._current_phase:
            return

        phase = self.phases[self._current_phase]
        phase.completed_steps += increment
        phase.current_step = step_description

        self._emit_progress(
            step_description or f"Step {phase.completed_steps}/{phase.total_steps}",
            phase=self._current_phase,
        )

    def complete_phase(self, message: str = "") -> None:
        """Mark current phase as complete"""
        if not self._current_phase:
            return

        phase = self.phases[self._current_phase]
        phase.completed_steps = phase.total_steps
        phase.completed_at = datetime.now().isoformat()
        self._completed_phases += 1

        duration = 0.0
        if phase.started_at:
            start = datetime.fromisoformat(phase.started_at)
            end = datetime.fromisoformat(phase.completed_at)
            duration = (end - start).total_seconds()

        if self.on_phase_complete:
            self.on_phase_complete(self._current_phase, duration)

        self._emit_progress(
            message or f"Completed phase: {self._current_phase}",
            phase=self._current_phase,
        )

        logger.info(f"Phase completed: {self._current_phase} ({duration:.1f}s)")
        self._current_phase = None

    def skip_phase(self, name: str, reason: str = "") -> None:
        """Mark a phase as skipped"""
        phase = PhaseProgress(
            name=name,
            total_steps=1,
            completed_steps=1,
            started_at=datetime.now().isoformat(),
            completed_at=datetime.now().isoformat(),
            current_step=f"Skipped: {reason}" if reason else "Skipped",
        )
        self.phases[name] = phase

        if name not in self.phase_order:
            self.phase_order.append(name)

        self._emit_progress(f"Skipped phase: {name}", phase=name)

    def fail_phase(self, error: str) -> None:
        """Mark current phase as failed"""
        if not self._current_phase:
            return

        phase = self.phases[self._current_phase]
        phase.current_step = f"Failed: {error}"
        phase.completed_at = datetime.now().isoformat()

        self._emit_progress(f"Phase failed: {error}", phase=self._current_phase)
        logger.error(f"Phase failed: {self._current_phase} - {error}")
        self._current_phase = None

    def _emit_progress(
        self,
        message: str,
        phase: str = "",
        details: Dict[str, Any] = None,
    ) -> None:
        """Emit progress event"""
        event = ProgressEvent(
            timestamp=datetime.now().isoformat(),
            progress=self.progress,
            message=message,
            phase=phase,
            details=details or {},
        )
        self.events.append(event)

        if self.on_progress:
            self.on_progress(self.progress, message, event.details)

    def get_summary(self) -> Dict[str, Any]:
        """Get progress summary"""
        return {
            "progress": self.progress,
            "progress_percent": f"{self.progress * 100:.1f}%",
            "elapsed": str(self.elapsed),
            "eta": str(self.eta) if self.eta else "Unknown",
            "completed_phases": self._completed_phases,
            "total_phases": self.total_phases,
            "current_phase": self._current_phase,
            "phases": {
                name: {
                    "progress": phase.progress,
                    "completed_steps": phase.completed_steps,
                    "total_steps": phase.total_steps,
                    "is_complete": phase.is_complete,
                }
                for name, phase in self.phases.items()
            },
        }

    def to_string(self) -> str:
        """Get human-readable progress string"""
        summary = self.get_summary()
        lines = [
            f"Progress: {summary['progress_percent']}",
            f"Elapsed: {summary['elapsed']}",
            f"ETA: {summary['eta']}",
            f"Phases: {summary['completed_phases']}/{summary['total_phases']}",
        ]

        if summary['current_phase']:
            phase = self.phases[summary['current_phase']]
            lines.append(f"Current: {summary['current_phase']} ({phase.current_step})")

        return " | ".join(lines)
