"""
AIPT Penetration Testing Tree (PTT) - Hierarchical task tracking
Tracks progress through pentest phases with visual feedback.

Inspired by: PentestGPT's PTT structure
Format:
1. Reconnaissance - [completed]
   1.1 Passive Information Gathering - (completed)
   1.2 Active Scanning - (in-progress)
2. Enumeration - [to-do]
   2.1 Service Enumeration - (to-do)
"""

import json
from enum import Enum
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


class TaskStatus(str, Enum):
    """Status of a task"""
    TODO = "to-do"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class PhaseType(str, Enum):
    """Penetration testing phases"""
    RECON = "recon"
    SCANNING = "enum"
    EXPLOITATION = "exploit"
    POST_EXPLOITATION = "post"
    REPORTING = "report"


@dataclass
class Task:
    """A single task in the PTT"""
    id: str
    description: str
    status: TaskStatus = TaskStatus.TODO
    findings: list[dict] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    notes: str = ""


@dataclass
class Phase:
    """A phase containing multiple tasks"""
    name: str
    description: str
    status: TaskStatus = TaskStatus.TODO
    tasks: list[Task] = field(default_factory=list)


class PTT:
    """
    Penetration Testing Tree - Hierarchical task tracking.

    Provides:
    - Visual progress tracking
    - Phase-based organization
    - Finding association
    - Session persistence
    """

    # Standard pentest phases
    PHASES = [
        ("recon", "Reconnaissance and information gathering"),
        ("enum", "Enumeration of services and vulnerabilities"),
        ("exploit", "Exploitation of discovered vulnerabilities"),
        ("post", "Post-exploitation and privilege escalation"),
        ("report", "Documentation and report generation"),
    ]

    def __init__(self, session_dir: Optional[str] = None):
        self.session_dir = Path(session_dir or "~/.aipt/sessions").expanduser()
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.target: str = ""
        self.phases: dict[str, Phase] = {}
        self.current_phase: str = "recon"
        self.session_id: Optional[str] = None

    def initialize(self, target: str) -> dict:
        """
        Initialize PTT for a new target.

        Args:
            target: Target being tested

        Returns:
            Initial PTT state as dict
        """
        self.target = target
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Initialize phases
        self.phases = {}
        for phase_name, phase_desc in self.PHASES:
            self.phases[phase_name] = Phase(
                name=phase_name,
                description=phase_desc,
                status=TaskStatus.TODO,
                tasks=[],
            )

        # Set first phase to in-progress
        self.phases["recon"].status = TaskStatus.IN_PROGRESS
        self.current_phase = "recon"

        return self.to_dict()

    def add_task(
        self,
        phase: str,
        description: str,
        status: TaskStatus = TaskStatus.TODO,
    ) -> str:
        """
        Add a task to a phase.

        Args:
            phase: Phase name (recon, enum, exploit, post, report)
            description: Task description

        Returns:
            Task ID
        """
        if phase not in self.phases:
            raise ValueError(f"Unknown phase: {phase}")

        phase_obj = self.phases[phase]
        task_num = len(phase_obj.tasks) + 1

        # Generate task ID (e.g., "R1", "E2")
        phase_prefix = phase[0].upper()
        task_id = f"{phase_prefix}{task_num}"

        task = Task(
            id=task_id,
            description=description,
            status=status,
        )

        if status == TaskStatus.IN_PROGRESS:
            task.started_at = datetime.now().isoformat()

        phase_obj.tasks.append(task)

        return task_id

    def update_task(
        self,
        task_id: str,
        status: Optional[TaskStatus] = None,
        findings: Optional[list[dict]] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """
        Update a task's status or findings.

        Args:
            task_id: Task identifier
            status: New status
            findings: Findings to add
            notes: Additional notes

        Returns:
            True if task was found and updated
        """
        task = self._find_task(task_id)
        if not task:
            return False

        if status:
            task.status = status
            if status == TaskStatus.IN_PROGRESS:
                task.started_at = datetime.now().isoformat()
            elif status == TaskStatus.COMPLETED:
                task.completed_at = datetime.now().isoformat()

        if findings:
            task.findings.extend(findings)

        if notes:
            task.notes = notes

        return True

    def complete_task(self, task_id: str, findings: Optional[list[dict]] = None) -> bool:
        """Mark a task as completed"""
        return self.update_task(task_id, TaskStatus.COMPLETED, findings)

    def add_findings(self, phase: str, findings: list[dict]) -> None:
        """
        Add findings to the current active task in a phase.
        If no active task, create one.
        """
        if phase not in self.phases:
            return

        phase_obj = self.phases[phase]

        # Find active task
        active_task = None
        for task in phase_obj.tasks:
            if task.status == TaskStatus.IN_PROGRESS:
                active_task = task
                break

        # Create task if none active
        if not active_task:
            task_id = self.add_task(phase, "Auto-generated task", TaskStatus.IN_PROGRESS)
            active_task = self._find_task(task_id)

        if active_task:
            active_task.findings.extend(findings)

    def advance_phase(self) -> str:
        """
        Advance to the next phase.

        Returns:
            New phase name
        """
        phase_names = [p[0] for p in self.PHASES]
        current_idx = phase_names.index(self.current_phase)

        if current_idx < len(phase_names) - 1:
            # Complete current phase
            self.phases[self.current_phase].status = TaskStatus.COMPLETED

            # Move to next phase
            self.current_phase = phase_names[current_idx + 1]
            self.phases[self.current_phase].status = TaskStatus.IN_PROGRESS

        return self.current_phase

    def set_phase(self, phase: str) -> None:
        """Set current phase directly"""
        if phase in self.phases:
            self.current_phase = phase
            self.phases[phase].status = TaskStatus.IN_PROGRESS

    def _find_task(self, task_id: str) -> Optional[Task]:
        """Find a task by ID"""
        for phase in self.phases.values():
            for task in phase.tasks:
                if task.id == task_id:
                    return task
        return None

    def to_prompt(self) -> str:
        """
        Generate PTT string for LLM prompt.

        Format:
        1. Reconnaissance - [completed]
           R1. Port scanning - (completed) - 5 findings
           R2. Service detection - (in-progress)
        2. Enumeration - [in-progress]
           E1. Directory brute-force - (to-do)
        """
        lines = [f"Target: {self.target}", ""]

        for i, (phase_name, _) in enumerate(self.PHASES, 1):
            phase = self.phases.get(phase_name)
            if not phase:
                continue

            # Phase line
            status_str = f"[{phase.status.value}]"
            phase_title = phase_name.title()
            lines.append(f"{i}. {phase_title} - {status_str}")

            # Task lines
            for task in phase.tasks:
                finding_count = len(task.findings)
                finding_str = f" - {finding_count} findings" if finding_count else ""
                status_str = f"({task.status.value})"
                lines.append(f"   {task.id}. {task.description} - {status_str}{finding_str}")

            if not phase.tasks:
                lines.append("   (no tasks yet)")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export PTT as dictionary"""
        return {
            "target": self.target,
            "session_id": self.session_id,
            "current_phase": self.current_phase,
            "phases": {
                name: {
                    "name": phase.name,
                    "description": phase.description,
                    "status": phase.status.value,
                    "tasks": [
                        {
                            "id": task.id,
                            "description": task.description,
                            "status": task.status.value,
                            "findings": task.findings,
                            "started_at": task.started_at,
                            "completed_at": task.completed_at,
                            "notes": task.notes,
                        }
                        for task in phase.tasks
                    ],
                }
                for name, phase in self.phases.items()
            },
        }

    def save(self, filename: Optional[str] = None) -> str:
        """
        Save PTT to file.

        Returns:
            Path to saved file
        """
        if not filename:
            filename = f"ptt_{self.session_id}_{self.target.replace('/', '_')}.json"

        filepath = self.session_dir / filename

        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

        return str(filepath)

    def load(self, filepath: str) -> None:
        """Load PTT from file"""
        with open(filepath, "r") as f:
            data = json.load(f)

        self.target = data.get("target", "")
        self.session_id = data.get("session_id")
        self.current_phase = data.get("current_phase", "recon")

        self.phases = {}
        for name, phase_data in data.get("phases", {}).items():
            tasks = [
                Task(
                    id=t["id"],
                    description=t["description"],
                    status=TaskStatus(t["status"]),
                    findings=t.get("findings", []),
                    started_at=t.get("started_at"),
                    completed_at=t.get("completed_at"),
                    notes=t.get("notes", ""),
                )
                for t in phase_data.get("tasks", [])
            ]

            self.phases[name] = Phase(
                name=phase_data["name"],
                description=phase_data["description"],
                status=TaskStatus(phase_data["status"]),
                tasks=tasks,
            )

    def get_summary(self) -> dict:
        """Get summary statistics"""
        total_tasks = 0
        completed_tasks = 0
        total_findings = 0

        for phase in self.phases.values():
            for task in phase.tasks:
                total_tasks += 1
                if task.status == TaskStatus.COMPLETED:
                    completed_tasks += 1
                total_findings += len(task.findings)

        completed_phases = sum(
            1 for p in self.phases.values()
            if p.status == TaskStatus.COMPLETED
        )

        return {
            "target": self.target,
            "current_phase": self.current_phase,
            "phases_completed": completed_phases,
            "phases_total": len(self.phases),
            "tasks_completed": completed_tasks,
            "tasks_total": total_tasks,
            "total_findings": total_findings,
        }

    def get_tasks_by_phase(self, phase: PhaseType) -> list[Task]:
        """Get all tasks for a specific phase"""
        phase_name = phase.value if isinstance(phase, PhaseType) else phase
        if phase_name in self.phases:
            return self.phases[phase_name].tasks
        return []

    def update_task_status(self, task_id: str, status: TaskStatus) -> bool:
        """Update a task's status by ID"""
        return self.update_task(task_id, status=status)
