"""
AIPT Orchestration Module

Enhanced pipeline orchestration with:
- Phase-based workflow management
- Tool coordination and scheduling
- Progress tracking and callbacks
- Result aggregation and reporting

The main Orchestrator class is re-exported from the original orchestrator.py
for backward compatibility.
"""
from __future__ import annotations

# Import from the original orchestrator (backward compatibility)
try:
    from aipt_v2.orchestrator import (
        Orchestrator,
        Phase,
        PhaseResult,
        OrchestratorConfig,
        validate_domain,
        validate_ip,
    )
except ImportError:
    Orchestrator = None
    Phase = None
    PhaseResult = None
    OrchestratorConfig = None

# New orchestration components
from .pipeline import Pipeline, PipelineStage, PipelineResult
from .scheduler import TaskScheduler, ScheduledTask, TaskPriority
from .progress import ProgressTracker, ProgressCallback

__all__ = [
    # Original orchestrator
    "Orchestrator",
    "Phase",
    "PhaseResult",
    "OrchestratorConfig",
    "validate_domain",
    # New components
    "Pipeline",
    "PipelineStage",
    "PipelineResult",
    "TaskScheduler",
    "ScheduledTask",
    "TaskPriority",
    "ProgressTracker",
    "ProgressCallback",
]
