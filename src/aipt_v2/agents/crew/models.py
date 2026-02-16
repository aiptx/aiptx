"""
Data Models for Crew Orchestration.

Defines the state machines and data structures for
managing parallel worker agents.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class CrewState(Enum):
    """State of the crew orchestrator."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"
    CANCELLED = "cancelled"


class AgentStatus(Enum):
    """Status of a worker agent."""

    PENDING = "pending"  # Queued, waiting to start
    RUNNING = "running"  # Currently executing
    COMPLETE = "complete"  # Successfully finished
    WARNING = "warning"  # Completed but hit max iterations
    ERROR = "error"  # Failed with error
    FAILED = "failed"  # Task determined infeasible
    CANCELLED = "cancelled"  # Cancelled by user/orchestrator


@dataclass
class AgentWorker:
    """
    Represents a worker agent managed by the crew.

    Workers are spawned by the orchestrator to execute
    specific tasks in parallel.
    """

    id: str
    task: str
    status: AgentStatus = AgentStatus.PENDING
    priority: int = 1  # Higher priority runs first
    depends_on: List[str] = field(default_factory=list)
    result: Optional[str] = None
    error: Optional[str] = None
    tools_used: List[str] = field(default_factory=list)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    # Execution metadata
    iterations: int = 0
    max_iterations: int = 50
    tokens_used: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "task": self.task,
            "status": self.status.value,
            "priority": self.priority,
            "depends_on": self.depends_on,
            "result": self.result,
            "error": self.error,
            "tools_used": self.tools_used,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "iterations": self.iterations,
            "tokens_used": self.tokens_used,
        }

    @property
    def duration(self) -> Optional[float]:
        """Get execution duration in seconds."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def is_terminal(self) -> bool:
        """Check if worker is in a terminal state."""
        return self.status in {
            AgentStatus.COMPLETE,
            AgentStatus.WARNING,
            AgentStatus.ERROR,
            AgentStatus.FAILED,
            AgentStatus.CANCELLED,
        }


@dataclass
class Finding:
    """A security finding discovered by an agent."""

    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    agent_id: str
    evidence: str = ""
    confidence: str = "medium"  # high, medium, low
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "agent_id": self.agent_id,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
        }


@dataclass
class CrewConfig:
    """Configuration for crew execution."""

    max_workers: int = 5  # Max concurrent workers
    max_iterations_per_worker: int = 50
    worker_timeout: int = 600  # Seconds
    retry_on_error: bool = True
    max_retries: int = 2
    share_findings: bool = True  # Share findings between workers
    parallel_execution: bool = True


# Type alias for worker event callback
# Signature: (worker_id: str, event: str, data: dict) -> None
WorkerCallback = Callable[[str, str, Dict[str, Any]], None]


@dataclass
class WorkerEvent:
    """Event emitted during worker execution."""

    worker_id: str
    event_type: str  # spawn, status, tool, complete, error, tokens
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "worker_id": self.worker_id,
            "event_type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp,
        }
