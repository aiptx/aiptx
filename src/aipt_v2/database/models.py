"""
AIPT Database Models - SQLAlchemy ORM models for persistence
Supports SQLite (development) and PostgreSQL (production)

Models:
- Project: Top-level container for pentests
- Session: Individual scan/attack session
- Finding: Discovered vulnerability/info
- Task: PTT task tracking
"""

from datetime import datetime
from typing import Optional
from enum import Enum

from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, JSON, Boolean, Float, Enum as SQLEnum,
    create_engine, Index
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class SeverityLevel(str, Enum):
    """Finding severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    """Task status values"""
    TODO = "to-do"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class PhaseType(str, Enum):
    """Pentest phases"""
    RECON = "recon"
    ENUM = "enum"
    EXPLOIT = "exploit"
    POST = "post"
    REPORT = "report"


class Project(Base):
    """
    Top-level project container.
    A project represents a complete pentest engagement.
    """
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    target = Column(String(255), nullable=False)  # Primary target
    scope = Column(JSON, default=list)  # List of in-scope targets

    # Metadata
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    status = Column(String(50), default="active")  # active, completed, archived

    # Configuration
    config = Column(JSON, default=dict)  # LLM settings, timeouts, etc.

    # Relationships
    sessions = relationship("Session", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index("idx_project_target", "target"),
        Index("idx_project_status", "status"),
    )

    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}', target='{self.target}')>"


class Session(Base):
    """
    Individual scan/attack session within a project.
    Tracks a single run of the agent.
    """
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)

    # Session info
    name = Column(String(255), nullable=True)
    phase = Column(SQLEnum(PhaseType), default=PhaseType.RECON)

    # Timing
    started_at = Column(DateTime, server_default=func.now())
    ended_at = Column(DateTime, nullable=True)

    # Progress
    iteration = Column(Integer, default=0)
    max_iterations = Column(Integer, default=100)
    status = Column(String(50), default="running")  # running, paused, completed, error

    # State
    state = Column(JSON, default=dict)  # Full agent state for resume
    memory_summary = Column(Text, nullable=True)  # Compressed memory

    # Relationships
    project = relationship("Project", back_populates="sessions")
    tasks = relationship("Task", back_populates="session", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index("idx_session_project", "project_id"),
        Index("idx_session_status", "status"),
    )

    def __repr__(self):
        return f"<Session(id={self.id}, project_id={self.project_id}, phase='{self.phase}')>"


class Finding(Base):
    """
    Discovered finding (vulnerability, service, credential, etc.)
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True)

    # Finding details
    type = Column(String(50), nullable=False)  # port, service, vuln, credential, host, path
    value = Column(String(500), nullable=False)  # Primary identifier
    description = Column(Text, nullable=True)
    severity = Column(SQLEnum(SeverityLevel), default=SeverityLevel.INFO)

    # Metadata
    phase = Column(SQLEnum(PhaseType), nullable=True)
    tool = Column(String(100), nullable=True)  # Tool that found this
    raw_output = Column(Text, nullable=True)  # Original tool output
    extra_data = Column(JSON, default=dict)  # Additional structured data (renamed from metadata - reserved in SQLAlchemy)

    # Verification
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)

    # Timing
    discovered_at = Column(DateTime, server_default=func.now())

    # Relationships
    project = relationship("Project", back_populates="findings")

    # Indexes
    __table_args__ = (
        Index("idx_finding_project", "project_id"),
        Index("idx_finding_type", "type"),
        Index("idx_finding_severity", "severity"),
        Index("idx_finding_value", "value"),
    )

    def __repr__(self):
        return f"<Finding(id={self.id}, type='{self.type}', value='{self.value[:30]}')>"

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity.value if self.severity else "info",
            "phase": self.phase.value if self.phase else None,
            "tool": self.tool,
            "extra_data": self.extra_data,
            "verified": self.verified,
            "false_positive": self.false_positive,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class Task(Base):
    """
    PTT task for tracking pentest progress
    """
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)

    # Task details
    task_id = Column(String(10), nullable=False)  # e.g., "R1", "E2"
    description = Column(Text, nullable=False)
    phase = Column(SQLEnum(PhaseType), nullable=False)
    status = Column(SQLEnum(TaskStatus), default=TaskStatus.TODO)

    # Timing
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Results
    findings_count = Column(Integer, default=0)
    notes = Column(Text, nullable=True)

    # Relationships
    session = relationship("Session", back_populates="tasks")

    # Indexes
    __table_args__ = (
        Index("idx_task_session", "session_id"),
        Index("idx_task_phase", "phase"),
        Index("idx_task_status", "status"),
    )

    def __repr__(self):
        return f"<Task(id={self.id}, task_id='{self.task_id}', status='{self.status}')>"


def create_database(db_url: str = "sqlite:///aipt.db") -> None:
    """Create database tables"""
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    return engine
