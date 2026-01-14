"""
AIPT Repository - Database access layer
Provides CRUD operations for all models.

Usage:
    repo = Repository("sqlite:///aipt.db")
    project = repo.create_project("Test", "192.168.1.0/24")
    session = repo.create_session(project.id)
    repo.add_finding(project.id, session.id, "port", "80/tcp", "HTTP server")
"""

from datetime import datetime
from typing import Optional, List
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session as DBSession

from .models import (
    Base, Project, Session, Finding, Task,
    SeverityLevel, TaskStatus, PhaseType
)


class Repository:
    """
    Database repository for AIPT.
    Handles all database operations.
    """

    def __init__(self, db_url: str = "sqlite:///~/.aipt/aipt.db"):
        """
        Initialize repository.

        Args:
            db_url: Database URL (SQLite or PostgreSQL)
                    SQLite: sqlite:///path/to/db.sqlite
                    PostgreSQL: postgresql://user:pass@host:port/db
        """
        import os

        # Expand ~ in path
        if db_url.startswith("sqlite:///~"):
            db_url = db_url.replace("~", os.path.expanduser("~"))
            # Ensure directory exists
            db_path = db_url.replace("sqlite:///", "")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

        self.engine = create_engine(db_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

        # Create tables
        Base.metadata.create_all(self.engine)

    @contextmanager
    def _get_db(self):
        """Get database session with automatic cleanup"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ============== Project Operations ==============

    def create_project(
        self,
        name: str,
        target: str,
        description: Optional[str] = None,
        scope: Optional[List[str]] = None,
        config: Optional[dict] = None,
    ) -> Project:
        """Create a new project"""
        with self._get_db() as session:
            project = Project(
                name=name,
                target=target,
                description=description,
                scope=scope or [target],
                config=config or {},
            )
            session.add(project)
            session.flush()
            session.refresh(project)
            return project

    def get_project(self, project_id: int) -> Optional[Project]:
        """Get project by ID"""
        with self._get_db() as session:
            return session.query(Project).filter(Project.id == project_id).first()

    def get_project_by_target(self, target: str) -> Optional[Project]:
        """Get project by target"""
        with self._get_db() as session:
            return session.query(Project).filter(Project.target == target).first()

    def list_projects(self, status: Optional[str] = None) -> List[Project]:
        """List all projects"""
        with self._get_db() as session:
            query = session.query(Project)
            if status:
                query = query.filter(Project.status == status)
            return query.order_by(Project.created_at.desc()).all()

    def update_project(
        self,
        project_id: int,
        **kwargs
    ) -> Optional[Project]:
        """Update project fields"""
        with self._get_db() as session:
            project = session.query(Project).filter(Project.id == project_id).first()
            if project:
                for key, value in kwargs.items():
                    if hasattr(project, key):
                        setattr(project, key, value)
                session.flush()
                session.refresh(project)
            return project

    def delete_project(self, project_id: int) -> bool:
        """Delete project and all related data"""
        with self._get_db() as session:
            project = session.query(Project).filter(Project.id == project_id).first()
            if project:
                session.delete(project)
                return True
            return False

    # ============== Session Operations ==============

    def create_session(
        self,
        project_id: int,
        name: Optional[str] = None,
        phase: PhaseType = PhaseType.RECON,
        max_iterations: int = 100,
    ) -> Session:
        """Create a new session"""
        with self._get_db() as db_session:
            session = Session(
                project_id=project_id,
                name=name or f"Session {datetime.now().strftime('%Y%m%d_%H%M%S')}",
                phase=phase,
                max_iterations=max_iterations,
            )
            db_session.add(session)
            db_session.flush()
            db_session.refresh(session)
            return session

    def get_session_by_id(self, session_id: int) -> Optional[Session]:
        """Get session by ID"""
        with self._get_db() as db_session:
            return db_session.query(Session).filter(Session.id == session_id).first()

    def get_active_session(self, project_id: int) -> Optional[Session]:
        """Get active session for project"""
        with self._get_db() as db_session:
            return db_session.query(Session).filter(
                Session.project_id == project_id,
                Session.status == "running"
            ).first()

    def list_sessions(self, project_id: int) -> List[Session]:
        """List all sessions for a project"""
        with self._get_db() as db_session:
            return db_session.query(Session).filter(
                Session.project_id == project_id
            ).order_by(Session.started_at.desc()).all()

    def update_session(
        self,
        session_id: int,
        **kwargs
    ) -> Optional[Session]:
        """Update session fields"""
        with self._get_db() as db_session:
            session = db_session.query(Session).filter(Session.id == session_id).first()
            if session:
                for key, value in kwargs.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                db_session.flush()
                db_session.refresh(session)
            return session

    def save_session_state(
        self,
        session_id: int,
        state: dict,
        memory_summary: Optional[str] = None,
    ) -> None:
        """Save session state for resume"""
        self.update_session(
            session_id,
            state=state,
            memory_summary=memory_summary,
        )

    def complete_session(self, session_id: int) -> None:
        """Mark session as completed"""
        self.update_session(
            session_id,
            status="completed",
            ended_at=datetime.now(),
        )

    # ============== Finding Operations ==============

    def add_finding(
        self,
        project_id: int,
        session_id: Optional[int],
        type: str,
        value: str,
        description: Optional[str] = None,
        severity: str = "info",
        phase: Optional[str] = None,
        tool: Optional[str] = None,
        raw_output: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Finding:
        """Add a new finding"""
        with self._get_db() as db_session:
            # Check for duplicate
            existing = db_session.query(Finding).filter(
                Finding.project_id == project_id,
                Finding.type == type,
                Finding.value == value,
            ).first()

            if existing:
                # Update existing finding
                if metadata:
                    existing.extra_data.update(metadata)
                return existing

            # Create new finding
            finding = Finding(
                project_id=project_id,
                session_id=session_id,
                type=type,
                value=value,
                description=description,
                severity=SeverityLevel(severity) if severity else SeverityLevel.INFO,
                phase=PhaseType(phase) if phase else None,
                tool=tool,
                raw_output=raw_output,
                extra_data=metadata or {},
            )
            db_session.add(finding)
            db_session.flush()
            db_session.refresh(finding)
            return finding

    def get_findings(
        self,
        project_id: int,
        type: Optional[str] = None,
        severity: Optional[str] = None,
        phase: Optional[str] = None,
        verified_only: bool = False,
    ) -> List[Finding]:
        """Get findings with optional filters"""
        with self._get_db() as db_session:
            query = db_session.query(Finding).filter(Finding.project_id == project_id)

            if type:
                query = query.filter(Finding.type == type)
            if severity:
                query = query.filter(Finding.severity == SeverityLevel(severity))
            if phase:
                query = query.filter(Finding.phase == PhaseType(phase))
            if verified_only:
                query = query.filter(Finding.verified == True)

            return query.order_by(Finding.discovered_at.desc()).all()

    def verify_finding(self, finding_id: int, verified: bool = True, notes: Optional[str] = None) -> None:
        """Mark finding as verified"""
        with self._get_db() as db_session:
            finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
            if finding:
                finding.verified = verified
                if notes:
                    finding.notes = notes

    def mark_false_positive(self, finding_id: int, notes: Optional[str] = None) -> None:
        """Mark finding as false positive"""
        with self._get_db() as db_session:
            finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
            if finding:
                finding.false_positive = True
                if notes:
                    finding.notes = notes

    def get_findings_summary(self, project_id: int) -> dict:
        """Get summary of findings by severity"""
        with self._get_db() as db_session:
            findings = db_session.query(Finding).filter(
                Finding.project_id == project_id,
                Finding.false_positive == False,
            ).all()

            summary = {
                "total": len(findings),
                "by_severity": {},
                "by_type": {},
                "verified": 0,
            }

            for f in findings:
                # By severity
                sev = f.severity.value if f.severity else "info"
                summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

                # By type
                summary["by_type"][f.type] = summary["by_type"].get(f.type, 0) + 1

                # Verified count
                if f.verified:
                    summary["verified"] += 1

            return summary

    # ============== Task Operations ==============

    def add_task(
        self,
        session_id: int,
        task_id: str,
        description: str,
        phase: str,
        status: str = "to-do",
    ) -> Task:
        """Add a new task"""
        with self._get_db() as db_session:
            task = Task(
                session_id=session_id,
                task_id=task_id,
                description=description,
                phase=PhaseType(phase),
                status=TaskStatus(status),
            )
            db_session.add(task)
            db_session.flush()
            db_session.refresh(task)
            return task

    def update_task(
        self,
        task_id: int,
        status: Optional[str] = None,
        findings_count: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> Optional[Task]:
        """Update task status"""
        with self._get_db() as db_session:
            task = db_session.query(Task).filter(Task.id == task_id).first()
            if task:
                if status:
                    task.status = TaskStatus(status)
                    if status == "in-progress":
                        task.started_at = datetime.now()
                    elif status == "completed":
                        task.completed_at = datetime.now()
                if findings_count is not None:
                    task.findings_count = findings_count
                if notes:
                    task.notes = notes
            return task

    def get_tasks(self, session_id: int) -> List[Task]:
        """Get all tasks for a session"""
        with self._get_db() as db_session:
            return db_session.query(Task).filter(
                Task.session_id == session_id
            ).order_by(Task.created_at).all()
