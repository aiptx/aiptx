"""
AIPT PTT (Penetration Testing Tree) Tracker

Hierarchical task tracking for pentest sessions.
Inspired by PentestGPT's PTT concept.
"""
from __future__ import annotations

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json


class TaskStatus(str, Enum):
    """Task status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class PTTNode:
    """A node in the Penetration Testing Tree"""
    id: str
    name: str
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    phase: str = "recon"
    parent_id: Optional[str] = None
    children: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "phase": self.phase,
            "parent_id": self.parent_id,
            "children": self.children,
            "findings": self.findings,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PTTNode":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            status=TaskStatus(data.get("status", "pending")),
            phase=data.get("phase", "recon"),
            parent_id=data.get("parent_id"),
            children=data.get("children", []),
            findings=data.get("findings", []),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
        )


class PTTTracker:
    """
    Penetration Testing Tree Tracker.

    Maintains a hierarchical view of pentest tasks:
    - Target (root)
      - Phase (recon, enum, exploit, post)
        - Task (specific action)
          - Finding (discovered information)

    Example:
        ptt = PTTTracker()
        ptt.initialize("192.168.1.0/24")
        ptt.add_task("recon", "Port scan with nmap")
        ptt.add_finding("recon", task_id, {"type": "port", "value": "80/tcp"})
    """

    def __init__(self):
        self.nodes: Dict[str, PTTNode] = {}
        self.root_id: Optional[str] = None
        self._id_counter: int = 0

    def _generate_id(self) -> str:
        """Generate unique node ID"""
        self._id_counter += 1
        return f"node_{self._id_counter}"

    def initialize(self, target: str) -> dict:
        """
        Initialize PTT for a new target.

        Creates root node and phase nodes.
        """
        self.nodes = {}
        self._id_counter = 0

        # Create root node
        root_id = self._generate_id()
        self.root_id = root_id
        root = PTTNode(
            id=root_id,
            name=target,
            description=f"Pentest target: {target}",
            phase="root",
        )
        self.nodes[root_id] = root

        # Create phase nodes
        phases = ["recon", "enum", "exploit", "post", "report"]
        for phase in phases:
            phase_id = self._generate_id()
            phase_node = PTTNode(
                id=phase_id,
                name=phase.upper(),
                description=f"{phase.title()} phase",
                phase=phase,
                parent_id=root_id,
            )
            self.nodes[phase_id] = phase_node
            root.children.append(phase_id)

        return self.to_dict()

    def add_task(
        self,
        phase: str,
        name: str,
        description: str = "",
        parent_id: Optional[str] = None,
    ) -> str:
        """
        Add a task to a phase.

        Args:
            phase: Phase name (recon, enum, exploit, post)
            name: Task name
            description: Task description
            parent_id: Optional parent task ID

        Returns:
            Task node ID
        """
        # Find phase node
        phase_node = self._get_phase_node(phase)
        if not phase_node:
            raise ValueError(f"Phase not found: {phase}")

        # Create task node
        task_id = self._generate_id()
        task = PTTNode(
            id=task_id,
            name=name,
            description=description,
            phase=phase,
            parent_id=parent_id or phase_node.id,
            status=TaskStatus.PENDING,
        )
        self.nodes[task_id] = task

        # Add to parent's children
        parent_node = self.nodes.get(parent_id or phase_node.id)
        if parent_node:
            parent_node.children.append(task_id)

        return task_id

    def update_task_status(self, task_id: str, status: TaskStatus) -> None:
        """Update task status"""
        if task_id in self.nodes:
            self.nodes[task_id].status = status
            self.nodes[task_id].updated_at = datetime.now().isoformat()

    def add_finding(self, task_id: str, finding: dict) -> None:
        """Add finding to a task"""
        if task_id in self.nodes:
            self.nodes[task_id].findings.append(finding)
            self.nodes[task_id].updated_at = datetime.now().isoformat()

    def add_findings(self, phase: str, findings: List[dict]) -> None:
        """Add multiple findings to a phase"""
        phase_node = self._get_phase_node(phase)
        if phase_node:
            for finding in findings:
                phase_node.findings.append(finding)
            phase_node.updated_at = datetime.now().isoformat()

    def _get_phase_node(self, phase: str) -> Optional[PTTNode]:
        """Get phase node by name"""
        for node in self.nodes.values():
            if node.phase == phase and node.parent_id == self.root_id:
                return node
        return None

    def get_tasks_by_phase(self, phase: str) -> List[PTTNode]:
        """Get all tasks in a phase"""
        phase_node = self._get_phase_node(phase)
        if not phase_node:
            return []

        return [
            self.nodes[child_id]
            for child_id in phase_node.children
            if child_id in self.nodes
        ]

    def get_pending_tasks(self, phase: Optional[str] = None) -> List[PTTNode]:
        """Get all pending tasks, optionally filtered by phase"""
        pending = []
        for node in self.nodes.values():
            if node.status == TaskStatus.PENDING:
                if phase is None or node.phase == phase:
                    pending.append(node)
        return pending

    def get_all_findings(self) -> List[dict]:
        """Get all findings across all nodes"""
        findings = []
        for node in self.nodes.values():
            for finding in node.findings:
                finding["task_id"] = node.id
                finding["task_name"] = node.name
                finding["phase"] = node.phase
                findings.append(finding)
        return findings

    def get_phase_summary(self, phase: str) -> dict:
        """Get summary for a phase"""
        phase_node = self._get_phase_node(phase)
        if not phase_node:
            return {}

        tasks = self.get_tasks_by_phase(phase)
        return {
            "phase": phase,
            "status": phase_node.status.value,
            "total_tasks": len(tasks),
            "completed_tasks": len([t for t in tasks if t.status == TaskStatus.COMPLETED]),
            "pending_tasks": len([t for t in tasks if t.status == TaskStatus.PENDING]),
            "findings_count": len(phase_node.findings) + sum(len(t.findings) for t in tasks),
        }

    def to_prompt(self) -> str:
        """Format PTT for LLM prompt"""
        if not self.root_id:
            return "No PTT initialized."

        lines = []
        root = self.nodes[self.root_id]
        lines.append(f"Target: {root.name}")
        lines.append("")

        for phase in ["recon", "enum", "exploit", "post"]:
            phase_node = self._get_phase_node(phase)
            if not phase_node:
                continue

            status_emoji = {
                TaskStatus.PENDING: "⏳",
                TaskStatus.IN_PROGRESS: "🔄",
                TaskStatus.COMPLETED: "✅",
                TaskStatus.FAILED: "❌",
                TaskStatus.BLOCKED: "🚫",
            }

            lines.append(f"## {phase.upper()} {status_emoji.get(phase_node.status, '⏳')}")

            tasks = self.get_tasks_by_phase(phase)
            if tasks:
                for task in tasks:
                    emoji = status_emoji.get(task.status, "⏳")
                    lines.append(f"  - {emoji} {task.name}")
                    if task.findings:
                        for finding in task.findings[:3]:  # Limit findings shown
                            lines.append(f"      • {finding.get('type', 'info')}: {finding.get('description', 'N/A')[:50]}")

            if phase_node.findings:
                lines.append(f"  Findings: {len(phase_node.findings)}")

            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export PTT to dictionary"""
        return {
            "root_id": self.root_id,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PTTTracker":
        """Create PTT from dictionary"""
        tracker = cls()
        tracker.root_id = data.get("root_id")
        tracker.nodes = {
            k: PTTNode.from_dict(v) for k, v in data.get("nodes", {}).items()
        }
        return tracker

    def to_json(self) -> str:
        """Export to JSON"""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> "PTTTracker":
        """Create from JSON"""
        return cls.from_dict(json.loads(json_str))

    def save(self, filepath: str) -> None:
        """Save PTT to file"""
        with open(filepath, "w") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, filepath: str) -> "PTTTracker":
        """Load PTT from file"""
        with open(filepath, "r") as f:
            return cls.from_json(f.read())
