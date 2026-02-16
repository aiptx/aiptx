"""
Quick Notes Tool for AIPTX.

Provides fast, lightweight note-taking capabilities for agents
to record findings, credentials, artifacts, and tasks during
penetration testing engagements.

Features:
    - CRUD operations for notes
    - Category-based organization
    - File persistence with JSON
    - Metadata support (timestamps, tags, severity)
    - Export to various formats

Example usage:
    from aipt_v2.tools.notes import (
        notes_create, notes_read, notes_update,
        notes_delete, notes_list, notes_export
    )

    # Create a finding
    await notes_create(
        key="sqli_login",
        value="SQL injection in /login endpoint",
        category="vulnerability",
        severity="high",
        evidence="' OR '1'='1 bypasses auth"
    )

    # List all vulnerabilities
    await notes_list(category="vulnerability")
"""

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class NoteCategory(Enum):
    """Categories for organizing notes."""

    FINDING = "finding"  # General findings
    CREDENTIAL = "credential"  # Discovered credentials
    VULNERABILITY = "vulnerability"  # Security vulnerabilities
    ARTIFACT = "artifact"  # Files, hashes, tokens
    TASK = "task"  # Pending tasks or follow-ups
    INFO = "info"  # General information


class NoteSeverity(Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Note:
    """
    A note entry with metadata.

    Attributes:
        key: Unique identifier for the note
        value: The note content
        category: Note category (finding, credential, etc.)
        severity: Severity level for findings
        tags: List of tags for filtering
        evidence: Supporting evidence
        created_at: Creation timestamp
        updated_at: Last update timestamp
        metadata: Additional custom metadata
    """

    key: str
    value: str
    category: str = "info"
    severity: str = "info"
    tags: List[str] = field(default_factory=list)
    evidence: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Note":
        """Create Note from dictionary."""
        return cls(**data)


class NotesStore:
    """
    In-memory notes store with file persistence.

    Stores notes in memory for fast access and persists
    to JSON file for durability across sessions.
    """

    def __init__(self, notes_file: Optional[Path] = None):
        """
        Initialize notes store.

        Args:
            notes_file: Path to JSON file for persistence.
                       Defaults to ~/.aiptx/notes.json
        """
        if notes_file is None:
            notes_file = Path.home() / ".aiptx" / "notes.json"

        self.notes_file = notes_file
        self._notes: Dict[str, Note] = {}
        self._load()

    def _load(self) -> None:
        """Load notes from file."""
        if self.notes_file.exists():
            try:
                with open(self.notes_file, "r") as f:
                    data = json.load(f)
                    for key, note_data in data.items():
                        self._notes[key] = Note.from_dict(note_data)
                logger.debug(f"Loaded {len(self._notes)} notes from {self.notes_file}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to load notes: {e}")
                self._notes = {}
        else:
            self._notes = {}

    def _save(self) -> None:
        """Save notes to file."""
        self.notes_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.notes_file, "w") as f:
            data = {key: note.to_dict() for key, note in self._notes.items()}
            json.dump(data, f, indent=2)
        logger.debug(f"Saved {len(self._notes)} notes to {self.notes_file}")

    def create(
        self,
        key: str,
        value: str,
        category: str = "info",
        severity: str = "info",
        tags: Optional[List[str]] = None,
        evidence: str = "",
        **metadata: Any,
    ) -> Note:
        """
        Create a new note.

        Args:
            key: Unique identifier
            value: Note content
            category: Note category
            severity: Severity level
            tags: List of tags
            evidence: Supporting evidence
            **metadata: Additional metadata

        Returns:
            Created Note

        Raises:
            ValueError: If key already exists
        """
        if key in self._notes:
            raise ValueError(f"Note with key '{key}' already exists. Use update instead.")

        note = Note(
            key=key,
            value=value,
            category=category,
            severity=severity,
            tags=tags or [],
            evidence=evidence,
            metadata=metadata,
        )
        self._notes[key] = note
        self._save()
        logger.info(f"Created note: {key} ({category})")
        return note

    def read(self, key: str) -> Optional[Note]:
        """
        Read a note by key.

        Args:
            key: Note identifier

        Returns:
            Note if found, None otherwise
        """
        return self._notes.get(key)

    def update(
        self,
        key: str,
        value: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        evidence: Optional[str] = None,
        **metadata: Any,
    ) -> Optional[Note]:
        """
        Update an existing note.

        Args:
            key: Note identifier
            value: New content (optional)
            category: New category (optional)
            severity: New severity (optional)
            tags: New tags (optional)
            evidence: New evidence (optional)
            **metadata: Additional metadata to merge

        Returns:
            Updated Note if found, None otherwise
        """
        note = self._notes.get(key)
        if note is None:
            return None

        if value is not None:
            note.value = value
        if category is not None:
            note.category = category
        if severity is not None:
            note.severity = severity
        if tags is not None:
            note.tags = tags
        if evidence is not None:
            note.evidence = evidence
        if metadata:
            note.metadata.update(metadata)

        note.updated_at = time.time()
        self._save()
        logger.info(f"Updated note: {key}")
        return note

    def delete(self, key: str) -> bool:
        """
        Delete a note.

        Args:
            key: Note identifier

        Returns:
            True if deleted, False if not found
        """
        if key in self._notes:
            del self._notes[key]
            self._save()
            logger.info(f"Deleted note: {key}")
            return True
        return False

    def list(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[Note]:
        """
        List notes with optional filtering.

        Args:
            category: Filter by category
            severity: Filter by severity
            tag: Filter by tag

        Returns:
            List of matching notes
        """
        notes = list(self._notes.values())

        if category:
            notes = [n for n in notes if n.category == category]
        if severity:
            notes = [n for n in notes if n.severity == severity]
        if tag:
            notes = [n for n in notes if tag in n.tags]

        # Sort by created_at descending (newest first)
        notes.sort(key=lambda n: n.created_at, reverse=True)
        return notes

    def search(self, query: str) -> List[Note]:
        """
        Search notes by content.

        Args:
            query: Search query (case-insensitive)

        Returns:
            List of matching notes
        """
        query_lower = query.lower()
        results = []
        for note in self._notes.values():
            if (
                query_lower in note.key.lower()
                or query_lower in note.value.lower()
                or query_lower in note.evidence.lower()
            ):
                results.append(note)
        return results

    def clear(self) -> int:
        """
        Clear all notes.

        Returns:
            Number of notes cleared
        """
        count = len(self._notes)
        self._notes.clear()
        self._save()
        logger.info(f"Cleared {count} notes")
        return count

    def export_json(self) -> str:
        """Export all notes as JSON string."""
        return json.dumps(
            {key: note.to_dict() for key, note in self._notes.items()},
            indent=2,
        )

    def export_markdown(self) -> str:
        """Export notes as Markdown."""
        lines = ["# AIPTX Notes", ""]

        # Group by category
        by_category: Dict[str, List[Note]] = {}
        for note in self._notes.values():
            category = note.category
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(note)

        for category, notes in sorted(by_category.items()):
            lines.append(f"## {category.title()}")
            lines.append("")
            for note in notes:
                severity_badge = f"[{note.severity.upper()}]" if note.severity != "info" else ""
                lines.append(f"### {note.key} {severity_badge}")
                lines.append(f"{note.value}")
                if note.evidence:
                    lines.append("")
                    lines.append(f"**Evidence:** {note.evidence}")
                if note.tags:
                    lines.append("")
                    lines.append(f"**Tags:** {', '.join(note.tags)}")
                lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about notes."""
        stats = {
            "total": len(self._notes),
            "by_category": {},
            "by_severity": {},
        }

        for note in self._notes.values():
            # Count by category
            cat = note.category
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

            # Count by severity
            sev = note.severity
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

        return stats


# Global notes store instance
_store: Optional[NotesStore] = None


def get_store() -> NotesStore:
    """Get the global notes store instance."""
    global _store
    if _store is None:
        _store = NotesStore()
    return _store


# Async wrapper functions for agent use


async def notes_create(
    key: str,
    value: str,
    category: str = "info",
    severity: str = "info",
    tags: Optional[List[str]] = None,
    evidence: str = "",
    **metadata: Any,
) -> str:
    """
    Create a new note.

    Args:
        key: Unique identifier for the note
        value: The note content
        category: One of: finding, credential, vulnerability, artifact, task, info
        severity: One of: critical, high, medium, low, info
        tags: Optional list of tags
        evidence: Optional supporting evidence
        **metadata: Additional metadata fields

    Returns:
        Success message with note details
    """
    try:
        store = get_store()
        note = store.create(
            key=key,
            value=value,
            category=category,
            severity=severity,
            tags=tags,
            evidence=evidence,
            **metadata,
        )
        return f"Created note '{key}' in category '{category}' with severity '{severity}'"
    except ValueError as e:
        return f"Error: {e}"


async def notes_read(key: str) -> str:
    """
    Read a note by key.

    Args:
        key: The note identifier

    Returns:
        Note content and metadata, or error if not found
    """
    store = get_store()
    note = store.read(key)
    if note:
        result = [
            f"Key: {note.key}",
            f"Category: {note.category}",
            f"Severity: {note.severity}",
            f"Value: {note.value}",
        ]
        if note.evidence:
            result.append(f"Evidence: {note.evidence}")
        if note.tags:
            result.append(f"Tags: {', '.join(note.tags)}")
        return "\n".join(result)
    return f"Note '{key}' not found"


async def notes_update(
    key: str,
    value: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[List[str]] = None,
    evidence: Optional[str] = None,
    **metadata: Any,
) -> str:
    """
    Update an existing note.

    Args:
        key: The note identifier
        value: New content (optional)
        category: New category (optional)
        severity: New severity (optional)
        tags: New tags (optional)
        evidence: New evidence (optional)
        **metadata: Additional metadata to merge

    Returns:
        Success message or error if not found
    """
    store = get_store()
    note = store.update(
        key=key,
        value=value,
        category=category,
        severity=severity,
        tags=tags,
        evidence=evidence,
        **metadata,
    )
    if note:
        return f"Updated note '{key}'"
    return f"Note '{key}' not found"


async def notes_delete(key: str) -> str:
    """
    Delete a note.

    Args:
        key: The note identifier

    Returns:
        Success message or error if not found
    """
    store = get_store()
    if store.delete(key):
        return f"Deleted note '{key}'"
    return f"Note '{key}' not found"


async def notes_list(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    tag: Optional[str] = None,
) -> str:
    """
    List all notes with optional filtering.

    Args:
        category: Filter by category (finding, credential, vulnerability, artifact, task, info)
        severity: Filter by severity (critical, high, medium, low, info)
        tag: Filter by tag

    Returns:
        Formatted list of notes
    """
    store = get_store()
    notes = store.list(category=category, severity=severity, tag=tag)

    if not notes:
        filters = []
        if category:
            filters.append(f"category={category}")
        if severity:
            filters.append(f"severity={severity}")
        if tag:
            filters.append(f"tag={tag}")
        filter_str = f" ({', '.join(filters)})" if filters else ""
        return f"No notes found{filter_str}"

    lines = [f"Found {len(notes)} notes:"]
    for note in notes:
        severity_badge = f"[{note.severity.upper()}]" if note.severity != "info" else ""
        lines.append(f"  - {note.key} ({note.category}) {severity_badge}: {note.value[:50]}...")

    return "\n".join(lines)


async def notes_search(query: str) -> str:
    """
    Search notes by content.

    Args:
        query: Search query (case-insensitive)

    Returns:
        Matching notes
    """
    store = get_store()
    notes = store.search(query)

    if not notes:
        return f"No notes matching '{query}'"

    lines = [f"Found {len(notes)} notes matching '{query}':"]
    for note in notes:
        lines.append(f"  - {note.key} ({note.category}): {note.value[:50]}...")

    return "\n".join(lines)


async def notes_export(format: str = "json") -> str:
    """
    Export all notes.

    Args:
        format: Export format ('json' or 'markdown')

    Returns:
        Exported notes content
    """
    store = get_store()
    if format.lower() == "markdown" or format.lower() == "md":
        return store.export_markdown()
    return store.export_json()


async def notes_stats() -> str:
    """
    Get notes statistics.

    Returns:
        Statistics about stored notes
    """
    store = get_store()
    stats = store.get_stats()

    lines = [
        f"Total notes: {stats['total']}",
        "",
        "By category:",
    ]
    for cat, count in sorted(stats["by_category"].items()):
        lines.append(f"  - {cat}: {count}")

    lines.append("")
    lines.append("By severity:")
    for sev, count in sorted(stats["by_severity"].items()):
        lines.append(f"  - {sev}: {count}")

    return "\n".join(lines)


async def notes_clear() -> str:
    """
    Clear all notes.

    Returns:
        Confirmation message
    """
    store = get_store()
    count = store.clear()
    return f"Cleared {count} notes"


# Tool definitions for AIPTX tool registry
NOTES_TOOLS = [
    {
        "name": "notes_create",
        "description": "Create a new note to record findings, credentials, vulnerabilities, or other information",
        "function": notes_create,
        "parameters": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Unique identifier for the note"},
                "value": {"type": "string", "description": "The note content"},
                "category": {
                    "type": "string",
                    "enum": ["finding", "credential", "vulnerability", "artifact", "task", "info"],
                    "description": "Note category",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level for findings",
                },
                "evidence": {"type": "string", "description": "Supporting evidence"},
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "notes_read",
        "description": "Read a specific note by its key",
        "function": notes_read,
        "parameters": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "The note identifier"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "notes_list",
        "description": "List all notes with optional filtering by category, severity, or tag",
        "function": notes_list,
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["finding", "credential", "vulnerability", "artifact", "task", "info"],
                    "description": "Filter by category",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity",
                },
                "tag": {"type": "string", "description": "Filter by tag"},
            },
        },
    },
    {
        "name": "notes_search",
        "description": "Search notes by content (case-insensitive)",
        "function": notes_search,
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "notes_delete",
        "description": "Delete a note by key",
        "function": notes_delete,
        "parameters": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "The note identifier"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "notes_export",
        "description": "Export all notes to JSON or Markdown format",
        "function": notes_export,
        "parameters": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["json", "markdown"],
                    "description": "Export format",
                },
            },
        },
    },
]
