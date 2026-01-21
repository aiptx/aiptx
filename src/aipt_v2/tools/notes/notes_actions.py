"""
AIPTX Notes Actions - CRUD Operations for Assessment Notes

Provides note management during security assessments. Notes are stored
in-memory by default with optional JSON persistence.

Categories:
- general: General observations
- findings: Discovered vulnerabilities/issues
- methodology: Attack methodology and approach
- questions: Questions to investigate
- plan: Attack planning notes
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# In-memory notes storage (keyed by note_id)
_notes_storage: dict[str, dict[str, Any]] = {}

# Valid categories for notes
VALID_CATEGORIES = ["general", "findings", "methodology", "questions", "plan"]

# Optional persistence file
_persistence_file: Path | None = None


def set_persistence_file(file_path: str | Path | None) -> None:
    """
    Enable or disable note persistence to JSON file.

    Args:
        file_path: Path to JSON file, or None to disable persistence
    """
    global _persistence_file
    if file_path:
        _persistence_file = Path(file_path)
        # Load existing notes if file exists
        if _persistence_file.exists():
            _load_from_file()
    else:
        _persistence_file = None


def _save_to_file() -> None:
    """Save notes to persistence file if configured."""
    if _persistence_file:
        try:
            with open(_persistence_file, "w", encoding="utf-8") as f:
                json.dump(_notes_storage, f, indent=2)
            logger.debug(f"Notes saved to {_persistence_file}")
        except Exception as e:
            logger.error(f"Failed to save notes: {e}")


def _load_from_file() -> None:
    """Load notes from persistence file if it exists."""
    global _notes_storage
    if _persistence_file and _persistence_file.exists():
        try:
            with open(_persistence_file, encoding="utf-8") as f:
                _notes_storage = json.load(f)
            logger.info(f"Loaded {len(_notes_storage)} notes from {_persistence_file}")
        except Exception as e:
            logger.error(f"Failed to load notes: {e}")


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
) -> list[dict[str, Any]]:
    """
    Filter notes by category, tags, or search query.

    Args:
        category: Filter by category name
        tags: Filter by any matching tag
        search_query: Search in title and content

    Returns:
        List of matching notes with note_id included
    """
    filtered_notes = []

    for note_id, note in _notes_storage.items():
        # Filter by category
        if category and note.get("category") != category:
            continue

        # Filter by tags (any match)
        if tags:
            note_tags = note.get("tags", [])
            if not any(tag in note_tags for tag in tags):
                continue

        # Filter by search query
        if search_query:
            search_lower = search_query.lower()
            title_match = search_lower in note.get("title", "").lower()
            content_match = search_lower in note.get("content", "").lower()
            tag_match = any(search_lower in t.lower() for t in note.get("tags", []))
            if not (title_match or content_match or tag_match):
                continue

        # Include note_id in result
        note_with_id = note.copy()
        note_with_id["note_id"] = note_id
        filtered_notes.append(note_with_id)

    # Sort by creation time (newest first)
    filtered_notes.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return filtered_notes


def create_note(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """
    Create a new note.

    Args:
        title: Note title (required)
        content: Note content (required)
        category: One of: general, findings, methodology, questions, plan
        tags: Optional list of tags for organization

    Returns:
        dict with success status and note_id
    """
    try:
        if not title or not title.strip():
            return {"success": False, "error": "Title cannot be empty", "note_id": None}

        if not content or not content.strip():
            return {"success": False, "error": "Content cannot be empty", "note_id": None}

        if category not in VALID_CATEGORIES:
            return {
                "success": False,
                "error": f"Invalid category. Must be one of: {', '.join(VALID_CATEGORIES)}",
                "note_id": None,
            }

        # Generate short unique ID
        note_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now(timezone.utc).isoformat()

        note = {
            "title": title.strip(),
            "content": content.strip(),
            "category": category,
            "tags": [t.strip() for t in (tags or []) if t.strip()],
            "created_at": timestamp,
            "updated_at": timestamp,
        }

        _notes_storage[note_id] = note
        _save_to_file()

        logger.info(f"Created note: {note_id} - {title}")

        return {
            "success": True,
            "note_id": note_id,
            "message": f"Note '{title}' created successfully in category '{category}'",
        }

    except Exception as e:
        logger.error(f"Failed to create note: {e}")
        return {"success": False, "error": f"Failed to create note: {e}", "note_id": None}


def list_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """
    List notes with optional filters.

    Args:
        category: Filter by category
        tags: Filter by tags (any match)
        search: Search in title and content
        limit: Maximum number of notes to return

    Returns:
        dict with notes list and count
    """
    try:
        filtered_notes = _filter_notes(category=category, tags=tags, search_query=search)

        if limit:
            filtered_notes = filtered_notes[:limit]

        return {
            "success": True,
            "notes": filtered_notes,
            "total_count": len(filtered_notes),
            "filters_applied": {
                "category": category,
                "tags": tags,
                "search": search,
            },
        }

    except Exception as e:
        logger.error(f"Failed to list notes: {e}")
        return {
            "success": False,
            "error": f"Failed to list notes: {e}",
            "notes": [],
            "total_count": 0,
        }


def get_note(note_id: str) -> dict[str, Any]:
    """
    Get a specific note by ID.

    Args:
        note_id: The note identifier

    Returns:
        dict with note data or error
    """
    try:
        if note_id not in _notes_storage:
            return {"success": False, "error": f"Note '{note_id}' not found", "note": None}

        note = _notes_storage[note_id].copy()
        note["note_id"] = note_id

        return {"success": True, "note": note}

    except Exception as e:
        logger.error(f"Failed to get note: {e}")
        return {"success": False, "error": f"Failed to get note: {e}", "note": None}


def update_note(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    category: str | None = None,
    tags: list[str] | None = None,
    append_content: str | None = None,
) -> dict[str, Any]:
    """
    Update an existing note.

    Args:
        note_id: The note identifier
        title: New title (optional)
        content: New content (optional)
        category: New category (optional)
        tags: New tags (optional)
        append_content: Content to append (optional)

    Returns:
        dict with success status
    """
    try:
        if note_id not in _notes_storage:
            return {"success": False, "error": f"Note '{note_id}' not found"}

        note = _notes_storage[note_id]

        if title is not None:
            if not title.strip():
                return {"success": False, "error": "Title cannot be empty"}
            note["title"] = title.strip()

        if content is not None:
            if not content.strip():
                return {"success": False, "error": "Content cannot be empty"}
            note["content"] = content.strip()

        if category is not None:
            if category not in VALID_CATEGORIES:
                return {
                    "success": False,
                    "error": f"Invalid category. Must be one of: {', '.join(VALID_CATEGORIES)}",
                }
            note["category"] = category

        if tags is not None:
            note["tags"] = [t.strip() for t in tags if t.strip()]

        if append_content:
            note["content"] = note["content"] + "\n\n" + append_content.strip()

        note["updated_at"] = datetime.now(timezone.utc).isoformat()
        _save_to_file()

        logger.info(f"Updated note: {note_id}")

        return {
            "success": True,
            "message": f"Note '{note['title']}' updated successfully",
        }

    except Exception as e:
        logger.error(f"Failed to update note: {e}")
        return {"success": False, "error": f"Failed to update note: {e}"}


def delete_note(note_id: str) -> dict[str, Any]:
    """
    Delete a note by ID.

    Args:
        note_id: The note identifier

    Returns:
        dict with success status
    """
    try:
        if note_id not in _notes_storage:
            return {"success": False, "error": f"Note '{note_id}' not found"}

        note_title = _notes_storage[note_id]["title"]
        del _notes_storage[note_id]
        _save_to_file()

        logger.info(f"Deleted note: {note_id} - {note_title}")

        return {
            "success": True,
            "message": f"Note '{note_title}' deleted successfully",
        }

    except Exception as e:
        logger.error(f"Failed to delete note: {e}")
        return {"success": False, "error": f"Failed to delete note: {e}"}


def export_notes(
    category: str | None = None,
    format: str = "markdown",
) -> dict[str, Any]:
    """
    Export notes to a formatted string.

    Args:
        category: Optional category filter
        format: Output format (markdown, json, text)

    Returns:
        dict with exported content
    """
    try:
        notes = _filter_notes(category=category)

        if format == "json":
            content = json.dumps(notes, indent=2)

        elif format == "text":
            lines = []
            for note in notes:
                lines.append(f"[{note['category'].upper()}] {note['title']}")
                lines.append(f"ID: {note['note_id']} | Created: {note['created_at']}")
                if note.get("tags"):
                    lines.append(f"Tags: {', '.join(note['tags'])}")
                lines.append("-" * 40)
                lines.append(note["content"])
                lines.append("\n")
            content = "\n".join(lines)

        else:  # markdown
            lines = ["# Assessment Notes\n"]

            # Group by category
            categories_found = {}
            for note in notes:
                cat = note["category"]
                if cat not in categories_found:
                    categories_found[cat] = []
                categories_found[cat].append(note)

            for cat, cat_notes in categories_found.items():
                lines.append(f"\n## {cat.title()}\n")
                for note in cat_notes:
                    lines.append(f"### {note['title']}")
                    lines.append(f"*ID: {note['note_id']} | {note['created_at']}*\n")
                    if note.get("tags"):
                        lines.append(f"**Tags:** {', '.join(note['tags'])}\n")
                    lines.append(note["content"])
                    lines.append("\n---\n")

            content = "\n".join(lines)

        return {
            "success": True,
            "content": content,
            "format": format,
            "note_count": len(notes),
        }

    except Exception as e:
        logger.error(f"Failed to export notes: {e}")
        return {
            "success": False,
            "error": f"Failed to export notes: {e}",
            "content": "",
        }


def clear_all_notes() -> dict[str, Any]:
    """
    Clear all notes from storage.

    Returns:
        dict with success status
    """
    global _notes_storage
    count = len(_notes_storage)
    _notes_storage = {}
    _save_to_file()
    logger.info(f"Cleared {count} notes")
    return {"success": True, "message": f"Cleared {count} notes"}


def get_notes_summary() -> dict[str, Any]:
    """
    Get a summary of notes by category.

    Returns:
        dict with category counts
    """
    summary = {cat: 0 for cat in VALID_CATEGORIES}
    for note in _notes_storage.values():
        cat = note.get("category", "general")
        summary[cat] = summary.get(cat, 0) + 1

    return {
        "success": True,
        "total": len(_notes_storage),
        "by_category": summary,
        "categories": VALID_CATEGORIES,
    }


__all__ = [
    "create_note",
    "list_notes",
    "get_note",
    "update_note",
    "delete_note",
    "export_notes",
    "clear_all_notes",
    "get_notes_summary",
    "set_persistence_file",
    "VALID_CATEGORIES",
]
