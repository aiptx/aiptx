"""
AIPTX Notes System - Assessment Findings Tracker

Track findings, methodology notes, and questions during security assessments.
Supports categories: general, findings, methodology, questions, plan

Features:
- In-memory storage with optional JSON persistence
- Full-text search across notes
- Tag-based organization
- Export to markdown for reports
"""

__version__ = "2.1.0"

from aipt_v2.tools.notes.notes_actions import (
    create_note,
    delete_note,
    export_notes,
    get_note,
    list_notes,
    update_note,
)

__all__ = [
    "create_note",
    "list_notes",
    "get_note",
    "update_note",
    "delete_note",
    "export_notes",
]
