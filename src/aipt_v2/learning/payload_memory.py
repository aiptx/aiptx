"""
AIPTX Beast Mode - Payload Memory
=================================

Long-term storage of successful payloads and their contexts.
Enables knowledge transfer between engagements.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class StoredPayload:
    """A payload stored in memory with its metadata."""
    payload: str
    payload_type: str
    success_rate: float
    total_uses: int
    waf_compatibility: dict[str, float] = field(default_factory=dict)
    contexts_successful: list[str] = field(default_factory=list)
    mutations_applied: list[str] = field(default_factory=list)
    first_success: str | None = None
    last_success: str | None = None
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    def payload_hash(self) -> str:
        """Generate hash for this payload."""
        return hashlib.sha256(self.payload.encode()).hexdigest()[:16]

    def is_effective_against_waf(self, waf: str, threshold: float = 0.5) -> bool:
        """Check if payload is effective against a specific WAF."""
        return self.waf_compatibility.get(waf, 0.0) >= threshold

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload": self.payload,
            "payload_type": self.payload_type,
            "success_rate": self.success_rate,
            "total_uses": self.total_uses,
            "waf_compatibility": self.waf_compatibility,
            "contexts_successful": self.contexts_successful,
            "mutations_applied": self.mutations_applied,
            "first_success": self.first_success,
            "last_success": self.last_success,
            "notes": self.notes,
            "tags": self.tags,
        }


class PayloadMemory:
    """
    Long-term memory for successful payloads.

    Stores payloads that have been successful in the past,
    along with context about when and where they worked.
    """

    def __init__(self, db_path: str | Path | None = None):
        """
        Initialize payload memory.

        Args:
            db_path: Path to SQLite database. Uses default location if None.
        """
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path.home() / ".aiptx" / "payload_memory.db"

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        """Initialize database schema."""
        cursor = self._conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                payload_hash TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                success_rate REAL DEFAULT 0.0,
                total_uses INTEGER DEFAULT 0,
                waf_compatibility TEXT DEFAULT '{}',
                contexts_successful TEXT DEFAULT '[]',
                mutations_applied TEXT DEFAULT '[]',
                first_success TEXT,
                last_success TEXT,
                notes TEXT DEFAULT '',
                tags TEXT DEFAULT '[]',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_payloads_type
            ON payloads(payload_type)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_payloads_success_rate
            ON payloads(success_rate DESC)
        """)

        # Context table for efficient querying
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payload_contexts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_hash TEXT NOT NULL,
                context_type TEXT NOT NULL,
                context_value TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                FOREIGN KEY (payload_hash) REFERENCES payloads(payload_hash)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_contexts_type
            ON payload_contexts(context_type, context_value)
        """)

        self._conn.commit()

    def store(
        self,
        payload: str,
        payload_type: str,
        success: bool = True,
        waf: str | None = None,
        context: str | None = None,
        mutations: list[str] | None = None,
        tags: list[str] | None = None,
        notes: str = "",
    ):
        """
        Store a payload in memory.

        Args:
            payload: The payload string
            payload_type: Type (sqli, xss, cmdi, etc.)
            success: Whether this use was successful
            waf: WAF type if detected
            context: Context identifier (e.g., "wordpress", "nginx")
            mutations: Mutations applied to this payload
            tags: Optional tags for categorization
            notes: Optional notes about this payload
        """
        cursor = self._conn.cursor()
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        timestamp = datetime.now(timezone.utc).isoformat()

        # Check if exists
        cursor.execute(
            "SELECT * FROM payloads WHERE payload_hash = ?",
            (payload_hash,)
        )
        existing = cursor.fetchone()

        if existing:
            # Update existing
            total_uses = existing[4] + 1
            successful = existing[4] * existing[3] + (1 if success else 0)
            success_rate = successful / total_uses

            # Update WAF compatibility
            waf_compat = json.loads(existing[5] or "{}")
            if waf:
                if waf not in waf_compat:
                    waf_compat[waf] = {"total": 0, "success": 0}
                waf_compat[waf]["total"] += 1
                if success:
                    waf_compat[waf]["success"] += 1

            # Update contexts
            contexts = json.loads(existing[6] or "[]")
            if context and context not in contexts and success:
                contexts.append(context)

            # Update mutations
            stored_mutations = json.loads(existing[7] or "[]")
            if mutations:
                for m in mutations:
                    if m not in stored_mutations:
                        stored_mutations.append(m)

            # Merge tags
            stored_tags = json.loads(existing[11] or "[]")
            if tags:
                for t in tags:
                    if t not in stored_tags:
                        stored_tags.append(t)

            cursor.execute("""
                UPDATE payloads SET
                    success_rate = ?,
                    total_uses = ?,
                    waf_compatibility = ?,
                    contexts_successful = ?,
                    mutations_applied = ?,
                    last_success = CASE WHEN ? THEN ? ELSE last_success END,
                    notes = CASE WHEN ? != '' THEN ? ELSE notes END,
                    tags = ?,
                    updated_at = ?
                WHERE payload_hash = ?
            """, (
                success_rate,
                total_uses,
                json.dumps(waf_compat),
                json.dumps(contexts),
                json.dumps(stored_mutations),
                success,
                timestamp,
                notes,
                notes,
                json.dumps(stored_tags),
                timestamp,
                payload_hash,
            ))

        else:
            # Insert new
            waf_compat = {}
            if waf:
                waf_compat[waf] = {"total": 1, "success": 1 if success else 0}

            contexts = [context] if context and success else []

            cursor.execute("""
                INSERT INTO payloads (
                    payload_hash, payload, payload_type, success_rate,
                    total_uses, waf_compatibility, contexts_successful,
                    mutations_applied, first_success, last_success,
                    notes, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                payload_hash,
                payload,
                payload_type,
                1.0 if success else 0.0,
                1,
                json.dumps(waf_compat),
                json.dumps(contexts),
                json.dumps(mutations or []),
                timestamp if success else None,
                timestamp if success else None,
                notes,
                json.dumps(tags or []),
            ))

        # Update context index
        if context:
            cursor.execute("""
                INSERT INTO payload_contexts (payload_hash, context_type, context_value, success_count)
                VALUES (?, 'general', ?, ?)
                ON CONFLICT DO UPDATE SET success_count = success_count + ?
            """, (payload_hash, context, 1 if success else 0, 1 if success else 0))

        self._conn.commit()
        logger.debug(f"Stored payload {payload_hash} ({payload_type})")

    def get(self, payload: str) -> StoredPayload | None:
        """Get a stored payload by its content."""
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        return self.get_by_hash(payload_hash)

    def get_by_hash(self, payload_hash: str) -> StoredPayload | None:
        """Get a stored payload by its hash."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT * FROM payloads WHERE payload_hash = ?",
            (payload_hash,)
        )
        row = cursor.fetchone()

        if not row:
            return None

        # Parse WAF compatibility
        waf_compat_raw = json.loads(row[5] or "{}")
        waf_compat = {
            waf: data["success"] / data["total"] if data["total"] > 0 else 0.0
            for waf, data in waf_compat_raw.items()
        }

        return StoredPayload(
            payload=row[1],
            payload_type=row[2],
            success_rate=row[3],
            total_uses=row[4],
            waf_compatibility=waf_compat,
            contexts_successful=json.loads(row[6] or "[]"),
            mutations_applied=json.loads(row[7] or "[]"),
            first_success=row[8],
            last_success=row[9],
            notes=row[10] or "",
            tags=json.loads(row[11] or "[]"),
        )

    def get_best(
        self,
        payload_type: str,
        waf: str | None = None,
        context: str | None = None,
        limit: int = 10,
        min_uses: int = 2,
    ) -> list[StoredPayload]:
        """
        Get the best payloads for a given scenario.

        Args:
            payload_type: Type of payload needed
            waf: Target WAF (if known)
            context: Target context
            limit: Maximum results
            min_uses: Minimum uses to consider

        Returns:
            List of StoredPayload objects sorted by effectiveness
        """
        cursor = self._conn.cursor()

        query = """
            SELECT * FROM payloads
            WHERE payload_type = ? AND total_uses >= ?
            ORDER BY success_rate DESC, total_uses DESC
            LIMIT ?
        """

        cursor.execute(query, (payload_type, min_uses, limit * 3))
        rows = cursor.fetchall()

        results = []
        for row in rows:
            stored = StoredPayload(
                payload=row[1],
                payload_type=row[2],
                success_rate=row[3],
                total_uses=row[4],
                waf_compatibility=json.loads(row[5] or "{}"),
                contexts_successful=json.loads(row[6] or "[]"),
                mutations_applied=json.loads(row[7] or "[]"),
                first_success=row[8],
                last_success=row[9],
                notes=row[10] or "",
                tags=json.loads(row[11] or "[]"),
            )

            # Calculate adjusted score
            score = stored.success_rate

            # Boost for WAF compatibility
            if waf and waf in stored.waf_compatibility:
                waf_rate = stored.waf_compatibility[waf]
                score = (score + waf_rate) / 2  # Average with WAF-specific rate

            # Boost for context match
            if context and context in stored.contexts_successful:
                score *= 1.2

            stored._adjusted_score = score
            results.append(stored)

        # Sort by adjusted score
        results.sort(key=lambda x: getattr(x, '_adjusted_score', 0), reverse=True)
        return results[:limit]

    def get_by_tag(self, tag: str, limit: int = 20) -> list[StoredPayload]:
        """Get payloads by tag."""
        cursor = self._conn.cursor()

        # SQLite JSON query
        cursor.execute("""
            SELECT * FROM payloads
            WHERE tags LIKE ?
            ORDER BY success_rate DESC
            LIMIT ?
        """, (f'%"{tag}"%', limit))

        return [self._row_to_stored(row) for row in cursor.fetchall()]

    def search(
        self,
        query: str,
        payload_type: str | None = None,
        limit: int = 20,
    ) -> list[StoredPayload]:
        """Search payloads by content."""
        cursor = self._conn.cursor()

        sql = """
            SELECT * FROM payloads
            WHERE payload LIKE ?
        """
        params = [f"%{query}%"]

        if payload_type:
            sql += " AND payload_type = ?"
            params.append(payload_type)

        sql += " ORDER BY success_rate DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, params)
        return [self._row_to_stored(row) for row in cursor.fetchall()]

    def _row_to_stored(self, row) -> StoredPayload:
        """Convert database row to StoredPayload."""
        waf_compat_raw = json.loads(row[5] or "{}")
        waf_compat = {
            waf: data["success"] / data["total"] if data["total"] > 0 else 0.0
            for waf, data in waf_compat_raw.items()
        }

        return StoredPayload(
            payload=row[1],
            payload_type=row[2],
            success_rate=row[3],
            total_uses=row[4],
            waf_compatibility=waf_compat,
            contexts_successful=json.loads(row[6] or "[]"),
            mutations_applied=json.loads(row[7] or "[]"),
            first_success=row[8],
            last_success=row[9],
            notes=row[10] or "",
            tags=json.loads(row[11] or "[]"),
        )

    def export(self, file_path: str | Path):
        """Export all payloads to JSON."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM payloads ORDER BY success_rate DESC")

        payloads = [self._row_to_stored(row).to_dict() for row in cursor.fetchall()]

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payloads, f, indent=2)

        logger.info(f"Exported {len(payloads)} payloads to {file_path}")

    def import_payloads(self, file_path: str | Path):
        """Import payloads from JSON."""
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        for entry in data:
            self.store(
                payload=entry.get("payload", ""),
                payload_type=entry.get("payload_type", "unknown"),
                success=entry.get("success_rate", 0) > 0.5,
                mutations=entry.get("mutations_applied", []),
                tags=entry.get("tags", []),
                notes=entry.get("notes", ""),
            )

        logger.info(f"Imported {len(data)} payloads")

    def close(self):
        """Close database connection."""
        self._conn.close()


# Global instance
_global_memory: PayloadMemory | None = None


def get_memory() -> PayloadMemory:
    """Get or create the global payload memory."""
    global _global_memory
    if _global_memory is None:
        _global_memory = PayloadMemory()
    return _global_memory


def get_best_payloads(
    payload_type: str,
    waf: str | None = None,
    limit: int = 10,
) -> list[StoredPayload]:
    """Convenience function to get best payloads."""
    memory = get_memory()
    return memory.get_best(payload_type, waf=waf, limit=limit)


__all__ = [
    "StoredPayload",
    "PayloadMemory",
    "get_memory",
    "get_best_payloads",
]
