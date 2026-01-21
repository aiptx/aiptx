"""
AIPTX Beast Mode - Feedback Collector
=====================================

Collect and store feedback from every exploitation attempt.
This data is used to improve payload selection and mutation strategies.
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
class PayloadFeedback:
    """Feedback data for a single payload attempt."""
    payload: str
    payload_type: str  # sqli, xss, cmdi, etc.
    success: bool
    target_url: str
    endpoint: str
    parameter: str
    http_method: str = "GET"
    status_code: int = 0
    response_length: int = 0
    response_time_ms: float = 0.0
    waf_detected: str | None = None
    mutations_applied: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def payload_hash(self) -> str:
        """Generate a hash of the payload for deduplication."""
        return hashlib.sha256(self.payload.encode()).hexdigest()[:16]

    def context_hash(self) -> str:
        """Generate a hash of the context for grouping similar attempts."""
        context_str = f"{self.target_url}:{self.endpoint}:{self.parameter}:{self.waf_detected or 'none'}"
        return hashlib.sha256(context_str.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload": self.payload,
            "payload_type": self.payload_type,
            "success": self.success,
            "target_url": self.target_url,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "http_method": self.http_method,
            "status_code": self.status_code,
            "response_length": self.response_length,
            "response_time_ms": self.response_time_ms,
            "waf_detected": self.waf_detected,
            "mutations_applied": self.mutations_applied,
            "context": self.context,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
        }


class FeedbackCollector:
    """
    Collect and persist feedback from exploitation attempts.

    Stores data in SQLite for efficient querying and analysis.
    """

    def __init__(self, db_path: str | Path | None = None):
        """
        Initialize the feedback collector.

        Args:
            db_path: Path to SQLite database. Uses in-memory if None.
        """
        if db_path:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        else:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)

        self._init_schema()
        self._feedback_cache: list[PayloadFeedback] = []

    def _init_schema(self):
        """Initialize database schema."""
        cursor = self._conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_hash TEXT NOT NULL,
                context_hash TEXT NOT NULL,
                payload TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                success INTEGER NOT NULL,
                target_url TEXT,
                endpoint TEXT,
                parameter TEXT,
                http_method TEXT,
                status_code INTEGER,
                response_length INTEGER,
                response_time_ms REAL,
                waf_detected TEXT,
                mutations_applied TEXT,
                context TEXT,
                error_message TEXT,
                timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_feedback_payload_hash
            ON feedback(payload_hash)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_feedback_context_hash
            ON feedback(context_hash)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_feedback_success
            ON feedback(success)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_feedback_payload_type
            ON feedback(payload_type)
        """)

        # Aggregated statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payload_stats (
                payload_hash TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                total_attempts INTEGER DEFAULT 0,
                successful_attempts INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0,
                avg_response_time REAL DEFAULT 0.0,
                last_success TEXT,
                last_attempt TEXT,
                waf_success_rates TEXT DEFAULT '{}'
            )
        """)

        self._conn.commit()

    def record(self, feedback: PayloadFeedback):
        """
        Record a payload feedback entry.

        Args:
            feedback: The feedback to record
        """
        cursor = self._conn.cursor()

        cursor.execute("""
            INSERT INTO feedback (
                payload_hash, context_hash, payload, payload_type, success,
                target_url, endpoint, parameter, http_method, status_code,
                response_length, response_time_ms, waf_detected, mutations_applied,
                context, error_message, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            feedback.payload_hash(),
            feedback.context_hash(),
            feedback.payload,
            feedback.payload_type,
            1 if feedback.success else 0,
            feedback.target_url,
            feedback.endpoint,
            feedback.parameter,
            feedback.http_method,
            feedback.status_code,
            feedback.response_length,
            feedback.response_time_ms,
            feedback.waf_detected,
            json.dumps(feedback.mutations_applied),
            json.dumps(feedback.context),
            feedback.error_message,
            feedback.timestamp,
        ))

        # Update aggregated stats
        self._update_stats(feedback)

        self._conn.commit()
        self._feedback_cache.append(feedback)

        logger.debug(
            f"Recorded feedback: {feedback.payload_type} "
            f"{'SUCCESS' if feedback.success else 'FAIL'}"
        )

    def record_batch(self, feedbacks: list[PayloadFeedback]):
        """Record multiple feedback entries."""
        for feedback in feedbacks:
            self.record(feedback)

    def _update_stats(self, feedback: PayloadFeedback):
        """Update aggregated statistics for a payload."""
        cursor = self._conn.cursor()
        payload_hash = feedback.payload_hash()

        # Get existing stats
        cursor.execute(
            "SELECT * FROM payload_stats WHERE payload_hash = ?",
            (payload_hash,)
        )
        existing = cursor.fetchone()

        if existing:
            # Update existing
            total = existing[3] + 1
            successful = existing[4] + (1 if feedback.success else 0)
            success_rate = successful / total
            avg_time = (existing[6] * existing[3] + feedback.response_time_ms) / total

            # Update WAF success rates
            waf_rates = json.loads(existing[8] or "{}")
            waf_key = feedback.waf_detected or "none"
            if waf_key not in waf_rates:
                waf_rates[waf_key] = {"total": 0, "success": 0}
            waf_rates[waf_key]["total"] += 1
            if feedback.success:
                waf_rates[waf_key]["success"] += 1

            cursor.execute("""
                UPDATE payload_stats SET
                    total_attempts = ?,
                    successful_attempts = ?,
                    success_rate = ?,
                    avg_response_time = ?,
                    last_attempt = ?,
                    last_success = CASE WHEN ? THEN ? ELSE last_success END,
                    waf_success_rates = ?
                WHERE payload_hash = ?
            """, (
                total,
                successful,
                success_rate,
                avg_time,
                feedback.timestamp,
                feedback.success,
                feedback.timestamp,
                json.dumps(waf_rates),
                payload_hash,
            ))
        else:
            # Insert new
            waf_rates = {
                feedback.waf_detected or "none": {
                    "total": 1,
                    "success": 1 if feedback.success else 0
                }
            }

            cursor.execute("""
                INSERT INTO payload_stats (
                    payload_hash, payload, payload_type, total_attempts,
                    successful_attempts, success_rate, avg_response_time,
                    last_success, last_attempt, waf_success_rates
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                payload_hash,
                feedback.payload,
                feedback.payload_type,
                1,
                1 if feedback.success else 0,
                1.0 if feedback.success else 0.0,
                feedback.response_time_ms,
                feedback.timestamp if feedback.success else None,
                feedback.timestamp,
                json.dumps(waf_rates),
            ))

    def get_success_rate(
        self,
        payload: str | None = None,
        payload_type: str | None = None,
        waf: str | None = None,
    ) -> float:
        """
        Get success rate for a payload or payload type.

        Args:
            payload: Specific payload to check
            payload_type: Payload type (sqli, xss, etc.)
            waf: WAF type to filter by

        Returns:
            Success rate as float (0.0 to 1.0)
        """
        cursor = self._conn.cursor()

        if payload:
            payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
            cursor.execute(
                "SELECT success_rate FROM payload_stats WHERE payload_hash = ?",
                (payload_hash,)
            )
            result = cursor.fetchone()
            return result[0] if result else 0.5  # Default to 50% for unknown

        # Build query for payload type
        query = "SELECT AVG(success) FROM feedback WHERE 1=1"
        params = []

        if payload_type:
            query += " AND payload_type = ?"
            params.append(payload_type)

        if waf:
            query += " AND waf_detected = ?"
            params.append(waf)

        cursor.execute(query, params)
        result = cursor.fetchone()
        return result[0] if result and result[0] is not None else 0.5

    def get_best_payloads(
        self,
        payload_type: str,
        waf: str | None = None,
        limit: int = 10,
    ) -> list[tuple[str, float]]:
        """
        Get the best performing payloads for a type.

        Args:
            payload_type: Payload type (sqli, xss, etc.)
            waf: Optional WAF filter
            limit: Maximum payloads to return

        Returns:
            List of (payload, success_rate) tuples
        """
        cursor = self._conn.cursor()

        query = """
            SELECT payload, success_rate
            FROM payload_stats
            WHERE payload_type = ? AND total_attempts >= 3
            ORDER BY success_rate DESC, total_attempts DESC
            LIMIT ?
        """

        cursor.execute(query, (payload_type, limit))
        results = cursor.fetchall()

        # Filter by WAF if specified
        if waf:
            filtered = []
            for payload, overall_rate in results:
                payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
                cursor.execute(
                    "SELECT waf_success_rates FROM payload_stats WHERE payload_hash = ?",
                    (payload_hash,)
                )
                row = cursor.fetchone()
                if row:
                    waf_rates = json.loads(row[0] or "{}")
                    if waf in waf_rates and waf_rates[waf]["total"] >= 2:
                        waf_rate = waf_rates[waf]["success"] / waf_rates[waf]["total"]
                        filtered.append((payload, waf_rate))
            return sorted(filtered, key=lambda x: x[1], reverse=True)[:limit]

        return results

    def get_mutation_effectiveness(
        self,
        payload_type: str,
        waf: str | None = None,
    ) -> dict[str, float]:
        """
        Get effectiveness of different mutation techniques.

        Args:
            payload_type: Payload type to analyze
            waf: Optional WAF filter

        Returns:
            Dict mapping mutation name to success rate
        """
        cursor = self._conn.cursor()

        query = """
            SELECT mutations_applied, success
            FROM feedback
            WHERE payload_type = ?
        """
        params = [payload_type]

        if waf:
            query += " AND waf_detected = ?"
            params.append(waf)

        cursor.execute(query, params)

        mutation_stats: dict[str, dict[str, int]] = {}

        for row in cursor.fetchall():
            mutations = json.loads(row[0] or "[]")
            success = row[1]

            for mutation in mutations:
                if mutation not in mutation_stats:
                    mutation_stats[mutation] = {"total": 0, "success": 0}
                mutation_stats[mutation]["total"] += 1
                if success:
                    mutation_stats[mutation]["success"] += 1

        # Calculate rates
        return {
            mutation: stats["success"] / stats["total"]
            for mutation, stats in mutation_stats.items()
            if stats["total"] >= 3
        }

    def export_data(self, file_path: str | Path):
        """Export all feedback data to JSON."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM feedback")
        columns = [desc[0] for desc in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)

        logger.info(f"Exported {len(rows)} feedback entries to {file_path}")

    def import_data(self, file_path: str | Path):
        """Import feedback data from JSON."""
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        for entry in data:
            feedback = PayloadFeedback(
                payload=entry.get("payload", ""),
                payload_type=entry.get("payload_type", "unknown"),
                success=bool(entry.get("success", False)),
                target_url=entry.get("target_url", ""),
                endpoint=entry.get("endpoint", ""),
                parameter=entry.get("parameter", ""),
                http_method=entry.get("http_method", "GET"),
                status_code=entry.get("status_code", 0),
                response_length=entry.get("response_length", 0),
                response_time_ms=entry.get("response_time_ms", 0.0),
                waf_detected=entry.get("waf_detected"),
                mutations_applied=entry.get("mutations_applied", []),
                context=entry.get("context", {}),
                error_message=entry.get("error_message"),
                timestamp=entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )
            self.record(feedback)

        logger.info(f"Imported {len(data)} feedback entries")

    def close(self):
        """Close database connection."""
        self._conn.close()


# Global collector instance
_global_collector: FeedbackCollector | None = None


def get_collector() -> FeedbackCollector:
    """Get or create the global feedback collector."""
    global _global_collector
    if _global_collector is None:
        _global_collector = FeedbackCollector()
    return _global_collector


def collect_feedback(feedback: PayloadFeedback):
    """Convenience function to record feedback."""
    collector = get_collector()
    collector.record(feedback)


__all__ = [
    "PayloadFeedback",
    "FeedbackCollector",
    "get_collector",
    "collect_feedback",
]
