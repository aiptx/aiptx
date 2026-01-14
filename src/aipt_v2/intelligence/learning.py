"""
AIPT Feedback Learning System

Learns from exploitation attempts to improve future scans:
- Records successful/failed exploitation attempts
- Builds knowledge of what works for specific contexts
- Suggests optimal payloads based on historical success
- Tracks WAF bypass techniques that work

This creates a feedback loop that makes AIPT smarter over time.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from aipt_v2.models.findings import VulnerabilityType

logger = logging.getLogger(__name__)


@dataclass
class ExploitAttempt:
    """Record of an exploitation attempt."""
    vuln_type: str
    target_url: str
    payload: str
    success: bool
    tech_stack: Optional[str] = None
    waf: Optional[str] = None
    response_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    notes: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "target_url": self.target_url,
            "payload": self.payload,
            "success": self.success,
            "tech_stack": self.tech_stack,
            "waf": self.waf,
            "response_code": self.response_code,
            "response_time_ms": self.response_time_ms,
            "error_message": self.error_message,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PayloadSuggestion:
    """A suggested payload based on historical success."""
    payload: str
    success_count: int
    total_attempts: int
    success_rate: float
    avg_response_time_ms: Optional[float] = None
    common_waf: Optional[str] = None
    common_tech: Optional[str] = None

    @property
    def confidence(self) -> float:
        """Calculate confidence score."""
        # Higher success rate and more attempts = higher confidence
        sample_bonus = min(self.total_attempts / 10, 1.0)  # Max bonus at 10 attempts
        return self.success_rate * (0.5 + 0.5 * sample_bonus)


@dataclass
class TechniqueStats:
    """Statistics for a vulnerability type."""
    vuln_type: str
    total_attempts: int
    successful_attempts: int
    success_rate: float
    best_payload: Optional[str] = None
    best_payload_success_rate: Optional[float] = None
    common_waf_bypasses: list[str] = field(default_factory=list)


class ExploitationLearner:
    """
    Learns from exploitation attempts to improve future scans.

    Maintains a SQLite database of exploitation attempts and their outcomes,
    allowing AIPT to learn which techniques work best in different contexts.

    Example:
        learner = ExploitationLearner()

        # Record an attempt
        learner.record_attempt(ExploitAttempt(
            vuln_type="sql_injection",
            target_url="https://example.com/login",
            payload="' OR '1'='1",
            success=True,
            waf="cloudflare",
            tech_stack="php/mysql"
        ))

        # Get suggestions for future attempts
        suggestions = learner.get_payload_suggestions(
            vuln_type="sql_injection",
            waf="cloudflare"
        )
    """

    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default to ~/.aiptx/learning.db
            aiptx_dir = Path.home() / ".aiptx"
            aiptx_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(aiptx_dir / "learning.db")

        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize the SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Exploitation attempts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploit_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_type TEXT NOT NULL,
                target_url TEXT NOT NULL,
                payload TEXT NOT NULL,
                success INTEGER NOT NULL,
                tech_stack TEXT,
                waf TEXT,
                response_code INTEGER,
                response_time_ms INTEGER,
                error_message TEXT,
                notes TEXT,
                timestamp TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Index for faster queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_type ON exploit_attempts(vuln_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_success ON exploit_attempts(success)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_waf ON exploit_attempts(waf)
        """)

        # WAF bypass techniques table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS waf_bypasses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                waf_name TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                original_payload TEXT NOT NULL,
                bypass_payload TEXT NOT NULL,
                success INTEGER NOT NULL,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Payload effectiveness table (aggregated stats)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payload_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_type TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                payload TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                avg_response_time_ms REAL,
                last_success TEXT,
                last_failure TEXT,
                UNIQUE(vuln_type, payload_hash)
            )
        """)

        conn.commit()
        conn.close()

    def record_attempt(self, attempt: ExploitAttempt):
        """
        Record an exploitation attempt.

        Args:
            attempt: The exploitation attempt to record
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Insert attempt
        cursor.execute("""
            INSERT INTO exploit_attempts
            (vuln_type, target_url, payload, success, tech_stack, waf,
             response_code, response_time_ms, error_message, notes, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            attempt.vuln_type,
            attempt.target_url,
            attempt.payload,
            1 if attempt.success else 0,
            attempt.tech_stack,
            attempt.waf,
            attempt.response_code,
            attempt.response_time_ms,
            attempt.error_message,
            attempt.notes,
            attempt.timestamp.isoformat(),
        ))

        # Update payload stats
        payload_hash = self._hash_payload(attempt.payload)
        if attempt.success:
            cursor.execute("""
                INSERT INTO payload_stats (vuln_type, payload_hash, payload, success_count, last_success)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(vuln_type, payload_hash) DO UPDATE SET
                    success_count = success_count + 1,
                    last_success = ?
            """, (attempt.vuln_type, payload_hash, attempt.payload,
                  attempt.timestamp.isoformat(), attempt.timestamp.isoformat()))
        else:
            cursor.execute("""
                INSERT INTO payload_stats (vuln_type, payload_hash, payload, failure_count, last_failure)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(vuln_type, payload_hash) DO UPDATE SET
                    failure_count = failure_count + 1,
                    last_failure = ?
            """, (attempt.vuln_type, payload_hash, attempt.payload,
                  attempt.timestamp.isoformat(), attempt.timestamp.isoformat()))

        conn.commit()
        conn.close()

        logger.debug(f"Recorded {'successful' if attempt.success else 'failed'} "
                     f"attempt for {attempt.vuln_type}")

    def record_waf_bypass(
        self,
        waf_name: str,
        vuln_type: str,
        original_payload: str,
        bypass_payload: str,
        success: bool,
        notes: str = "",
    ):
        """
        Record a WAF bypass technique.

        Args:
            waf_name: Name of the WAF (e.g., "cloudflare", "akamai")
            vuln_type: Type of vulnerability being exploited
            original_payload: The blocked payload
            bypass_payload: The modified payload that bypassed the WAF
            success: Whether the bypass was successful
            notes: Additional notes
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO waf_bypasses
            (waf_name, vuln_type, original_payload, bypass_payload, success, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (waf_name, vuln_type, original_payload, bypass_payload,
              1 if success else 0, notes))

        conn.commit()
        conn.close()

        logger.info(f"Recorded WAF bypass for {waf_name}: {'success' if success else 'failure'}")

    def get_payload_suggestions(
        self,
        vuln_type: str,
        waf: str = None,
        tech_stack: str = None,
        limit: int = 10,
    ) -> list[PayloadSuggestion]:
        """
        Get payload suggestions based on historical success.

        Args:
            vuln_type: Type of vulnerability (e.g., "sql_injection")
            waf: Optional WAF name to filter for
            tech_stack: Optional tech stack to filter for
            limit: Maximum number of suggestions

        Returns:
            List of PayloadSuggestion objects ordered by success rate
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Build query based on filters
        query = """
            SELECT
                payload,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count,
                COUNT(*) as total_attempts,
                AVG(CASE WHEN success = 1 THEN response_time_ms ELSE NULL END) as avg_time,
                waf,
                tech_stack
            FROM exploit_attempts
            WHERE vuln_type = ?
        """
        params = [vuln_type]

        if waf:
            query += " AND (waf = ? OR waf IS NULL)"
            params.append(waf)

        if tech_stack:
            query += " AND (tech_stack LIKE ? OR tech_stack IS NULL)"
            params.append(f"%{tech_stack}%")

        query += """
            GROUP BY payload
            HAVING total_attempts >= 1
            ORDER BY (CAST(success_count AS FLOAT) / total_attempts) DESC,
                     success_count DESC
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        suggestions = []
        for row in rows:
            payload, success_count, total, avg_time, common_waf, common_tech = row
            suggestions.append(PayloadSuggestion(
                payload=payload,
                success_count=success_count,
                total_attempts=total,
                success_rate=success_count / total if total > 0 else 0,
                avg_response_time_ms=avg_time,
                common_waf=common_waf,
                common_tech=common_tech,
            ))

        return suggestions

    def get_waf_bypass_payloads(
        self,
        waf_name: str,
        vuln_type: str = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Get successful WAF bypass payloads.

        Args:
            waf_name: Name of the WAF
            vuln_type: Optional vulnerability type filter
            limit: Maximum results

        Returns:
            List of bypass payload dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = """
            SELECT vuln_type, original_payload, bypass_payload, notes
            FROM waf_bypasses
            WHERE waf_name = ? AND success = 1
        """
        params = [waf_name]

        if vuln_type:
            query += " AND vuln_type = ?"
            params.append(vuln_type)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "vuln_type": row[0],
                "original_payload": row[1],
                "bypass_payload": row[2],
                "notes": row[3],
            }
            for row in rows
        ]

    def get_technique_stats(self, vuln_type: str) -> TechniqueStats:
        """
        Get statistics for a vulnerability type.

        Args:
            vuln_type: The vulnerability type to analyze

        Returns:
            TechniqueStats with aggregated information
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get overall stats
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
            FROM exploit_attempts
            WHERE vuln_type = ?
        """, (vuln_type,))
        total, successes = cursor.fetchone()
        total = total or 0
        successes = successes or 0

        # Get best payload
        cursor.execute("""
            SELECT payload,
                   CAST(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) as rate
            FROM exploit_attempts
            WHERE vuln_type = ?
            GROUP BY payload
            HAVING COUNT(*) >= 3
            ORDER BY rate DESC
            LIMIT 1
        """, (vuln_type,))
        best_row = cursor.fetchone()

        # Get common WAF bypasses
        cursor.execute("""
            SELECT DISTINCT waf
            FROM exploit_attempts
            WHERE vuln_type = ? AND waf IS NOT NULL AND success = 1
            LIMIT 5
        """, (vuln_type,))
        waf_rows = cursor.fetchall()

        conn.close()

        return TechniqueStats(
            vuln_type=vuln_type,
            total_attempts=total,
            successful_attempts=successes,
            success_rate=successes / total if total > 0 else 0,
            best_payload=best_row[0] if best_row else None,
            best_payload_success_rate=best_row[1] if best_row else None,
            common_waf_bypasses=[row[0] for row in waf_rows],
        )

    def get_success_rate(
        self,
        vuln_type: str,
        tech_stack: str = None,
        waf: str = None,
    ) -> float:
        """
        Get historical success rate for a vulnerability type.

        Args:
            vuln_type: Vulnerability type
            tech_stack: Optional tech stack filter
            waf: Optional WAF filter

        Returns:
            Success rate as a float (0.0 to 1.0)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = """
            SELECT
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
                COUNT(*) as total
            FROM exploit_attempts
            WHERE vuln_type = ?
        """
        params = [vuln_type]

        if tech_stack:
            query += " AND tech_stack LIKE ?"
            params.append(f"%{tech_stack}%")

        if waf:
            query += " AND waf = ?"
            params.append(waf)

        cursor.execute(query, params)
        successes, total = cursor.fetchone()
        conn.close()

        if total and total > 0:
            return successes / total
        return 0.0

    def export_knowledge(self, output_path: str):
        """
        Export learned knowledge to JSON file.

        Args:
            output_path: Path to write JSON export
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get all payload stats
        cursor.execute("""
            SELECT vuln_type, payload, success_count, failure_count
            FROM payload_stats
            ORDER BY vuln_type, (success_count * 1.0 / (success_count + failure_count + 1)) DESC
        """)
        payload_rows = cursor.fetchall()

        # Get all WAF bypasses
        cursor.execute("""
            SELECT waf_name, vuln_type, original_payload, bypass_payload, success
            FROM waf_bypasses
            WHERE success = 1
        """)
        bypass_rows = cursor.fetchall()

        conn.close()

        export_data = {
            "exported_at": datetime.utcnow().isoformat(),
            "payload_knowledge": [
                {
                    "vuln_type": row[0],
                    "payload": row[1],
                    "success_count": row[2],
                    "failure_count": row[3],
                    "success_rate": row[2] / (row[2] + row[3]) if (row[2] + row[3]) > 0 else 0,
                }
                for row in payload_rows
            ],
            "waf_bypasses": [
                {
                    "waf": row[0],
                    "vuln_type": row[1],
                    "original": row[2],
                    "bypass": row[3],
                }
                for row in bypass_rows
            ],
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported knowledge to {output_path}")

    def import_knowledge(self, input_path: str):
        """
        Import knowledge from JSON file.

        Args:
            input_path: Path to JSON file to import
        """
        with open(input_path, "r") as f:
            data = json.load(f)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Import payload knowledge
        for payload_data in data.get("payload_knowledge", []):
            payload_hash = self._hash_payload(payload_data["payload"])
            cursor.execute("""
                INSERT OR REPLACE INTO payload_stats
                (vuln_type, payload_hash, payload, success_count, failure_count)
                VALUES (?, ?, ?, ?, ?)
            """, (
                payload_data["vuln_type"],
                payload_hash,
                payload_data["payload"],
                payload_data["success_count"],
                payload_data["failure_count"],
            ))

        # Import WAF bypasses
        for bypass in data.get("waf_bypasses", []):
            cursor.execute("""
                INSERT INTO waf_bypasses
                (waf_name, vuln_type, original_payload, bypass_payload, success)
                VALUES (?, ?, ?, ?, 1)
            """, (
                bypass["waf"],
                bypass["vuln_type"],
                bypass["original"],
                bypass["bypass"],
            ))

        conn.commit()
        conn.close()

        logger.info(f"Imported knowledge from {input_path}")

    def _hash_payload(self, payload: str) -> str:
        """Create a hash of a payload for deduplication."""
        import hashlib
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def clear_all(self):
        """Clear all learned data (use with caution)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM exploit_attempts")
        cursor.execute("DELETE FROM waf_bypasses")
        cursor.execute("DELETE FROM payload_stats")
        conn.commit()
        conn.close()
        logger.warning("Cleared all learning data")
