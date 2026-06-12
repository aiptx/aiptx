"""
AIPTX Pipeline Persistence - Save and load canonical findings

This module handles persistence of findings at various pipeline stages:

Output structure:
  {output_dir}/
  ├── normalized/
  │   └── findings_raw.json           # Raw normalized findings (Phase 2)
  ├── verified/
  │   ├── canonical_findings.json     # Final verified findings (Phase 5)
  │   ├── confirmed.json              # Only CONFIRMED findings
  │   ├── needs_review.json           # Only NEEDS_REVIEW findings
  │   └── suppressed_fp.json          # Only SUPPRESSED_FP findings
  └── reports/
      ├── VAPT_Report_{domain}.html
      ├── report.json
      └── report.sarif

Report generators read ONLY from canonical_findings.json.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from aipt_v2.models.finding_v2 import (
    FindingCategory,
    FindingV2,
    SeverityV2,
    VerificationStatusV2,
)

logger = logging.getLogger(__name__)


@dataclass
class CanonicalSummary:
    """Summary statistics for canonical findings"""

    total_raw: int = 0
    after_dedup: int = 0
    after_verification: int = 0
    confirmed: int = 0
    likely: int = 0
    needs_review: int = 0
    manual_review: int = 0
    suppressed_fp: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_raw": self.total_raw,
            "after_dedup": self.after_dedup,
            "after_verification": self.after_verification,
            "confirmed": self.confirmed,
            "likely": self.likely,
            "needs_review": self.needs_review,
            "manual_review": self.manual_review,
            "suppressed_fp": self.suppressed_fp,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
        }


@dataclass
class ToolStatusEntry:
    """Status entry for a single tool"""

    tool_name: str
    status: str  # "completed", "failed", "timeout", "skipped"
    finding_count: int = 0
    error: Optional[str] = None
    duration: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "tool_name": self.tool_name,
            "status": self.status,
            "finding_count": self.finding_count,
        }
        if self.error:
            result["error"] = self.error
        if self.duration is not None:
            result["duration"] = self.duration
        return result


@dataclass
class CanonicalFindings:
    """
    Container for canonical findings output.

    This is the final output of the pipeline, containing all verified
    findings with proper categorization and statistics.
    """

    scan_id: str
    target: str
    verified_at: datetime
    pipeline_version: str = "2.0"

    summary: CanonicalSummary = field(default_factory=CanonicalSummary)
    findings: list[FindingV2] = field(default_factory=list)
    tool_status: dict[str, ToolStatusEntry] = field(default_factory=dict)

    # Metadata
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    scan_duration_seconds: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "verified_at": self.verified_at.isoformat(),
            "pipeline_version": self.pipeline_version,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "tool_status": {name: entry.to_dict() for name, entry in self.tool_status.items()},
            "metadata": {
                "scan_started_at": (
                    self.scan_started_at.isoformat() if self.scan_started_at else None
                ),
                "scan_completed_at": (
                    self.scan_completed_at.isoformat() if self.scan_completed_at else None
                ),
                "scan_duration_seconds": self.scan_duration_seconds,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CanonicalFindings":
        """Create from dictionary"""
        summary = CanonicalSummary(
            total_raw=data.get("summary", {}).get("total_raw", 0),
            after_dedup=data.get("summary", {}).get("after_dedup", 0),
            after_verification=data.get("summary", {}).get("after_verification", 0),
            confirmed=data.get("summary", {}).get("confirmed", 0),
            likely=data.get("summary", {}).get("likely", 0),
            needs_review=data.get("summary", {}).get("needs_review", 0),
            manual_review=data.get("summary", {}).get("manual_review", 0),
            suppressed_fp=data.get("summary", {}).get("suppressed_fp", 0),
            by_severity=data.get("summary", {}).get("by_severity", {}),
            by_category=data.get("summary", {}).get("by_category", {}),
        )

        tool_status = {}
        for name, entry in data.get("tool_status", {}).items():
            tool_status[name] = ToolStatusEntry(
                tool_name=entry.get("tool_name", name),
                status=entry.get("status", "unknown"),
                finding_count=entry.get("finding_count", 0),
                error=entry.get("error"),
                duration=entry.get("duration"),
            )

        findings = [FindingV2.from_dict(f) for f in data.get("findings", [])]

        metadata = data.get("metadata", {})

        return cls(
            scan_id=data.get("scan_id", ""),
            target=data.get("target", ""),
            verified_at=(
                datetime.fromisoformat(data["verified_at"])
                if data.get("verified_at")
                else datetime.now(timezone.utc)
            ),
            pipeline_version=data.get("pipeline_version", "2.0"),
            summary=summary,
            findings=findings,
            tool_status=tool_status,
            scan_started_at=(
                datetime.fromisoformat(metadata["scan_started_at"])
                if metadata.get("scan_started_at")
                else None
            ),
            scan_completed_at=(
                datetime.fromisoformat(metadata["scan_completed_at"])
                if metadata.get("scan_completed_at")
                else None
            ),
            scan_duration_seconds=metadata.get("scan_duration_seconds"),
        )

    def get_reportable_findings(self) -> list[FindingV2]:
        """Get only findings that should appear in reports"""
        return [f for f in self.findings if f.is_reportable()]

    def get_confirmed_findings(self) -> list[FindingV2]:
        """Get only CONFIRMED findings"""
        return [f for f in self.findings if f.verification_status == VerificationStatusV2.CONFIRMED]

    def get_needs_review_findings(self) -> list[FindingV2]:
        """Get findings that need manual review"""
        return [
            f
            for f in self.findings
            if f.verification_status
            in [
                VerificationStatusV2.NEEDS_REVIEW,
                VerificationStatusV2.MANUAL_REVIEW,
            ]
        ]

    def get_suppressed_findings(self) -> list[FindingV2]:
        """Get suppressed (false positive) findings"""
        return [
            f for f in self.findings if f.verification_status == VerificationStatusV2.SUPPRESSED_FP
        ]

    def get_by_severity(self, severity: SeverityV2) -> list[FindingV2]:
        """Get findings by severity level"""
        return [f for f in self.findings if f.severity == severity]

    def get_by_category(self, category: FindingCategory) -> list[FindingV2]:
        """Get findings by category"""
        return [f for f in self.findings if f.category == category]


class PipelinePersistence:
    """
    Handles saving and loading pipeline data at various stages.

    Creates proper directory structure and saves findings in
    appropriate formats for each stage.
    """

    def __init__(self, output_dir: Path):
        """
        Initialize persistence handler.

        Args:
            output_dir: Root output directory for scan results
        """
        self.output_dir = Path(output_dir)
        self.normalized_dir = self.output_dir / "normalized"
        self.verified_dir = self.output_dir / "verified"
        self.reports_dir = self.output_dir / "reports"

        # Create directories
        self.normalized_dir.mkdir(parents=True, exist_ok=True)
        self.verified_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def save_findings_raw(
        self,
        findings: list[FindingV2],
        scan_id: str,
        target: str,
        tool_stats: Optional[dict] = None,
    ) -> Path:
        """
        Save normalized findings to findings_raw.json.

        Args:
            findings: List of normalized FindingV2 objects
            scan_id: Unique scan identifier
            target: Target domain/IP
            tool_stats: Optional tool execution statistics

        Returns:
            Path to saved file
        """
        output_path = self.normalized_dir / "findings_raw.json"

        data = {
            "scan_id": scan_id,
            "target": target,
            "normalized_at": datetime.now(timezone.utc).isoformat(),
            "total_raw_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
            "tool_stats": tool_stats or {},
        }

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Saved {len(findings)} raw findings to {output_path}")
        return output_path

    def save_canonical_findings(
        self,
        canonical: CanonicalFindings,
    ) -> Path:
        """
        Save canonical findings to verified/canonical_findings.json.

        Also creates separate files for confirmed, needs_review, and suppressed.

        Args:
            canonical: CanonicalFindings container

        Returns:
            Path to main canonical findings file
        """
        # Save main canonical file
        main_path = self.verified_dir / "canonical_findings.json"
        with open(main_path, "w") as f:
            json.dump(canonical.to_dict(), f, indent=2, default=str)

        logger.info(f"Saved canonical findings to {main_path}")

        # Save confirmed-only file
        confirmed = canonical.get_confirmed_findings()
        confirmed_path = self.verified_dir / "confirmed.json"
        with open(confirmed_path, "w") as f:
            json.dump(
                {
                    "scan_id": canonical.scan_id,
                    "target": canonical.target,
                    "count": len(confirmed),
                    "findings": [f.to_dict() for f in confirmed],
                },
                f,
                indent=2,
                default=str,
            )

        # Save needs-review file
        needs_review = canonical.get_needs_review_findings()
        needs_review_path = self.verified_dir / "needs_review.json"
        with open(needs_review_path, "w") as f:
            json.dump(
                {
                    "scan_id": canonical.scan_id,
                    "target": canonical.target,
                    "count": len(needs_review),
                    "findings": [f.to_dict() for f in needs_review],
                },
                f,
                indent=2,
                default=str,
            )

        # Save suppressed file
        suppressed = canonical.get_suppressed_findings()
        suppressed_path = self.verified_dir / "suppressed_fp.json"
        with open(suppressed_path, "w") as f:
            json.dump(
                {
                    "scan_id": canonical.scan_id,
                    "target": canonical.target,
                    "count": len(suppressed),
                    "findings": [f.to_dict() for f in suppressed],
                },
                f,
                indent=2,
                default=str,
            )

        logger.info(
            f"Saved split files: confirmed={len(confirmed)}, "
            f"needs_review={len(needs_review)}, suppressed={len(suppressed)}"
        )

        return main_path

    def load_findings_raw(self) -> list[FindingV2]:
        """
        Load normalized findings from findings_raw.json.

        Returns:
            List of FindingV2 objects
        """
        raw_path = self.normalized_dir / "findings_raw.json"

        if not raw_path.exists():
            logger.warning(f"No findings_raw.json found at {raw_path}")
            return []

        with open(raw_path) as f:
            data = json.load(f)

        findings = [FindingV2.from_dict(f) for f in data.get("findings", [])]
        logger.info(f"Loaded {len(findings)} findings from {raw_path}")

        return findings

    def load_canonical_findings(self) -> Optional[CanonicalFindings]:
        """
        Load canonical findings from canonical_findings.json.

        Returns:
            CanonicalFindings container or None if not found
        """
        canonical_path = self.verified_dir / "canonical_findings.json"

        if not canonical_path.exists():
            logger.warning(f"No canonical_findings.json found at {canonical_path}")
            return None

        with open(canonical_path) as f:
            data = json.load(f)

        canonical = CanonicalFindings.from_dict(data)
        logger.info(f"Loaded canonical findings from {canonical_path}")

        return canonical


def save_findings_raw(
    findings: list[FindingV2],
    output_dir: Path,
    scan_id: str,
    target: str,
    tool_stats: Optional[dict] = None,
) -> Path:
    """
    Convenience function to save normalized findings.

    Args:
        findings: List of normalized FindingV2 objects
        output_dir: Output directory
        scan_id: Unique scan identifier
        target: Target domain/IP
        tool_stats: Optional tool statistics

    Returns:
        Path to saved file
    """
    persistence = PipelinePersistence(output_dir)
    return persistence.save_findings_raw(findings, scan_id, target, tool_stats)


def save_canonical_findings(
    findings: list[FindingV2],
    output_dir: Path,
    scan_id: str,
    target: str,
    total_raw: int = 0,
    after_dedup: int = 0,
    tool_stats: Optional[dict] = None,
    scan_started_at: Optional[datetime] = None,
    scan_completed_at: Optional[datetime] = None,
) -> Path:
    """
    Convenience function to save canonical findings.

    Creates CanonicalFindings container with computed summary and saves.

    Args:
        findings: List of verified FindingV2 objects
        output_dir: Output directory
        scan_id: Unique scan identifier
        target: Target domain/IP
        total_raw: Total raw findings before dedup
        after_dedup: Findings after deduplication
        tool_stats: Tool execution statistics
        scan_started_at: When scan started
        scan_completed_at: When scan completed

    Returns:
        Path to saved file
    """
    # Compute summary
    summary = CanonicalSummary(
        total_raw=total_raw,
        after_dedup=after_dedup,
        after_verification=len(findings),
    )

    # Count by status
    for f in findings:
        if f.verification_status == VerificationStatusV2.CONFIRMED:
            summary.confirmed += 1
        elif f.verification_status == VerificationStatusV2.LIKELY:
            summary.likely += 1
        elif f.verification_status == VerificationStatusV2.NEEDS_REVIEW:
            summary.needs_review += 1
        elif f.verification_status == VerificationStatusV2.MANUAL_REVIEW:
            summary.manual_review += 1
        elif f.verification_status == VerificationStatusV2.SUPPRESSED_FP:
            summary.suppressed_fp += 1

    # Count by severity and category
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}

    for f in findings:
        sev = f.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1

        cat = f.category.value
        by_category[cat] = by_category.get(cat, 0) + 1

    summary.by_severity = by_severity
    summary.by_category = by_category

    # Convert tool stats
    tool_status = {}
    if tool_stats:
        for name, stats in tool_stats.items():
            if isinstance(stats, dict):
                tool_status[name] = ToolStatusEntry(
                    tool_name=name,
                    status=stats.get("status", "unknown"),
                    finding_count=stats.get("finding_count", 0),
                    error=stats.get("error"),
                    duration=stats.get("duration"),
                )
            else:
                tool_status[name] = ToolStatusEntry(
                    tool_name=name,
                    status=(
                        getattr(stats, "status", "unknown").value
                        if hasattr(getattr(stats, "status", ""), "value")
                        else str(getattr(stats, "status", "unknown"))
                    ),
                    finding_count=getattr(stats, "finding_count", 0),
                    error=getattr(stats, "error", None),
                    duration=getattr(stats, "duration", None),
                )

    # Calculate duration
    duration = None
    if scan_started_at and scan_completed_at:
        # Guard against naive/aware mismatch: normalize both to tz-aware UTC
        # before subtracting so a naive timestamp can never raise TypeError.
        start = (
            scan_started_at
            if scan_started_at.tzinfo
            else scan_started_at.replace(tzinfo=timezone.utc)
        )
        end = (
            scan_completed_at
            if scan_completed_at.tzinfo
            else scan_completed_at.replace(tzinfo=timezone.utc)
        )
        duration = (end - start).total_seconds()

    # Create container
    canonical = CanonicalFindings(
        scan_id=scan_id,
        target=target,
        verified_at=datetime.now(timezone.utc),
        summary=summary,
        findings=findings,
        tool_status=tool_status,
        scan_started_at=scan_started_at,
        scan_completed_at=scan_completed_at,
        scan_duration_seconds=duration,
    )

    # Save
    persistence = PipelinePersistence(output_dir)
    return persistence.save_canonical_findings(canonical)


def load_canonical_findings(output_dir: Path) -> Optional[CanonicalFindings]:
    """
    Convenience function to load canonical findings.

    Args:
        output_dir: Output directory containing verified/canonical_findings.json

    Returns:
        CanonicalFindings container or None if not found
    """
    persistence = PipelinePersistence(output_dir)
    return persistence.load_canonical_findings()
