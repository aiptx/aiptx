"""
AIPT Phase Result Model

Tracks results and status for each phase of the scanning pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .findings import Finding


class Phase(Enum):
    """
    AIPT Pipeline Phases

    The pipeline executes in order:
    1. RECON - Asset discovery and reconnaissance
    2. SCAN - Traditional vulnerability scanning (Acunetix, Burp, Nuclei, ZAP)
    3. AI_PENTEST - AI-autonomous penetration testing (Strix)
    4. EXPLOIT - Exploitation and validation of findings
    5. VERIFY - Verification phase to eliminate false positives
    6. REPORT - Report generation and delivery
    """

    RECON = "recon"
    SCAN = "scan"
    AI_PENTEST = "ai_pentest"  # NEW: Strix integration
    EXPLOIT = "exploit"
    VERIFY = "verify"  # NEW: False positive elimination
    REPORT = "report"


class PhaseStatus(Enum):
    """Status of a pipeline phase"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class PhaseResult:
    """
    Result of a single pipeline phase

    Contains all findings, errors, and metadata from phase execution.
    """

    phase: Phase
    status: PhaseStatus = PhaseStatus.PENDING

    # Findings discovered in this phase
    findings: list[Finding] = field(default_factory=list)

    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Error tracking
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Phase-specific data
    metadata: dict[str, Any] = field(default_factory=dict)

    # Scanner results (for SCAN phase)
    scanner_results: dict[str, Any] = field(default_factory=dict)

    # AI agent traces (for AI_PENTEST phase)
    agent_traces: list[dict[str, Any]] = field(default_factory=list)

    def start(self) -> None:
        """Mark phase as started"""
        self.status = PhaseStatus.RUNNING
        self.started_at = datetime.utcnow()

    def complete(self) -> None:
        """Mark phase as completed"""
        self.status = PhaseStatus.COMPLETED
        self.completed_at = datetime.utcnow()

    def fail(self, error: str) -> None:
        """Mark phase as failed"""
        self.status = PhaseStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.errors.append(error)

    def skip(self, reason: str) -> None:
        """Mark phase as skipped"""
        self.status = PhaseStatus.SKIPPED
        self.completed_at = datetime.utcnow()
        self.metadata["skip_reason"] = reason

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to this phase"""
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        """Add multiple findings"""
        self.findings.extend(findings)

    @property
    def duration_seconds(self) -> float | None:
        """Get phase duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def finding_counts(self) -> dict[str, int]:
        """Get finding counts by severity"""
        from .findings import Severity

        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "finding_counts": self.finding_counts,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


@dataclass
class PipelineResult:
    """
    Complete result of an AIPT scan pipeline

    Aggregates results from all phases with deduplication.
    """

    scan_id: str
    target: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    # Phase results
    phases: dict[Phase, PhaseResult] = field(default_factory=dict)

    # Aggregated and deduplicated findings
    _all_findings: list[Finding] = field(default_factory=list)

    def add_phase_result(self, result: PhaseResult) -> None:
        """Add a phase result and merge findings"""
        self.phases[result.phase] = result

    def get_all_findings(
        self,
        deduplicate: bool = True,
        use_llm: bool = False,
        reportable_only: bool = False,
    ) -> list[Finding]:
        """
        Get all findings across all phases with smart deduplication.

        Args:
            deduplicate: If True, removes duplicate findings
            use_llm: If True and deduplicate=True, uses LLM semantic deduplication
            reportable_only: If True, only returns findings that pass is_reportable()

        Returns:
            List of findings (deduplicated and/or filtered based on args)
        """
        all_findings: list[Finding] = []
        for phase_result in self.phases.values():
            all_findings.extend(phase_result.findings)

        if not deduplicate:
            if reportable_only:
                return [f for f in all_findings if f.is_reportable()]
            return all_findings

        if use_llm:
            # Use LLM-based semantic deduplication
            deduped = self._deduplicate_with_llm(all_findings)
        else:
            # Use smart fingerprint-based deduplication
            deduped = self._deduplicate_smart(all_findings)

        if reportable_only:
            return [f for f in deduped if f.is_reportable()]
        return deduped

    def _deduplicate_smart(self, findings: list[Finding]) -> list[Finding]:
        """
        Smart fingerprint-based deduplication that prevents over-aggressive merging.

        Key logic:
        - Same fingerprint = merge (fingerprint includes host, path, method, param, vuln_type, root cause)
        - Different endpoints are NEVER merged even if same vuln type
        - Considers verification status when merging (prefer confirmed findings)
        """
        from .findings import VerificationStatus

        unique_findings: dict[str, Finding] = {}

        for finding in findings:
            fp = finding.fingerprint

            if fp in unique_findings:
                existing = unique_findings[fp]

                # Prefer findings with better verification status
                existing_confirmed = existing.verification_status == VerificationStatus.CONFIRMED
                new_confirmed = finding.verification_status == VerificationStatus.CONFIRMED

                if new_confirmed and not existing_confirmed:
                    # New finding is confirmed, existing is not - use new as base
                    unique_findings[fp] = finding.merge_with(existing)
                else:
                    # Existing is confirmed or both same status - use existing as base
                    unique_findings[fp] = existing.merge_with(finding)
            else:
                unique_findings[fp] = finding

        return list(unique_findings.values())

    def _deduplicate_with_llm(self, findings: list[Finding]) -> list[Finding]:
        """
        LLM-based semantic deduplication for high accuracy.

        Uses the LLM dedupe module to semantically compare findings
        and determine true duplicates based on root cause analysis.

        Note: This is slower but more accurate than fingerprint-based dedup.
        """
        try:
            from aipt_v2.llm.dedupe import check_duplicate, quick_hash_check
        except ImportError:
            # Fallback to smart dedup if LLM module not available
            return self._deduplicate_smart(findings)

        unique_findings: list[Finding] = []

        for finding in findings:
            # Convert finding to dict for LLM comparison
            candidate = finding.to_dict()
            existing_dicts = [f.to_dict() for f in unique_findings]

            # Quick hash check first (cheap)
            quick_result = quick_hash_check(candidate, existing_dicts)
            if quick_result and quick_result.get("is_duplicate"):
                # Merge with the duplicate
                dup_id = quick_result.get("duplicate_id", "")
                for i, existing in enumerate(unique_findings):
                    if existing.fingerprint == dup_id or existing.source_id == dup_id:
                        unique_findings[i] = existing.merge_with(finding)
                        break
                continue

            # LLM semantic check (more expensive)
            try:
                result = check_duplicate(candidate, existing_dicts)
                if result.get("is_duplicate") and result.get("confidence", 0) >= 0.8:
                    # High confidence duplicate - merge
                    dup_id = result.get("duplicate_id", "")
                    merged = False
                    for i, existing in enumerate(unique_findings):
                        if existing.fingerprint == dup_id or existing.source_id == dup_id:
                            unique_findings[i] = existing.merge_with(finding)
                            merged = True
                            break
                    if not merged:
                        # Could not find the duplicate to merge with, add as new
                        unique_findings.append(finding)
                else:
                    # Not a duplicate
                    unique_findings.append(finding)
            except Exception:
                # LLM check failed, add as unique to be safe
                unique_findings.append(finding)

        return unique_findings

    def get_findings_by_severity(
        self,
        reportable_only: bool = True,
    ) -> dict[str, list[Finding]]:
        """
        Group findings by severity.

        Args:
            reportable_only: If True, only includes verified/reportable findings
        """
        from .findings import Severity

        grouped = {s.value: [] for s in Severity}
        for finding in self.get_all_findings(reportable_only=reportable_only):
            grouped[finding.severity.value].append(finding)
        return grouped

    def get_verification_summary(self) -> dict[str, Any]:
        """
        Get detailed verification statistics.

        Returns breakdown of findings by verification status.
        """
        from .findings import Severity, VerificationStatus

        all_findings = self.get_all_findings(deduplicate=True)

        by_status = {status.value: [] for status in VerificationStatus}
        for finding in all_findings:
            by_status[finding.verification_status.value].append(finding)

        # Critical findings breakdown
        critical = [f for f in all_findings if f.severity == Severity.CRITICAL]
        high = [f for f in all_findings if f.severity == Severity.HIGH]

        return {
            "total_discovered": len(all_findings),
            "by_status": {k: len(v) for k, v in by_status.items()},
            "reportable_count": len([f for f in all_findings if f.is_reportable()]),
            "critical_findings": {
                "total": len(critical),
                "confirmed": len(
                    [f for f in critical if f.verification_status == VerificationStatus.CONFIRMED]
                ),
                "false_positive": len(
                    [
                        f
                        for f in critical
                        if f.verification_status == VerificationStatus.FALSE_POSITIVE
                    ]
                ),
                "pending": len(
                    [
                        f
                        for f in critical
                        if f.verification_status
                        in [VerificationStatus.UNVERIFIED, VerificationStatus.PENDING]
                    ]
                ),
            },
            "high_findings": {
                "total": len(high),
                "confirmed": len(
                    [f for f in high if f.verification_status == VerificationStatus.CONFIRMED]
                ),
                "false_positive": len(
                    [f for f in high if f.verification_status == VerificationStatus.FALSE_POSITIVE]
                ),
                "pending": len(
                    [
                        f
                        for f in high
                        if f.verification_status
                        in [VerificationStatus.UNVERIFIED, VerificationStatus.PENDING]
                    ]
                ),
            },
        }

    def get_summary(self) -> dict[str, Any]:
        """Get executive summary of the scan with verification stats"""
        from .findings import Severity, VerificationStatus

        # Get all findings (not filtered by reportable)
        all_findings = self.get_all_findings(deduplicate=True)

        # Get only reportable findings for the main counts
        reportable = [f for f in all_findings if f.is_reportable()]

        # Verification statistics
        confirmed = [
            f for f in all_findings if f.verification_status == VerificationStatus.CONFIRMED
        ]
        false_positives = [
            f for f in all_findings if f.verification_status == VerificationStatus.FALSE_POSITIVE
        ]
        pending_review = [
            f for f in all_findings if f.verification_status == VerificationStatus.MANUAL_REVIEW
        ]

        return {
            "scan_id": self.scan_id,
            "target": self.target,
            # Reportable counts (verified findings)
            "total_findings": len(reportable),
            "critical": len([f for f in reportable if f.severity == Severity.CRITICAL]),
            "high": len([f for f in reportable if f.severity == Severity.HIGH]),
            "medium": len([f for f in reportable if f.severity == Severity.MEDIUM]),
            "low": len([f for f in reportable if f.severity == Severity.LOW]),
            "info": len([f for f in reportable if f.severity == Severity.INFO]),
            # Verification stats
            "verified_confirmed": len(confirmed),
            "false_positives_filtered": len(false_positives),
            "pending_manual_review": len(pending_review),
            "total_discovered": len(all_findings),
            # Legacy fields for compatibility
            "confirmed_findings": len([f for f in reportable if f.confirmed]),
            "exploited_findings": len([f for f in reportable if f.exploited]),
            "ai_findings": len([f for f in reportable if f.source == "aipt"]),
            "phases_completed": len(
                [p for p in self.phases.values() if p.status == PhaseStatus.COMPLETED]
            ),
            "phases_failed": len(
                [p for p in self.phases.values() if p.status == PhaseStatus.FAILED]
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "summary": self.get_summary(),
            "phases": {p.value: r.to_dict() for p, r in self.phases.items()},
            "all_findings": [f.to_dict() for f in self.get_all_findings()],
        }
