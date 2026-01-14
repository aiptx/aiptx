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
    5. REPORT - Report generation and delivery
    """
    RECON = "recon"
    SCAN = "scan"
    AI_PENTEST = "ai_pentest"  # NEW: Strix integration
    EXPLOIT = "exploit"
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

    def get_all_findings(self, deduplicate: bool = True) -> list[Finding]:
        """
        Get all findings across all phases.

        If deduplicate=True, merges duplicate findings from different sources.
        """
        all_findings: list[Finding] = []
        for phase_result in self.phases.values():
            all_findings.extend(phase_result.findings)

        if not deduplicate:
            return all_findings

        # Deduplicate by fingerprint
        unique_findings: dict[str, Finding] = {}
        for finding in all_findings:
            if finding.fingerprint in unique_findings:
                # Merge with existing finding
                existing = unique_findings[finding.fingerprint]
                unique_findings[finding.fingerprint] = existing.merge_with(finding)
            else:
                unique_findings[finding.fingerprint] = finding

        return list(unique_findings.values())

    def get_findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity"""
        from .findings import Severity
        grouped = {s.value: [] for s in Severity}
        for finding in self.get_all_findings():
            grouped[finding.severity.value].append(finding)
        return grouped

    def get_summary(self) -> dict[str, Any]:
        """Get executive summary of the scan"""
        findings = self.get_all_findings()
        from .findings import Severity

        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.severity == Severity.CRITICAL]),
            "high": len([f for f in findings if f.severity == Severity.HIGH]),
            "medium": len([f for f in findings if f.severity == Severity.MEDIUM]),
            "low": len([f for f in findings if f.severity == Severity.LOW]),
            "info": len([f for f in findings if f.severity == Severity.INFO]),
            "confirmed_findings": len([f for f in findings if f.confirmed]),
            "exploited_findings": len([f for f in findings if f.exploited]),
            "ai_findings": len([f for f in findings if f.source == "aipt"]),
            "phases_completed": len([p for p in self.phases.values() if p.status == PhaseStatus.COMPLETED]),
            "phases_failed": len([p for p in self.phases.values() if p.status == PhaseStatus.FAILED]),
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
