"""
AIPT Report Generator

Generates professional pentest reports from pipeline results.

Supports both:
- Legacy PipelineResult format
- New CanonicalFindings format (reads only from canonical_findings.json)

The new format provides:
- Separate sections for Confirmed/Needs Review/Suppressed findings
- Proper severity mapping (enum strings only, no numeric)
- URL normalization (no double slashes)
- Totals that match actual finding counts
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

from ..models.findings import Finding, Severity, VerificationStatus
from ..models.phase_result import PipelineResult

if TYPE_CHECKING:
    from ..pipeline.persistence import CanonicalFindings
    from ..models.finding_v2 import FindingV2


logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    # Report metadata
    client_name: str = "Client"
    project_name: str = "Security Assessment"
    assessor_name: str = "AIPT"

    # Output settings
    output_dir: Path = field(default_factory=lambda: Path("./reports"))
    formats: list[str] = field(default_factory=lambda: ["html", "json", "markdown"])

    # Content settings
    include_evidence: bool = True
    include_remediation: bool = True
    include_ai_reasoning: bool = True
    redact_sensitive: bool = False


@dataclass
class ReportData:
    """Data structure for report generation"""
    # Metadata
    scan_id: str
    target: str
    generated_at: datetime
    config: ReportConfig

    # Findings by severity (VERIFIED/REPORTABLE ONLY)
    critical_findings: list[Finding] = field(default_factory=list)
    high_findings: list[Finding] = field(default_factory=list)
    medium_findings: list[Finding] = field(default_factory=list)
    low_findings: list[Finding] = field(default_factory=list)
    info_findings: list[Finding] = field(default_factory=list)

    # Statistics
    total_findings: int = 0
    unique_vuln_types: int = 0
    sources: list[str] = field(default_factory=list)

    # Verification statistics (for transparency)
    total_discovered: int = 0  # Before filtering
    false_positives_filtered: int = 0
    pending_manual_review: int = 0

    # AI-specific
    ai_findings_count: int = 0
    ai_reasoning_samples: list[str] = field(default_factory=list)

    @classmethod
    def from_pipeline_result(
        cls,
        result: PipelineResult,
        config: ReportConfig,
    ) -> "ReportData":
        """
        Create ReportData from pipeline result.

        IMPORTANT: Only includes VERIFIED/REPORTABLE findings in the report.
        - Critical/High findings MUST be CONFIRMED
        - Medium findings can be CONFIRMED or LIKELY
        - Low/Info findings can be POTENTIAL

        This eliminates false positives from the final report.
        """
        # Get ALL findings for statistics (before filtering)
        all_findings = result.get_all_findings(deduplicate=True, reportable_only=False)
        total_discovered = len(all_findings)

        # Get only REPORTABLE findings for the actual report
        findings = result.get_all_findings(deduplicate=True, reportable_only=True)

        # Count false positives and pending review
        false_positives = [
            f for f in all_findings
            if f.verification_status == VerificationStatus.FALSE_POSITIVE
        ]
        pending_review = [
            f for f in all_findings
            if f.verification_status == VerificationStatus.MANUAL_REVIEW
        ]

        # Group by severity - ONLY verified findings
        # Critical and High MUST be CONFIRMED
        critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL and f.verification_status == VerificationStatus.CONFIRMED
        ]
        high = [
            f for f in findings
            if f.severity == Severity.HIGH and f.verification_status == VerificationStatus.CONFIRMED
        ]
        # Medium can be CONFIRMED or LIKELY
        medium = [
            f for f in findings
            if f.severity == Severity.MEDIUM and f.verification_status in [
                VerificationStatus.CONFIRMED, VerificationStatus.LIKELY
            ]
        ]
        # Low and Info can be POTENTIAL or better
        low = [
            f for f in findings
            if f.severity == Severity.LOW and f.verification_status not in [
                VerificationStatus.UNVERIFIED, VerificationStatus.FALSE_POSITIVE
            ]
        ]
        info = [
            f for f in findings
            if f.severity == Severity.INFO and f.verification_status not in [
                VerificationStatus.UNVERIFIED, VerificationStatus.FALSE_POSITIVE
            ]
        ]

        # Extract unique sources
        sources = list(set(f.source for f in findings))

        # Count AI findings
        ai_findings = [f for f in findings if f.source == "aipt" or f.ai_reasoning]
        ai_reasoning = [f.ai_reasoning for f in ai_findings if f.ai_reasoning][:5]

        # Unique vulnerability types
        unique_types = len(set(f.vuln_type for f in findings))

        return cls(
            scan_id=result.scan_id,
            target=result.target,
            generated_at=datetime.utcnow(),
            config=config,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            info_findings=info,
            total_findings=len(findings),
            unique_vuln_types=unique_types,
            sources=sources,
            total_discovered=total_discovered,
            false_positives_filtered=len(false_positives),
            pending_manual_review=len(pending_review),
            ai_findings_count=len(ai_findings),
            ai_reasoning_samples=ai_reasoning,
        )

    @classmethod
    def from_canonical_findings(
        cls,
        canonical: "CanonicalFindings",
        config: ReportConfig,
    ) -> "ReportData":
        """
        Create ReportData from CanonicalFindings (new pipeline format).

        This is the preferred method for the new pipeline as it:
        - Reads only from canonical_findings.json
        - Uses proper severity enums (no numeric)
        - Respects verification status for reportability
        - Provides separate sections for Confirmed/Needs Review/Suppressed
        """
        from ..models.finding_v2 import SeverityV2, VerificationStatusV2

        all_findings = canonical.findings
        total_discovered = canonical.summary.total_raw

        # Get reportable findings only
        reportable = [f for f in all_findings if f.is_reportable()]

        # Count false positives and pending review
        false_positives = [
            f for f in all_findings
            if f.verification_status == VerificationStatusV2.SUPPRESSED_FP
        ]
        pending_review = [
            f for f in all_findings
            if f.verification_status in [
                VerificationStatusV2.NEEDS_REVIEW,
                VerificationStatusV2.MANUAL_REVIEW,
            ]
        ]

        # Group by severity - ONLY verified findings for Critical/High
        critical = [
            f for f in reportable
            if f.severity == SeverityV2.CRITICAL
            and f.verification_status == VerificationStatusV2.CONFIRMED
        ]
        high = [
            f for f in reportable
            if f.severity == SeverityV2.HIGH
            and f.verification_status == VerificationStatusV2.CONFIRMED
        ]
        # Medium can be CONFIRMED or LIKELY
        medium = [
            f for f in reportable
            if f.severity == SeverityV2.MEDIUM
            and f.verification_status in [
                VerificationStatusV2.CONFIRMED,
                VerificationStatusV2.LIKELY,
            ]
        ]
        # Low and Info - more lenient
        low = [
            f for f in reportable
            if f.severity == SeverityV2.LOW
        ]
        info = [
            f for f in reportable
            if f.severity == SeverityV2.INFO
        ]

        # Convert to legacy Finding format for existing HTML template compatibility
        def to_legacy_finding(fv2: "FindingV2") -> Finding:
            return fv2.to_legacy()

        critical_legacy = [to_legacy_finding(f) for f in critical]
        high_legacy = [to_legacy_finding(f) for f in high]
        medium_legacy = [to_legacy_finding(f) for f in medium]
        low_legacy = [to_legacy_finding(f) for f in low]
        info_legacy = [to_legacy_finding(f) for f in info]

        # Extract unique sources
        sources = list(set(f.source_tool for f in reportable))

        # Count AI findings
        ai_findings = [f for f in reportable if f.source_tool == "aipt" or f.ai_reasoning]
        ai_reasoning = [f.ai_reasoning for f in ai_findings if f.ai_reasoning][:5]

        # Unique vulnerability types
        unique_types = len(set(f.vuln_type for f in reportable))

        return cls(
            scan_id=canonical.scan_id,
            target=canonical.target,
            generated_at=datetime.utcnow(),
            config=config,
            critical_findings=critical_legacy,
            high_findings=high_legacy,
            medium_findings=medium_legacy,
            low_findings=low_legacy,
            info_findings=info_legacy,
            total_findings=len(reportable),
            unique_vuln_types=unique_types,
            sources=sources,
            total_discovered=total_discovered,
            false_positives_filtered=len(false_positives),
            pending_manual_review=len(pending_review),
            ai_findings_count=len(ai_findings),
            ai_reasoning_samples=ai_reasoning,
        )

    def get_severity_counts(self) -> dict[str, int]:
        return {
            "critical": len(self.critical_findings),
            "high": len(self.high_findings),
            "medium": len(self.medium_findings),
            "low": len(self.low_findings),
            "info": len(self.info_findings),
        }

    def get_risk_score(self) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        score += len(self.critical_findings) * 25
        score += len(self.high_findings) * 15
        score += len(self.medium_findings) * 8
        score += len(self.low_findings) * 2
        return min(100, score)

    def get_risk_rating(self) -> str:
        """Get risk rating based on score"""
        score = self.get_risk_score()
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        elif score > 0:
            return "Low"
        return "Informational"


class ReportGenerator:
    """
    Generates professional pentest reports.

    Supports two input formats:
    1. Legacy PipelineResult: generate(pipeline_result)
    2. New CanonicalFindings: generate_from_canonical(canonical_findings)

    Example:
        generator = ReportGenerator(config)

        # Legacy format
        paths = await generator.generate(pipeline_result)

        # New format (preferred)
        paths = await generator.generate_from_canonical(canonical_findings)

        print(f"Reports saved to: {paths}")
    """

    def __init__(self, config: ReportConfig | None = None):
        self.config = config or ReportConfig()

    async def generate_from_canonical(
        self,
        canonical: "CanonicalFindings",
    ) -> dict[str, Path]:
        """
        Generate reports from CanonicalFindings (new pipeline format).

        This is the preferred method for the new pipeline.
        Reads only from canonical_findings.json.

        Args:
            canonical: CanonicalFindings container

        Returns:
            Dictionary of format -> file path
        """
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Prepare report data from canonical findings
        data = ReportData.from_canonical_findings(canonical, self.config)

        generated_files = {}

        if "html" in self.config.formats:
            path = await self._generate_html_v2(data, canonical)
            generated_files["html"] = path

        if "json" in self.config.formats:
            path = await self._generate_json_v2(data, canonical)
            generated_files["json"] = path

        if "markdown" in self.config.formats:
            path = await self._generate_markdown(data)
            generated_files["markdown"] = path

        logger.info(f"Generated {len(generated_files)} report(s) from canonical findings")
        return generated_files

    async def _generate_html_v2(
        self,
        data: "ReportData",
        canonical: "CanonicalFindings",
    ) -> Path:
        """Generate HTML report with Confirmed/Needs Review/Suppressed sections"""
        from .html_report import generate_html_report_v2

        html_content = generate_html_report_v2(data, canonical)

        filename = f"VAPT_Report_{data.target}_{data.generated_at.strftime('%Y%m%d_%H%M%S')}.html"
        path = self.config.output_dir / filename

        path.write_text(html_content)
        logger.info(f"Generated HTML report: {path}")

        return path

    async def _generate_json_v2(
        self,
        data: "ReportData",
        canonical: "CanonicalFindings",
    ) -> Path:
        """Generate JSON report from canonical findings"""
        from ..models.finding_v2 import VerificationStatusV2

        # Get findings by verification status
        confirmed = [f.to_dict() for f in canonical.get_confirmed_findings()]
        needs_review = [f.to_dict() for f in canonical.get_needs_review_findings()]
        suppressed = [f.to_dict() for f in canonical.get_suppressed_findings()]

        json_data = {
            "metadata": {
                "scan_id": data.scan_id,
                "target": data.target,
                "generated_at": data.generated_at.isoformat(),
                "client_name": data.config.client_name,
                "project_name": data.config.project_name,
                "assessor": data.config.assessor_name,
                "pipeline_version": canonical.pipeline_version,
            },
            "summary": {
                "total_raw": canonical.summary.total_raw,
                "after_dedup": canonical.summary.after_dedup,
                "confirmed": canonical.summary.confirmed,
                "likely": canonical.summary.likely,
                "needs_review": canonical.summary.needs_review,
                "suppressed_fp": canonical.summary.suppressed_fp,
                "severity_counts": data.get_severity_counts(),
                "risk_score": data.get_risk_score(),
                "risk_rating": data.get_risk_rating(),
                "unique_vuln_types": data.unique_vuln_types,
                "sources": data.sources,
                "ai_findings_count": data.ai_findings_count,
            },
            "verification": {
                "total_discovered": data.total_discovered,
                "reportable_findings": data.total_findings,
                "false_positives_filtered": data.false_positives_filtered,
                "pending_manual_review": data.pending_manual_review,
                "verification_rate": (
                    f"{(data.total_findings / data.total_discovered * 100):.1f}%"
                    if data.total_discovered > 0 else "N/A"
                ),
            },
            "findings": {
                "confirmed": confirmed,
                "needs_review": needs_review,
                "suppressed": suppressed,
            },
            "tool_status": {
                name: entry.to_dict()
                for name, entry in canonical.tool_status.items()
            },
        }

        filename = f"report_{data.scan_id}_{data.generated_at.strftime('%Y%m%d_%H%M%S')}.json"
        path = self.config.output_dir / filename

        path.write_text(json.dumps(json_data, indent=2, default=str))
        logger.info(f"Generated JSON report: {path}")

        return path

    async def generate(self, result: PipelineResult) -> dict[str, Path]:
        """
        Generate reports in all configured formats.

        Args:
            result: Pipeline result with findings

        Returns:
            Dictionary of format -> file path
        """
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Prepare report data
        data = ReportData.from_pipeline_result(result, self.config)

        generated_files = {}

        if "html" in self.config.formats:
            path = await self._generate_html(data)
            generated_files["html"] = path

        if "json" in self.config.formats:
            path = await self._generate_json(data, result)
            generated_files["json"] = path

        if "markdown" in self.config.formats:
            path = await self._generate_markdown(data)
            generated_files["markdown"] = path

        logger.info(f"Generated {len(generated_files)} report(s)")
        return generated_files

    async def _generate_html(self, data: ReportData) -> Path:
        """Generate HTML report"""
        from .html_report import generate_html_report

        html_content = generate_html_report(data)

        filename = f"aipt3_report_{data.scan_id}_{data.generated_at.strftime('%Y%m%d_%H%M%S')}.html"
        path = self.config.output_dir / filename

        path.write_text(html_content)
        logger.info(f"Generated HTML report: {path}")

        return path

    async def _generate_json(self, data: ReportData, result: PipelineResult) -> Path:
        """Generate JSON report with verification statistics"""
        # Get only reportable findings for the report
        reportable_findings = result.get_all_findings(deduplicate=True, reportable_only=True)

        json_data = {
            "metadata": {
                "scan_id": data.scan_id,
                "target": data.target,
                "generated_at": data.generated_at.isoformat(),
                "client_name": data.config.client_name,
                "project_name": data.config.project_name,
                "assessor": data.config.assessor_name,
            },
            "summary": {
                "total_findings": data.total_findings,
                "severity_counts": data.get_severity_counts(),
                "risk_score": data.get_risk_score(),
                "risk_rating": data.get_risk_rating(),
                "unique_vuln_types": data.unique_vuln_types,
                "sources": data.sources,
                "ai_findings_count": data.ai_findings_count,
            },
            "verification": {
                "total_discovered": data.total_discovered,
                "reportable_findings": data.total_findings,
                "false_positives_filtered": data.false_positives_filtered,
                "pending_manual_review": data.pending_manual_review,
                "verification_rate": f"{(data.total_findings / data.total_discovered * 100):.1f}%" if data.total_discovered > 0 else "N/A",
            },
            "findings": [f.to_dict() for f in reportable_findings],
            "phases": {
                phase.value: {
                    "status": pr.status.value,
                    "duration": pr.duration_seconds,
                    "findings_count": len(pr.findings),
                    "errors": pr.errors,
                }
                for phase, pr in result.phase_results.items()
            },
        }

        filename = f"aipt3_report_{data.scan_id}_{data.generated_at.strftime('%Y%m%d_%H%M%S')}.json"
        path = self.config.output_dir / filename

        path.write_text(json.dumps(json_data, indent=2, default=str))
        logger.info(f"Generated JSON report: {path}")

        return path

    async def _generate_markdown(self, data: ReportData) -> Path:
        """Generate Markdown report with verification statistics"""
        lines = [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {data.target}",
            f"**Scan ID:** {data.scan_id}",
            f"**Date:** {data.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Risk Rating:** {data.get_risk_rating()} ({data.get_risk_score()}/100)",
            f"",
            f"## Executive Summary",
            f"",
            f"This automated security assessment identified **{data.total_findings}** verified vulnerabilities:",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {len(data.critical_findings)} |",
            f"| High | {len(data.high_findings)} |",
            f"| Medium | {len(data.medium_findings)} |",
            f"| Low | {len(data.low_findings)} |",
            f"| Info | {len(data.info_findings)} |",
            f"",
        ]

        # Add verification statistics if there was filtering
        if data.false_positives_filtered > 0 or data.pending_manual_review > 0:
            lines.extend([
                f"### Verification Summary",
                f"",
                f"| Metric | Count |",
                f"|--------|-------|",
                f"| Total Discovered | {data.total_discovered} |",
                f"| Verified (Reportable) | {data.total_findings} |",
                f"| False Positives Filtered | {data.false_positives_filtered} |",
                f"| Pending Manual Review | {data.pending_manual_review} |",
                f"",
                f"> **Note:** Only verified findings are included in this report. ",
                f"> Critical and High severity findings require confirmed exploitation evidence.",
                f"",
            ])

        # Add findings sections
        for severity_name, findings in [
            ("Critical", data.critical_findings),
            ("High", data.high_findings),
            ("Medium", data.medium_findings),
            ("Low", data.low_findings),
        ]:
            if findings:
                lines.append(f"## {severity_name} Severity Findings")
                lines.append("")

                for i, finding in enumerate(findings, 1):
                    lines.append(f"### {i}. {finding.title}")
                    lines.append(f"")
                    lines.append(f"**URL:** `{finding.url}`")
                    if finding.parameter:
                        lines.append(f"**Parameter:** `{finding.parameter}`")
                    lines.append(f"**Source:** {finding.source}")
                    lines.append(f"")
                    if finding.description:
                        lines.append(f"**Description:**")
                        lines.append(f"{finding.description}")
                        lines.append(f"")
                    if finding.evidence and self.config.include_evidence:
                        lines.append(f"**Evidence:**")
                        lines.append(f"```")
                        lines.append(finding.evidence[:1000])
                        lines.append(f"```")
                        lines.append(f"")
                    if finding.remediation and self.config.include_remediation:
                        lines.append(f"**Remediation:**")
                        lines.append(f"{finding.remediation}")
                        lines.append(f"")

        # Footer
        lines.extend([
            f"---",
            f"",
            f"*Generated by AIPT - AI-Powered Penetration Testing Framework*",
        ])

        content = "\n".join(lines)

        filename = f"aipt3_report_{data.scan_id}_{data.generated_at.strftime('%Y%m%d_%H%M%S')}.md"
        path = self.config.output_dir / filename

        path.write_text(content)
        logger.info(f"Generated Markdown report: {path}")

        return path
