"""
AIPTX Findings Normalizer - Convert tool outputs to canonical FindingV2 format

This module normalizes findings from ALL scanners into the canonical FindingV2 format.
All findings start with verification_status = NEEDS_REVIEW (not falsely confirmed).

Output:
- {output_dir}/normalized/findings_raw.json - All normalized findings

Key features:
- Tool-specific normalizers for proper field mapping
- Severity normalization (no numeric, enum only)
- URL normalization (no double slashes)
- Category assignment for verification routing
- Proper tool failure tracking (FAILED status, not misleading "0")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Protocol

from aipt_v2.models.finding_v2 import (
    FindingCategory,
    FindingV2,
    ScannerType,
    SeverityV2,
    VerificationStatusV2,
    categorize_vuln_type,
    determine_scanner_type,
    normalize_url,
)

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Status of tool execution"""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    NOT_INSTALLED = "not_installed"


@dataclass
class ToolStats:
    """Statistics for a single tool"""

    tool_name: str
    status: ToolStatus
    finding_count: int = 0
    error: Optional[str] = None
    duration: Optional[float] = None
    scanner_type: ScannerType = ScannerType.LOCAL


@dataclass
class NormalizerResult:
    """Result of normalization process"""

    scan_id: str
    target: str
    normalized_at: datetime
    total_raw_findings: int
    findings: list[FindingV2]
    tool_stats: dict[str, ToolStats]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "normalized_at": self.normalized_at.isoformat(),
            "total_raw_findings": self.total_raw_findings,
            "findings": [f.to_dict() for f in self.findings],
            "tool_stats": {
                name: {
                    "tool_name": stats.tool_name,
                    "status": stats.status.value,
                    "finding_count": stats.finding_count,
                    "error": stats.error,
                    "duration": stats.duration,
                    "scanner_type": stats.scanner_type.value,
                }
                for name, stats in self.tool_stats.items()
            },
        }


class ToolNormalizer(Protocol):
    """Protocol for tool-specific normalizers"""

    def normalize(self, raw_finding: dict[str, Any], target: str) -> FindingV2:
        """Convert raw tool finding to FindingV2"""
        ...


class GenericNormalizer:
    """Generic normalizer for simple finding formats"""

    def normalize(self, raw_finding: dict[str, Any], target: str) -> FindingV2:
        """Convert generic finding dict to FindingV2"""
        # Extract severity (handle multiple formats)
        severity = self._extract_severity(raw_finding)

        # Determine category
        vuln_type = raw_finding.get("vuln_type") or raw_finding.get("type") or "other"
        if hasattr(vuln_type, "value"):
            vuln_type = vuln_type.value
        category = categorize_vuln_type(str(vuln_type))

        # Extract URL
        url = raw_finding.get("url") or raw_finding.get("target") or f"https://{target}/"
        url = normalize_url(url, target)

        # Determine scanner type
        source = raw_finding.get("source") or raw_finding.get("tool") or "unknown"
        scanner_type = determine_scanner_type(source)

        return FindingV2(
            title=raw_finding.get("title")
            or raw_finding.get("value")
            or raw_finding.get("name")
            or "Unknown Finding",
            severity=severity,
            category=category,
            vuln_type=str(vuln_type),
            target=target,
            url=url,
            parameter=raw_finding.get("parameter"),
            method=raw_finding.get("method", "GET"),
            description=raw_finding.get("description") or "",
            evidence=raw_finding.get("evidence") or "",
            raw_request=raw_finding.get("request") or raw_finding.get("raw_request"),
            raw_response=raw_finding.get("response") or raw_finding.get("raw_response"),
            verification_status=VerificationStatusV2.NEEDS_REVIEW,  # Default!
            source_tool=source,
            source_scanner_type=scanner_type,
            source_raw_id=raw_finding.get("source_id")
            or raw_finding.get("vuln_id")
            or raw_finding.get("id"),
            discovered_at=self._parse_timestamp(
                raw_finding.get("discovered_at") or raw_finding.get("timestamp")
            ),
            cvss_score=raw_finding.get("cvss_score"),
            cwe_id=raw_finding.get("cwe_id") or raw_finding.get("cwe"),
            cve_ids=raw_finding.get("cve_ids") or raw_finding.get("cve") or [],
            references=raw_finding.get("references") or [],
            remediation=raw_finding.get("remediation") or "",
        )

    def _extract_severity(self, raw: dict[str, Any]) -> SeverityV2:
        """Extract and normalize severity from various formats"""
        sev = raw.get("severity")

        if sev is None:
            return SeverityV2.INFO

        # Handle enum
        if hasattr(sev, "value"):
            sev = sev.value

        # Handle string
        if isinstance(sev, str):
            return SeverityV2.from_string(sev)

        # Handle numeric
        if isinstance(sev, (int, float)):
            if sev >= 9.0:
                return SeverityV2.CRITICAL
            elif sev >= 7.0:
                return SeverityV2.HIGH
            elif sev >= 4.0:
                return SeverityV2.MEDIUM
            elif sev > 0:
                return SeverityV2.LOW
            return SeverityV2.INFO

        return SeverityV2.INFO

    def _parse_timestamp(self, ts: Any) -> datetime:
        """Parse timestamp from various formats"""
        if ts is None:
            return datetime.utcnow()
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return datetime.utcnow()
        return datetime.utcnow()


class SSLScanNormalizer(GenericNormalizer):
    """Normalizer for sslscan/testssl findings"""

    def normalize(self, raw_finding: dict[str, Any], target: str) -> FindingV2:
        finding = super().normalize(raw_finding, target)
        # SSL/TLS findings are always TLS_SSL category
        finding.category = FindingCategory.TLS_SSL
        finding.source_scanner_type = ScannerType.LOCAL
        return finding


class NessusNormalizer(GenericNormalizer):
    """Normalizer for Nessus findings"""

    def normalize(self, raw_finding: dict[str, Any], target: str) -> FindingV2:
        # Map Nessus severity (0-4) to enum
        nessus_sev = raw_finding.get("severity")
        if isinstance(nessus_sev, int):
            severity_map = {
                4: SeverityV2.CRITICAL,
                3: SeverityV2.HIGH,
                2: SeverityV2.MEDIUM,
                1: SeverityV2.LOW,
                0: SeverityV2.INFO,
            }
            severity = severity_map.get(nessus_sev, SeverityV2.INFO)
        else:
            severity = self._extract_severity(raw_finding)

        # Build URL from host/port
        host = raw_finding.get("host") or target
        port = raw_finding.get("port") or 443
        url = f"https://{host}:{port}/" if port not in [80, 443] else f"https://{host}/"

        # Determine category from plugin name
        plugin_name = raw_finding.get("plugin_name") or ""
        if any(x in plugin_name.lower() for x in ["ssl", "tls", "certificate"]):
            category = FindingCategory.TLS_SSL
        elif "cve" in plugin_name.lower():
            category = FindingCategory.CVE_VERSION
        else:
            category = categorize_vuln_type(plugin_name)

        return FindingV2(
            title=raw_finding.get("plugin_name") or "Nessus Finding",
            severity=severity,
            category=category,
            vuln_type=raw_finding.get("plugin_id") or "nessus",
            target=target,
            url=normalize_url(url, target),
            description=raw_finding.get("description") or "",
            evidence=raw_finding.get("plugin_output") or raw_finding.get("output") or "",
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
            source_tool="nessus",
            source_scanner_type=ScannerType.API_ENTERPRISE,
            source_raw_id=str(raw_finding.get("plugin_id")),
            cvss_score=raw_finding.get("cvss_score"),
            cve_ids=raw_finding.get("cve") or [],
        )


class AcunetixNormalizer(GenericNormalizer):
    """Normalizer for Acunetix findings"""

    def normalize(self, raw_finding: dict[str, Any], target: str) -> FindingV2:
        # Map Acunetix severity (0-4 or string)
        acunetix_sev = raw_finding.get("severity")
        if isinstance(acunetix_sev, int):
            severity_map = {
                4: SeverityV2.CRITICAL,
                3: SeverityV2.HIGH,
                2: SeverityV2.MEDIUM,
                1: SeverityV2.LOW,
                0: SeverityV2.INFO,
            }
            severity = severity_map.get(acunetix_sev, SeverityV2.INFO)
        else:
            severity = self._extract_severity(raw_finding)

        url = raw_finding.get("affected_url") or raw_finding.get("url") or f"https://{target}/"

        return FindingV2(
            title=raw_finding.get("name") or raw_finding.get("vt_name") or "Acunetix Finding",
            severity=severity,
            category=categorize_vuln_type(raw_finding.get("name") or ""),
            vuln_type=raw_finding.get("vt_id") or "acunetix",
            target=target,
            url=normalize_url(url, target),
            description=raw_finding.get("description") or "",
            evidence=raw_finding.get("details") or "",
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
            source_tool="acunetix",
            source_scanner_type=ScannerType.API_ENTERPRISE,
            source_raw_id=raw_finding.get("vuln_id"),
            cvss_score=raw_finding.get("cvss_score"),
        )


class BurpNormalizer(GenericNormalizer):
    """Normalizer for Burp Suite findings"""

    def normalize(self, raw_finding: dict[str, Any], target: str) -> FindingV2:
        severity_str = raw_finding.get("severity", "info").lower()
        severity = SeverityV2.from_string(severity_str)

        url = raw_finding.get("url") or raw_finding.get("path") or f"https://{target}/"

        return FindingV2(
            title=raw_finding.get("name") or raw_finding.get("issue_type") or "Burp Finding",
            severity=severity,
            category=categorize_vuln_type(raw_finding.get("name") or ""),
            vuln_type=raw_finding.get("type_index") or "burp",
            target=target,
            url=normalize_url(url, target),
            description=raw_finding.get("description") or raw_finding.get("issue_detail") or "",
            evidence=raw_finding.get("evidence") or "",
            raw_request=raw_finding.get("request"),
            raw_response=raw_finding.get("response"),
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
            source_tool="burp",
            source_scanner_type=ScannerType.API_ENTERPRISE,
            source_raw_id=raw_finding.get("serial_number"),
        )


class NucleiNormalizer(GenericNormalizer):
    """Normalizer for Nuclei findings"""

    def normalize(self, raw_finding: dict[str, Any], target: str) -> FindingV2:
        # Nuclei has good severity strings
        severity = self._extract_severity(raw_finding)

        # Template ID determines category
        template_id = raw_finding.get("template-id") or raw_finding.get("template_id") or ""
        if "cve" in template_id.lower():
            category = FindingCategory.CVE_VERSION
        else:
            category = categorize_vuln_type(template_id)

        url = raw_finding.get("matched-at") or raw_finding.get("host") or f"https://{target}/"

        # Get info section if available
        info = raw_finding.get("info", {})

        return FindingV2(
            title=info.get("name") or template_id or "Nuclei Finding",
            severity=severity,
            category=category,
            vuln_type=template_id,
            target=target,
            url=normalize_url(url, target),
            description=info.get("description") or "",
            evidence=raw_finding.get("extracted-results") or raw_finding.get("matcher-name") or "",
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
            source_tool="nuclei",
            source_scanner_type=ScannerType.LOCAL,
            source_raw_id=raw_finding.get("matched-at"),
            cve_ids=info.get("classification", {}).get("cve-id") or [],
            cwe_id=info.get("classification", {}).get("cwe-id"),
            references=info.get("reference") or [],
        )


# Registry of tool-specific normalizers
TOOL_NORMALIZERS: dict[str, ToolNormalizer] = {
    "sslscan": SSLScanNormalizer(),
    "testssl": SSLScanNormalizer(),
    "nessus": NessusNormalizer(),
    "acunetix": AcunetixNormalizer(),
    "burp": BurpNormalizer(),
    "burp suite": BurpNormalizer(),
    "nuclei": NucleiNormalizer(),
}


class FindingsNormalizer:
    """
    Main normalizer that converts all tool outputs to FindingV2 format.

    Processes phase results and produces normalized/findings_raw.json
    """

    def __init__(self):
        self.generic_normalizer = GenericNormalizer()
        self.tool_stats: dict[str, ToolStats] = {}

    def normalize_all(
        self,
        phase_results: dict,
        output_dir: Path,
        scan_id: str,
        target: str,
    ) -> NormalizerResult:
        """
        Normalize all findings from phase results.

        Args:
            phase_results: Dict of Phase -> PhaseResult
            output_dir: Directory to write findings_raw.json
            scan_id: Unique scan identifier
            target: Target domain/IP

        Returns:
            NormalizerResult with all normalized findings
        """
        all_findings: list[FindingV2] = []
        self.tool_stats = {}

        # Process each phase
        for phase, result in phase_results.items():
            phase_findings = self._normalize_phase_findings(result, target)
            all_findings.extend(phase_findings)

        # Create result
        result = NormalizerResult(
            scan_id=scan_id,
            target=target,
            normalized_at=datetime.utcnow(),
            total_raw_findings=len(all_findings),
            findings=all_findings,
            tool_stats=self.tool_stats,
        )

        # Save to disk
        normalized_dir = output_dir / "normalized"
        normalized_dir.mkdir(parents=True, exist_ok=True)

        findings_raw_path = normalized_dir / "findings_raw.json"
        with open(findings_raw_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

        logger.info(f"Normalized {len(all_findings)} findings to {findings_raw_path}")

        return result

    def _normalize_phase_findings(self, phase_result: Any, target: str) -> list[FindingV2]:
        """Normalize findings from a single phase result"""
        findings: list[FindingV2] = []

        # Get findings from phase result
        if hasattr(phase_result, "findings"):
            raw_findings = phase_result.findings
        elif hasattr(phase_result, "get_all_findings"):
            raw_findings = phase_result.get_all_findings(deduplicate=False)
        elif isinstance(phase_result, dict):
            raw_findings = phase_result.get("findings", [])
        else:
            raw_findings = []

        # Process each finding
        for raw in raw_findings:
            try:
                finding = self._normalize_single_finding(raw, target)
                findings.append(finding)

                # Track tool stats
                tool_name = finding.source_tool
                if tool_name not in self.tool_stats:
                    self.tool_stats[tool_name] = ToolStats(
                        tool_name=tool_name,
                        status=ToolStatus.COMPLETED,
                        finding_count=0,
                        scanner_type=finding.source_scanner_type,
                    )
                self.tool_stats[tool_name].finding_count += 1

            except Exception as e:
                logger.warning(f"Failed to normalize finding: {e}")
                continue

        # Check for tool errors in phase result
        if hasattr(phase_result, "errors") and phase_result.errors:
            for error in phase_result.errors:
                tool_name = error.get("tool") or "unknown"
                self.tool_stats[tool_name] = ToolStats(
                    tool_name=tool_name,
                    status=ToolStatus.FAILED,
                    finding_count=0,
                    error=str(error.get("error") or error.get("message") or "Unknown error"),
                )

        return findings

    def _normalize_single_finding(self, raw: Any, target: str) -> FindingV2:
        """Normalize a single finding using appropriate normalizer"""
        # Handle FindingV2 (already normalized)
        if isinstance(raw, FindingV2):
            return raw

        # Handle legacy Finding
        if hasattr(raw, "title") and hasattr(raw, "severity") and hasattr(raw, "vuln_type"):
            return FindingV2.from_legacy(raw)

        # Handle dict
        if isinstance(raw, dict):
            # Get tool name to select normalizer
            tool_name = (raw.get("source") or raw.get("tool") or "unknown").lower()

            # Find appropriate normalizer
            normalizer = TOOL_NORMALIZERS.get(tool_name, self.generic_normalizer)

            return normalizer.normalize(raw, target)

        # Fallback - create minimal finding
        return FindingV2(
            title=str(raw),
            severity=SeverityV2.INFO,
            target=target,
            url=f"https://{target}/",
            source_tool="unknown",
        )

    def normalize_from_json_files(
        self,
        output_dir: Path,
        scan_id: str,
        target: str,
    ) -> NormalizerResult:
        """
        Normalize findings from JSON files in output directory.

        Looks for:
        - findings.json
        - *_findings.json
        - *_scan.json
        - scanner_results_summary.json (for tool status)
        """
        all_findings: list[FindingV2] = []
        self.tool_stats = {}

        # Find JSON files
        json_files = list(output_dir.glob("*.json"))

        for json_file in json_files:
            try:
                with open(json_file) as f:
                    data = json.load(f)

                # Skip non-finding files
                if json_file.name == "scanner_results_summary.json":
                    self._process_scanner_summary(data)
                    continue

                if json_file.name == "triage_result.json":
                    continue  # Skip triage, it's analysis not findings

                # Extract findings
                findings_data = []
                if isinstance(data, list):
                    findings_data = data
                elif isinstance(data, dict):
                    findings_data = data.get("findings") or data.get("vulnerabilities") or []

                # Normalize each finding
                for raw in findings_data:
                    try:
                        finding = self._normalize_single_finding(raw, target)
                        all_findings.append(finding)

                        # Track stats
                        tool_name = finding.source_tool
                        if tool_name not in self.tool_stats:
                            self.tool_stats[tool_name] = ToolStats(
                                tool_name=tool_name,
                                status=ToolStatus.COMPLETED,
                                finding_count=0,
                                scanner_type=finding.source_scanner_type,
                            )
                        self.tool_stats[tool_name].finding_count += 1

                    except Exception as e:
                        logger.warning(f"Failed to normalize finding from {json_file}: {e}")

            except Exception as e:
                logger.warning(f"Failed to process {json_file}: {e}")

        # Create result
        result = NormalizerResult(
            scan_id=scan_id,
            target=target,
            normalized_at=datetime.utcnow(),
            total_raw_findings=len(all_findings),
            findings=all_findings,
            tool_stats=self.tool_stats,
        )

        # Save to disk
        normalized_dir = output_dir / "normalized"
        normalized_dir.mkdir(parents=True, exist_ok=True)

        findings_raw_path = normalized_dir / "findings_raw.json"
        with open(findings_raw_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

        logger.info(
            f"Normalized {len(all_findings)} findings from JSON files to {findings_raw_path}"
        )

        return result

    def _process_scanner_summary(self, data: dict) -> None:
        """Process scanner_results_summary.json for tool status"""
        # Completed scanners
        for scanner in data.get("completed", []):
            self.tool_stats[scanner] = ToolStats(
                tool_name=scanner,
                status=ToolStatus.COMPLETED,
                scanner_type=determine_scanner_type(scanner),
            )

        # Still running scanners
        for scanner in data.get("still_running", []):
            self.tool_stats[scanner] = ToolStats(
                tool_name=scanner,
                status=ToolStatus.COMPLETED,  # Treat as completed for now
                scanner_type=determine_scanner_type(scanner),
            )

        # Failed scanners - IMPORTANT: properly track failures
        for failure in data.get("failed", []):
            if isinstance(failure, dict):
                scanner = failure.get("scanner", "unknown")
                error = failure.get("error", "Unknown error")
            else:
                scanner = str(failure)
                error = "Failed"

            self.tool_stats[scanner] = ToolStats(
                tool_name=scanner,
                status=ToolStatus.FAILED,
                finding_count=0,  # NOT misleading - explicitly 0
                error=error,
                scanner_type=determine_scanner_type(scanner),
            )
