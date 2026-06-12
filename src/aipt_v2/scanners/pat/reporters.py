"""
PAT Scanner Report Pipeline

Unified reporting for PAT scan results with multiple output formats:
- SARIF: GitHub Code Scanning integration
- HTML: Standalone styled reports
- JSON: Machine-readable export
- Compliance: OWASP/PCI/NIST mapping

Usage:
    from aipt_v2.scanners.pat.reporters import PATReportPipeline

    scanner = ChainEscalatingPATScanner(config)
    result = await scanner.scan()

    pipeline = PATReportPipeline(result)
    pipeline.to_sarif("results.sarif")
    pipeline.to_html("report.html")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import VulnerabilityType
from .pat_scanner import PATScanResult

logger = logging.getLogger(__name__)

# SARIF version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# Tool information
PAT_TOOL_NAME = "AIPTX-PAT-Scanner"
PAT_TOOL_VERSION = "4.0.0"
PAT_TOOL_URI = "https://github.com/swisskyrepo/PayloadsAllTheThings"

# CWE mappings for PAT vulnerability types
PAT_CWE_MAPPINGS = {
    # Core injection types
    VulnerabilityType.SQL_INJECTION: "CWE-89",
    VulnerabilityType.XSS: "CWE-79",
    VulnerabilityType.COMMAND_INJECTION: "CWE-78",
    VulnerabilityType.SSRF: "CWE-918",
    VulnerabilityType.XXE: "CWE-611",
    VulnerabilityType.LFI: "CWE-98",
    VulnerabilityType.RFI: "CWE-98",
    VulnerabilityType.SSTI: "CWE-94",
    VulnerabilityType.NOSQL_INJECTION: "CWE-943",
    VulnerabilityType.LDAP_INJECTION: "CWE-90",
    VulnerabilityType.XPATH_INJECTION: "CWE-643",
    VulnerabilityType.CRLF_INJECTION: "CWE-93",
    VulnerabilityType.OPEN_REDIRECT: "CWE-601",
    VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
    VulnerabilityType.INSECURE_DESERIALIZATION: "CWE-502",
    VulnerabilityType.JWT_ATTACKS: "CWE-347",
    VulnerabilityType.GRAPHQL: "CWE-200",
    VulnerabilityType.WEBSOCKET: "CWE-1385",
    VulnerabilityType.FILE_UPLOAD: "CWE-434",
    # New - Authentication & Access
    VulnerabilityType.CSRF: "CWE-352",
    VulnerabilityType.IDOR: "CWE-639",
    VulnerabilityType.OAUTH_MISCONFIG: "CWE-287",
    VulnerabilityType.SAML_INJECTION: "CWE-290",
    VulnerabilityType.ACCOUNT_TAKEOVER: "CWE-287",
    # New - Protocol attacks
    VulnerabilityType.HTTP_SMUGGLING: "CWE-444",
    VulnerabilityType.HPP: "CWE-235",
    VulnerabilityType.DNS_REBINDING: "CWE-350",
    VulnerabilityType.CORS_MISCONFIG: "CWE-942",
    VulnerabilityType.TABNABBING: "CWE-1022",
    VulnerabilityType.CACHE_POISONING: "CWE-525",
    # New - Client-side
    VulnerabilityType.DOM_CLOBBERING: "CWE-79",
    VulnerabilityType.CLICKJACKING: "CWE-1021",
    VulnerabilityType.PROTOTYPE_POLLUTION: "CWE-1321",
    VulnerabilityType.CLIENT_PATH_TRAVERSAL: "CWE-22",
    # New - File & Data
    VulnerabilityType.CSV_INJECTION: "CWE-1236",
    VulnerabilityType.ZIP_SLIP: "CWE-22",
    VulnerabilityType.ORM_LEAK: "CWE-200",
    VulnerabilityType.SECRETS_EXPOSURE: "CWE-798",
    VulnerabilityType.API_KEY_LEAK: "CWE-798",
    # New - Business Logic
    VulnerabilityType.RACE_CONDITION: "CWE-362",
    VulnerabilityType.MASS_ASSIGNMENT: "CWE-915",
    VulnerabilityType.TYPE_JUGGLING: "CWE-843",
    VulnerabilityType.BUSINESS_LOGIC: "CWE-840",
    VulnerabilityType.INSECURE_RANDOM: "CWE-330",
    # New - Injection variants
    VulnerabilityType.LATEX_INJECTION: "CWE-94",
    VulnerabilityType.SSI_INJECTION: "CWE-97",
    VulnerabilityType.XSLT_INJECTION: "CWE-91",
    VulnerabilityType.PROMPT_INJECTION: "CWE-77",
    VulnerabilityType.REGEX_DOS: "CWE-1333",
    VulnerabilityType.JAVA_RMI: "CWE-502",
    # New - Misconfig
    VulnerabilityType.GIT_EXPOSURE: "CWE-538",
    VulnerabilityType.HIDDEN_PARAMS: "CWE-472",
    VulnerabilityType.ADMIN_INTERFACE: "CWE-749",
    VulnerabilityType.VIRTUAL_HOST: "CWE-200",
    VulnerabilityType.REVERSE_PROXY: "CWE-441",
    VulnerabilityType.GWT_VULN: "CWE-502",
    VulnerabilityType.DEPENDENCY_CONFUSION: "CWE-427",
    VulnerabilityType.CVE_EXPLOITS: "CWE-1035",
    # New - Edge cases
    VulnerabilityType.ENV_INJECTION: "CWE-94",
    VulnerabilityType.HEADLESS_BROWSER: "CWE-94",
    VulnerabilityType.ENCODING_BYPASS: "CWE-838",
    VulnerabilityType.HOST_HEADER: "CWE-644",
    VulnerabilityType.HTTP_VERB_TAMPERING: "CWE-650",
    VulnerabilityType.SUBDOMAIN_TAKEOVER: "CWE-284",
}

# OWASP Top 10 2021 mappings
OWASP_TOP_10_MAPPINGS = {
    VulnerabilityType.SQL_INJECTION: "A03:2021-Injection",
    VulnerabilityType.COMMAND_INJECTION: "A03:2021-Injection",
    VulnerabilityType.NOSQL_INJECTION: "A03:2021-Injection",
    VulnerabilityType.LDAP_INJECTION: "A03:2021-Injection",
    VulnerabilityType.XPATH_INJECTION: "A03:2021-Injection",
    VulnerabilityType.XXE: "A03:2021-Injection",
    VulnerabilityType.SSTI: "A03:2021-Injection",
    VulnerabilityType.LATEX_INJECTION: "A03:2021-Injection",
    VulnerabilityType.SSI_INJECTION: "A03:2021-Injection",
    VulnerabilityType.XSLT_INJECTION: "A03:2021-Injection",
    VulnerabilityType.XSS: "A03:2021-Injection",
    VulnerabilityType.DOM_CLOBBERING: "A03:2021-Injection",
    VulnerabilityType.PROTOTYPE_POLLUTION: "A03:2021-Injection",
    VulnerabilityType.CSRF: "A01:2021-Broken Access Control",
    VulnerabilityType.IDOR: "A01:2021-Broken Access Control",
    VulnerabilityType.PATH_TRAVERSAL: "A01:2021-Broken Access Control",
    VulnerabilityType.LFI: "A01:2021-Broken Access Control",
    VulnerabilityType.RFI: "A01:2021-Broken Access Control",
    VulnerabilityType.SSRF: "A10:2021-SSRF",
    VulnerabilityType.OAUTH_MISCONFIG: "A07:2021-Identification and Authentication Failures",
    VulnerabilityType.JWT_ATTACKS: "A07:2021-Identification and Authentication Failures",
    VulnerabilityType.ACCOUNT_TAKEOVER: "A07:2021-Identification and Authentication Failures",
    VulnerabilityType.SAML_INJECTION: "A07:2021-Identification and Authentication Failures",
    VulnerabilityType.CORS_MISCONFIG: "A05:2021-Security Misconfiguration",
    VulnerabilityType.ADMIN_INTERFACE: "A05:2021-Security Misconfiguration",
    VulnerabilityType.GIT_EXPOSURE: "A05:2021-Security Misconfiguration",
    VulnerabilityType.SECRETS_EXPOSURE: "A05:2021-Security Misconfiguration",
    VulnerabilityType.API_KEY_LEAK: "A05:2021-Security Misconfiguration",
    VulnerabilityType.INSECURE_DESERIALIZATION: "A08:2021-Software and Data Integrity Failures",
    VulnerabilityType.JAVA_RMI: "A08:2021-Software and Data Integrity Failures",
    VulnerabilityType.DEPENDENCY_CONFUSION: "A08:2021-Software and Data Integrity Failures",
    VulnerabilityType.INSECURE_RANDOM: "A02:2021-Cryptographic Failures",
}


@dataclass
class PATReportConfig:
    """Configuration for PAT report generation."""

    include_poc: bool = True
    include_evidence: bool = True
    include_requests: bool = True
    include_recommendations: bool = True
    min_severity: str = "low"
    tool_version: str = PAT_TOOL_VERSION


class PATReportPipeline:
    """
    Unified reporting pipeline for PAT scan results.

    Generates reports in multiple formats:
    - SARIF: For GitHub Code Scanning integration
    - HTML: Standalone styled reports
    - JSON: Machine-readable export
    - Compliance: OWASP/PCI mapping

    Usage:
        scanner = ChainEscalatingPATScanner(config)
        result = await scanner.scan()

        pipeline = PATReportPipeline(result)
        pipeline.to_sarif("results.sarif")
        pipeline.to_html("report.html")
        pipeline.to_json("results.json")
    """

    def __init__(
        self,
        scan_result: PATScanResult,
        config: Optional[PATReportConfig] = None,
    ):
        """
        Initialize report pipeline.

        Args:
            scan_result: PATScanResult from scanner
            config: Optional report configuration
        """
        self.result = scan_result
        self.config = config or PATReportConfig()

    def to_sarif(self, output_path: str) -> str:
        """
        Generate SARIF report for GitHub Code Scanning.

        Args:
            output_path: Path to write SARIF file

        Returns:
            Path to generated file
        """
        sarif = self._build_sarif()

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, default=str)

        logger.info(f"Generated SARIF report: {output_path}")
        return str(path)

    def _build_sarif(self) -> dict:
        """Build SARIF 2.1.0 compliant document."""
        # Build rules from findings
        rules = {}
        results = []

        for finding in self.result.findings:
            # Get vuln type from template
            vuln_type_str = finding.template or "unknown"
            try:
                vuln_type = VulnerabilityType(vuln_type_str)
            except ValueError:
                vuln_type = None

            rule_id = f"PAT-{vuln_type_str.upper().replace('_', '-')}"

            # Add rule if not seen
            if rule_id not in rules:
                cwe = PAT_CWE_MAPPINGS.get(vuln_type, "CWE-693") if vuln_type else "CWE-693"
                owasp = OWASP_TOP_10_MAPPINGS.get(vuln_type, "Unknown") if vuln_type else "Unknown"

                rules[rule_id] = {
                    "id": rule_id,
                    "name": (
                        finding.title.split(" in ")[0] if " in " in finding.title else finding.title
                    ),
                    "shortDescription": {
                        "text": f"{vuln_type_str.replace('_', ' ').title()} vulnerability"
                    },
                    "fullDescription": {
                        "text": finding.description
                        or f"Potential {vuln_type_str} vulnerability detected by PAT scanner."
                    },
                    "helpUri": f"https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/{vuln_type_str.replace('_', '%20').title()}",
                    "properties": {
                        "tags": [cwe, owasp] + (finding.tags or []),
                        "security-severity": self._severity_to_score(finding.severity.value),
                    },
                }

            # Build result
            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(finding.severity.value),
                "message": {"text": finding.description or finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.url or self.result.target,
                                "uriBaseId": "ROOTPATH",
                            }
                        }
                    }
                ],
            }

            # Add evidence if available
            if finding.evidence and self.config.include_evidence:
                result["fingerprints"] = {"evidence": finding.evidence[:500]}

            # Add PoC if available
            if finding.request and self.config.include_poc:
                result["codeFlows"] = [
                    {
                        "message": {"text": "Proof of Concept"},
                        "threadFlows": [
                            {
                                "locations": [
                                    {"location": {"message": {"text": finding.request[:1000]}}}
                                ]
                            }
                        ],
                    }
                ]

            results.append(result)

        # Build SARIF document
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": PAT_TOOL_NAME,
                            "version": self.config.tool_version,
                            "informationUri": PAT_TOOL_URI,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": self.result.status == "completed",
                            "startTimeUtc": (
                                self.result.start_time.isoformat()
                                if self.result.start_time
                                else None
                            ),
                            "endTimeUtc": (
                                self.result.end_time.isoformat() if self.result.end_time else None
                            ),
                        }
                    ],
                }
            ],
        }

        return sarif

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return mapping.get(severity.lower(), "warning")

    def _severity_to_score(self, severity: str) -> str:
        """Convert severity to security-severity score."""
        mapping = {
            "critical": "9.5",
            "high": "7.5",
            "medium": "5.0",
            "low": "3.0",
            "info": "1.0",
        }
        return mapping.get(severity.lower(), "5.0")

    def to_html(self, output_path: str, title: Optional[str] = None) -> str:
        """
        Generate standalone HTML report.

        Args:
            output_path: Path to write HTML file
            title: Optional report title

        Returns:
            Path to generated file
        """
        html = self._build_html(title or f"PAT Scan: {self.result.target}")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Generated HTML report: {output_path}")
        return str(path)

    def _build_html(self, title: str) -> str:
        """Build HTML report document."""
        # Count severities
        severity_counts = self.result.severity_counts()
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        medium = severity_counts.get("medium", 0)
        low = severity_counts.get("low", 0)

        # Build findings HTML
        findings_html = ""
        for i, finding in enumerate(self.result.findings, 1):
            severity_class = finding.severity.value.lower()
            vuln_type = finding.template or "Unknown"

            # Get CWE and OWASP mappings
            try:
                vt = VulnerabilityType(vuln_type)
                cwe = PAT_CWE_MAPPINGS.get(vt, "N/A")
                owasp = OWASP_TOP_10_MAPPINGS.get(vt, "N/A")
            except ValueError:
                cwe = "N/A"
                owasp = "N/A"

            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="finding-number">#{i}</span>
                    <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                    <h3>{finding.title}</h3>
                </div>
                <div class="finding-body">
                    <p><strong>URL:</strong> <code>{finding.url}</code></p>
                    <p><strong>CWE:</strong> {cwe} | <strong>OWASP:</strong> {owasp}</p>
                    <p><strong>Description:</strong> {finding.description or 'N/A'}</p>
                    {'<details><summary>Evidence</summary><pre>' + (finding.evidence or 'N/A') + '</pre></details>' if finding.evidence else ''}
                    {'<details><summary>Request</summary><pre>' + (finding.request or 'N/A') + '</pre></details>' if finding.request and self.config.include_requests else ''}
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card.critical {{ border-left: 4px solid var(--critical); }}
        .summary-card.high {{ border-left: 4px solid var(--high); }}
        .summary-card.medium {{ border-left: 4px solid var(--medium); }}
        .summary-card.low {{ border-left: 4px solid var(--low); }}
        .summary-card h2 {{ font-size: 2em; margin-bottom: 5px; }}
        .finding {{ background: white; margin-bottom: 15px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding-header {{ padding: 15px 20px; background: #f8f9fa; display: flex; align-items: center; gap: 15px; }}
        .finding-number {{ background: #e9ecef; padding: 5px 10px; border-radius: 4px; font-weight: bold; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 4px; color: white; font-size: 0.8em; font-weight: bold; }}
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); }}
        .severity-badge.low {{ background: var(--low); }}
        .severity-badge.info {{ background: var(--info); }}
        .finding-body {{ padding: 20px; }}
        .finding-body p {{ margin-bottom: 10px; }}
        .finding-body code {{ background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: monospace; word-break: break-all; }}
        details {{ margin-top: 10px; }}
        summary {{ cursor: pointer; font-weight: bold; color: #0066cc; }}
        pre {{ background: #1a1a2e; color: #00ff00; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-size: 0.85em; }}
        .finding.critical {{ border-left: 4px solid var(--critical); }}
        .finding.high {{ border-left: 4px solid var(--high); }}
        .finding.medium {{ border-left: 4px solid var(--medium); }}
        .finding.low {{ border-left: 4px solid var(--low); }}
        footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 {title}</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {self.result.target}</p>
            <p>Duration: {self.result.duration_seconds:.2f}s | Requests: {self.result.requests_made} | Payloads Tested: {self.result.payloads_tested}</p>
        </header>

        <div class="summary">
            <div class="summary-card critical">
                <h2>{critical}</h2>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h2>{high}</h2>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h2>{medium}</h2>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h2>{low}</h2>
                <p>Low</p>
            </div>
        </div>

        <h2 style="margin: 20px 0;">Findings ({len(self.result.findings)})</h2>
        {findings_html if findings_html else '<p style="background: white; padding: 20px; border-radius: 8px;">No vulnerabilities found.</p>'}

        <footer>
            <p>Generated by {PAT_TOOL_NAME} v{self.config.tool_version}</p>
            <p>Payloads from <a href="{PAT_TOOL_URI}">PayloadsAllTheThings</a></p>
        </footer>
    </div>
</body>
</html>"""
        return html

    def to_json(self, output_path: str) -> str:
        """
        Export full JSON with metadata.

        Args:
            output_path: Path to write JSON file

        Returns:
            Path to generated file
        """
        export = self._build_json_export()

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, default=str)

        logger.info(f"Generated JSON export: {output_path}")
        return str(path)

    def _build_json_export(self) -> dict:
        """Build comprehensive JSON export."""
        return {
            "meta": {
                "tool": PAT_TOOL_NAME,
                "version": self.config.tool_version,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "scan": {
                "target": self.result.target,
                "status": self.result.status,
                "start_time": (
                    self.result.start_time.isoformat() if self.result.start_time else None
                ),
                "end_time": self.result.end_time.isoformat() if self.result.end_time else None,
                "duration_seconds": self.result.duration_seconds,
                "requests_made": self.result.requests_made,
                "payloads_tested": self.result.payloads_tested,
            },
            "summary": {
                "total_findings": len(self.result.findings),
                "severity_counts": self.result.severity_counts(),
                "vuln_types_found": self.result.vuln_types_found,
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "url": f.url,
                    "description": f.description,
                    "evidence": f.evidence if self.config.include_evidence else None,
                    "request": f.request if self.config.include_poc else None,
                    "response": f.response[:500] if f.response else None,
                    "template": f.template,
                    "tags": f.tags,
                    "cwe": (
                        PAT_CWE_MAPPINGS.get(VulnerabilityType(f.template), "Unknown")
                        if f.template
                        else None
                    ),
                }
                for f in self.result.findings
            ],
            "errors": self.result.errors,
        }

    def to_compliance(self, framework: str, output_path: str) -> str:
        """
        Generate compliance-mapped report.

        Args:
            framework: Compliance framework (owasp, pci, nist)
            output_path: Path to write report

        Returns:
            Path to generated file
        """
        if framework.lower() == "owasp":
            report = self._build_owasp_report()
        elif framework.lower() == "pci":
            report = self._build_pci_report()
        elif framework.lower() == "nist":
            report = self._build_nist_report()
        else:
            raise ValueError(f"Unknown framework: {framework}")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Generated {framework.upper()} compliance report: {output_path}")
        return str(path)

    def _build_owasp_report(self) -> dict:
        """Build OWASP Top 10 2021 mapped report."""
        # Group findings by OWASP category
        owasp_groups: dict[str, list] = {}

        for finding in self.result.findings:
            try:
                vt = VulnerabilityType(finding.template) if finding.template else None
                owasp_cat = OWASP_TOP_10_MAPPINGS.get(vt, "Unknown") if vt else "Unknown"
            except ValueError:
                owasp_cat = "Unknown"

            if owasp_cat not in owasp_groups:
                owasp_groups[owasp_cat] = []
            owasp_groups[owasp_cat].append(
                {
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "url": finding.url,
                }
            )

        return {
            "framework": "OWASP Top 10 2021",
            "target": self.result.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(self.result.findings),
                "categories_affected": len(owasp_groups),
            },
            "categories": owasp_groups,
        }

    def _build_pci_report(self) -> dict:
        """Build PCI DSS 4.0 mapped report."""
        # PCI DSS requirement mappings
        pci_mappings = {
            VulnerabilityType.SQL_INJECTION: "6.2.4 - Injection Flaws",
            VulnerabilityType.XSS: "6.2.4 - Injection Flaws",
            VulnerabilityType.COMMAND_INJECTION: "6.2.4 - Injection Flaws",
            VulnerabilityType.SECRETS_EXPOSURE: "8.3.1 - Strong Cryptography",
            VulnerabilityType.API_KEY_LEAK: "8.3.1 - Strong Cryptography",
            VulnerabilityType.INSECURE_RANDOM: "8.3.1 - Strong Cryptography",
        }

        pci_groups: dict[str, list] = {}

        for finding in self.result.findings:
            try:
                vt = VulnerabilityType(finding.template) if finding.template else None
                pci_req = (
                    pci_mappings.get(vt, "6.5.x - Secure Coding") if vt else "6.5.x - Secure Coding"
                )
            except ValueError:
                pci_req = "6.5.x - Secure Coding"

            if pci_req not in pci_groups:
                pci_groups[pci_req] = []
            pci_groups[pci_req].append(
                {
                    "title": finding.title,
                    "severity": finding.severity.value,
                }
            )

        return {
            "framework": "PCI DSS 4.0",
            "target": self.result.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "requirements": pci_groups,
        }

    def _build_nist_report(self) -> dict:
        """Build NIST CSF mapped report."""
        return {
            "framework": "NIST Cybersecurity Framework",
            "target": self.result.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(self.result.findings),
                "severity_counts": self.result.severity_counts(),
            },
            "categories": {
                "Identify (ID)": [],
                "Protect (PR)": [f.title for f in self.result.findings],
                "Detect (DE)": [],
                "Respond (RS)": [],
                "Recover (RC)": [],
            },
        }


# Convenience functions
def generate_pat_sarif(
    scan_result: PATScanResult,
    output_path: str,
) -> str:
    """Quick function to generate SARIF report."""
    pipeline = PATReportPipeline(scan_result)
    return pipeline.to_sarif(output_path)


def generate_pat_html(
    scan_result: PATScanResult,
    output_path: str,
    title: Optional[str] = None,
) -> str:
    """Quick function to generate HTML report."""
    pipeline = PATReportPipeline(scan_result)
    return pipeline.to_html(output_path, title)
