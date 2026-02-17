"""
AIPTX SARIF Report Generator - GitHub Security Tab Integration

Generates SARIF 2.1.0 compliant reports for:
- GitHub Code Scanning
- GitHub Actions integration
- PR blocking based on findings
- Security tab visualization

SARIF = Static Analysis Results Interchange Format
https://sarifweb.azurewebsites.net/
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    VulnerabilityType,
)

logger = logging.getLogger(__name__)

# SARIF version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# Tool information
TOOL_NAME = "AIPTX"
TOOL_VERSION = "4.0.0"
TOOL_INFORMATION_URI = "https://aiptx.io"
TOOL_DOWNLOAD_URI = "https://pypi.org/project/aiptx/"


# CWE mappings for common vulnerability types
CWE_MAPPINGS = {
    VulnerabilityType.SQLI: "CWE-89",
    VulnerabilityType.XSS: "CWE-79",
    VulnerabilityType.COMMAND_INJECTION: "CWE-78",
    VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
    VulnerabilityType.SSRF: "CWE-918",
    VulnerabilityType.XXE: "CWE-611",
    VulnerabilityType.LFI: "CWE-98",
    VulnerabilityType.RFI: "CWE-98",
    VulnerabilityType.IDOR: "CWE-639",
    VulnerabilityType.AUTH_BYPASS: "CWE-287",
    VulnerabilityType.BROKEN_AUTH: "CWE-287",
    VulnerabilityType.DESERIALIZATION: "CWE-502",
    VulnerabilityType.HARDCODED_SECRETS: "CWE-798",
    VulnerabilityType.SSTI: "CWE-94",
    VulnerabilityType.OPEN_REDIRECT: "CWE-601",
    VulnerabilityType.CORS_MISCONFIGURATION: "CWE-346",
    VulnerabilityType.RCE: "CWE-94",
    VulnerabilityType.RACE_CONDITION: "CWE-362",
    VulnerabilityType.WEAK_CRYPTO: "CWE-327",
    VulnerabilityType.MISCONFIGURATION: "CWE-16",
    VulnerabilityType.INFORMATION_DISCLOSURE: "CWE-200",
    VulnerabilityType.NOSQL_INJECTION: "CWE-943",
}


@dataclass
class SARIFConfig:
    """Configuration for SARIF generation."""
    include_poc: bool = True
    include_evidence: bool = True
    include_fixes: bool = True
    min_severity: FindingSeverity = FindingSeverity.INFO
    tool_version: str = TOOL_VERSION


class SARIFGenerator:
    """
    Generates SARIF 2.1.0 compliant reports.

    SARIF is the standard format for:
    - GitHub Code Scanning integration
    - Security vulnerability visualization
    - CI/CD pipeline blocking

    Usage:
        generator = SARIFGenerator()
        sarif = generator.generate(findings)
        generator.to_file("results.sarif", sarif)
    """

    def __init__(self, config: Optional[SARIFConfig] = None):
        """
        Initialize SARIF generator.

        Args:
            config: Optional configuration
        """
        self.config = config or SARIFConfig()

    def generate(
        self,
        findings: list[Finding],
        target: Optional[str] = None,
        scan_metadata: Optional[dict] = None,
    ) -> dict:
        """
        Generate SARIF report from findings.

        Args:
            findings: List of findings to include
            target: Target URL/path
            scan_metadata: Optional metadata about the scan

        Returns:
            SARIF-compliant dictionary
        """
        # Filter by severity
        severity_order = [
            FindingSeverity.INFO,
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]
        min_index = severity_order.index(self.config.min_severity)
        filtered_findings = [
            f for f in findings
            if severity_order.index(f.severity) >= min_index
        ]

        # Build SARIF structure
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                self._build_run(filtered_findings, target, scan_metadata)
            ],
        }

        return sarif

    def _build_run(
        self,
        findings: list[Finding],
        target: Optional[str],
        metadata: Optional[dict],
    ) -> dict:
        """Build a SARIF run object."""
        # Collect unique rules
        rules = self._build_rules(findings)

        run = {
            "tool": self._build_tool(rules),
            "results": [self._build_result(f) for f in findings],
            "invocations": [self._build_invocation(target, metadata)],
        }

        # Add artifacts if we have file paths
        artifacts = self._build_artifacts(findings)
        if artifacts:
            run["artifacts"] = artifacts

        return run

    def _build_tool(self, rules: list[dict]) -> dict:
        """Build SARIF tool object."""
        return {
            "driver": {
                "name": TOOL_NAME,
                "version": self.config.tool_version,
                "informationUri": TOOL_INFORMATION_URI,
                "downloadUri": TOOL_DOWNLOAD_URI,
                "rules": rules,
                "organization": "AIPTX",
                "shortDescription": {
                    "text": "AI-Powered Penetration Testing Framework"
                },
                "fullDescription": {
                    "text": "AIPTX is an AI-native security testing framework with "
                           "multi-agent collaboration, PoC validation, and SAST+DAST capabilities."
                },
            }
        }

    def _build_rules(self, findings: list[Finding]) -> list[dict]:
        """Build unique rules from findings."""
        rules_dict = {}

        for finding in findings:
            rule_id = self._get_rule_id(finding)
            if rule_id in rules_dict:
                continue

            rules_dict[rule_id] = {
                "id": rule_id,
                "name": finding.vuln_type.value.replace("_", " ").title(),
                "shortDescription": {
                    "text": self._get_short_description(finding.vuln_type)
                },
                "fullDescription": {
                    "text": self._get_full_description(finding.vuln_type)
                },
                "help": {
                    "text": self._get_help_text(finding.vuln_type),
                    "markdown": self._get_help_markdown(finding.vuln_type),
                },
                "defaultConfiguration": {
                    "level": self._severity_to_level(finding.severity)
                },
                "properties": {
                    "tags": self._get_rule_tags(finding.vuln_type),
                    "security-severity": self._severity_to_score(finding.severity),
                },
            }

            # Add CWE if available
            cwe = CWE_MAPPINGS.get(finding.vuln_type)
            if cwe:
                rules_dict[rule_id]["relationships"] = [
                    {
                        "target": {
                            "id": cwe,
                            "guid": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",
                            "toolComponent": {
                                "name": "CWE",
                            }
                        },
                        "kinds": ["superset"]
                    }
                ]

        return list(rules_dict.values())

    def _build_result(self, finding: Finding) -> dict:
        """Build a SARIF result from a finding."""
        result = {
            "ruleId": self._get_rule_id(finding),
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": finding.description or finding.title,
            },
            "locations": [self._build_location(finding)],
        }

        # Add fingerprints for deduplication
        result["fingerprints"] = {
            "aiptx/v1": finding.get_fingerprint()
        }

        # Add partial fingerprints
        result["partialFingerprints"] = {
            "targetUrl": finding.url or finding.target,
            "vulnType": finding.vuln_type.value,
        }

        # Add fix information if available
        if self.config.include_fixes:
            fix = self._get_fix_suggestion(finding)
            if fix:
                result["fixes"] = [fix]

        # Add code flows for injection findings
        if finding.payload and finding.evidence:
            result["codeFlows"] = [self._build_code_flow(finding)]

        # Add properties
        result["properties"] = {
            "confidence": finding.confidence,
            "validated": finding.poc.validated if finding.poc else False,
            "tags": finding.tags,
        }

        if finding.cve_id:
            result["properties"]["cve"] = finding.cve_id
        if finding.cvss_score:
            result["properties"]["cvssScore"] = finding.cvss_score

        return result

    def _build_location(self, finding: Finding) -> dict:
        """Build SARIF location from finding."""
        location = {}

        # Physical location (file-based)
        if finding.file_path:
            location["physicalLocation"] = {
                "artifactLocation": {
                    "uri": finding.file_path,
                },
            }
            if finding.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line_number,
                }

        # Logical location (URL-based)
        if finding.url:
            location["logicalLocations"] = [
                {
                    "fullyQualifiedName": finding.url,
                    "kind": "endpoint",
                }
            ]
            if finding.parameter:
                location["logicalLocations"].append({
                    "fullyQualifiedName": f"{finding.url}?{finding.parameter}",
                    "kind": "parameter",
                    "name": finding.parameter,
                })

        # Message with details
        if finding.endpoint or finding.parameter:
            details = []
            if finding.endpoint:
                details.append(f"Endpoint: {finding.endpoint}")
            if finding.parameter:
                details.append(f"Parameter: {finding.parameter}")
            location["message"] = {"text": ", ".join(details)}

        return location

    def _build_artifacts(self, findings: list[Finding]) -> list[dict]:
        """Build artifacts list from findings."""
        artifacts = {}

        for finding in findings:
            if finding.file_path and finding.file_path not in artifacts:
                artifacts[finding.file_path] = {
                    "location": {
                        "uri": finding.file_path,
                    },
                    "sourceLanguage": self._detect_language(finding.file_path),
                }

        return list(artifacts.values())

    def _build_invocation(
        self,
        target: Optional[str],
        metadata: Optional[dict],
    ) -> dict:
        """Build invocation object."""
        invocation = {
            "executionSuccessful": True,
            "startTimeUtc": datetime.utcnow().isoformat() + "Z",
        }

        if target:
            invocation["arguments"] = [target]

        if metadata:
            invocation["properties"] = metadata

        return invocation

    def _build_code_flow(self, finding: Finding) -> dict:
        """Build code flow for injection findings."""
        thread_flows = []

        # Source (user input)
        if finding.parameter:
            thread_flows.append({
                "locations": [
                    {
                        "location": {
                            "message": {
                                "text": f"User input via parameter: {finding.parameter}"
                            },
                        },
                        "kinds": ["source"],
                    }
                ]
            })

        # Sink (vulnerable code)
        thread_flows.append({
            "locations": [
                {
                    "location": self._build_location(finding),
                    "kinds": ["sink"],
                }
            ]
        })

        return {"threadFlows": thread_flows}

    def _get_rule_id(self, finding: Finding) -> str:
        """Generate rule ID from finding."""
        return f"aiptx/{finding.vuln_type.value}"

    def _get_short_description(self, vuln_type: VulnerabilityType) -> str:
        """Get short description for vulnerability type."""
        descriptions = {
            VulnerabilityType.SQLI: "SQL Injection vulnerability",
            VulnerabilityType.XSS: "Cross-Site Scripting (XSS) vulnerability",
            VulnerabilityType.COMMAND_INJECTION: "Command Injection vulnerability",
            VulnerabilityType.SSRF: "Server-Side Request Forgery (SSRF)",
            VulnerabilityType.PATH_TRAVERSAL: "Path Traversal vulnerability",
            VulnerabilityType.AUTH_BYPASS: "Authentication Bypass",
            VulnerabilityType.IDOR: "Insecure Direct Object Reference (IDOR)",
            VulnerabilityType.HARDCODED_SECRETS: "Hardcoded Secret detected",
        }
        return descriptions.get(vuln_type, f"{vuln_type.value} vulnerability")

    def _get_full_description(self, vuln_type: VulnerabilityType) -> str:
        """Get full description for vulnerability type."""
        descriptions = {
            VulnerabilityType.SQLI: (
                "SQL Injection allows attackers to interfere with database queries, "
                "potentially accessing or modifying data they shouldn't."
            ),
            VulnerabilityType.XSS: (
                "Cross-Site Scripting allows attackers to inject malicious scripts "
                "into web pages viewed by other users."
            ),
            VulnerabilityType.SSRF: (
                "Server-Side Request Forgery allows attackers to make the server "
                "perform requests to internal resources or external services."
            ),
        }
        return descriptions.get(vuln_type, f"Security vulnerability: {vuln_type.value}")

    def _get_help_text(self, vuln_type: VulnerabilityType) -> str:
        """Get help text for vulnerability type."""
        return f"For more information about {vuln_type.value}, see the OWASP documentation."

    def _get_help_markdown(self, vuln_type: VulnerabilityType) -> str:
        """Get help markdown for vulnerability type."""
        cwe = CWE_MAPPINGS.get(vuln_type, "CWE-0")
        cwe_num = cwe.split("-")[1] if "-" in cwe else "0"

        return f"""## {vuln_type.value.replace('_', ' ').title()}

**Severity**: High

**CWE**: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)

### Description
{self._get_full_description(vuln_type)}

### Remediation
- Validate and sanitize all user input
- Use parameterized queries for database operations
- Implement proper output encoding

### References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE {cwe_num}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)
"""

    def _get_rule_tags(self, vuln_type: VulnerabilityType) -> list[str]:
        """Get tags for vulnerability type."""
        tags = ["security", "vulnerability"]

        if vuln_type in [VulnerabilityType.SQLI, VulnerabilityType.XSS,
                         VulnerabilityType.COMMAND_INJECTION]:
            tags.append("injection")
        if vuln_type in [VulnerabilityType.AUTH_BYPASS, VulnerabilityType.IDOR]:
            tags.append("authentication")
        if vuln_type in [VulnerabilityType.HARDCODED_SECRETS]:
            tags.append("secrets")

        return tags

    def _get_fix_suggestion(self, finding: Finding) -> Optional[dict]:
        """Get fix suggestion for finding."""
        if not finding.file_path:
            return None

        # Generate fix based on vulnerability type
        fix_suggestions = {
            VulnerabilityType.SQLI: "Use parameterized queries instead of string concatenation",
            VulnerabilityType.XSS: "Encode output before rendering to HTML",
            VulnerabilityType.HARDCODED_SECRETS: "Move secrets to environment variables",
        }

        suggestion = fix_suggestions.get(finding.vuln_type)
        if not suggestion:
            return None

        return {
            "description": {
                "text": suggestion
            },
            "changes": []  # Would need more context for actual code changes
        }

    def _severity_to_level(self, severity: FindingSeverity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            FindingSeverity.CRITICAL: "error",
            FindingSeverity.HIGH: "error",
            FindingSeverity.MEDIUM: "warning",
            FindingSeverity.LOW: "note",
            FindingSeverity.INFO: "note",
        }
        return mapping.get(severity, "note")

    def _severity_to_score(self, severity: FindingSeverity) -> str:
        """Convert severity to security-severity score."""
        mapping = {
            FindingSeverity.CRITICAL: "9.0",
            FindingSeverity.HIGH: "7.0",
            FindingSeverity.MEDIUM: "5.0",
            FindingSeverity.LOW: "3.0",
            FindingSeverity.INFO: "1.0",
        }
        return mapping.get(severity, "1.0")

    def _detect_language(self, file_path: str) -> str:
        """Detect source language from file path."""
        ext_mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
        }
        ext = Path(file_path).suffix.lower()
        return ext_mapping.get(ext, "unknown")

    def to_file(self, path: str, sarif: Optional[dict] = None, findings: Optional[list[Finding]] = None) -> None:
        """
        Write SARIF report to file.

        Args:
            path: Output file path
            sarif: Pre-generated SARIF dict, or
            findings: Findings to generate SARIF from
        """
        if sarif is None and findings is not None:
            sarif = self.generate(findings)

        if sarif is None:
            raise ValueError("Either sarif or findings must be provided")

        with open(path, "w") as f:
            json.dump(sarif, f, indent=2)

        logger.info(f"SARIF report written to {path}")

    def to_json(self, sarif: dict) -> str:
        """Convert SARIF to JSON string."""
        return json.dumps(sarif, indent=2)


def generate_sarif(
    findings: list[Finding],
    output_path: Optional[str] = None,
    **config_kwargs,
) -> dict:
    """
    Convenience function to generate SARIF report.

    Args:
        findings: Findings to include
        output_path: Optional path to write report
        **config_kwargs: SARIFConfig parameters

    Returns:
        SARIF dictionary
    """
    config = SARIFConfig(**config_kwargs)
    generator = SARIFGenerator(config)
    sarif = generator.generate(findings)

    if output_path:
        generator.to_file(output_path, sarif)

    return sarif
