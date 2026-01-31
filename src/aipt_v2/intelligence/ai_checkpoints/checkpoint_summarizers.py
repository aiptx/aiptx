"""
AIPTX Checkpoint Summarizers
============================

Summarizes phase results for efficient LLM consumption.
Handles context window limitations by intelligent compression.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SummarizationConfig:
    """Configuration for result summarization."""

    max_tokens: int = 6000  # Target output size in tokens
    prioritize_severity: bool = True
    include_evidence: bool = False  # Evidence is verbose
    group_by_type: bool = True
    max_findings_per_type: int = 5
    max_findings_total: int = 25


@dataclass
class CompactFinding:
    """Minimal representation for LLM consumption."""

    id: str           # e.g., "F001"
    type: str         # "sqli", "xss", "open_port"
    target: str       # URL or host:port
    severity: str     # "C", "H", "M", "L", "I"
    key_detail: str   # One-line essence (< 100 chars)
    chain_potential: List[str] = field(default_factory=list)

    def to_compact_str(self) -> str:
        """Format: [F001|sqli|H] /api/users?id= -> auth_bypass,rce"""
        chain_str = f" -> {','.join(self.chain_potential)}" if self.chain_potential else ""
        return f"[{self.id}|{self.type}|{self.severity}] {self.target}: {self.key_detail}{chain_str}"


class ReconSummarizer:
    """
    Summarize RECON results for POST_RECON checkpoint.

    Focuses on attack surface discovery: hosts, ports, services, technologies.
    """

    def __init__(self, config: Optional[SummarizationConfig] = None):
        self.config = config or SummarizationConfig()

    def summarize(self, findings: List[Dict[str, Any]]) -> str:
        """
        Summarize recon findings for LLM analysis.

        Args:
            findings: List of Finding dictionaries

        Returns:
            Formatted summary string
        """
        # Group findings by type
        hosts = []
        ports = []
        services = []
        technologies = []
        other = []

        for f in findings:
            f_type = f.get("type", "").lower()
            if f_type in ("host", "subdomain", "domain"):
                hosts.append(f)
            elif f_type == "port":
                ports.append(f)
            elif f_type == "service":
                services.append(f)
            elif f_type in ("technology", "tech", "framework"):
                technologies.append(f)
            else:
                other.append(f)

        # Build summary
        lines = [
            f"## RECON SUMMARY",
            f"Hosts: {len(hosts)} | Ports: {len(ports)} | Services: {len(services)} | Tech: {len(technologies)}",
            "",
        ]

        # High-value hosts (live, with services)
        if hosts:
            lines.append("### DISCOVERED HOSTS")
            for h in hosts[:self.config.max_findings_per_type]:
                status = "alive" if h.get("metadata", {}).get("alive") else "unknown"
                lines.append(f"- {h.get('value', 'unknown')} [{status}]")
            if len(hosts) > self.config.max_findings_per_type:
                lines.append(f"  ... and {len(hosts) - self.config.max_findings_per_type} more")
            lines.append("")

        # Open ports with services
        if ports:
            lines.append("### OPEN PORTS")
            port_summary = {}
            for p in ports:
                port = p.get("value", "unknown")
                service = p.get("metadata", {}).get("service", "")
                version = p.get("metadata", {}).get("version", "")
                port_summary[port] = f"{service} {version}".strip()

            for port, svc in list(port_summary.items())[:10]:
                lines.append(f"- {port}: {svc}" if svc else f"- {port}")
            if len(port_summary) > 10:
                lines.append(f"  ... and {len(port_summary) - 10} more ports")
            lines.append("")

        # Technologies detected
        if technologies:
            lines.append("### TECHNOLOGIES")
            tech_names = [t.get("value", "") for t in technologies if t.get("value")]
            unique_tech = list(set(tech_names))[:10]
            lines.append(f"Detected: {', '.join(unique_tech)}")
            lines.append("")

        # Notable findings
        notable = [f for f in other if f.get("severity") in ("critical", "high")]
        if notable:
            lines.append("### NOTABLE FINDINGS")
            for n in notable[:5]:
                lines.append(f"- [{n.get('severity', '').upper()}] {n.get('description', n.get('value', ''))[:100]}")
            lines.append("")

        return "\n".join(lines)

    def get_attack_surface(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract attack surface summary.

        Returns:
            Dictionary with attack surface analysis
        """
        surface = {
            "total_hosts": 0,
            "live_hosts": 0,
            "total_ports": 0,
            "web_servers": 0,
            "databases": 0,
            "api_endpoints": 0,
            "admin_panels": 0,
            "technologies": [],
            "high_value_targets": [],
        }

        for f in findings:
            f_type = f.get("type", "").lower()
            value = f.get("value", "")
            meta = f.get("metadata", {})

            if f_type in ("host", "subdomain"):
                surface["total_hosts"] += 1
                if meta.get("alive"):
                    surface["live_hosts"] += 1

            elif f_type == "port":
                surface["total_ports"] += 1
                service = meta.get("service", "").lower()
                if service in ("http", "https", "nginx", "apache"):
                    surface["web_servers"] += 1
                elif service in ("mysql", "postgresql", "mongodb", "redis"):
                    surface["databases"] += 1

            elif f_type == "technology":
                if value not in surface["technologies"]:
                    surface["technologies"].append(value)

            # Identify high-value targets
            if "admin" in value.lower() or "api" in value.lower():
                surface["high_value_targets"].append(value)
                if "api" in value.lower():
                    surface["api_endpoints"] += 1
                if "admin" in value.lower():
                    surface["admin_panels"] += 1

        return surface


class ScanSummarizer:
    """
    Summarize SCAN results for POST_SCAN checkpoint.

    Focuses on vulnerabilities: type, severity, exploitability.
    """

    def __init__(self, config: Optional[SummarizationConfig] = None):
        self.config = config or SummarizationConfig()

    def summarize(self, findings: List[Dict[str, Any]]) -> str:
        """
        Summarize scan findings for LLM analysis.

        Args:
            findings: List of vulnerability findings

        Returns:
            Formatted summary string
        """
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Group by type
        by_type: Dict[str, List[Dict]] = {}
        for f in findings:
            vuln_type = self._classify_vulnerability(f)
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(f)

        # Build summary
        lines = [
            "## VULNERABILITY SUMMARY",
            f"Critical: {severity_counts['critical']} | High: {severity_counts['high']} | Medium: {severity_counts['medium']} | Low: {severity_counts['low']}",
            "",
        ]

        # Critical and high findings first
        critical_high = [f for f in findings if f.get("severity", "").lower() in ("critical", "high")]

        if critical_high:
            lines.append("### CRITICAL/HIGH FINDINGS")
            for i, f in enumerate(critical_high[:self.config.max_findings_per_type]):
                fid = f"F{i+1:03d}"
                sev = f.get("severity", "?")[0].upper()
                target = f.get("url") or f.get("host") or f.get("target", "unknown")
                title = f.get("title") or f.get("description", "")[:60]
                cve = f.get("cve", "")
                cve_str = f" ({cve})" if cve else ""

                lines.append(f"[{fid}|{sev}] {title}{cve_str}")
                lines.append(f"    Target: {target[:80]}")
            lines.append("")

        # By vulnerability type
        if by_type:
            lines.append("### BY VULNERABILITY TYPE")
            for vtype, vfindings in sorted(by_type.items(), key=lambda x: -len(x[1])):
                count = len(vfindings)
                if count > 0:
                    lines.append(f"- {vtype}: {count} findings")
            lines.append("")

        return "\n".join(lines)

    def _classify_vulnerability(self, finding: Dict[str, Any]) -> str:
        """Classify vulnerability by type."""
        title = (finding.get("title") or finding.get("description") or "").lower()
        template = finding.get("template", "").lower()

        classifications = [
            (["sql injection", "sqli", "sql-injection"], "SQLi"),
            (["xss", "cross-site scripting", "cross site scripting"], "XSS"),
            (["ssrf", "server-side request"], "SSRF"),
            (["lfi", "local file", "path traversal", "directory traversal"], "LFI/Path Traversal"),
            (["rce", "remote code", "command injection", "os command"], "RCE/Command Injection"),
            (["xxe", "xml external"], "XXE"),
            (["idor", "insecure direct"], "IDOR"),
            (["auth", "authentication", "login", "password"], "Authentication"),
            (["exposure", "disclosure", "leak", "exposed"], "Information Disclosure"),
            (["misconfiguration", "misconfig"], "Misconfiguration"),
            (["outdated", "version", "cve-"], "Outdated Software/CVE"),
        ]

        for keywords, classification in classifications:
            if any(kw in title or kw in template for kw in keywords):
                return classification

        return "Other"

    def get_exploitable_findings(self, findings: List[Dict[str, Any]]) -> List[CompactFinding]:
        """
        Get list of exploitable findings in compact format.

        Returns:
            List of CompactFinding objects
        """
        result = []
        exploitable = [
            f for f in findings
            if f.get("severity", "").lower() in ("critical", "high", "medium")
        ]

        for i, f in enumerate(exploitable[:self.config.max_findings_total]):
            vuln_type = self._classify_vulnerability(f)

            # Determine chain potential
            chain_potential = []
            if vuln_type == "SQLi":
                chain_potential = ["auth_bypass", "data_exfil", "rce"]
            elif vuln_type == "XSS":
                chain_potential = ["session_hijack", "phishing"]
            elif vuln_type == "SSRF":
                chain_potential = ["internal_scan", "cloud_metadata"]
            elif vuln_type in ("RCE/Command Injection", "LFI/Path Traversal"):
                chain_potential = ["full_compromise"]

            result.append(CompactFinding(
                id=f"F{i+1:03d}",
                type=vuln_type.lower().replace("/", "_").replace(" ", "_"),
                target=(f.get("url") or f.get("host") or "unknown")[:60],
                severity=f.get("severity", "?")[0].upper(),
                key_detail=(f.get("title") or f.get("description", ""))[:80],
                chain_potential=chain_potential,
            ))

        return result


class ExploitSummarizer:
    """
    Summarize EXPLOIT results for POST_EXPLOIT checkpoint.

    Focuses on: success indicators, extracted data, next steps.
    """

    def __init__(self, config: Optional[SummarizationConfig] = None):
        self.config = config or SummarizationConfig()

    def summarize_attempt(
        self,
        target: str,
        vuln_type: str,
        tool: str,
        command: str,
        exit_code: int,
        output: str,
        previous_attempts: List[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """
        Summarize an exploitation attempt.

        Returns:
            Dictionary with formatted fields for prompt
        """
        # Truncate output intelligently
        output_truncated = self._truncate_output(output, max_lines=30)

        # Format previous attempts
        prev_str = "None"
        if previous_attempts:
            prev_lines = []
            for attempt in previous_attempts[-3:]:  # Last 3 attempts
                status = "SUCCESS" if attempt.get("success") else "FAILED"
                prev_lines.append(f"- {attempt.get('tool')}: {status}")
            prev_str = "\n".join(prev_lines)

        return {
            "target": target,
            "vuln_type": vuln_type,
            "tool": tool,
            "command": command[:200] + "..." if len(command) > 200 else command,
            "exit_code": str(exit_code),
            "output_truncated": output_truncated,
            "previous_attempts": prev_str,
        }

    def _truncate_output(self, output: str, max_lines: int = 30) -> str:
        """Truncate output while preserving important information."""
        if not output:
            return "(no output)"

        lines = output.strip().split("\n")

        # If short enough, return as-is
        if len(lines) <= max_lines:
            return output

        # Keep first and last lines, summarize middle
        keep_start = max_lines // 2
        keep_end = max_lines - keep_start - 1

        result = lines[:keep_start]
        result.append(f"\n... ({len(lines) - max_lines} lines omitted) ...\n")
        result.extend(lines[-keep_end:])

        return "\n".join(result)

    def extract_success_indicators(self, output: str, vuln_type: str) -> List[str]:
        """
        Extract indicators of successful exploitation.

        Returns:
            List of success indicator strings
        """
        indicators = []
        output_lower = output.lower()

        # General success indicators
        general_success = [
            "vulnerable", "injection successful", "pwned", "shell obtained",
            "access granted", "authenticated", "logged in", "admin",
        ]
        for indicator in general_success:
            if indicator in output_lower:
                indicators.append(indicator)

        # SQLi specific
        if "sqli" in vuln_type.lower():
            sqli_indicators = [
                "database", "mysql", "postgresql", "oracle", "mssql",
                "table", "column", "row", "user", "password", "hash",
            ]
            for ind in sqli_indicators:
                if ind in output_lower:
                    indicators.append(f"sqli:{ind}")

        # XSS specific
        if "xss" in vuln_type.lower():
            if "alert" in output_lower or "script" in output_lower:
                indicators.append("xss:payload_reflected")

        # RCE specific
        if "rce" in vuln_type.lower() or "command" in vuln_type.lower():
            rce_indicators = ["uid=", "whoami", "root", "www-data", "shell"]
            for ind in rce_indicators:
                if ind in output_lower:
                    indicators.append(f"rce:{ind}")

        return indicators[:5]  # Limit to 5 indicators
