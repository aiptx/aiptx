"""
AIPTX Tool Output Summarization
===============================

Intelligent summarization of security tool outputs for LLM consumption.
Optimized for local LLMs with limited context windows (4K-32K tokens).
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger(__name__)


class SummarizationLevel(Enum):
    """Summarization levels for different context budgets."""
    MINIMAL = "minimal"     # <500 tokens - just critical findings
    COMPACT = "compact"     # <1500 tokens - key findings with context
    STANDARD = "standard"   # <3000 tokens - full findings, trimmed evidence
    VERBOSE = "verbose"     # <6000 tokens - detailed findings


@dataclass
class CompactFinding:
    """
    Compact finding representation for LLM consumption.

    Designed for maximum information density within token limits.
    Each finding compresses to ~20-50 tokens.
    """
    id: str           # "F001", "F002", etc.
    type: str         # "sqli", "xss", "open_port", etc.
    target: str       # URL or host:port
    severity: str     # "C", "H", "M", "L", "I" (Critical, High, Medium, Low, Info)
    key_detail: str   # One-line summary (<100 chars)
    chain_potential: List[str] = field(default_factory=list)  # ["auth_bypass", "rce"]

    def to_compact_string(self) -> str:
        """Convert to compact LLM-friendly format."""
        # Format: [F001|sqli|H] /api/users?id= -> auth_bypass,rce
        chain_str = ",".join(self.chain_potential) if self.chain_potential else ""
        chain_part = f" -> {chain_str}" if chain_str else ""
        return f"[{self.id}|{self.type}|{self.severity}] {self.key_detail}{chain_part}"


class ToolOutputSummarizer(ABC):
    """Base class for tool-specific summarizers."""

    TOOL_NAME: str = "unknown"

    @abstractmethod
    def summarize(
        self,
        output: str,
        level: SummarizationLevel = SummarizationLevel.COMPACT
    ) -> str:
        """Summarize tool output to specified level."""
        pass

    @abstractmethod
    def extract_findings(self, output: str) -> List[CompactFinding]:
        """Extract structured findings from output."""
        pass


class NmapSummarizer(ToolOutputSummarizer):
    """
    Summarizer for nmap output.

    Keeps: Open ports, services, NSE vulnerabilities, OS detection
    Discards: Closed ports, timing info, scan progress
    """

    TOOL_NAME = "nmap"

    # Patterns for extraction
    PORT_PATTERN = re.compile(r"(\d+)/(\w+)\s+(\w+)\s+(.+)")
    OS_PATTERN = re.compile(r"OS details:\s*(.+)", re.IGNORECASE)
    SCRIPT_PATTERN = re.compile(r"\|_?\s*([^:]+):\s*(.+)")

    def summarize(
        self,
        output: str,
        level: SummarizationLevel = SummarizationLevel.COMPACT
    ) -> str:
        """Summarize nmap output."""
        findings = self.extract_findings(output)

        if level == SummarizationLevel.MINIMAL:
            # Just port list
            ports = [f.key_detail.split()[0] for f in findings if f.type == "port"]
            return f"Open ports: {', '.join(ports[:10])}"

        elif level == SummarizationLevel.COMPACT:
            # Compact findings
            lines = [f.to_compact_string() for f in findings[:15]]
            return "\n".join(lines)

        elif level == SummarizationLevel.STANDARD:
            # More detail
            sections = []

            # Group by type
            ports = [f for f in findings if f.type == "port"]
            vulns = [f for f in findings if f.type == "vuln"]

            if ports:
                sections.append("PORTS:\n" + "\n".join(f.to_compact_string() for f in ports[:20]))
            if vulns:
                sections.append("VULNS:\n" + "\n".join(f.to_compact_string() for f in vulns[:10]))

            return "\n\n".join(sections)

        else:  # VERBOSE
            return output[:5000]  # First 5K chars

    def extract_findings(self, output: str) -> List[CompactFinding]:
        """Extract findings from nmap output."""
        findings = []
        finding_id = 1

        # Extract open ports
        for match in self.PORT_PATTERN.finditer(output):
            port, proto, state, service = match.groups()

            if state.lower() == "open":
                # Determine severity based on service
                severity = self._port_severity(port, service)
                chain = self._port_chain_potential(port, service)

                findings.append(CompactFinding(
                    id=f"P{finding_id:03d}",
                    type="port",
                    target=f"{port}/{proto}",
                    severity=severity,
                    key_detail=f"{port}/{proto} {service.strip()[:40]}",
                    chain_potential=chain,
                ))
                finding_id += 1

        # Extract script findings (vulnerabilities)
        if "VULNERABLE" in output.upper() or "CVE-" in output:
            for line in output.split("\n"):
                if "CVE-" in line or "VULNERABLE" in line.upper():
                    cve_match = re.search(r"(CVE-\d{4}-\d+)", line)
                    cve = cve_match.group(1) if cve_match else ""

                    findings.append(CompactFinding(
                        id=f"V{finding_id:03d}",
                        type="vuln",
                        target=cve or "nse_script",
                        severity="H" if cve else "M",
                        key_detail=line.strip()[:80],
                        chain_potential=["exploit", "rce"] if cve else [],
                    ))
                    finding_id += 1

        return findings

    def _port_severity(self, port: str, service: str) -> str:
        """Determine port severity."""
        high_risk = ["21", "22", "23", "445", "3389", "5985", "5986"]
        medium_risk = ["80", "443", "8080", "8443", "3306", "5432", "1433"]

        if port in high_risk:
            return "H"
        elif port in medium_risk:
            return "M"
        return "L"

    def _port_chain_potential(self, port: str, service: str) -> List[str]:
        """Determine exploit chain potential."""
        chains = []
        service_lower = service.lower()

        if "ssh" in service_lower or port == "22":
            chains.extend(["brute_force", "cred_reuse"])
        elif "http" in service_lower or port in ["80", "443", "8080"]:
            chains.extend(["web_exploit", "sqli", "xss"])
        elif "mysql" in service_lower or port == "3306":
            chains.extend(["brute_force", "data_exfil"])
        elif "smb" in service_lower or port == "445":
            chains.extend(["eternal_blue", "relay"])
        elif "rdp" in service_lower or port == "3389":
            chains.extend(["brute_force", "bluekeep"])

        return chains


class NucleiSummarizer(ToolOutputSummarizer):
    """
    Summarizer for nuclei output.

    Keeps: Template ID, severity, CVE, matched URL
    Discards: Full request/response, headers, timing
    """

    TOOL_NAME = "nuclei"

    def summarize(
        self,
        output: str,
        level: SummarizationLevel = SummarizationLevel.COMPACT
    ) -> str:
        """Summarize nuclei output."""
        findings = self.extract_findings(output)

        if level == SummarizationLevel.MINIMAL:
            # Just critical/high
            critical = [f for f in findings if f.severity in ["C", "H"]]
            return f"Critical/High: {len(critical)}, Total: {len(findings)}\n" + \
                   "\n".join(f.to_compact_string() for f in critical[:5])

        elif level == SummarizationLevel.COMPACT:
            # Group by severity
            by_severity = {}
            for f in findings:
                by_severity.setdefault(f.severity, []).append(f)

            lines = []
            for sev in ["C", "H", "M", "L"]:
                if sev in by_severity:
                    lines.append(f"[{sev}] x{len(by_severity[sev])}")
                    for f in by_severity[sev][:5]:
                        lines.append(f"  {f.key_detail}")

            return "\n".join(lines)

        else:
            return "\n".join(f.to_compact_string() for f in findings[:30])

    def extract_findings(self, output: str) -> List[CompactFinding]:
        """Extract findings from nuclei output."""
        findings = []
        finding_id = 1

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                # Try JSON parsing first
                if line.startswith("{"):
                    data = json.loads(line)
                    template_id = data.get("template-id", "")
                    severity = data.get("info", {}).get("severity", "unknown")
                    matched = data.get("matched-at", data.get("host", ""))

                    sev_map = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}

                    findings.append(CompactFinding(
                        id=f"N{finding_id:03d}",
                        type="nuclei",
                        target=matched[:60],
                        severity=sev_map.get(severity.lower(), "I"),
                        key_detail=f"{template_id} @ {matched[:40]}",
                        chain_potential=self._template_chain(template_id),
                    ))
                    finding_id += 1

                # Parse text format: [template-id] [severity] url
                elif "[" in line:
                    parts = re.findall(r"\[([^\]]+)\]", line)
                    if len(parts) >= 2:
                        template_id = parts[0]
                        severity = parts[1] if len(parts) > 1 else "info"

                        sev_map = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}

                        findings.append(CompactFinding(
                            id=f"N{finding_id:03d}",
                            type="nuclei",
                            target=line.split("]")[-1].strip()[:50],
                            severity=sev_map.get(severity.lower(), "I"),
                            key_detail=f"{template_id}",
                            chain_potential=self._template_chain(template_id),
                        ))
                        finding_id += 1

            except (json.JSONDecodeError, KeyError):
                continue

        return findings

    def _template_chain(self, template_id: str) -> List[str]:
        """Determine chain potential from template ID."""
        chains = []
        tid_lower = template_id.lower()

        if "rce" in tid_lower or "command" in tid_lower:
            chains.append("rce")
        if "sqli" in tid_lower or "sql" in tid_lower:
            chains.extend(["sqli", "data_exfil"])
        if "lfi" in tid_lower or "path-traversal" in tid_lower:
            chains.extend(["lfi", "config_leak"])
        if "ssrf" in tid_lower:
            chains.extend(["ssrf", "internal_scan"])
        if "auth" in tid_lower or "bypass" in tid_lower:
            chains.append("auth_bypass")
        if "cve" in tid_lower:
            chains.append("exploit")

        return chains


class SqlmapSummarizer(ToolOutputSummarizer):
    """
    Summarizer for sqlmap output.

    Keeps: Injection type, DBMS, extracted data
    Discards: Raw queries, verbose output, timing
    """

    TOOL_NAME = "sqlmap"

    def summarize(
        self,
        output: str,
        level: SummarizationLevel = SummarizationLevel.COMPACT
    ) -> str:
        """Summarize sqlmap output."""
        findings = self.extract_findings(output)

        if not findings:
            if "is vulnerable" in output.lower():
                return "[VULNERABLE] SQL injection confirmed - parse manually"
            return "[NO VULN] No injection found"

        if level == SummarizationLevel.MINIMAL:
            return f"SQLi: {len(findings)} injection points"

        return "\n".join(f.to_compact_string() for f in findings)

    def extract_findings(self, output: str) -> List[CompactFinding]:
        """Extract findings from sqlmap output."""
        findings = []
        finding_id = 1

        # Extract injection points
        param_sections = re.split(r"Parameter:", output)[1:]

        for section in param_sections:
            lines = section.strip().split("\n")
            param = lines[0].strip() if lines else ""

            injection_type = ""
            for line in lines:
                if line.strip().startswith("Type:"):
                    injection_type = line.split(":", 1)[1].strip()
                    break

            if param and injection_type:
                # Determine severity based on injection type
                severity = "C" if any(x in injection_type.lower() for x in ["stacked", "union"]) else "H"

                chains = ["data_exfil"]
                if "stacked" in injection_type.lower():
                    chains.extend(["rce", "file_read"])

                findings.append(CompactFinding(
                    id=f"S{finding_id:03d}",
                    type="sqli",
                    target=param[:40],
                    severity=severity,
                    key_detail=f"{param[:30]}: {injection_type[:40]}",
                    chain_potential=chains,
                ))
                finding_id += 1

        # Extract enumerated data
        if "available databases" in output.lower():
            db_match = re.search(r"available databases.*?:\n(.*?)(?:\n\n|\[|$)", output, re.DOTALL | re.IGNORECASE)
            if db_match:
                dbs = [db.strip().strip("[]* ") for db in db_match.group(1).split("\n") if db.strip()]
                if dbs:
                    findings.append(CompactFinding(
                        id=f"S{finding_id:03d}",
                        type="sqli_enum",
                        target="databases",
                        severity="H",
                        key_detail=f"DBs: {', '.join(dbs[:5])}",
                        chain_potential=["data_exfil", "priv_esc"],
                    ))

        return findings


class HttpxSummarizer(ToolOutputSummarizer):
    """
    Summarizer for httpx output.

    Keeps: Live hosts, status codes, tech stack, titles
    Discards: Headers, response bodies
    """

    TOOL_NAME = "httpx"

    def summarize(
        self,
        output: str,
        level: SummarizationLevel = SummarizationLevel.COMPACT
    ) -> str:
        """Summarize httpx output."""
        findings = self.extract_findings(output)

        if level == SummarizationLevel.MINIMAL:
            return f"Live hosts: {len(findings)}"

        # Group by status code
        by_status = {}
        for f in findings:
            status = f.key_detail.split("]")[0].strip("[") if "[" in f.key_detail else "200"
            by_status.setdefault(status, []).append(f)

        lines = [f"Live: {len(findings)} hosts"]
        for status, hosts in sorted(by_status.items()):
            lines.append(f"  [{status}] x{len(hosts)}: {hosts[0].target[:50]}...")

        return "\n".join(lines[:15])

    def extract_findings(self, output: str) -> List[CompactFinding]:
        """Extract findings from httpx output."""
        findings = []
        finding_id = 1

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                if line.startswith("{"):
                    data = json.loads(line)
                    url = data.get("url", "")
                    status = data.get("status_code", 0)
                    title = data.get("title", "")
                    tech = data.get("tech", [])

                    severity = "L" if status == 200 else "I"
                    if status in (401, 403):
                        severity = "L"
                    elif status >= 500:
                        severity = "M"

                    detail = f"[{status}] {title[:30]}"
                    if tech:
                        detail += f" | {','.join(tech[:3])}"

                    findings.append(CompactFinding(
                        id=f"H{finding_id:03d}",
                        type="http",
                        target=url[:60],
                        severity=severity,
                        key_detail=detail[:80],
                        chain_potential=self._tech_chain(tech),
                    ))
                    finding_id += 1
                else:
                    # Plain URL
                    findings.append(CompactFinding(
                        id=f"H{finding_id:03d}",
                        type="http",
                        target=line.strip()[:60],
                        severity="I",
                        key_detail=line.strip()[:60],
                    ))
                    finding_id += 1

            except json.JSONDecodeError:
                continue

        return findings

    def _tech_chain(self, tech: List[str]) -> List[str]:
        """Determine chain potential from tech stack."""
        chains = []
        tech_str = " ".join(tech).lower()

        if "wordpress" in tech_str:
            chains.extend(["wpscan", "plugin_vuln"])
        if "nginx" in tech_str or "apache" in tech_str:
            chains.append("misconfig")
        if "php" in tech_str:
            chains.extend(["lfi", "rce"])
        if "node" in tech_str or "express" in tech_str:
            chains.append("prototype_pollution")

        return chains


class SummarizationManager:
    """
    Manages tool-specific summarizers.

    Provides unified interface for summarizing any tool output.
    """

    # Registry of summarizers
    SUMMARIZERS: Dict[str, Type[ToolOutputSummarizer]] = {
        "nmap": NmapSummarizer,
        "nuclei": NucleiSummarizer,
        "sqlmap": SqlmapSummarizer,
        "httpx": HttpxSummarizer,
    }

    def __init__(self):
        self._instances: Dict[str, ToolOutputSummarizer] = {}

    def get_summarizer(self, tool: str) -> Optional[ToolOutputSummarizer]:
        """Get or create summarizer for tool."""
        if tool not in self._instances:
            if tool in self.SUMMARIZERS:
                self._instances[tool] = self.SUMMARIZERS[tool]()
            else:
                return None
        return self._instances[tool]

    def summarize(
        self,
        tool: str,
        output: str,
        level: SummarizationLevel = SummarizationLevel.COMPACT
    ) -> str:
        """Summarize tool output."""
        summarizer = self.get_summarizer(tool)

        if summarizer:
            return summarizer.summarize(output, level)
        else:
            # Generic summarization - first N lines
            lines = output.strip().split("\n")
            max_lines = {
                SummarizationLevel.MINIMAL: 5,
                SummarizationLevel.COMPACT: 15,
                SummarizationLevel.STANDARD: 30,
                SummarizationLevel.VERBOSE: 60,
            }
            return "\n".join(lines[:max_lines.get(level, 15)])

    def extract_all_findings(
        self,
        results: Dict[str, str]
    ) -> List[CompactFinding]:
        """
        Extract findings from multiple tool outputs.

        Args:
            results: Dict mapping tool name to output

        Returns:
            List of all findings, sorted by severity
        """
        all_findings = []

        for tool, output in results.items():
            summarizer = self.get_summarizer(tool)
            if summarizer:
                findings = summarizer.extract_findings(output)
                all_findings.extend(findings)

        # Sort by severity (C > H > M > L > I)
        severity_order = {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return all_findings

    def generate_compact_report(
        self,
        results: Dict[str, str],
        max_tokens: int = 2000
    ) -> str:
        """
        Generate compact report for LLM consumption.

        Args:
            results: Dict mapping tool name to output
            max_tokens: Approximate token limit

        Returns:
            Compact report string
        """
        findings = self.extract_all_findings(results)

        # Estimate ~5 tokens per finding line
        max_findings = max_tokens // 5

        lines = [f"FINDINGS ({len(findings)} total):"]

        # Add findings up to limit
        for finding in findings[:max_findings]:
            lines.append(finding.to_compact_string())

        if len(findings) > max_findings:
            lines.append(f"... and {len(findings) - max_findings} more")

        # Add chain analysis if room
        if max_tokens > 1500:
            chains = self._analyze_chains(findings[:20])
            if chains:
                lines.append("\nPOTENTIAL CHAINS:")
                for chain in chains[:5]:
                    lines.append(f"  {chain}")

        return "\n".join(lines)

    def _analyze_chains(self, findings: List[CompactFinding]) -> List[str]:
        """Analyze potential exploit chains from findings."""
        chains = []

        # Look for common chain patterns
        has_sqli = any(f.type == "sqli" for f in findings)
        has_auth_bypass = any("auth_bypass" in f.chain_potential for f in findings)
        has_ssrf = any("ssrf" in f.chain_potential for f in findings)
        has_lfi = any("lfi" in f.chain_potential for f in findings)

        if has_sqli and has_auth_bypass:
            chains.append("SQLI -> AUTH_BYPASS -> PRIV_ESC (confidence: 0.8)")

        if has_ssrf:
            internal_ports = [f for f in findings if f.type == "port" and f.severity in ["H", "M"]]
            if internal_ports:
                chains.append(f"SSRF -> INTERNAL_SCAN ({len(internal_ports)} targets) (confidence: 0.7)")

        if has_lfi:
            chains.append("LFI -> CONFIG_LEAK -> CRED_HARVEST (confidence: 0.6)")

        return chains
