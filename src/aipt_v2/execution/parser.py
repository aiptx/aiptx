"""
AIPT Output Parser - Extract structured data from tool outputs

Uses regex patterns + LLM fallback for complex parsing.

Supports:
- nmap, masscan (port scanning)
- gobuster, ffuf (directory enumeration)
- nuclei (vulnerability scanning)
- hydra (credential brute-forcing)
- Custom patterns
"""
from __future__ import annotations

import re
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A structured finding from tool output"""
    type: str  # port, service, vuln, credential, host, path, info
    value: str
    description: str
    severity: str = "info"  # info, low, medium, high, critical
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_tool: str = ""
    raw_line: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity,
            "metadata": self.metadata,
            "source_tool": self.source_tool,
        }


class OutputParser:
    """
    Parse tool outputs into structured findings.

    Uses regex patterns for known tools, with LLM fallback
    for unstructured or unknown outputs.
    """

    # Regex patterns for common tools
    PATTERNS = {
        # nmap patterns
        "nmap_port": re.compile(
            r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?",
            re.MULTILINE
        ),
        "nmap_host": re.compile(
            r"Nmap scan report for\s+(\S+)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?",
            re.MULTILINE
        ),
        "nmap_os": re.compile(
            r"OS details?:\s*(.+)",
            re.MULTILINE
        ),

        # masscan patterns
        "masscan_port": re.compile(
            r"Discovered open port\s+(\d+)/(tcp|udp)\s+on\s+(\S+)",
            re.MULTILINE
        ),

        # gobuster/ffuf patterns
        "directory": re.compile(
            r"(/\S+)\s+\(Status:\s*(\d+)\)",
            re.MULTILINE
        ),
        "ffuf_result": re.compile(
            r'"url":\s*"([^"]+)".*?"status":\s*(\d+)',
            re.MULTILINE
        ),

        # nuclei patterns
        "nuclei_vuln": re.compile(
            r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)",
            re.MULTILINE
        ),

        # hydra patterns
        "hydra_cred": re.compile(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
            re.MULTILINE
        ),

        # sqlmap patterns
        "sqlmap_injectable": re.compile(
            r"Parameter:\s+(\S+)\s+\(([^)]+)\)",
            re.MULTILINE
        ),
        "sqlmap_dbms": re.compile(
            r"back-end DBMS:\s+(.+)",
            re.MULTILINE
        ),

        # generic patterns
        "ip_address": re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        ),
        "domain": re.compile(
            r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b"
        ),
        "email": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ),
        "hash_md5": re.compile(
            r"\b[a-fA-F0-9]{32}\b"
        ),
        "hash_sha1": re.compile(
            r"\b[a-fA-F0-9]{40}\b"
        ),
        "hash_sha256": re.compile(
            r"\b[a-fA-F0-9]{64}\b"
        ),
        "cve": re.compile(
            r"CVE-\d{4}-\d{4,}",
            re.IGNORECASE
        ),
        "url": re.compile(
            r"https?://[^\s<>\"']+",
            re.IGNORECASE
        ),
    }

    # Custom parsers for specific tools
    _custom_parsers: Dict[str, Callable] = {}

    def __init__(self, llm: Any = None):
        self.llm = llm

    def register_parser(self, tool_name: str, parser_func: Callable) -> None:
        """Register a custom parser for a tool"""
        self._custom_parsers[tool_name.lower()] = parser_func

    def parse(
        self,
        output: str,
        tool_name: Optional[str] = None,
        include_generic: bool = True,
    ) -> List[Finding]:
        """
        Parse tool output into structured findings.

        Args:
            output: Raw tool output
            tool_name: Name of the tool (for tool-specific parsing)
            include_generic: Include generic pattern matching

        Returns:
            List of Finding objects
        """
        findings = []

        if not output:
            return findings

        # Check for custom parser
        if tool_name and tool_name.lower() in self._custom_parsers:
            custom_findings = self._custom_parsers[tool_name.lower()](output)
            findings.extend(custom_findings)
        elif tool_name:
            # Tool-specific parsing
            tool_findings = self._parse_tool_specific(output, tool_name.lower())
            findings.extend(tool_findings)

        # Generic pattern matching
        if include_generic:
            generic_findings = self._parse_generic(output)
            findings.extend(generic_findings)

        # Set source tool
        for finding in findings:
            if not finding.source_tool and tool_name:
                finding.source_tool = tool_name

        # Deduplicate
        findings = self._deduplicate(findings)

        return findings

    def _parse_tool_specific(self, output: str, tool_name: str) -> List[Finding]:
        """Parse output based on known tool"""
        findings = []

        if tool_name in ["nmap", "nmap-scan"]:
            findings.extend(self._parse_nmap(output))

        elif tool_name == "masscan":
            findings.extend(self._parse_masscan(output))

        elif tool_name in ["gobuster", "ffuf", "dirb", "dirbuster", "feroxbuster"]:
            findings.extend(self._parse_directory(output))

        elif tool_name == "nuclei":
            findings.extend(self._parse_nuclei(output))

        elif tool_name == "hydra":
            findings.extend(self._parse_hydra(output))

        elif tool_name == "sqlmap":
            findings.extend(self._parse_sqlmap(output))

        elif tool_name in ["nikto", "wpscan", "whatweb"]:
            findings.extend(self._parse_vuln_scanner(output))

        return findings

    def _parse_nmap(self, output: str) -> List[Finding]:
        """Parse nmap output"""
        findings = []

        # Parse hosts
        for match in self.PATTERNS["nmap_host"].finditer(output):
            hostname = match.group(1)
            ip = match.group(2) or hostname
            findings.append(Finding(
                type="host",
                value=ip,
                description=f"Host discovered: {hostname} ({ip})",
                metadata={"hostname": hostname, "ip": ip},
                raw_line=match.group(0),
            ))

        # Parse ports
        for match in self.PATTERNS["nmap_port"].finditer(output):
            port = match.group(1)
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5) or ""

            if state == "open":
                findings.append(Finding(
                    type="port",
                    value=f"{port}/{protocol}",
                    description=f"Open port {port}/{protocol}: {service} {version}".strip(),
                    severity="low" if service in ["http", "https", "ftp", "ssh"] else "info",
                    metadata={
                        "port": int(port),
                        "protocol": protocol,
                        "service": service,
                        "version": version,
                    },
                    raw_line=match.group(0),
                ))

        # Parse OS detection
        for match in self.PATTERNS["nmap_os"].finditer(output):
            os_info = match.group(1)
            findings.append(Finding(
                type="info",
                value=os_info,
                description=f"OS detected: {os_info}",
                metadata={"os": os_info},
            ))

        return findings

    def _parse_masscan(self, output: str) -> List[Finding]:
        """Parse masscan output"""
        findings = []

        for match in self.PATTERNS["masscan_port"].finditer(output):
            port = match.group(1)
            protocol = match.group(2)
            ip = match.group(3)

            findings.append(Finding(
                type="port",
                value=f"{ip}:{port}/{protocol}",
                description=f"Open port {port}/{protocol} on {ip}",
                metadata={"ip": ip, "port": int(port), "protocol": protocol},
            ))

        return findings

    def _parse_directory(self, output: str) -> List[Finding]:
        """Parse directory brute-force output"""
        findings = []

        # Standard format
        for match in self.PATTERNS["directory"].finditer(output):
            path = match.group(1)
            status = match.group(2)

            severity = "info"
            if status in ["200", "301", "302"]:
                severity = "low"
            if any(kw in path.lower() for kw in ["admin", "backup", "config", "upload", "api", "debug"]):
                severity = "medium"

            findings.append(Finding(
                type="path",
                value=path,
                description=f"Directory found: {path} (Status: {status})",
                severity=severity,
                metadata={"status_code": int(status)},
            ))

        # ffuf JSON format
        for match in self.PATTERNS["ffuf_result"].finditer(output):
            url = match.group(1)
            status = match.group(2)

            findings.append(Finding(
                type="path",
                value=url,
                description=f"Endpoint found: {url} (Status: {status})",
                severity="low",
                metadata={"status_code": int(status)},
            ))

        return findings

    def _parse_nuclei(self, output: str) -> List[Finding]:
        """Parse nuclei vulnerability scanner output"""
        findings = []

        for match in self.PATTERNS["nuclei_vuln"].finditer(output):
            template_id = match.group(1)
            severity = match.group(2).lower()
            protocol = match.group(3)
            target = match.group(4)

            if severity not in ["info", "low", "medium", "high", "critical"]:
                severity = "info"

            findings.append(Finding(
                type="vuln",
                value=template_id,
                description=f"Vulnerability: {template_id} on {target}",
                severity=severity,
                metadata={
                    "template": template_id,
                    "protocol": protocol,
                    "target": target,
                },
            ))

        return findings

    def _parse_hydra(self, output: str) -> List[Finding]:
        """Parse hydra brute-force output"""
        findings = []

        for match in self.PATTERNS["hydra_cred"].finditer(output):
            port = match.group(1)
            service = match.group(2)
            host = match.group(3)
            username = match.group(4)
            password = match.group(5)

            findings.append(Finding(
                type="credential",
                value=f"{username}:{password}",
                description=f"Valid credentials found for {service} on {host}:{port}",
                severity="critical",
                metadata={
                    "host": host,
                    "port": int(port),
                    "service": service,
                    "username": username,
                    "password": password,
                },
            ))

        return findings

    def _parse_sqlmap(self, output: str) -> List[Finding]:
        """Parse sqlmap output"""
        findings = []

        # Injectable parameters
        for match in self.PATTERNS["sqlmap_injectable"].finditer(output):
            param = match.group(1)
            injection_type = match.group(2)

            findings.append(Finding(
                type="vuln",
                value=f"SQLi: {param}",
                description=f"SQL Injection in parameter '{param}' ({injection_type})",
                severity="high",
                metadata={"parameter": param, "injection_type": injection_type},
            ))

        # DBMS detection
        for match in self.PATTERNS["sqlmap_dbms"].finditer(output):
            dbms = match.group(1)
            findings.append(Finding(
                type="info",
                value=dbms,
                description=f"Backend DBMS: {dbms}",
                metadata={"dbms": dbms},
            ))

        return findings

    def _parse_vuln_scanner(self, output: str) -> List[Finding]:
        """Parse generic vulnerability scanner output (nikto, wpscan)"""
        findings = []

        # Look for CVEs
        for match in self.PATTERNS["cve"].finditer(output):
            cve = match.group(0).upper()
            findings.append(Finding(
                type="vuln",
                value=cve,
                description=f"CVE detected: {cve}",
                severity="high",
                metadata={"cve": cve},
            ))

        # Look for common vulnerability keywords
        vuln_keywords = [
            ("SQL injection", "high", "sqli"),
            ("XSS", "medium", "xss"),
            ("Cross-Site Scripting", "medium", "xss"),
            ("CSRF", "medium", "csrf"),
            ("directory listing", "low", "info_disclosure"),
            ("information disclosure", "medium", "info_disclosure"),
            ("remote code execution", "critical", "rce"),
            ("RCE", "critical", "rce"),
            ("LFI", "high", "lfi"),
            ("Local File Inclusion", "high", "lfi"),
            ("RFI", "high", "rfi"),
            ("Remote File Inclusion", "high", "rfi"),
            ("SSRF", "high", "ssrf"),
            ("XXE", "high", "xxe"),
        ]

        output_lower = output.lower()
        for keyword, severity, vuln_type in vuln_keywords:
            if keyword.lower() in output_lower:
                findings.append(Finding(
                    type="vuln",
                    value=keyword,
                    description=f"Potential vulnerability: {keyword}",
                    severity=severity,
                    metadata={"vuln_type": vuln_type},
                ))

        return findings

    def _parse_generic(self, output: str) -> List[Finding]:
        """Extract generic patterns from any output"""
        findings = []

        # Extract CVEs
        cves_found = set()
        for match in self.PATTERNS["cve"].finditer(output):
            cve = match.group(0).upper()
            if cve not in cves_found:
                cves_found.add(cve)
                findings.append(Finding(
                    type="vuln",
                    value=cve,
                    description=f"CVE reference: {cve}",
                    severity="medium",
                ))

        # Extract emails
        emails_found = set()
        for match in self.PATTERNS["email"].finditer(output):
            email = match.group(0)
            if email not in emails_found:
                emails_found.add(email)
                findings.append(Finding(
                    type="info",
                    value=email,
                    description=f"Email discovered: {email}",
                ))

        return findings

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings"""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.type, finding.value)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def parse_with_llm(self, output: str, tool_name: str = "unknown") -> List[Finding]:
        """
        Parse output using LLM for complex/unknown formats.

        Falls back to regex if LLM not available.
        """
        if not self.llm:
            return self.parse(output, tool_name)

        prompt = f"""Analyze this security tool output and extract findings.

Tool: {tool_name}

Output:
{output[:5000]}

Extract findings in this JSON format:
[
  {{"type": "port|service|vuln|credential|host|path|info", "value": "identifier", "description": "brief description", "severity": "info|low|medium|high|critical"}}
]

Only return valid JSON array. If no findings, return []."""

        try:
            response = self.llm.invoke([
                {"role": "system", "content": "You are a security findings parser. Return only valid JSON."},
                {"role": "user", "content": prompt},
            ], max_tokens=1000)

            import json
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]

            raw_findings = json.loads(content)
            return [
                Finding(
                    type=f.get("type", "info"),
                    value=f.get("value", ""),
                    description=f.get("description", ""),
                    severity=f.get("severity", "info"),
                    source_tool=tool_name,
                )
                for f in raw_findings
            ]
        except Exception:
            return self.parse(output, tool_name)
