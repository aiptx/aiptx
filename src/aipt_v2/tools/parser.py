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

import re
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A structured finding from tool output"""
    type: str  # port, service, vuln, credential, host, path
    value: str
    description: str
    severity: str = "info"  # info, low, medium, high, critical
    metadata: dict = field(default_factory=dict)


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
        "cve": re.compile(
            r"CVE-\d{4}-\d{4,}",
            re.IGNORECASE
        ),
    }

    def __init__(self):
        pass

    def parse_nmap(self, output: str) -> list[Finding]:
        """Parse nmap output - public wrapper"""
        return self._parse_nmap(output)

    def parse_masscan(self, output: str) -> list[Finding]:
        """Parse masscan output - public wrapper"""
        return self._parse_masscan(output)

    def parse_directory(self, output: str) -> list[Finding]:
        """Parse directory brute-force output - public wrapper"""
        return self._parse_directory(output)

    def parse_nuclei(self, output: str) -> list[Finding]:
        """Parse nuclei output - public wrapper"""
        return self._parse_nuclei(output)

    def parse_hydra(self, output: str) -> list[Finding]:
        """Parse hydra output - public wrapper"""
        return self._parse_hydra(output)

    def parse_generic(self, output: str) -> list[Finding]:
        """Parse generic patterns from output - public wrapper"""
        return self._parse_generic(output)

    def parse(
        self,
        output: str,
        tool_name: Optional[str] = None,
    ) -> list[Finding]:
        """
        Parse tool output into structured findings.

        Args:
            output: Raw tool output
            tool_name: Name of the tool (for tool-specific parsing)

        Returns:
            List of Finding objects
        """
        findings = []

        if not output:
            return findings

        # Tool-specific parsing
        if tool_name:
            tool_findings = self._parse_tool_specific(output, tool_name.lower())
            findings.extend(tool_findings)

        # Generic pattern matching
        generic_findings = self._parse_generic(output)
        findings.extend(generic_findings)

        # Deduplicate
        findings = self._deduplicate(findings)

        return findings

    def _parse_tool_specific(self, output: str, tool_name: str) -> list[Finding]:
        """Parse output based on known tool"""
        findings = []

        if tool_name in ["nmap", "nmap-scan"]:
            findings.extend(self._parse_nmap(output))

        elif tool_name == "masscan":
            findings.extend(self._parse_masscan(output))

        elif tool_name in ["gobuster", "ffuf", "dirb", "dirbuster"]:
            findings.extend(self._parse_directory(output))

        elif tool_name == "nuclei":
            findings.extend(self._parse_nuclei(output))

        elif tool_name == "hydra":
            findings.extend(self._parse_hydra(output))

        elif tool_name in ["nikto", "wpscan"]:
            findings.extend(self._parse_vuln_scanner(output))

        return findings

    def _parse_nmap(self, output: str) -> list[Finding]:
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
                metadata={"hostname": hostname, "ip": ip}
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
                    metadata={
                        "port": int(port),
                        "protocol": protocol,
                        "service": service,
                        "version": version,
                    }
                ))

        return findings

    def _parse_masscan(self, output: str) -> list[Finding]:
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
                metadata={"ip": ip, "port": int(port), "protocol": protocol}
            ))

        return findings

    def _parse_directory(self, output: str) -> list[Finding]:
        """Parse directory brute-force output"""
        findings = []

        # Standard format
        for match in self.PATTERNS["directory"].finditer(output):
            path = match.group(1)
            status = match.group(2)

            severity = "info"
            if status in ["200", "301", "302"]:
                severity = "low"
            if any(kw in path.lower() for kw in ["admin", "backup", "config", "upload"]):
                severity = "medium"

            findings.append(Finding(
                type="path",
                value=path,
                description=f"Directory found: {path} (Status: {status})",
                severity=severity,
                metadata={"status_code": int(status)}
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
                metadata={"status_code": int(status)}
            ))

        return findings

    def _parse_nuclei(self, output: str) -> list[Finding]:
        """Parse nuclei vulnerability scanner output"""
        findings = []

        for match in self.PATTERNS["nuclei_vuln"].finditer(output):
            template_id = match.group(1)
            severity = match.group(2).lower()
            protocol = match.group(3)
            target = match.group(4)

            # Normalize severity
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
                }
            ))

        return findings

    def _parse_hydra(self, output: str) -> list[Finding]:
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
                }
            ))

        return findings

    def _parse_vuln_scanner(self, output: str) -> list[Finding]:
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
                metadata={"cve": cve}
            ))

        # Look for common vulnerability keywords
        vuln_keywords = [
            ("SQL injection", "high"),
            ("XSS", "medium"),
            ("CSRF", "medium"),
            ("directory listing", "low"),
            ("information disclosure", "medium"),
            ("remote code execution", "critical"),
            ("RCE", "critical"),
            ("LFI", "high"),
            ("RFI", "high"),
        ]

        output_lower = output.lower()
        for keyword, severity in vuln_keywords:
            if keyword.lower() in output_lower:
                findings.append(Finding(
                    type="vuln",
                    value=keyword,
                    description=f"Potential vulnerability: {keyword}",
                    severity=severity,
                ))

        return findings

    def _parse_generic(self, output: str) -> list[Finding]:
        """Extract generic patterns from any output"""
        findings = []

        # Extract CVEs
        for match in self.PATTERNS["cve"].finditer(output):
            cve = match.group(0).upper()
            findings.append(Finding(
                type="vuln",
                value=cve,
                description=f"CVE reference: {cve}",
                severity="medium",
            ))

        # Extract emails (potential targets for phishing)
        for match in self.PATTERNS["email"].finditer(output):
            email = match.group(0)
            findings.append(Finding(
                type="info",
                value=email,
                description=f"Email discovered: {email}",
            ))

        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings"""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.type, finding.value)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique
