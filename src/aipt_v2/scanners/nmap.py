"""
AIPT Nmap Scanner Integration

Network scanning and service detection using Nmap.
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .base import BaseScanner, ScanFinding, ScanResult, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class NmapConfig:
    """Nmap scanner configuration"""
    # Scan types
    syn_scan: bool = True  # -sS (requires root)
    version_scan: bool = True  # -sV
    os_detection: bool = False  # -O (requires root)
    script_scan: bool = True  # -sC (default scripts)
    aggressive: bool = False  # -A

    # Port selection
    ports: str = ""  # e.g., "1-1000" or "22,80,443"
    top_ports: int = 0  # --top-ports N
    all_ports: bool = False  # -p-

    # Timing
    timing: int = 4  # -T0 to -T5

    # Output
    xml_output: bool = True

    # Scripts
    scripts: list[str] = field(default_factory=list)  # Specific NSE scripts
    script_args: dict[str, str] = field(default_factory=dict)

    # Advanced
    no_ping: bool = False  # -Pn
    udp_scan: bool = False  # -sU


@dataclass
class NmapHost:
    """Parsed Nmap host result"""
    address: str
    hostname: str = ""
    state: str = "unknown"
    os: str = ""
    ports: list[dict] = field(default_factory=list)
    scripts: list[dict] = field(default_factory=list)


class NmapScanner(BaseScanner):
    """
    Nmap network scanner integration.

    Features:
    - Port scanning
    - Service version detection
    - OS fingerprinting
    - NSE script execution

    Example:
        scanner = NmapScanner(NmapConfig(
            version_scan=True,
            top_ports=100,
        ))
        result = await scanner.scan("192.168.1.0/24")

        for finding in result.findings:
            print(f"{finding.host}:{finding.port} - {finding.title}")
    """

    def __init__(self, config: Optional[NmapConfig] = None):
        super().__init__()
        self.config = config or NmapConfig()
        self._hosts: list[NmapHost] = []

    def is_available(self) -> bool:
        """Check if Nmap is installed"""
        return self._check_tool("nmap")

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Nmap scan on target.

        Args:
            target: IP, hostname, or CIDR range
            **kwargs: Override config options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="nmap", target=target)
        result.start_time = datetime.utcnow()
        result.status = "running"

        if not self.is_available():
            result.status = "failed"
            result.errors.append("Nmap is not installed")
            return result

        # Build command
        command = self._build_command(target, **kwargs)
        logger.info(f"Running Nmap: {' '.join(command)}")

        # Execute
        exit_code, stdout, stderr = await self._run_command(
            command,
            timeout=kwargs.get("timeout", 900.0),  # 15 min default
        )

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()
        result.raw_output = stdout

        if exit_code != 0:
            result.status = "failed"
            result.errors.append(stderr)
        else:
            result.status = "completed"

        # Parse output
        if self.config.xml_output:
            result.findings = self.parse_output(stdout)
        else:
            result.findings = self._parse_text_output(stdout, target)

        logger.info(
            f"Nmap scan complete: {len(result.findings)} findings in {result.duration_seconds:.1f}s"
        )

        return result

    def parse_output(self, output: str) -> list[ScanFinding]:
        """Parse Nmap XML output"""
        findings = []
        self._hosts = []

        try:
            # Find XML content
            xml_start = output.find("<?xml")
            if xml_start == -1:
                return self._parse_text_output(output, "")

            xml_content = output[xml_start:]
            root = ET.fromstring(xml_content)

            for host_elem in root.findall(".//host"):
                host = self._parse_host(host_elem)
                self._hosts.append(host)

                # Create findings for open ports
                for port_info in host.ports:
                    if port_info["state"] == "open":
                        finding = ScanFinding(
                            title=f"Open Port: {port_info['port']}/{port_info['protocol']}",
                            severity=ScanSeverity.INFO,
                            description=f"Service: {port_info['service']} {port_info['version']}".strip(),
                            host=host.address,
                            port=int(port_info["port"]),
                            scanner="nmap",
                        )

                        # Add product/version info
                        if port_info.get("product"):
                            finding.evidence = f"Product: {port_info['product']}"
                            if port_info.get("version"):
                                finding.evidence += f" Version: {port_info['version']}"

                        findings.append(finding)

                # Create findings from script results
                for script in host.scripts:
                    severity = self._script_severity(script)
                    finding = ScanFinding(
                        title=f"NSE Script: {script['id']}",
                        severity=severity,
                        description=script.get("output", "")[:500],
                        host=host.address,
                        scanner="nmap",
                        template=script["id"],
                    )
                    findings.append(finding)

        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
            return self._parse_text_output(output, "")
        except Exception as e:
            logger.error(f"Nmap output parse error: {e}")

        return findings

    def _parse_host(self, host_elem: ET.Element) -> NmapHost:
        """Parse host element from Nmap XML"""
        host = NmapHost(address="")

        # Address
        addr_elem = host_elem.find("address")
        if addr_elem is not None:
            host.address = addr_elem.get("addr", "")

        # Hostname
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            host.hostname = hostname_elem.get("name", "")

        # Status
        status_elem = host_elem.find("status")
        if status_elem is not None:
            host.state = status_elem.get("state", "unknown")

        # OS detection
        os_elem = host_elem.find(".//osmatch")
        if os_elem is not None:
            host.os = os_elem.get("name", "")

        # Ports
        for port_elem in host_elem.findall(".//port"):
            port_info = {
                "port": port_elem.get("portid", ""),
                "protocol": port_elem.get("protocol", "tcp"),
                "state": "",
                "service": "",
                "product": "",
                "version": "",
            }

            state_elem = port_elem.find("state")
            if state_elem is not None:
                port_info["state"] = state_elem.get("state", "")

            service_elem = port_elem.find("service")
            if service_elem is not None:
                port_info["service"] = service_elem.get("name", "")
                port_info["product"] = service_elem.get("product", "")
                port_info["version"] = service_elem.get("version", "")

            host.ports.append(port_info)

            # Port-level scripts
            for script_elem in port_elem.findall("script"):
                host.scripts.append({
                    "id": script_elem.get("id", ""),
                    "output": script_elem.get("output", ""),
                    "port": port_info["port"],
                })

        # Host-level scripts
        for script_elem in host_elem.findall(".//hostscript/script"):
            host.scripts.append({
                "id": script_elem.get("id", ""),
                "output": script_elem.get("output", ""),
            })

        return host

    def _parse_text_output(self, output: str, target: str) -> list[ScanFinding]:
        """Fallback text output parsing"""
        findings = []

        # Simple regex for open ports
        port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?"

        for match in re.finditer(port_pattern, output):
            port, protocol, service, version = match.groups()
            finding = ScanFinding(
                title=f"Open Port: {port}/{protocol}",
                severity=ScanSeverity.INFO,
                description=f"Service: {service}" + (f" - {version}" if version else ""),
                host=target,
                port=int(port),
                scanner="nmap",
            )
            findings.append(finding)

        return findings

    def _script_severity(self, script: dict) -> ScanSeverity:
        """Determine severity from script results"""
        script_id = script.get("id", "").lower()
        output = script.get("output", "").lower()

        # High severity indicators
        if any(kw in script_id for kw in ["vuln", "exploit", "backdoor"]):
            return ScanSeverity.HIGH

        # Medium severity
        if any(kw in script_id for kw in ["default", "brute", "enum"]):
            return ScanSeverity.MEDIUM

        # Check output for vulnerability indicators
        if "vulnerable" in output or "exploitable" in output:
            return ScanSeverity.HIGH

        return ScanSeverity.LOW

    def _build_command(self, target: str, **kwargs) -> list[str]:
        """Build Nmap command"""
        command = ["nmap"]

        # Scan types
        if self.config.syn_scan:
            command.append("-sS")
        else:
            command.append("-sT")  # TCP connect scan

        if self.config.version_scan:
            command.append("-sV")

        if self.config.os_detection:
            command.append("-O")

        if self.config.script_scan:
            command.append("-sC")

        if self.config.aggressive:
            command.append("-A")

        if self.config.udp_scan:
            command.append("-sU")

        # Port selection
        if self.config.all_ports:
            command.append("-p-")
        elif self.config.ports:
            command.extend(["-p", self.config.ports])
        elif self.config.top_ports:
            command.extend(["--top-ports", str(self.config.top_ports)])

        # Timing
        command.append(f"-T{self.config.timing}")

        # Scripts
        if self.config.scripts:
            command.extend(["--script", ",".join(self.config.scripts)])

        if self.config.script_args:
            args = ",".join(f"{k}={v}" for k, v in self.config.script_args.items())
            command.extend(["--script-args", args])

        # Options
        if self.config.no_ping:
            command.append("-Pn")

        # Output format
        if self.config.xml_output:
            command.extend(["-oX", "-"])  # XML to stdout

        # Target
        command.append(target)

        return command

    def get_hosts(self) -> list[NmapHost]:
        """Get parsed hosts from last scan"""
        return self._hosts


# Convenience functions
async def quick_port_scan(target: str, ports: str = "1-1000") -> ScanResult:
    """Quick port scan"""
    config = NmapConfig(
        ports=ports,
        version_scan=False,
        script_scan=False,
        timing=4,
    )
    scanner = NmapScanner(config)
    return await scanner.scan(target)


async def service_scan(target: str) -> ScanResult:
    """Service version detection scan"""
    config = NmapConfig(
        top_ports=1000,
        version_scan=True,
        script_scan=True,
        timing=3,
    )
    scanner = NmapScanner(config)
    return await scanner.scan(target)


async def vuln_scan(target: str) -> ScanResult:
    """Vulnerability scan with NSE scripts"""
    config = NmapConfig(
        top_ports=1000,
        version_scan=True,
        scripts=["vuln", "exploit"],
        timing=3,
    )
    scanner = NmapScanner(config)
    return await scanner.scan(target, timeout=1800.0)
