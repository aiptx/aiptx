"""
AIPTX Recon Agent - Reconnaissance Specialist

Focuses on information gathering and attack surface discovery:
- Subdomain enumeration
- Port scanning
- Technology detection
- Directory/file discovery
- DNS reconnaissance
- WHOIS lookups
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from aipt_v2.agents.specialized.base_specialized import (
    SpecializedAgent,
    AgentCapability,
    AgentConfig,
)
from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    VulnerabilityType,
    Evidence,
)

logger = logging.getLogger(__name__)


class ReconAgent(SpecializedAgent):
    """
    Reconnaissance agent for attack surface discovery.

    Discovers:
    - Subdomains and related hosts
    - Open ports and services
    - Technologies and frameworks
    - Hidden directories and files
    - Potential entry points

    Findings are pushed to central repository for other agents.
    """

    name = "ReconAgent"

    def get_capabilities(self) -> list[AgentCapability]:
        return [
            AgentCapability.SUBDOMAIN_ENUM,
            AgentCapability.PORT_SCAN,
            AgentCapability.TECH_DETECTION,
            AgentCapability.DIRECTORY_ENUM,
        ]

    async def run(self) -> dict[str, Any]:
        """Execute reconnaissance tasks."""
        await self.initialize()
        self._progress.status = "running"
        self._progress.started_at = asyncio.get_event_loop().time()

        results = {
            "subdomains": [],
            "ports": [],
            "technologies": [],
            "directories": [],
            "findings_count": 0,
            "success": True,
        }

        try:
            # Phase 1: Subdomain enumeration (20%)
            await self.update_progress("Enumerating subdomains", 0)
            subdomains = await self._enumerate_subdomains()
            results["subdomains"] = subdomains

            # Phase 2: Port scanning (40%)
            self.check_cancelled()
            await self.update_progress("Scanning ports", 20)
            ports = await self._scan_ports()
            results["ports"] = ports

            # Phase 3: Technology detection (60%)
            self.check_cancelled()
            await self.update_progress("Detecting technologies", 40)
            technologies = await self._detect_technologies()
            results["technologies"] = technologies

            # Phase 4: Directory enumeration (80%)
            self.check_cancelled()
            await self.update_progress("Enumerating directories", 60)
            directories = await self._enumerate_directories()
            results["directories"] = directories

            # Phase 5: Analysis (100%)
            self.check_cancelled()
            await self.update_progress("Analyzing results", 80)
            await self._analyze_and_report(results)

            await self.update_progress("Complete", 100)
            results["findings_count"] = self._findings_count

        except asyncio.CancelledError:
            logger.info(f"ReconAgent cancelled")
            results["success"] = False
            results["error"] = "Cancelled"
        except Exception as e:
            logger.error(f"ReconAgent error: {e}", exc_info=True)
            results["success"] = False
            results["error"] = str(e)
        finally:
            await self.cleanup()

        return results

    async def _enumerate_subdomains(self) -> list[str]:
        """
        Enumerate subdomains using available tools.

        Uses: subfinder, amass, assetfinder, etc.
        """
        subdomains = []

        try:
            from aipt_v2.execution.tool_registry import get_registry

            registry = get_registry()

            # Try subfinder first
            if await registry.is_tool_available("subfinder"):
                result = await self._run_tool("subfinder", [
                    "-d", self._extract_domain(self.target),
                    "-silent"
                ])
                if result.get("output"):
                    subdomains.extend(result["output"].strip().split("\n"))

            # Also try amass if available
            if await registry.is_tool_available("amass"):
                result = await self._run_tool("amass", [
                    "enum", "-passive",
                    "-d", self._extract_domain(self.target)
                ])
                if result.get("output"):
                    for line in result["output"].strip().split("\n"):
                        if line and line not in subdomains:
                            subdomains.append(line)

        except Exception as e:
            logger.warning(f"Subdomain enumeration partial failure: {e}")

        # Create findings for discovered subdomains
        for subdomain in subdomains[:50]:  # Limit to prevent spam
            finding = Finding(
                vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                title=f"Subdomain discovered: {subdomain}",
                description=f"Discovered subdomain during reconnaissance",
                severity=FindingSeverity.INFO,
                target=self.target,
                url=f"https://{subdomain}",
                component=subdomain,
                tags=["recon", "subdomain"],
            )
            await self.add_finding(finding)

        return subdomains

    async def _scan_ports(self) -> list[dict]:
        """
        Scan for open ports and services.

        Uses: nmap, masscan, rustscan
        """
        ports = []

        try:
            from aipt_v2.execution.tool_registry import get_registry

            registry = get_registry()
            host = self._extract_host(self.target)

            if await registry.is_tool_available("nmap"):
                # Quick scan of common ports
                result = await self._run_tool("nmap", [
                    "-sV", "-sC",
                    "-p", "21,22,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,27017",
                    "--open",
                    host
                ], timeout=120)

                if result.get("output"):
                    ports = self._parse_nmap_output(result["output"])

        except Exception as e:
            logger.warning(f"Port scanning partial failure: {e}")

        # Create findings for interesting ports
        for port_info in ports:
            if port_info.get("state") == "open":
                severity = self._assess_port_severity(port_info)
                finding = Finding(
                    vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    title=f"Open port: {port_info['port']}/{port_info['protocol']} ({port_info.get('service', 'unknown')})",
                    description=f"Port {port_info['port']} is open running {port_info.get('service', 'unknown')} {port_info.get('version', '')}",
                    severity=severity,
                    target=self.target,
                    endpoint=f":{port_info['port']}",
                    component=port_info.get("service", "unknown"),
                    tags=["recon", "port-scan"],
                    metadata=port_info,
                )
                await self.add_finding(finding)

        return ports

    async def _detect_technologies(self) -> list[dict]:
        """
        Detect technologies and frameworks.

        Uses: wappalyzer, whatweb, httpx
        """
        technologies = []

        try:
            from aipt_v2.execution.tool_registry import get_registry

            registry = get_registry()

            if await registry.is_tool_available("httpx"):
                result = await self._run_tool("httpx", [
                    "-u", self.target,
                    "-tech-detect",
                    "-json"
                ])
                if result.get("output"):
                    technologies = self._parse_httpx_tech(result["output"])

            # Also try whatweb
            if await registry.is_tool_available("whatweb"):
                result = await self._run_tool("whatweb", [
                    self.target,
                    "--color=never"
                ])
                if result.get("output"):
                    for tech in self._parse_whatweb_output(result["output"]):
                        if tech not in technologies:
                            technologies.append(tech)

        except Exception as e:
            logger.warning(f"Technology detection partial failure: {e}")

        # Create findings for interesting technologies
        for tech in technologies:
            severity = self._assess_tech_severity(tech)
            if severity != FindingSeverity.INFO:
                finding = Finding(
                    vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    title=f"Technology detected: {tech.get('name', 'Unknown')}",
                    description=f"Detected {tech.get('name', 'Unknown')} version {tech.get('version', 'unknown')}",
                    severity=severity,
                    target=self.target,
                    component=tech.get("name"),
                    tags=["recon", "technology"],
                    metadata=tech,
                )
                await self.add_finding(finding)

        return technologies

    async def _enumerate_directories(self) -> list[str]:
        """
        Enumerate directories and files.

        Uses: feroxbuster, dirsearch, gobuster
        """
        directories = []

        try:
            from aipt_v2.execution.tool_registry import get_registry

            registry = get_registry()

            # Use feroxbuster if available
            if await registry.is_tool_available("feroxbuster"):
                result = await self._run_tool("feroxbuster", [
                    "-u", self.target,
                    "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
                    "--quiet",
                    "-t", "10",
                    "--depth", "2"
                ], timeout=180)

                if result.get("output"):
                    directories = self._parse_feroxbuster_output(result["output"])

            elif await registry.is_tool_available("gobuster"):
                result = await self._run_tool("gobuster", [
                    "dir",
                    "-u", self.target,
                    "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
                    "-t", "10",
                    "-q"
                ], timeout=180)

                if result.get("output"):
                    directories = self._parse_gobuster_output(result["output"])

        except Exception as e:
            logger.warning(f"Directory enumeration partial failure: {e}")

        # Create findings for interesting directories
        sensitive_patterns = [
            ".git", ".env", "config", "admin", "backup", ".svn",
            "phpinfo", "debug", "test", "staging", "api"
        ]

        for directory in directories[:100]:
            is_sensitive = any(p in directory.lower() for p in sensitive_patterns)
            if is_sensitive:
                finding = Finding(
                    vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    title=f"Sensitive path discovered: {directory}",
                    description=f"Potentially sensitive path found during directory enumeration",
                    severity=FindingSeverity.MEDIUM if ".git" in directory or ".env" in directory else FindingSeverity.LOW,
                    target=self.target,
                    url=f"{self.target.rstrip('/')}/{directory.lstrip('/')}",
                    endpoint=directory,
                    tags=["recon", "directory"],
                )
                await self.add_finding(finding)

        return directories

    async def _analyze_and_report(self, results: dict) -> None:
        """Analyze collected data and report attack surface."""
        # Share findings with other agents via coordination
        await self.request_coordination(
            request_type="recon_complete",
            data={
                "target": self.target,
                "subdomains_count": len(results.get("subdomains", [])),
                "ports_count": len(results.get("ports", [])),
                "technologies": results.get("technologies", []),
                "directories_count": len(results.get("directories", [])),
                "findings_count": self._findings_count,
            }
        )

    async def _run_tool(
        self,
        tool_name: str,
        args: list[str],
        timeout: int = 60,
    ) -> dict:
        """
        Run a reconnaissance tool.

        Args:
            tool_name: Name of the tool
            args: Command arguments
            timeout: Execution timeout

        Returns:
            Tool output dictionary
        """
        try:
            from aipt_v2.execution.tool_runner import ToolRunner

            runner = ToolRunner()
            result = await runner.run(
                tool_name=tool_name,
                args=args,
                timeout=timeout,
            )
            return result
        except Exception as e:
            logger.warning(f"Tool {tool_name} failed: {e}")
            return {"output": "", "error": str(e)}

    def _extract_domain(self, target: str) -> str:
        """Extract domain from target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.netloc or target

    def _extract_host(self, target: str) -> str:
        """Extract host from target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc or target
        # Remove port if present
        if ":" in host:
            host = host.split(":")[0]
        return host

    def _parse_nmap_output(self, output: str) -> list[dict]:
        """Parse nmap output into structured port data."""
        ports = []
        for line in output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    port, proto = port_proto.split("/")
                    ports.append({
                        "port": int(port),
                        "protocol": proto,
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown",
                        "version": " ".join(parts[3:]) if len(parts) > 3 else "",
                    })
        return ports

    def _parse_httpx_tech(self, output: str) -> list[dict]:
        """Parse httpx technology detection output."""
        import json
        technologies = []
        try:
            for line in output.strip().split("\n"):
                if line:
                    data = json.loads(line)
                    for tech in data.get("tech", []):
                        technologies.append({"name": tech, "version": ""})
        except json.JSONDecodeError:
            pass
        return technologies

    def _parse_whatweb_output(self, output: str) -> list[dict]:
        """Parse whatweb output."""
        technologies = []
        # Simple parsing - whatweb output is complex
        import re
        for match in re.findall(r'\[([^\]]+)\]', output):
            if match and not match.startswith("http"):
                technologies.append({"name": match, "version": ""})
        return technologies

    def _parse_feroxbuster_output(self, output: str) -> list[str]:
        """Parse feroxbuster output."""
        directories = []
        for line in output.strip().split("\n"):
            if line and "http" in line:
                parts = line.split()
                for part in parts:
                    if part.startswith("http"):
                        from urllib.parse import urlparse
                        parsed = urlparse(part)
                        if parsed.path:
                            directories.append(parsed.path)
        return list(set(directories))

    def _parse_gobuster_output(self, output: str) -> list[str]:
        """Parse gobuster output."""
        directories = []
        for line in output.strip().split("\n"):
            if line.startswith("/"):
                path = line.split()[0]
                directories.append(path)
        return directories

    def _assess_port_severity(self, port_info: dict) -> FindingSeverity:
        """Assess severity based on port/service."""
        high_risk_ports = {21, 22, 23, 3389, 5900}  # FTP, SSH, Telnet, RDP, VNC
        medium_risk_services = {"mysql", "postgresql", "mongodb", "redis", "elasticsearch"}

        port = port_info.get("port", 0)
        service = port_info.get("service", "").lower()

        if port in high_risk_ports:
            return FindingSeverity.MEDIUM
        if any(s in service for s in medium_risk_services):
            return FindingSeverity.MEDIUM
        return FindingSeverity.INFO

    def _assess_tech_severity(self, tech: dict) -> FindingSeverity:
        """Assess severity based on technology version."""
        name = tech.get("name", "").lower()
        version = tech.get("version", "")

        # Known vulnerable patterns
        if "php/5" in f"{name}/{version}".lower():
            return FindingSeverity.MEDIUM
        if "apache/2.2" in f"{name}/{version}".lower():
            return FindingSeverity.LOW
        if "wordpress" in name:
            return FindingSeverity.LOW

        return FindingSeverity.INFO
