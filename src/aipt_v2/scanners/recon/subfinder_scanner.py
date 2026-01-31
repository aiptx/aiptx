"""
AIPTX Subfinder Scanner
=======================

Scanner for subfinder - subdomain discovery tool.
https://github.com/projectdiscovery/subfinder
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class SubfinderConfig:
    """Configuration for subfinder scanner."""

    # Source options
    all_sources: bool = False  # Use all sources
    sources: List[str] = field(default_factory=list)  # Specific sources
    exclude_sources: List[str] = field(default_factory=list)
    recursive: bool = False

    # Rate limiting
    rate_limit: int = 0  # Requests per second (0 = unlimited)
    timeout: int = 30
    max_time: int = 0  # Max execution time in minutes

    # Output
    json_output: bool = True
    output_file: Optional[str] = None
    output_ip: bool = False  # Include IP addresses

    # Filtering
    match: List[str] = field(default_factory=list)  # Match subdomains
    filter: List[str] = field(default_factory=list)  # Filter out subdomains

    # API keys (for premium sources)
    config_file: Optional[str] = None

    # Resolver
    resolvers: Optional[str] = None  # Custom resolvers file


class SubfinderScanner(BaseScanner):
    """
    Scanner for subfinder - subdomain discovery.

    Uses multiple sources:
    - Passive sources (crt.sh, DNSDumpster, etc.)
    - Active sources (API-based)
    - Recursive enumeration

    Example:
        scanner = SubfinderScanner()
        result = await scanner.scan("example.com")

        for finding in result.findings:
            print(f"Subdomain: {finding.host}")
    """

    def __init__(self, config: Optional[SubfinderConfig] = None):
        self.config = config or SubfinderConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if subfinder is installed."""
        return shutil.which("subfinder") is not None

    async def scan(
        self,
        target: str,
        domains_file: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run subfinder scan.

        Args:
            target: Domain to enumerate
            domains_file: Optional file with list of domains
            **kwargs: Additional options

        Returns:
            ScanResult with subdomain findings
        """
        result = ScanResult(scanner="subfinder", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        try:
            cmd = self._build_command(target, domains_file)
            logger.debug(f"Running: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = process

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=kwargs.get("timeout", 300)
            )

            result.raw_output = stdout.decode("utf-8", errors="replace")
            result.findings = self.parse_output(result.raw_output)
            result.status = "completed"

        except asyncio.TimeoutError:
            result.status = "failed"
            result.errors.append("Scan timed out")
        except Exception as e:
            result.status = "failed"
            result.errors.append(str(e))
            logger.error(f"subfinder scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, domains_file: Optional[str] = None) -> List[str]:
        """Build subfinder command."""
        cmd = ["subfinder"]

        # Input
        if domains_file:
            cmd.extend(["-dL", domains_file])
        else:
            cmd.extend(["-d", target])

        # Sources
        if self.config.all_sources:
            cmd.append("-all")

        if self.config.sources:
            cmd.extend(["-sources", ",".join(self.config.sources)])

        if self.config.exclude_sources:
            cmd.extend(["-exclude-sources", ",".join(self.config.exclude_sources)])

        if self.config.recursive:
            cmd.append("-recursive")

        # Rate limiting
        if self.config.rate_limit > 0:
            cmd.extend(["-rl", str(self.config.rate_limit)])

        cmd.extend(["-timeout", str(self.config.timeout)])

        if self.config.max_time > 0:
            cmd.extend(["-max-time", str(self.config.max_time)])

        # Output
        if self.config.json_output:
            cmd.append("-json")

        if self.config.output_file:
            cmd.extend(["-o", self.config.output_file])

        if self.config.output_ip:
            cmd.append("-ip")

        # Filtering
        for m in self.config.match:
            cmd.extend(["-match", m])

        for f in self.config.filter:
            cmd.extend(["-filter", f])

        # Config
        if self.config.config_file:
            cmd.extend(["-config", self.config.config_file])

        if self.config.resolvers:
            cmd.extend(["-r", self.config.resolvers])

        cmd.append("-silent")

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse subfinder output."""
        findings = []
        seen = set()

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                # Try JSON parsing
                if line.startswith("{"):
                    data = json.loads(line)
                    subdomain = data.get("host", "")
                    source = data.get("source", "")
                    ip = data.get("ip", "")

                    if subdomain and subdomain not in seen:
                        seen.add(subdomain)
                        findings.append(self._create_finding(subdomain, source, ip))
                else:
                    # Plain subdomain
                    subdomain = line.strip()
                    if subdomain and subdomain not in seen:
                        seen.add(subdomain)
                        findings.append(self._create_finding(subdomain))

            except json.JSONDecodeError:
                # Plain text
                subdomain = line.strip()
                if subdomain and subdomain not in seen:
                    seen.add(subdomain)
                    findings.append(self._create_finding(subdomain))

        return findings

    def _create_finding(
        self,
        subdomain: str,
        source: str = "",
        ip: str = "",
    ) -> ScanFinding:
        """Create finding from subdomain."""
        tags = ["subdomain", "recon"]
        description_parts = [f"Subdomain discovered: {subdomain}"]

        if source:
            tags.append(source.lower())
            description_parts.append(f"Source: {source}")

        if ip:
            description_parts.append(f"IP: {ip}")

        # Check for interesting subdomains
        severity = ScanSeverity.INFO
        subdomain_lower = subdomain.lower()

        if any(x in subdomain_lower for x in ["admin", "dev", "staging", "test", "api", "internal"]):
            severity = ScanSeverity.LOW
            tags.append("interesting")

        if any(x in subdomain_lower for x in ["vpn", "mail", "ftp", "ssh", "db", "database"]):
            severity = ScanSeverity.LOW
            tags.append("service")

        return ScanFinding(
            title=f"Subdomain: {subdomain}",
            severity=severity,
            description="; ".join(description_parts),
            host=subdomain,
            scanner="subfinder",
            tags=tags,
        )

    async def stop(self) -> bool:
        """Stop running scan."""
        if self._process and self._running:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
            self._running = False
            return True
        return False
