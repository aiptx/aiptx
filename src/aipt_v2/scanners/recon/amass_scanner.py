"""
AIPTX Amass Scanner
===================

Scanner for amass - attack surface mapping tool.
https://github.com/owasp-amass/amass
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
class AmassConfig:
    """Configuration for amass scanner."""

    # Mode
    mode: str = "enum"  # enum, intel, track, db

    # Enumeration options
    passive: bool = False  # Passive only (no DNS resolution)
    active: bool = False  # Aggressive collection
    brute: bool = False  # Brute force subdomain
    alts: bool = False  # Alterations of discovered names

    # Scope
    include_unresolvable: bool = False

    # Sources
    sources: List[str] = field(default_factory=list)
    exclude_sources: List[str] = field(default_factory=list)

    # Rate limiting
    max_dns_queries: int = 0  # 0 = unlimited
    timeout: int = 0  # Minutes (0 = unlimited)

    # DNS options
    resolvers: Optional[str] = None
    trusted_resolvers: Optional[str] = None

    # Output
    json_output: bool = True
    output_file: Optional[str] = None
    dir: Optional[str] = None  # Output directory

    # Config
    config_file: Optional[str] = None


class AmassScanner(BaseScanner):
    """
    Scanner for amass - comprehensive attack surface mapping.

    Capabilities:
    - Subdomain enumeration
    - ASN discovery
    - Network infrastructure mapping
    - DNS intelligence gathering

    Example:
        scanner = AmassScanner()
        result = await scanner.scan("example.com")

        for finding in result.findings:
            print(f"Found: {finding.host}")
    """

    def __init__(self, config: Optional[AmassConfig] = None):
        self.config = config or AmassConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if amass is installed."""
        return shutil.which("amass") is not None

    async def scan(
        self,
        target: str,
        domains_file: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run amass scan.

        Args:
            target: Domain to enumerate
            domains_file: Optional file with list of domains
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="amass", target=target)
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
                timeout=kwargs.get("timeout", 1200)  # 20 min default for amass
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
            logger.error(f"amass scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, domains_file: Optional[str] = None) -> List[str]:
        """Build amass command."""
        cmd = ["amass", self.config.mode]

        # Input
        if domains_file:
            cmd.extend(["-df", domains_file])
        else:
            cmd.extend(["-d", target])

        # Mode options
        if self.config.passive:
            cmd.append("-passive")

        if self.config.active:
            cmd.append("-active")

        if self.config.brute:
            cmd.append("-brute")

        if self.config.alts:
            cmd.append("-alts")

        # Scope
        if self.config.include_unresolvable:
            cmd.append("-include-unresolvable")

        # Sources
        if self.config.sources:
            cmd.extend(["-src", ",".join(self.config.sources)])

        if self.config.exclude_sources:
            cmd.extend(["-exclude-src", ",".join(self.config.exclude_sources)])

        # Rate limiting
        if self.config.max_dns_queries > 0:
            cmd.extend(["-max-dns-queries", str(self.config.max_dns_queries)])

        if self.config.timeout > 0:
            cmd.extend(["-timeout", str(self.config.timeout)])

        # DNS options
        if self.config.resolvers:
            cmd.extend(["-rf", self.config.resolvers])

        if self.config.trusted_resolvers:
            cmd.extend(["-trf", self.config.trusted_resolvers])

        # Output
        if self.config.json_output:
            cmd.append("-json")

        if self.config.output_file:
            cmd.extend(["-o", self.config.output_file])

        if self.config.dir:
            cmd.extend(["-dir", self.config.dir])

        # Config
        if self.config.config_file:
            cmd.extend(["-config", self.config.config_file])

        cmd.append("-silent")

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse amass output."""
        findings = []
        seen_names = set()

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                # JSON output
                if line.startswith("{"):
                    data = json.loads(line)
                    finding = self._json_to_finding(data)
                    if finding and finding.host not in seen_names:
                        seen_names.add(finding.host)
                        findings.append(finding)
                else:
                    # Plain text (hostname)
                    hostname = line.strip()
                    if hostname and hostname not in seen_names:
                        seen_names.add(hostname)
                        findings.append(ScanFinding(
                            title=f"Subdomain: {hostname}",
                            severity=ScanSeverity.INFO,
                            description=f"Discovered: {hostname}",
                            host=hostname,
                            scanner="amass",
                            tags=["subdomain", "recon"],
                        ))

            except json.JSONDecodeError:
                hostname = line.strip()
                if hostname and hostname not in seen_names:
                    seen_names.add(hostname)
                    findings.append(ScanFinding(
                        title=f"Subdomain: {hostname}",
                        severity=ScanSeverity.INFO,
                        description=f"Discovered: {hostname}",
                        host=hostname,
                        scanner="amass",
                        tags=["subdomain", "recon"],
                    ))

        return findings

    def _json_to_finding(self, data: Dict[str, Any]) -> Optional[ScanFinding]:
        """Convert JSON data to finding."""
        name = data.get("name", "")
        if not name:
            return None

        # Extract data
        domain = data.get("domain", "")
        addresses = data.get("addresses", [])
        sources = data.get("sources", [])
        tag = data.get("tag", "")

        # Build description
        desc_parts = []
        if domain:
            desc_parts.append(f"Domain: {domain}")
        if addresses:
            ips = [a.get("ip", "") for a in addresses[:3]]
            desc_parts.append(f"IPs: {', '.join(ips)}")
        if sources:
            desc_parts.append(f"Sources: {', '.join(sources[:3])}")

        # Determine severity
        severity = ScanSeverity.INFO
        tags = ["subdomain", "recon"]

        name_lower = name.lower()
        if any(x in name_lower for x in ["admin", "dev", "staging", "test", "internal"]):
            severity = ScanSeverity.LOW
            tags.append("interesting")

        if tag:
            tags.append(tag.lower())

        return ScanFinding(
            title=f"Subdomain: {name}",
            severity=severity,
            description="; ".join(desc_parts) if desc_parts else f"Discovered: {name}",
            host=name,
            scanner="amass",
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
