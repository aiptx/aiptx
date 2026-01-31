"""
AIPTX HTTPX Scanner
===================

Scanner for httpx - fast HTTP toolkit for probing live hosts.
https://github.com/projectdiscovery/httpx
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

from ..base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class HttpxConfig:
    """Configuration for httpx scanner."""

    # Probing options
    status_code: bool = True
    content_length: bool = True
    content_type: bool = True
    title: bool = True
    web_server: bool = True
    tech_detect: bool = True
    favicon: bool = False

    # Output options
    json_output: bool = True
    no_color: bool = True

    # Rate limiting
    threads: int = 50
    rate_limit: int = 150
    timeout: int = 10

    # TLS options
    tls_probe: bool = True
    tls_grab: bool = False

    # Follow redirects
    follow_redirects: bool = True
    max_redirects: int = 10

    # Additional flags
    silent: bool = True
    no_fallback: bool = False


class HttpxScanner(BaseScanner):
    """
    Scanner for httpx - HTTP toolkit.

    Probes hosts for:
    - Live status and response codes
    - Web server identification
    - Technology detection
    - TLS/SSL information
    - Content analysis

    Example:
        scanner = HttpxScanner()
        result = await scanner.scan("example.com")

        for finding in result.findings:
            print(f"{finding.url}: {finding.title}")
    """

    def __init__(self, config: Optional[HttpxConfig] = None):
        self.config = config or HttpxConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if httpx is installed."""
        return shutil.which("httpx") is not None

    async def scan(
        self,
        target: str,
        targets_file: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run httpx scan on target(s).

        Args:
            target: Single target or domain
            targets_file: Optional file with list of targets
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="httpx", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        try:
            # Build command
            cmd = self._build_command(target, targets_file)
            logger.debug(f"Running: {' '.join(cmd)}")

            # Execute
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

            # Parse output
            if self.config.json_output:
                result.findings = self._parse_json_output(result.raw_output)
            else:
                result.findings = self._parse_text_output(result.raw_output)

            result.status = "completed"

        except asyncio.TimeoutError:
            result.status = "failed"
            result.errors.append("Scan timed out")
        except Exception as e:
            result.status = "failed"
            result.errors.append(str(e))
            logger.error(f"httpx scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, targets_file: Optional[str] = None) -> List[str]:
        """Build httpx command."""
        cmd = ["httpx"]

        # Input
        if targets_file:
            cmd.extend(["-l", targets_file])
        else:
            cmd.extend(["-u", target])

        # Probing options
        if self.config.status_code:
            cmd.append("-sc")
        if self.config.content_length:
            cmd.append("-cl")
        if self.config.content_type:
            cmd.append("-ct")
        if self.config.title:
            cmd.append("-title")
        if self.config.web_server:
            cmd.append("-server")
        if self.config.tech_detect:
            cmd.append("-td")
        if self.config.favicon:
            cmd.append("-favicon")

        # TLS
        if self.config.tls_probe:
            cmd.append("-tls-probe")
        if self.config.tls_grab:
            cmd.append("-tls-grab")

        # Redirects
        if self.config.follow_redirects:
            cmd.extend(["-fr", "-maxr", str(self.config.max_redirects)])

        # Output
        if self.config.json_output:
            cmd.append("-json")
        if self.config.no_color:
            cmd.append("-nc")
        if self.config.silent:
            cmd.append("-silent")

        # Rate limiting
        cmd.extend(["-t", str(self.config.threads)])
        cmd.extend(["-rl", str(self.config.rate_limit)])
        cmd.extend(["-timeout", str(self.config.timeout)])

        return cmd

    def _parse_json_output(self, output: str) -> List[ScanFinding]:
        """Parse JSON output from httpx."""
        findings = []

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)
                finding = self._json_to_finding(data)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def _json_to_finding(self, data: Dict[str, Any]) -> Optional[ScanFinding]:
        """Convert JSON object to ScanFinding."""
        url = data.get("url", "")
        if not url:
            return None

        # Determine severity based on findings
        severity = ScanSeverity.INFO
        title_parts = []

        status_code = data.get("status_code", 0)
        if status_code:
            title_parts.append(f"[{status_code}]")

        title = data.get("title", "")
        if title:
            title_parts.append(title[:50])

        # Check for interesting findings
        tech = data.get("tech", [])
        server = data.get("webserver", "")

        description_parts = []
        if server:
            description_parts.append(f"Server: {server}")
        if tech:
            description_parts.append(f"Tech: {', '.join(tech[:5])}")

        # Flag potentially interesting findings
        if status_code in (401, 403):
            severity = ScanSeverity.LOW
            description_parts.append("Protected endpoint")
        elif status_code >= 500:
            severity = ScanSeverity.MEDIUM
            description_parts.append("Server error detected")

        return ScanFinding(
            title=" ".join(title_parts) if title_parts else url,
            severity=severity,
            description="; ".join(description_parts),
            url=url,
            host=data.get("host", ""),
            port=data.get("port", 0),
            evidence=json.dumps(data, indent=2)[:500],
            scanner="httpx",
            tags=tech if tech else [],
        )

    def _parse_text_output(self, output: str) -> List[ScanFinding]:
        """Parse text output from httpx."""
        findings = []

        for line in output.strip().split("\n"):
            if not line or line.startswith("["):
                continue

            # Basic parsing: URL [status] [title]
            parts = line.split()
            if parts:
                url = parts[0]
                findings.append(ScanFinding(
                    title=url,
                    severity=ScanSeverity.INFO,
                    description="Live host detected",
                    url=url,
                    scanner="httpx",
                ))

        return findings

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse httpx output."""
        if self.config.json_output:
            return self._parse_json_output(output)
        return self._parse_text_output(output)

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
