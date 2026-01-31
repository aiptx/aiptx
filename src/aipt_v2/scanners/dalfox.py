"""
AIPTX Dalfox Scanner
====================

Scanner for dalfox - XSS scanner.
https://github.com/hahwul/dalfox
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class DalfoxConfig:
    """Configuration for dalfox scanner."""

    # Scan mode
    mining: bool = True  # DOM mining
    deep_domxss: bool = False
    grep: bool = True  # Grep patterns

    # Output
    json_output: bool = True
    output_all: bool = False  # Include all results, not just vulnerabilities

    # Request options
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    data: str = ""
    user_agent: str = ""

    # Rate limiting
    worker: int = 100
    delay: int = 0
    timeout: int = 10

    # WAF bypass
    waf_evasion: bool = False
    blind_url: Optional[str] = None  # For blind XSS

    # Custom payloads
    custom_payload: Optional[str] = None
    custom_payload_file: Optional[str] = None

    # Filtering
    skip_mining: bool = False
    skip_bav: bool = False  # Skip BAV analysis


class DalfoxScanner(BaseScanner):
    """
    Scanner for dalfox - XSS vulnerability scanner.

    Detects:
    - Reflected XSS
    - Stored XSS
    - DOM-based XSS
    - Blind XSS

    Example:
        scanner = DalfoxScanner()
        result = await scanner.scan("https://example.com/search?q=test")
    """

    def __init__(self, config: Optional[DalfoxConfig] = None):
        self.config = config or DalfoxConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if dalfox is installed."""
        return shutil.which("dalfox") is not None

    async def scan(
        self,
        target: str,
        targets_file: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run dalfox scan.

        Args:
            target: URL with parameters to test
            targets_file: Optional file with URLs
            **kwargs: Additional options

        Returns:
            ScanResult with XSS findings
        """
        result = ScanResult(scanner="dalfox", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        try:
            cmd = self._build_command(target, targets_file)
            logger.debug(f"Running: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = process

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=kwargs.get("timeout", 600)
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
            logger.error(f"dalfox scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, targets_file: Optional[str] = None) -> List[str]:
        """Build dalfox command."""
        if targets_file:
            cmd = ["dalfox", "file", targets_file]
        else:
            cmd = ["dalfox", "url", target]

        # Scan options
        if self.config.mining:
            cmd.append("--mining-dom")
        if self.config.deep_domxss:
            cmd.append("--deep-domxss")
        if self.config.grep:
            cmd.append("--grep")

        # Output
        if self.config.json_output:
            cmd.append("--format=json")
        if self.config.output_all:
            cmd.append("--output-all")

        # Request options
        if self.config.method != "GET":
            cmd.extend(["--method", self.config.method])

        for key, value in self.config.headers.items():
            cmd.extend(["--header", f"{key}: {value}"])

        if self.config.cookies:
            cmd.extend(["--cookie", self.config.cookies])

        if self.config.data:
            cmd.extend(["--data", self.config.data])

        if self.config.user_agent:
            cmd.extend(["--user-agent", self.config.user_agent])

        # Rate limiting
        cmd.extend(["--worker", str(self.config.worker)])
        if self.config.delay > 0:
            cmd.extend(["--delay", str(self.config.delay)])
        cmd.extend(["--timeout", str(self.config.timeout)])

        # WAF bypass
        if self.config.waf_evasion:
            cmd.append("--waf-evasion")

        if self.config.blind_url:
            cmd.extend(["--blind", self.config.blind_url])

        # Custom payloads
        if self.config.custom_payload:
            cmd.extend(["--custom-payload", self.config.custom_payload])
        if self.config.custom_payload_file:
            cmd.extend(["--custom-payload-file", self.config.custom_payload_file])

        # Filtering
        if self.config.skip_mining:
            cmd.append("--skip-mining")
        if self.config.skip_bav:
            cmd.append("--skip-bav")

        cmd.append("--silence")

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse dalfox output."""
        findings = []

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                # Try JSON parsing
                if line.startswith("{"):
                    data = json.loads(line)
                    finding = self._json_to_finding(data)
                    if finding:
                        findings.append(finding)
                else:
                    # Parse text output
                    finding = self._text_to_finding(line)
                    if finding:
                        findings.append(finding)

            except json.JSONDecodeError:
                finding = self._text_to_finding(line)
                if finding:
                    findings.append(finding)

        return findings

    def _json_to_finding(self, data: Dict[str, Any]) -> Optional[ScanFinding]:
        """Convert JSON to finding."""
        vuln_type = data.get("type", "")
        if not vuln_type:
            return None

        url = data.get("data", "")
        param = data.get("param", "")
        payload = data.get("payload", "")
        poc = data.get("poc", "")

        # Determine severity
        severity = ScanSeverity.HIGH
        if "dom" in vuln_type.lower():
            severity = ScanSeverity.HIGH
        elif "reflected" in vuln_type.lower():
            severity = ScanSeverity.HIGH
        elif "stored" in vuln_type.lower():
            severity = ScanSeverity.CRITICAL

        tags = ["xss"]
        if "dom" in vuln_type.lower():
            tags.append("dom")
        if "reflected" in vuln_type.lower():
            tags.append("reflected")
        if "stored" in vuln_type.lower():
            tags.append("stored")

        return ScanFinding(
            title=f"XSS: {vuln_type}",
            severity=severity,
            description=f"Parameter: {param}" if param else vuln_type,
            url=url if url else poc,
            evidence=f"Payload: {payload[:200]}" if payload else "",
            cwe="CWE-79",
            scanner="dalfox",
            tags=tags,
        )

    def _text_to_finding(self, line: str) -> Optional[ScanFinding]:
        """Parse text line to finding."""
        # Look for vulnerability indicators
        line_lower = line.lower()

        if "[vuln]" in line_lower or "[poc]" in line_lower:
            severity = ScanSeverity.HIGH
        elif "[weak]" in line_lower:
            severity = ScanSeverity.MEDIUM
        elif "[info]" in line_lower:
            severity = ScanSeverity.LOW
        else:
            return None

        # Extract URL if present
        url = ""
        if "http" in line:
            parts = line.split()
            for part in parts:
                if part.startswith("http"):
                    url = part
                    break

        return ScanFinding(
            title="XSS Vulnerability",
            severity=severity,
            description=line[:200],
            url=url,
            cwe="CWE-79",
            scanner="dalfox",
            tags=["xss"],
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
