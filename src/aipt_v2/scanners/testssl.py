"""
AIPTX TestSSL Scanner
=====================

Scanner for testssl.sh - SSL/TLS testing tool.
https://github.com/drwetter/testssl.sh
"""

import asyncio
import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class TestSSLConfig:
    """Configuration for testssl.sh scanner."""

    # Test options
    protocols: bool = True  # Check protocols (SSLv2, SSLv3, TLS)
    ciphers: bool = True  # Check cipher suites
    vulnerabilities: bool = True  # Check known vulnerabilities
    headers: bool = True  # Check HTTP headers
    certificate: bool = True  # Check certificate

    # Specific vulnerability tests
    heartbleed: bool = True
    ccs_injection: bool = True
    ticketbleed: bool = True
    robot: bool = True
    breach: bool = True
    poodle: bool = True
    beast: bool = True
    freak: bool = True
    logjam: bool = True
    drown: bool = True
    sweet32: bool = True
    lucky13: bool = True

    # Speed options
    fast: bool = False
    parallel: bool = True
    sneaky: bool = False  # Slower but less detectable

    # Output
    json_output: bool = True
    severity_level: str = "LOW"  # Filter: LOW, MEDIUM, HIGH, CRITICAL

    # Timeouts
    connect_timeout: int = 5
    openssl_timeout: int = 5

    # Misc
    quiet: bool = False
    warnings: str = "batch"  # off, batch, on


class TestSSLScanner(BaseScanner):
    """
    Scanner for testssl.sh - comprehensive SSL/TLS security testing.

    Tests:
    - Protocol support (SSLv2, SSLv3, TLS 1.0-1.3)
    - Cipher suite strength
    - Certificate validation
    - Known vulnerabilities (Heartbleed, POODLE, etc.)
    - HTTP security headers

    Example:
        scanner = TestSSLScanner()
        result = await scanner.scan("example.com:443")

        for finding in result.findings:
            if finding.severity in [ScanSeverity.HIGH, ScanSeverity.CRITICAL]:
                print(f"Issue: {finding.title}")
    """

    def __init__(self, config: Optional[TestSSLConfig] = None):
        self.config = config or TestSSLConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if testssl.sh is installed."""
        return shutil.which("testssl.sh") is not None or shutil.which("testssl") is not None

    def _get_binary(self) -> str:
        """Get testssl binary name."""
        if shutil.which("testssl.sh"):
            return "testssl.sh"
        return "testssl"

    async def scan(
        self,
        target: str,
        **kwargs
    ) -> ScanResult:
        """
        Run testssl.sh scan.

        Args:
            target: Host:port or URL to test
            **kwargs: Additional options

        Returns:
            ScanResult with SSL/TLS findings
        """
        result = ScanResult(scanner="testssl", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        # Normalize target
        if not ":" in target and not target.startswith("http"):
            target = f"{target}:443"

        try:
            cmd = self._build_command(target)
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
            logger.error(f"testssl scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str) -> List[str]:
        """Build testssl.sh command."""
        binary = self._get_binary()
        cmd = [binary]

        # Test selection
        if not (self.config.protocols and self.config.ciphers and
                self.config.vulnerabilities and self.config.headers and
                self.config.certificate):
            # Selective testing
            if self.config.protocols:
                cmd.append("-p")
            if self.config.ciphers:
                cmd.append("-E")
            if self.config.vulnerabilities:
                cmd.append("-U")
            if self.config.headers:
                cmd.append("-h")
            if self.config.certificate:
                cmd.append("-S")
        # else: default is to test everything

        # Speed options
        if self.config.fast:
            cmd.append("--fast")

        if self.config.parallel:
            cmd.append("--parallel")

        if self.config.sneaky:
            cmd.append("--sneaky")

        # Output
        if self.config.json_output:
            cmd.append("--jsonfile-pretty")
            cmd.append("-")  # Output to stdout

        if self.config.severity_level:
            cmd.extend(["--severity", self.config.severity_level])

        # Timeouts
        cmd.extend(["--connect-timeout", str(self.config.connect_timeout)])
        cmd.extend(["--openssl-timeout", str(self.config.openssl_timeout)])

        # Misc
        if self.config.quiet:
            cmd.append("--quiet")

        cmd.extend(["--warnings", self.config.warnings])

        # Target
        cmd.append(target)

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse testssl.sh output."""
        findings = []

        # Try JSON parsing first
        try:
            # Find JSON in output
            json_start = output.find("[")
            if json_start != -1:
                json_data = output[json_start:]
                data = json.loads(json_data)

                for item in data:
                    finding = self._json_to_finding(item)
                    if finding:
                        findings.append(finding)

                return findings
        except json.JSONDecodeError:
            pass

        # Fall back to text parsing
        return self._parse_text_output(output)

    def _json_to_finding(self, item: Dict[str, Any]) -> Optional[ScanFinding]:
        """Convert JSON item to finding."""
        finding_id = item.get("id", "")
        finding_value = item.get("finding", "")
        severity_str = item.get("severity", "INFO")

        if not finding_id or not finding_value:
            return None

        # Skip OK findings unless they're informational
        if severity_str == "OK" and "NOT" not in finding_value.upper():
            return None

        # Map severity
        severity_map = {
            "CRITICAL": ScanSeverity.CRITICAL,
            "HIGH": ScanSeverity.HIGH,
            "MEDIUM": ScanSeverity.MEDIUM,
            "LOW": ScanSeverity.LOW,
            "WARN": ScanSeverity.LOW,
            "INFO": ScanSeverity.INFO,
            "OK": ScanSeverity.INFO,
        }
        severity = severity_map.get(severity_str.upper(), ScanSeverity.INFO)

        # Determine tags
        tags = ["ssl", "tls"]
        finding_id_lower = finding_id.lower()

        if "protocol" in finding_id_lower:
            tags.append("protocol")
        elif "cipher" in finding_id_lower:
            tags.append("cipher")
        elif "cert" in finding_id_lower:
            tags.append("certificate")
        elif "vuln" in finding_id_lower or any(v in finding_id_lower for v in
            ["heartbleed", "poodle", "beast", "freak", "logjam", "drown", "robot"]):
            tags.append("vulnerability")

        # CWE mapping for common issues
        cwe = None
        if "heartbleed" in finding_id_lower:
            cwe = "CWE-119"
        elif "poodle" in finding_id_lower or "sslv3" in finding_id_lower:
            cwe = "CWE-327"
        elif "weak" in finding_id_lower or "export" in finding_id_lower:
            cwe = "CWE-326"
        elif "expired" in finding_id_lower or "cert" in finding_id_lower:
            cwe = "CWE-295"

        return ScanFinding(
            title=f"{finding_id}: {finding_value[:60]}",
            severity=severity,
            description=finding_value,
            cwe=cwe,
            scanner="testssl",
            tags=tags,
        )

    def _parse_text_output(self, output: str) -> List[ScanFinding]:
        """Parse text output when JSON fails."""
        findings = []

        # Patterns for common issues
        vuln_patterns = [
            (r"VULNERABLE.*?(heartbleed|poodle|beast|freak|logjam|drown|robot)", ScanSeverity.CRITICAL),
            (r"(SSLv2|SSLv3)\s+offered", ScanSeverity.HIGH),
            (r"TLS 1\.0\s+offered", ScanSeverity.MEDIUM),
            (r"(WEAK|EXPORT)\s+cipher", ScanSeverity.HIGH),
            (r"certificate.*?(expired|invalid|self-signed)", ScanSeverity.HIGH),
            (r"no\s+HSTS", ScanSeverity.LOW),
        ]

        for pattern, severity in vuln_patterns:
            matches = re.finditer(pattern, output, re.IGNORECASE)
            for match in matches:
                line = output[max(0, match.start()-50):match.end()+50]
                findings.append(ScanFinding(
                    title=match.group(0)[:80],
                    severity=severity,
                    description=line.strip(),
                    scanner="testssl",
                    tags=["ssl", "tls"],
                ))

        return findings

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
