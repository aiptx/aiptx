"""
AIPT Nikto Scanner Integration

Web server vulnerability scanning using Nikto.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .base import BaseScanner, ScanFinding, ScanResult, ScanSeverity

logger = logging.getLogger(__name__)


class NiktoScanner(BaseScanner):
    """
    Nikto web server scanner integration.

    Nikto scans for:
    - Dangerous files/programs
    - Outdated server versions
    - Version-specific vulnerabilities
    - Server configuration issues
    - Default files

    Example:
        scanner = NiktoScanner()
        result = await scanner.scan("https://target.com")

        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
    """

    def __init__(
        self,
        timeout: int = 10,
        tuning: str = "",  # Scan tuning: 1-9,a,b,c,x
        plugins: list[str] = None,
        no_ssl: bool = False,
    ):
        super().__init__()
        self.timeout = timeout
        self.tuning = tuning
        self.plugins = plugins or []
        self.no_ssl = no_ssl

    def is_available(self) -> bool:
        """Check if Nikto is installed"""
        return self._check_tool("nikto")

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Nikto scan on target.

        Args:
            target: URL to scan
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="nikto", target=target)
        result.start_time = datetime.utcnow()
        result.status = "running"

        if not self.is_available():
            result.status = "failed"
            result.errors.append("Nikto is not installed")
            return result

        # Build command
        command = self._build_command(target, **kwargs)
        logger.info(f"Running Nikto: {' '.join(command)}")

        # Execute
        exit_code, stdout, stderr = await self._run_command(
            command,
            timeout=kwargs.get("timeout", 1200.0),  # 20 min default
        )

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()
        result.raw_output = stdout

        if exit_code != 0 and "0 error(s)" not in stdout:
            if "OSVDB" in stdout or "vulnerability" in stdout.lower():
                # Nikto found something, not a failure
                result.status = "completed"
            else:
                result.status = "failed"
                result.errors.append(stderr)
        else:
            result.status = "completed"

        # Parse output
        result.findings = self.parse_output(stdout)

        logger.info(
            f"Nikto scan complete: {len(result.findings)} findings in {result.duration_seconds:.1f}s"
        )

        return result

    def parse_output(self, output: str) -> list[ScanFinding]:
        """Parse Nikto output"""
        findings = []

        # Pattern for Nikto findings
        # Format: + OSVDB-XXXX: /path: Description
        # Or: + /path: Description
        finding_pattern = r"\+ (?:OSVDB-(\d+): )?([^:]+): (.+)"

        for line in output.split("\n"):
            line = line.strip()
            if not line.startswith("+"):
                continue

            match = re.match(finding_pattern, line)
            if match:
                osvdb, path, description = match.groups()

                # Determine severity
                severity = self._determine_severity(description, path)

                finding = ScanFinding(
                    title=self._clean_title(description),
                    severity=severity,
                    description=description,
                    url=path,
                    scanner="nikto",
                )

                if osvdb:
                    finding.template = f"OSVDB-{osvdb}"
                    finding.evidence = f"OSVDB-{osvdb}"

                findings.append(finding)

        return findings

    def _determine_severity(self, description: str, path: str) -> ScanSeverity:
        """Determine severity from finding description"""
        desc_lower = description.lower()
        path_lower = path.lower()

        # Critical
        if any(kw in desc_lower for kw in ["rce", "remote code execution", "backdoor", "shell"]):
            return ScanSeverity.CRITICAL

        # High
        if any(kw in desc_lower for kw in [
            "sql injection", "sqli",
            "command injection",
            "file inclusion", "lfi", "rfi",
            "authentication bypass",
            "default password",
            "admin access",
        ]):
            return ScanSeverity.HIGH

        # Medium
        if any(kw in desc_lower for kw in [
            "xss", "cross-site",
            "information disclosure",
            "directory listing",
            "source code",
            "backup file",
            "config file",
            "outdated",
        ]):
            return ScanSeverity.MEDIUM

        # Path-based severity
        if any(p in path_lower for p in [
            "/admin", "/manager", "/phpmyadmin",
            ".bak", ".old", ".sql", ".zip",
            "phpinfo", "test.php",
        ]):
            return ScanSeverity.MEDIUM

        # Low
        if any(kw in desc_lower for kw in [
            "cookie", "header",
            "version", "banner",
            "allowed method",
        ]):
            return ScanSeverity.LOW

        return ScanSeverity.INFO

    def _clean_title(self, description: str) -> str:
        """Create clean title from description"""
        # Truncate long descriptions
        if len(description) > 100:
            return description[:97] + "..."
        return description

    def _build_command(self, target: str, **kwargs) -> list[str]:
        """Build Nikto command"""
        command = ["nikto", "-h", target]

        # Timeout
        command.extend(["-timeout", str(self.timeout)])

        # Output format
        command.extend(["-Format", "txt"])

        # Tuning
        if self.tuning:
            command.extend(["-Tuning", self.tuning])

        # Plugins
        if self.plugins:
            command.extend(["-Plugins", ",".join(self.plugins)])

        # SSL
        if self.no_ssl:
            command.append("-nossl")

        # Disable interactive mode
        command.append("-ask")
        command.append("no")

        return command


# Convenience functions
async def quick_nikto_scan(target: str) -> ScanResult:
    """Quick Nikto scan"""
    scanner = NiktoScanner(timeout=5)
    return await scanner.scan(target, timeout=300.0)


async def full_nikto_scan(target: str) -> ScanResult:
    """Comprehensive Nikto scan"""
    scanner = NiktoScanner(
        timeout=15,
        tuning="123456789abc",  # All checks
    )
    return await scanner.scan(target, timeout=3600.0)
