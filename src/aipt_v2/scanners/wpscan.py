"""
AIPTX WPScan Scanner
====================

Scanner for wpscan - WordPress security scanner.
https://github.com/wpscanteam/wpscan
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
class WPScanConfig:
    """Configuration for wpscan scanner."""

    # Enumeration options
    enumerate_plugins: bool = True  # vp = vulnerable plugins
    enumerate_themes: bool = True   # vt = vulnerable themes
    enumerate_users: bool = True    # u = users
    enumerate_config_backups: bool = True  # cb = config backups
    enumerate_db_exports: bool = True  # dbe = database exports
    enumerate_all_plugins: bool = False  # ap = all plugins
    enumerate_all_themes: bool = False  # at = all themes

    # Detection mode
    detection_mode: str = "mixed"  # passive, aggressive, mixed

    # API token for vulnerability data
    api_token: Optional[str] = None

    # Request options
    user_agent: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    proxy: Optional[str] = None

    # Rate limiting
    throttle: int = 0  # Milliseconds between requests
    request_timeout: int = 60

    # Output
    format: str = "json"

    # Stealth
    random_user_agent: bool = False
    stealthy: bool = False


class WPScanScanner(BaseScanner):
    """
    Scanner for wpscan - WordPress vulnerability scanner.

    Detects:
    - WordPress version vulnerabilities
    - Vulnerable plugins and themes
    - User enumeration
    - Configuration issues
    - Security misconfigurations

    Example:
        scanner = WPScanScanner()
        result = await scanner.scan("https://wordpress-site.com")

        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
    """

    def __init__(self, config: Optional[WPScanConfig] = None):
        self.config = config or WPScanConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if wpscan is installed."""
        return shutil.which("wpscan") is not None

    async def scan(
        self,
        target: str,
        **kwargs
    ) -> ScanResult:
        """
        Run wpscan against target.

        Args:
            target: WordPress site URL
            **kwargs: Additional options

        Returns:
            ScanResult with vulnerability findings
        """
        result = ScanResult(scanner="wpscan", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

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
            logger.error(f"wpscan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str) -> List[str]:
        """Build wpscan command."""
        cmd = ["wpscan", "--url", target]

        # Enumeration
        enumerate_flags = []
        if self.config.enumerate_plugins:
            enumerate_flags.append("vp")
        if self.config.enumerate_themes:
            enumerate_flags.append("vt")
        if self.config.enumerate_users:
            enumerate_flags.append("u")
        if self.config.enumerate_config_backups:
            enumerate_flags.append("cb")
        if self.config.enumerate_db_exports:
            enumerate_flags.append("dbe")
        if self.config.enumerate_all_plugins:
            enumerate_flags.append("ap")
        if self.config.enumerate_all_themes:
            enumerate_flags.append("at")

        if enumerate_flags:
            cmd.extend(["--enumerate", ",".join(enumerate_flags)])

        # Detection mode
        cmd.extend(["--detection-mode", self.config.detection_mode])

        # API token
        if self.config.api_token:
            cmd.extend(["--api-token", self.config.api_token])

        # Request options
        if self.config.user_agent:
            cmd.extend(["--user-agent", self.config.user_agent])

        for key, value in self.config.headers.items():
            cmd.extend(["--headers", f"{key}: {value}"])

        if self.config.cookies:
            cmd.extend(["--cookie", self.config.cookies])

        if self.config.proxy:
            cmd.extend(["--proxy", self.config.proxy])

        # Rate limiting
        if self.config.throttle > 0:
            cmd.extend(["--throttle", str(self.config.throttle)])

        cmd.extend(["--request-timeout", str(self.config.request_timeout)])

        # Output format
        cmd.extend(["--format", self.config.format])

        # Stealth options
        if self.config.random_user_agent:
            cmd.append("--random-user-agent")
        if self.config.stealthy:
            cmd.append("--stealthy")

        # No banner
        cmd.append("--no-banner")

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse wpscan JSON output."""
        findings = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # Try to extract findings from text output
            return self._parse_text_output(output)

        # WordPress version
        if "version" in data:
            version_info = data["version"]
            if version_info.get("vulnerabilities"):
                for vuln in version_info["vulnerabilities"]:
                    findings.append(self._vuln_to_finding(vuln, "WordPress Core"))

            # Version info finding
            if version_info.get("number"):
                findings.append(ScanFinding(
                    title=f"WordPress Version: {version_info['number']}",
                    severity=ScanSeverity.INFO,
                    description=f"WordPress {version_info['number']} detected",
                    scanner="wpscan",
                    tags=["wordpress", "version"],
                ))

        # Main theme
        if "main_theme" in data and data["main_theme"]:
            theme = data["main_theme"]
            if theme.get("vulnerabilities"):
                for vuln in theme["vulnerabilities"]:
                    findings.append(self._vuln_to_finding(vuln, f"Theme: {theme.get('slug', 'unknown')}"))

        # Plugins
        if "plugins" in data:
            for plugin_name, plugin_data in data["plugins"].items():
                if plugin_data.get("vulnerabilities"):
                    for vuln in plugin_data["vulnerabilities"]:
                        findings.append(self._vuln_to_finding(vuln, f"Plugin: {plugin_name}"))

                # Outdated plugin
                if plugin_data.get("outdated"):
                    findings.append(ScanFinding(
                        title=f"Outdated Plugin: {plugin_name}",
                        severity=ScanSeverity.LOW,
                        description=f"Plugin {plugin_name} version {plugin_data.get('version', 'unknown')} is outdated",
                        scanner="wpscan",
                        tags=["wordpress", "plugin", "outdated"],
                    ))

        # Users
        if "users" in data:
            for username, user_data in data["users"].items():
                findings.append(ScanFinding(
                    title=f"User Enumerated: {username}",
                    severity=ScanSeverity.LOW,
                    description=f"WordPress user '{username}' discovered (ID: {user_data.get('id', 'unknown')})",
                    scanner="wpscan",
                    tags=["wordpress", "user", "enumeration"],
                ))

        # Config backups
        if "config_backups" in data:
            for backup in data["config_backups"]:
                findings.append(ScanFinding(
                    title="Config Backup Found",
                    severity=ScanSeverity.HIGH,
                    description=f"Configuration backup file found: {backup}",
                    url=backup,
                    scanner="wpscan",
                    tags=["wordpress", "config", "backup", "sensitive"],
                ))

        # DB exports
        if "db_exports" in data:
            for export in data["db_exports"]:
                findings.append(ScanFinding(
                    title="Database Export Found",
                    severity=ScanSeverity.CRITICAL,
                    description=f"Database export file found: {export}",
                    url=export,
                    scanner="wpscan",
                    tags=["wordpress", "database", "export", "sensitive"],
                ))

        # Interesting findings
        if "interesting_findings" in data:
            for item in data["interesting_findings"]:
                severity = ScanSeverity.INFO
                if "readme" in item.get("url", "").lower():
                    severity = ScanSeverity.LOW
                elif "debug" in item.get("url", "").lower():
                    severity = ScanSeverity.MEDIUM

                findings.append(ScanFinding(
                    title=item.get("to_s", "Interesting Finding"),
                    severity=severity,
                    description=item.get("to_s", ""),
                    url=item.get("url", ""),
                    scanner="wpscan",
                    tags=["wordpress", "interesting"],
                ))

        return findings

    def _vuln_to_finding(self, vuln: Dict[str, Any], component: str) -> ScanFinding:
        """Convert vulnerability data to finding."""
        title = vuln.get("title", "Unknown Vulnerability")

        # Determine severity from vuln type
        severity = ScanSeverity.MEDIUM
        vuln_type = vuln.get("vuln_type", "").lower()
        title_lower = title.lower()

        if any(x in title_lower for x in ["rce", "remote code", "sql injection", "sqli"]):
            severity = ScanSeverity.CRITICAL
        elif any(x in title_lower for x in ["xss", "csrf", "auth bypass", "privilege"]):
            severity = ScanSeverity.HIGH
        elif any(x in title_lower for x in ["disclosure", "path traversal", "lfi"]):
            severity = ScanSeverity.HIGH

        # Extract CVE if present
        cve = None
        refs = vuln.get("references", {})
        if "cve" in refs:
            cve_list = refs["cve"]
            if cve_list:
                cve = f"CVE-{cve_list[0]}" if not str(cve_list[0]).startswith("CVE") else cve_list[0]

        return ScanFinding(
            title=f"{component}: {title[:80]}",
            severity=severity,
            description=title,
            cwe=vuln.get("cwe", ""),
            scanner="wpscan",
            tags=["wordpress", "vulnerability", vuln_type] if vuln_type else ["wordpress", "vulnerability"],
        )

    def _parse_text_output(self, output: str) -> List[ScanFinding]:
        """Parse text output when JSON fails."""
        findings = []

        # Look for vulnerability indicators
        if "[!]" in output:
            for line in output.split("\n"):
                if "[!]" in line:
                    findings.append(ScanFinding(
                        title=line.replace("[!]", "").strip()[:100],
                        severity=ScanSeverity.MEDIUM,
                        description=line.strip(),
                        scanner="wpscan",
                        tags=["wordpress"],
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
