"""
AIPTX Gobuster Scanner
======================

Scanner for gobuster - directory/DNS brute-forcing tool.
https://github.com/OJ/gobuster
"""

import asyncio
import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class GobusterConfig:
    """Configuration for gobuster scanner."""

    # Mode
    mode: str = "dir"  # dir, dns, vhost, fuzz, s3, gcs, tftp

    # Wordlist
    wordlist: Optional[str] = None

    # Request options
    threads: int = 10
    timeout: str = "10s"
    delay: str = ""  # Delay between requests

    # HTTP options (for dir/vhost mode)
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    user_agent: str = ""
    proxy: Optional[str] = None
    follow_redirect: bool = False
    insecure_ssl: bool = False

    # Filtering
    status_codes: str = "200,204,301,302,307,401,403,405"
    exclude_status: str = ""
    exclude_length: Optional[int] = None

    # Extensions (for dir mode)
    extensions: str = ""  # e.g., "php,html,txt"
    add_slash: bool = False

    # DNS options (for dns mode)
    resolver: Optional[str] = None
    show_ips: bool = True
    show_cname: bool = True
    wildcard: bool = False

    # Output
    output_file: Optional[str] = None
    quiet: bool = False
    no_progress: bool = True
    no_color: bool = True


class GobusterScanner(BaseScanner):
    """
    Scanner for gobuster - directory/DNS brute-forcing.

    Modes:
    - dir: Directory/file brute-forcing
    - dns: DNS subdomain brute-forcing
    - vhost: Virtual host brute-forcing
    - fuzz: Fuzzing mode
    - s3: S3 bucket enumeration
    - gcs: GCS bucket enumeration

    Example:
        scanner = GobusterScanner()

        # Directory brute-force
        result = await scanner.scan("https://example.com", mode="dir")

        # DNS subdomain enumeration
        result = await scanner.scan("example.com", mode="dns")

        # Virtual host discovery
        result = await scanner.scan("https://example.com", mode="vhost")
    """

    # Default wordlist locations
    DEFAULT_WORDLISTS = {
        "dir": [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            str(Path.home() / ".aiptx/data/wordlists/common.txt"),
        ],
        "dns": [
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/namelist.txt",
            str(Path.home() / ".aiptx/data/wordlists/subdomains.txt"),
        ],
        "vhost": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            str(Path.home() / ".aiptx/data/wordlists/vhosts.txt"),
        ],
    }

    def __init__(self, config: Optional[GobusterConfig] = None):
        self.config = config or GobusterConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if gobuster is installed."""
        return shutil.which("gobuster") is not None

    def _get_wordlist(self, mode: str) -> Optional[str]:
        """Get wordlist path for mode."""
        if self.config.wordlist and Path(self.config.wordlist).exists():
            return self.config.wordlist

        for wl in self.DEFAULT_WORDLISTS.get(mode, []):
            if Path(wl).exists():
                return wl

        return None

    async def scan(
        self,
        target: str,
        mode: Optional[str] = None,
        wordlist: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run gobuster scan.

        Args:
            target: URL or domain to scan
            mode: Override mode (dir, dns, vhost, fuzz)
            wordlist: Override wordlist path
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="gobuster", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        actual_mode = mode or self.config.mode
        wl = wordlist or self._get_wordlist(actual_mode)

        if not wl:
            result.status = "failed"
            result.errors.append(f"No wordlist found for mode '{actual_mode}'")
            return result

        try:
            cmd = self._build_command(target, actual_mode, wl)
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
            result.findings = self.parse_output(result.raw_output, actual_mode)
            result.status = "completed"

        except asyncio.TimeoutError:
            result.status = "failed"
            result.errors.append("Scan timed out")
        except Exception as e:
            result.status = "failed"
            result.errors.append(str(e))
            logger.error(f"gobuster scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, mode: str, wordlist: str) -> List[str]:
        """Build gobuster command."""
        cmd = ["gobuster", mode]

        # Target
        if mode == "dir":
            cmd.extend(["-u", target])
        elif mode == "dns":
            cmd.extend(["-d", target])
        elif mode == "vhost":
            cmd.extend(["-u", target])
        else:
            cmd.extend(["-u", target])

        # Wordlist
        cmd.extend(["-w", wordlist])

        # Threads
        cmd.extend(["-t", str(self.config.threads)])

        # Timeout
        if self.config.timeout:
            cmd.extend(["--timeout", self.config.timeout])

        # Delay
        if self.config.delay:
            cmd.extend(["--delay", self.config.delay])

        # Mode-specific options
        if mode in ["dir", "vhost", "fuzz"]:
            self._add_http_options(cmd)

        if mode == "dir":
            self._add_dir_options(cmd)

        if mode == "dns":
            self._add_dns_options(cmd)

        # Output options
        if self.config.output_file:
            cmd.extend(["-o", self.config.output_file])

        if self.config.quiet:
            cmd.append("-q")

        if self.config.no_progress:
            cmd.append("--no-progress")

        if self.config.no_color:
            cmd.append("--no-color")

        return cmd

    def _add_http_options(self, cmd: List[str]) -> None:
        """Add HTTP-specific options."""
        if self.config.method != "GET":
            cmd.extend(["-m", self.config.method])

        for key, value in self.config.headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        if self.config.cookies:
            cmd.extend(["-c", self.config.cookies])

        if self.config.user_agent:
            cmd.extend(["-a", self.config.user_agent])

        if self.config.proxy:
            cmd.extend(["--proxy", self.config.proxy])

        if self.config.follow_redirect:
            cmd.append("-r")

        if self.config.insecure_ssl:
            cmd.append("-k")

        # Status codes
        if self.config.status_codes:
            cmd.extend(["-s", self.config.status_codes])

        if self.config.exclude_status:
            cmd.extend(["-b", self.config.exclude_status])

        if self.config.exclude_length is not None:
            cmd.extend(["--exclude-length", str(self.config.exclude_length)])

    def _add_dir_options(self, cmd: List[str]) -> None:
        """Add directory mode options."""
        if self.config.extensions:
            cmd.extend(["-x", self.config.extensions])

        if self.config.add_slash:
            cmd.append("-f")

    def _add_dns_options(self, cmd: List[str]) -> None:
        """Add DNS mode options."""
        if self.config.resolver:
            cmd.extend(["-r", self.config.resolver])

        if self.config.show_ips:
            cmd.append("-i")

        if self.config.show_cname:
            cmd.append("--show-cname")

        if self.config.wildcard:
            cmd.append("--wildcard")

    def parse_output(self, output: str, mode: str) -> List[ScanFinding]:
        """Parse gobuster output."""
        findings = []

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("=") or "Starting" in line or "Finished" in line:
                continue

            if mode == "dir":
                finding = self._parse_dir_line(line)
            elif mode == "dns":
                finding = self._parse_dns_line(line)
            elif mode == "vhost":
                finding = self._parse_vhost_line(line)
            else:
                finding = self._parse_generic_line(line)

            if finding:
                findings.append(finding)

        return findings

    def _parse_dir_line(self, line: str) -> Optional[ScanFinding]:
        """Parse directory mode output line."""
        # Format: /path (Status: 200) [Size: 1234]
        match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)

        if match:
            path = match.group(1)
            status = int(match.group(2))
            size = match.group(3)

            # Determine severity
            severity = ScanSeverity.INFO
            tags = ["directory"]

            if status == 200:
                severity = ScanSeverity.LOW
                tags.append("found")
            elif status in (301, 302, 307):
                tags.append("redirect")
            elif status == 401:
                severity = ScanSeverity.LOW
                tags.append("auth_required")
            elif status == 403:
                severity = ScanSeverity.LOW
                tags.append("forbidden")

            # Check for interesting paths
            path_lower = path.lower()
            if any(p in path_lower for p in ["admin", "backup", "config", "api", "secret", "debug"]):
                severity = ScanSeverity.MEDIUM
                tags.append("interesting")

            return ScanFinding(
                title=f"[{status}] {path}",
                severity=severity,
                description=f"Size: {size}" if size else f"Status: {status}",
                url=path,
                scanner="gobuster",
                tags=tags,
            )

        return None

    def _parse_dns_line(self, line: str) -> Optional[ScanFinding]:
        """Parse DNS mode output line."""
        # Format: subdomain.example.com [A: 1.2.3.4]
        # Or: Found: subdomain.example.com

        if "Found:" in line:
            subdomain = line.replace("Found:", "").strip()
            return ScanFinding(
                title=f"Subdomain: {subdomain}",
                severity=ScanSeverity.INFO,
                description=f"Subdomain discovered: {subdomain}",
                host=subdomain,
                scanner="gobuster",
                tags=["subdomain", "dns"],
            )

        match = re.match(r"(\S+)\s+\[([^\]]+)\]", line)
        if match:
            subdomain = match.group(1)
            records = match.group(2)

            return ScanFinding(
                title=f"Subdomain: {subdomain}",
                severity=ScanSeverity.INFO,
                description=f"Records: {records}",
                host=subdomain,
                scanner="gobuster",
                tags=["subdomain", "dns"],
            )

        return None

    def _parse_vhost_line(self, line: str) -> Optional[ScanFinding]:
        """Parse vhost mode output line."""
        # Format: Found: vhost.example.com (Status: 200) [Size: 1234]
        match = re.match(r"Found:\s*(\S+)\s+\(Status:\s*(\d+)\)", line)

        if match:
            vhost = match.group(1)
            status = int(match.group(2))

            return ScanFinding(
                title=f"Virtual Host: {vhost}",
                severity=ScanSeverity.LOW,
                description=f"Virtual host found with status {status}",
                host=vhost,
                scanner="gobuster",
                tags=["vhost", "virtual_host"],
            )

        return None

    def _parse_generic_line(self, line: str) -> Optional[ScanFinding]:
        """Parse generic output line."""
        if "Found" in line or ":" in line:
            return ScanFinding(
                title=line[:80],
                severity=ScanSeverity.INFO,
                description=line,
                scanner="gobuster",
            )
        return None

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
