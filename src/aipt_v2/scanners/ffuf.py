"""
AIPTX FFUF Scanner
==================

Scanner for ffuf - fast web fuzzer.
https://github.com/ffuf/ffuf
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class FfufConfig:
    """Configuration for ffuf scanner."""

    # Wordlist
    wordlist: Optional[str] = None  # Will use default if None

    # Request options
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    data: str = ""

    # Matching
    match_codes: List[int] = field(default_factory=lambda: [200, 204, 301, 302, 307, 401, 403, 405])
    match_size: Optional[int] = None
    match_words: Optional[int] = None
    match_lines: Optional[int] = None
    match_regex: Optional[str] = None

    # Filtering (exclude)
    filter_codes: List[int] = field(default_factory=list)
    filter_size: Optional[int] = None
    filter_words: Optional[int] = None
    filter_lines: Optional[int] = None
    filter_regex: Optional[str] = None

    # Output
    json_output: bool = True
    output_file: Optional[str] = None

    # Rate limiting
    threads: int = 40
    rate: int = 0  # 0 = unlimited
    timeout: int = 10

    # Recursion
    recursion: bool = False
    recursion_depth: int = 2

    # Extensions
    extensions: List[str] = field(default_factory=list)

    # Auto-calibration
    auto_calibrate: bool = True


class FfufScanner(BaseScanner):
    """
    Scanner for ffuf - web fuzzer.

    Discovers:
    - Hidden directories and files
    - API endpoints
    - Backup files
    - Parameter values

    Example:
        scanner = FfufScanner()
        result = await scanner.scan("https://example.com/FUZZ")
    """

    # Default wordlist locations
    DEFAULT_WORDLISTS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        str(Path.home() / ".aiptx/data/wordlists/common.txt"),
    ]

    def __init__(self, config: Optional[FfufConfig] = None):
        self.config = config or FfufConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if ffuf is installed."""
        return shutil.which("ffuf") is not None

    def _get_wordlist(self) -> Optional[str]:
        """Get wordlist path."""
        if self.config.wordlist and Path(self.config.wordlist).exists():
            return self.config.wordlist

        for wl in self.DEFAULT_WORDLISTS:
            if Path(wl).exists():
                return wl

        return None

    async def scan(
        self,
        target: str,
        wordlist: Optional[str] = None,
        fuzz_keyword: str = "FUZZ",
        **kwargs
    ) -> ScanResult:
        """
        Run ffuf scan.

        Args:
            target: URL with FUZZ keyword (e.g., https://example.com/FUZZ)
            wordlist: Optional wordlist path
            fuzz_keyword: Keyword to replace (default: FUZZ)
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="ffuf", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        # Add FUZZ keyword if not present
        if fuzz_keyword not in target:
            target = target.rstrip("/") + "/" + fuzz_keyword

        # Get wordlist
        wl = wordlist or self._get_wordlist()
        if not wl:
            result.status = "failed"
            result.errors.append("No wordlist found")
            return result

        try:
            cmd = self._build_command(target, wl, fuzz_keyword)
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
            logger.error(f"ffuf scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, wordlist: str, fuzz_keyword: str) -> List[str]:
        """Build ffuf command."""
        cmd = ["ffuf", "-u", target, "-w", wordlist]

        # Method
        if self.config.method != "GET":
            cmd.extend(["-X", self.config.method])

        # Headers
        for key, value in self.config.headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        # Cookies
        if self.config.cookies:
            cmd.extend(["-b", self.config.cookies])

        # Data
        if self.config.data:
            cmd.extend(["-d", self.config.data])

        # Matching
        if self.config.match_codes:
            cmd.extend(["-mc", ",".join(str(c) for c in self.config.match_codes)])
        if self.config.match_size is not None:
            cmd.extend(["-ms", str(self.config.match_size)])
        if self.config.match_words is not None:
            cmd.extend(["-mw", str(self.config.match_words)])
        if self.config.match_lines is not None:
            cmd.extend(["-ml", str(self.config.match_lines)])
        if self.config.match_regex:
            cmd.extend(["-mr", self.config.match_regex])

        # Filtering
        if self.config.filter_codes:
            cmd.extend(["-fc", ",".join(str(c) for c in self.config.filter_codes)])
        if self.config.filter_size is not None:
            cmd.extend(["-fs", str(self.config.filter_size)])
        if self.config.filter_words is not None:
            cmd.extend(["-fw", str(self.config.filter_words)])
        if self.config.filter_lines is not None:
            cmd.extend(["-fl", str(self.config.filter_lines)])
        if self.config.filter_regex:
            cmd.extend(["-fr", self.config.filter_regex])

        # Output
        if self.config.json_output:
            cmd.extend(["-of", "json"])
        if self.config.output_file:
            cmd.extend(["-o", self.config.output_file])

        # Rate limiting
        cmd.extend(["-t", str(self.config.threads)])
        if self.config.rate > 0:
            cmd.extend(["-rate", str(self.config.rate)])
        cmd.extend(["-timeout", str(self.config.timeout)])

        # Recursion
        if self.config.recursion:
            cmd.append("-recursion")
            cmd.extend(["-recursion-depth", str(self.config.recursion_depth)])

        # Extensions
        if self.config.extensions:
            cmd.extend(["-e", ",".join(self.config.extensions)])

        # Auto-calibration
        if self.config.auto_calibrate:
            cmd.append("-ac")

        cmd.append("-s")  # Silent mode

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse ffuf output."""
        findings = []

        # Try to parse as JSON
        try:
            data = json.loads(output)
            results = data.get("results", [])

            for item in results:
                finding = self._result_to_finding(item)
                if finding:
                    findings.append(finding)

        except json.JSONDecodeError:
            # Parse line by line
            for line in output.strip().split("\n"):
                finding = self._line_to_finding(line)
                if finding:
                    findings.append(finding)

        return findings

    def _result_to_finding(self, item: Dict[str, Any]) -> Optional[ScanFinding]:
        """Convert ffuf result to finding."""
        url = item.get("url", "")
        if not url:
            return None

        status = item.get("status", 0)
        length = item.get("length", 0)
        words = item.get("words", 0)
        lines = item.get("lines", 0)
        input_val = item.get("input", {}).get("FUZZ", "")

        # Determine severity
        severity = ScanSeverity.INFO
        tags = []

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
        input_lower = input_val.lower()
        if any(p in input_lower for p in ["admin", "backup", "config", "secret", "api"]):
            severity = ScanSeverity.MEDIUM
            tags.append("interesting")

        return ScanFinding(
            title=f"[{status}] {input_val}",
            severity=severity,
            description=f"Size: {length} | Words: {words} | Lines: {lines}",
            url=url,
            evidence=f"Status: {status}, Size: {length}, Words: {words}",
            scanner="ffuf",
            tags=tags,
        )

    def _line_to_finding(self, line: str) -> Optional[ScanFinding]:
        """Parse text line to finding."""
        # Format: URL [Status: XXX, Size: XXX, Words: XXX, Lines: XXX]
        if not line or "[Status:" not in line:
            return None

        parts = line.split("[Status:")
        if len(parts) < 2:
            return None

        url = parts[0].strip()

        return ScanFinding(
            title=url,
            severity=ScanSeverity.INFO,
            description=parts[1].rstrip("]"),
            url=url,
            scanner="ffuf",
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
