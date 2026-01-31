"""
AIPTX Katana Scanner
====================

Scanner for katana - fast web crawler.
https://github.com/projectdiscovery/katana
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class KatanaConfig:
    """Configuration for katana scanner."""

    # Crawling options
    depth: int = 3
    js_crawl: bool = True
    headless: bool = False  # Use headless browser
    automatic_form_fill: bool = False

    # Scope
    crawl_scope: str = "sdn"  # sdn (same domain), rdn (root domain), fqdn, dn
    crawl_out_scope: List[str] = field(default_factory=list)

    # Output options
    json_output: bool = True
    store_response: bool = False
    store_response_dir: Optional[str] = None

    # Rate limiting
    concurrency: int = 10
    parallelism: int = 10
    delay: int = 0
    rate_limit: int = 150
    timeout: int = 10

    # Filtering
    extension_filter: List[str] = field(default_factory=lambda: [
        "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot"
    ])
    match_regex: Optional[str] = None
    filter_regex: Optional[str] = None

    # Headers
    custom_headers: Dict[str, str] = field(default_factory=dict)


class KatanaScanner(BaseScanner):
    """
    Scanner for katana - web crawler.

    Discovers:
    - Endpoints and URLs
    - JavaScript files and endpoints
    - Forms and parameters
    - API endpoints
    - File paths

    Example:
        scanner = KatanaScanner()
        result = await scanner.scan("https://example.com")

        for finding in result.findings:
            print(f"Endpoint: {finding.url}")
    """

    def __init__(self, config: Optional[KatanaConfig] = None):
        self.config = config or KatanaConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if katana is installed."""
        return shutil.which("katana") is not None

    async def scan(
        self,
        target: str,
        targets_file: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run katana crawl.

        Args:
            target: URL to crawl
            targets_file: Optional file with URLs
            **kwargs: Additional options

        Returns:
            ScanResult with discovered endpoints
        """
        result = ScanResult(scanner="katana", target=target)
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
            result.errors.append("Crawl timed out")
        except Exception as e:
            result.status = "failed"
            result.errors.append(str(e))
            logger.error(f"katana crawl failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, targets_file: Optional[str] = None) -> List[str]:
        """Build katana command."""
        cmd = ["katana"]

        # Input
        if targets_file:
            cmd.extend(["-list", targets_file])
        else:
            cmd.extend(["-u", target])

        # Crawling options
        cmd.extend(["-d", str(self.config.depth)])

        if self.config.js_crawl:
            cmd.append("-jc")

        if self.config.headless:
            cmd.append("-headless")

        if self.config.automatic_form_fill:
            cmd.append("-aff")

        # Scope
        cmd.extend(["-cs", self.config.crawl_scope])

        for out_scope in self.config.crawl_out_scope:
            cmd.extend(["-cos", out_scope])

        # Output
        if self.config.json_output:
            cmd.append("-jsonl")

        if self.config.store_response and self.config.store_response_dir:
            cmd.extend(["-sr", "-srd", self.config.store_response_dir])

        # Rate limiting
        cmd.extend(["-c", str(self.config.concurrency)])
        cmd.extend(["-p", str(self.config.parallelism)])

        if self.config.delay > 0:
            cmd.extend(["-delay", str(self.config.delay)])

        cmd.extend(["-rl", str(self.config.rate_limit)])
        cmd.extend(["-timeout", str(self.config.timeout)])

        # Filtering
        if self.config.extension_filter:
            cmd.extend(["-ef", ",".join(self.config.extension_filter)])

        if self.config.match_regex:
            cmd.extend(["-mr", self.config.match_regex])

        if self.config.filter_regex:
            cmd.extend(["-fr", self.config.filter_regex])

        # Headers
        for key, value in self.config.custom_headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        cmd.append("-silent")

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse katana output."""
        findings = []
        seen_urls = set()

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                if self.config.json_output:
                    data = json.loads(line)
                    finding = self._json_to_finding(data)
                else:
                    finding = self._url_to_finding(line.strip())

                if finding and finding.url not in seen_urls:
                    findings.append(finding)
                    seen_urls.add(finding.url)

            except json.JSONDecodeError:
                # Try as plain URL
                url = line.strip()
                if url and url not in seen_urls:
                    finding = self._url_to_finding(url)
                    if finding:
                        findings.append(finding)
                        seen_urls.add(url)

        return findings

    def _json_to_finding(self, data: Dict[str, Any]) -> Optional[ScanFinding]:
        """Convert JSON to ScanFinding."""
        url = data.get("request", {}).get("endpoint", "") or data.get("endpoint", "")
        if not url:
            return None

        # Classify endpoint
        severity = ScanSeverity.INFO
        tags = []
        description_parts = []

        source = data.get("source", "")
        if source:
            tags.append(source)

        # Analyze URL for interesting patterns
        url_lower = url.lower()
        parsed = urlparse(url)
        path = parsed.path.lower()

        # API endpoints
        if "/api/" in path or "/v1/" in path or "/v2/" in path or "/graphql" in path:
            tags.append("api")
            severity = ScanSeverity.LOW
            description_parts.append("API endpoint")

        # Admin/config paths
        if any(p in path for p in ["/admin", "/config", "/settings", "/dashboard"]):
            tags.append("admin")
            severity = ScanSeverity.LOW
            description_parts.append("Administrative endpoint")

        # Authentication
        if any(p in path for p in ["/login", "/auth", "/oauth", "/signin", "/signup"]):
            tags.append("auth")
            description_parts.append("Authentication endpoint")

        # File uploads
        if any(p in path for p in ["/upload", "/file", "/import", "/attachment"]):
            tags.append("upload")
            severity = ScanSeverity.LOW
            description_parts.append("File upload endpoint")

        # Sensitive paths
        if any(p in path for p in ["/backup", "/.git", "/.env", "/debug", "/trace"]):
            tags.append("sensitive")
            severity = ScanSeverity.MEDIUM
            description_parts.append("Potentially sensitive path")

        # JavaScript files
        if path.endswith(".js"):
            tags.append("js")
            description_parts.append("JavaScript file")

        # Forms
        if "form" in source.lower():
            tags.append("form")
            description_parts.append("Form endpoint")

        # Query parameters
        if parsed.query:
            params = parsed.query.split("&")
            tags.append(f"{len(params)}_params")
            description_parts.append(f"{len(params)} parameters")

        return ScanFinding(
            title=f"Endpoint: {parsed.path[:60]}",
            severity=severity,
            description="; ".join(description_parts) if description_parts else "Discovered endpoint",
            url=url,
            host=parsed.netloc,
            evidence=json.dumps(data, indent=2)[:500] if data else url,
            scanner="katana",
            tags=tags,
        )

    def _url_to_finding(self, url: str) -> Optional[ScanFinding]:
        """Convert plain URL to finding."""
        if not url.startswith(("http://", "https://")):
            return None

        try:
            parsed = urlparse(url)
            return ScanFinding(
                title=f"Endpoint: {parsed.path[:60]}",
                severity=ScanSeverity.INFO,
                description="Discovered endpoint",
                url=url,
                host=parsed.netloc,
                scanner="katana",
            )
        except Exception:
            return None

    async def stop(self) -> bool:
        """Stop running crawl."""
        if self._process and self._running:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
            self._running = False
            return True
        return False
