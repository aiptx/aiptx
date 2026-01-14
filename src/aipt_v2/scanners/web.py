"""
AIPT Web Scanner

Built-in web vulnerability scanner for common issues.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseScanner, ScanFinding, ScanResult, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class WebScanConfig:
    """Web scanner configuration"""
    # Checks to perform
    check_headers: bool = True
    check_ssl: bool = True
    check_directories: bool = True
    check_methods: bool = True
    check_robots: bool = True
    check_security_txt: bool = True

    # Request settings
    timeout: float = 10.0
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    follow_redirects: bool = True

    # Authentication
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    # Directory enumeration
    common_dirs: list[str] = field(default_factory=lambda: [
        "admin", "administrator", "wp-admin", "login", "dashboard",
        "api", "api/v1", "api/v2", "graphql",
        "backup", "backups", "db", "database",
        "config", "configuration", "settings",
        "test", "testing", "dev", "development", "staging",
        "uploads", "upload", "files", "media",
        ".git", ".svn", ".env", ".htaccess",
        "phpinfo.php", "info.php", "test.php",
        "server-status", "server-info",
    ])


class WebScanner(BaseScanner):
    """
    Built-in web vulnerability scanner.

    Performs common security checks:
    - Security header analysis
    - SSL/TLS configuration
    - Directory enumeration
    - HTTP method testing
    - robots.txt/security.txt analysis

    Example:
        scanner = WebScanner(WebScanConfig(
            check_directories=True,
            check_headers=True,
        ))
        result = await scanner.scan("https://target.com")
    """

    def __init__(self, config: Optional[WebScanConfig] = None):
        super().__init__()
        self.config = config or WebScanConfig()
        self._client: Optional[httpx.AsyncClient] = None

    def is_available(self) -> bool:
        """Always available - uses httpx"""
        return True

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run web security scan.

        Args:
            target: Target URL
            **kwargs: Override config options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="web_scanner", target=target)
        result.start_time = datetime.utcnow()
        result.status = "running"

        # Ensure URL has scheme
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Create HTTP client
        headers = {"User-Agent": self.config.user_agent}
        headers.update(self.config.headers)

        self._client = httpx.AsyncClient(
            timeout=self.config.timeout,
            follow_redirects=self.config.follow_redirects,
            headers=headers,
            cookies=self.config.cookies,
            verify=False,  # For testing sites with self-signed certs
        )

        try:
            # Run checks concurrently
            tasks = []

            if self.config.check_headers:
                tasks.append(self._check_security_headers(target))

            if self.config.check_ssl:
                tasks.append(self._check_ssl(target))

            if self.config.check_methods:
                tasks.append(self._check_http_methods(target))

            if self.config.check_robots:
                tasks.append(self._check_robots_txt(target))

            if self.config.check_security_txt:
                tasks.append(self._check_security_txt(target))

            if self.config.check_directories:
                tasks.append(self._check_directories(target))

            # Gather results
            findings_lists = await asyncio.gather(*tasks, return_exceptions=True)

            for findings in findings_lists:
                if isinstance(findings, list):
                    result.findings.extend(findings)
                elif isinstance(findings, Exception):
                    result.errors.append(str(findings))

            result.status = "completed"

        except Exception as e:
            result.status = "failed"
            result.errors.append(str(e))
        finally:
            await self._client.aclose()
            result.end_time = datetime.utcnow()
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        logger.info(f"Web scan complete: {len(result.findings)} findings")
        return result

    def parse_output(self, output: str) -> list[ScanFinding]:
        """Not used - findings created directly"""
        return []

    async def _check_security_headers(self, url: str) -> list[ScanFinding]:
        """Check for missing security headers"""
        findings = []

        try:
            response = await self._client.get(url)

            # Required security headers
            security_headers = {
                "Strict-Transport-Security": {
                    "severity": ScanSeverity.MEDIUM,
                    "description": "HSTS header not set. Site may be vulnerable to protocol downgrade attacks.",
                },
                "X-Content-Type-Options": {
                    "severity": ScanSeverity.LOW,
                    "description": "X-Content-Type-Options header not set. Browser MIME sniffing not prevented.",
                },
                "X-Frame-Options": {
                    "severity": ScanSeverity.MEDIUM,
                    "description": "X-Frame-Options header not set. Site may be vulnerable to clickjacking.",
                },
                "Content-Security-Policy": {
                    "severity": ScanSeverity.MEDIUM,
                    "description": "CSP header not set. Site may be vulnerable to XSS attacks.",
                },
                "X-XSS-Protection": {
                    "severity": ScanSeverity.LOW,
                    "description": "X-XSS-Protection header not set (legacy browsers).",
                },
                "Referrer-Policy": {
                    "severity": ScanSeverity.LOW,
                    "description": "Referrer-Policy header not set. Referrer information may leak.",
                },
                "Permissions-Policy": {
                    "severity": ScanSeverity.LOW,
                    "description": "Permissions-Policy header not set. Browser features not restricted.",
                },
            }

            for header, info in security_headers.items():
                if header.lower() not in [h.lower() for h in response.headers.keys()]:
                    findings.append(ScanFinding(
                        title=f"Missing Security Header: {header}",
                        severity=info["severity"],
                        description=info["description"],
                        url=url,
                        scanner="web_scanner",
                        tags=["header", "security"],
                    ))

            # Check for information disclosure in headers
            sensitive_headers = ["X-Powered-By", "Server", "X-AspNet-Version"]
            for header in sensitive_headers:
                if header.lower() in [h.lower() for h in response.headers.keys()]:
                    value = response.headers.get(header, "")
                    findings.append(ScanFinding(
                        title=f"Information Disclosure: {header}",
                        severity=ScanSeverity.LOW,
                        description=f"Header reveals: {value}",
                        url=url,
                        evidence=f"{header}: {value}",
                        scanner="web_scanner",
                        tags=["header", "disclosure"],
                    ))

        except Exception as e:
            logger.debug(f"Header check error: {e}")

        return findings

    async def _check_ssl(self, url: str) -> list[ScanFinding]:
        """Check SSL/TLS configuration"""
        findings = []

        parsed = urlparse(url)
        if parsed.scheme != "https":
            findings.append(ScanFinding(
                title="Site Not Using HTTPS",
                severity=ScanSeverity.HIGH,
                description="Site is not using HTTPS. All traffic is unencrypted.",
                url=url,
                scanner="web_scanner",
                tags=["ssl", "encryption"],
            ))
            return findings

        # Check for SSL issues
        try:
            import ssl
            import socket

            hostname = parsed.netloc.split(":")[0]
            port = int(parsed.port) if parsed.port else 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check expiry
                    from datetime import datetime
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (not_after - datetime.utcnow()).days

                    if days_until_expiry < 0:
                        findings.append(ScanFinding(
                            title="SSL Certificate Expired",
                            severity=ScanSeverity.HIGH,
                            description=f"Certificate expired {abs(days_until_expiry)} days ago",
                            url=url,
                            scanner="web_scanner",
                            tags=["ssl", "certificate"],
                        ))
                    elif days_until_expiry < 30:
                        findings.append(ScanFinding(
                            title="SSL Certificate Expiring Soon",
                            severity=ScanSeverity.MEDIUM,
                            description=f"Certificate expires in {days_until_expiry} days",
                            url=url,
                            scanner="web_scanner",
                            tags=["ssl", "certificate"],
                        ))

        except Exception as e:
            logger.debug(f"SSL check error: {e}")

        return findings

    async def _check_http_methods(self, url: str) -> list[ScanFinding]:
        """Check for dangerous HTTP methods"""
        findings = []
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

        try:
            # OPTIONS request
            response = await self._client.options(url)
            allowed = response.headers.get("Allow", "")

            for method in dangerous_methods:
                if method in allowed.upper():
                    findings.append(ScanFinding(
                        title=f"Dangerous HTTP Method Allowed: {method}",
                        severity=ScanSeverity.MEDIUM,
                        description=f"HTTP {method} method is enabled on the server",
                        url=url,
                        evidence=f"Allow: {allowed}",
                        scanner="web_scanner",
                        tags=["method", "configuration"],
                    ))

            # Check TRACE specifically
            try:
                response = await self._client.request("TRACE", url)
                if response.status_code == 200:
                    findings.append(ScanFinding(
                        title="HTTP TRACE Method Enabled",
                        severity=ScanSeverity.MEDIUM,
                        description="TRACE method is enabled, potential XST vulnerability",
                        url=url,
                        scanner="web_scanner",
                        tags=["method", "xst"],
                    ))
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"Method check error: {e}")

        return findings

    async def _check_robots_txt(self, url: str) -> list[ScanFinding]:
        """Analyze robots.txt for sensitive paths"""
        findings = []

        try:
            robots_url = urljoin(url, "/robots.txt")
            response = await self._client.get(robots_url)

            if response.status_code == 200:
                content = response.text

                # Look for sensitive paths
                sensitive_patterns = [
                    r"disallow:\s*/admin",
                    r"disallow:\s*/backup",
                    r"disallow:\s*/private",
                    r"disallow:\s*/config",
                    r"disallow:\s*/api",
                    r"disallow:\s*/\*password",
                    r"disallow:\s*/\*secret",
                ]

                found_paths = []
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    found_paths.extend(matches)

                if found_paths:
                    findings.append(ScanFinding(
                        title="Sensitive Paths in robots.txt",
                        severity=ScanSeverity.LOW,
                        description="robots.txt reveals potentially sensitive paths",
                        url=robots_url,
                        evidence="\n".join(found_paths[:10]),
                        scanner="web_scanner",
                        tags=["robots", "disclosure"],
                    ))

        except Exception as e:
            logger.debug(f"robots.txt check error: {e}")

        return findings

    async def _check_security_txt(self, url: str) -> list[ScanFinding]:
        """Check for security.txt"""
        findings = []

        try:
            # Check both locations
            locations = [
                urljoin(url, "/.well-known/security.txt"),
                urljoin(url, "/security.txt"),
            ]

            found = False
            for security_url in locations:
                response = await self._client.get(security_url)
                if response.status_code == 200 and "contact" in response.text.lower():
                    found = True
                    break

            if not found:
                findings.append(ScanFinding(
                    title="Missing security.txt",
                    severity=ScanSeverity.INFO,
                    description="No security.txt found. Consider adding one for vulnerability disclosure.",
                    url=url,
                    scanner="web_scanner",
                    tags=["security.txt", "best-practice"],
                ))

        except Exception as e:
            logger.debug(f"security.txt check error: {e}")

        return findings

    async def _check_directories(self, url: str) -> list[ScanFinding]:
        """Check for exposed directories"""
        findings = []
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests

        async def check_dir(path: str) -> Optional[ScanFinding]:
            async with semaphore:
                try:
                    check_url = urljoin(url, f"/{path}")
                    response = await self._client.get(check_url)

                    if response.status_code == 200:
                        severity = ScanSeverity.MEDIUM
                        if any(s in path for s in [".git", ".env", "backup", "config"]):
                            severity = ScanSeverity.HIGH

                        return ScanFinding(
                            title=f"Exposed Path: /{path}",
                            severity=severity,
                            description=f"Path /{path} is accessible (HTTP {response.status_code})",
                            url=check_url,
                            scanner="web_scanner",
                            tags=["directory", "enumeration"],
                        )
                    elif response.status_code == 403:
                        return ScanFinding(
                            title=f"Protected Path Found: /{path}",
                            severity=ScanSeverity.INFO,
                            description=f"Path /{path} exists but is forbidden",
                            url=check_url,
                            scanner="web_scanner",
                            tags=["directory", "forbidden"],
                        )
                except Exception:
                    pass
                return None

        tasks = [check_dir(path) for path in self.config.common_dirs]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                findings.append(result)

        return findings
