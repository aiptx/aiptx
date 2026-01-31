"""
AIPTX SPA Scanner - Browser-Based SPA Security Testing

Uses Playwright for:
- Full SPA rendering and hydration
- DOM-based XSS detection
- Client-side route discovery
- API request interception
- JavaScript error monitoring
- Local/session storage analysis
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

from aipt_v2.scanners.base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


class SPAFramework(str, Enum):
    """Detected SPA frameworks."""
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    SVELTE = "svelte"
    NEXT = "next.js"
    NUXT = "nuxt"
    UNKNOWN = "unknown"


class DOMSink(str, Enum):
    """DOM XSS sink types."""
    INNER_HTML = "innerHTML"
    OUTER_HTML = "outerHTML"
    DOCUMENT_WRITE = "document.write"
    EVAL = "eval"
    SET_TIMEOUT = "setTimeout"
    SET_INTERVAL = "setInterval"
    LOCATION = "location"
    LOCATION_HREF = "location.href"
    LOCATION_HASH = "location.hash"
    JQUERY_HTML = "$.html()"


@dataclass
class DOMXSSFinding:
    """DOM-based XSS finding."""
    sink: DOMSink
    source: str  # Where the data comes from
    payload: str
    triggered: bool
    element: str = ""
    url: str = ""
    evidence: str = ""

    def to_scan_finding(self) -> ScanFinding:
        severity = ScanSeverity.HIGH if self.triggered else ScanSeverity.MEDIUM
        return ScanFinding(
            title=f"DOM XSS via {self.sink.value}",
            severity=severity,
            description=f"DOM XSS detected: {self.source} flows to {self.sink.value}",
            url=self.url,
            evidence=self.evidence,
            cwe="CWE-79",
            scanner="spa_scanner",
            tags=["dom_xss", self.sink.value],
        )


@dataclass
class InterceptedRequest:
    """Intercepted API request."""
    method: str
    url: str
    headers: dict
    body: Optional[str] = None
    response_status: int = 0
    response_body: str = ""


@dataclass
class SPAScanConfig:
    """Configuration for SPA scanning."""
    timeout: float = 60.0
    wait_for_idle: float = 5.0  # Wait for network idle
    max_depth: int = 3  # Navigation depth
    max_pages: int = 50
    test_dom_xss: bool = True
    intercept_requests: bool = True
    check_storage: bool = True
    check_source_maps: bool = True
    headless: bool = True
    viewport_width: int = 1280
    viewport_height: int = 720
    custom_headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict] = field(default_factory=list)


@dataclass
class SPAScanResult:
    """Result of SPA security scan."""
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    framework: SPAFramework = SPAFramework.UNKNOWN
    routes_discovered: list[str] = field(default_factory=list)
    api_requests: list[InterceptedRequest] = field(default_factory=list)
    dom_xss_findings: list[DOMXSSFinding] = field(default_factory=list)
    storage_findings: list[dict] = field(default_factory=list)
    js_errors: list[str] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_scan_result(self) -> ScanResult:
        result = ScanResult(
            scanner="spa_scanner",
            target=self.target,
            status="completed" if self.completed_at else "failed",
            start_time=self.started_at,
            end_time=self.completed_at,
        )
        for finding in self.findings:
            result.add_finding(finding)
        for dom_xss in self.dom_xss_findings:
            result.add_finding(dom_xss.to_scan_finding())
        result.errors = self.errors
        return result


class SPAScanner(BaseScanner):
    """
    Browser-based SPA security scanner.

    Uses Playwright to:
    - Fully render SPAs (React, Vue, Angular, etc.)
    - Detect DOM-based XSS vulnerabilities
    - Discover client-side routes
    - Intercept and analyze API requests
    - Check local/session storage for sensitive data

    Usage:
        scanner = SPAScanner()
        result = await scanner.scan("https://spa-app.example.com")

        for finding in result.dom_xss_findings:
            print(f"DOM XSS: {finding.sink} via {finding.source}")
    """

    def __init__(self, config: Optional[SPAScanConfig] = None):
        super().__init__()
        self.config = config or SPAScanConfig()
        self._browser = None
        self._context = None

    def is_available(self) -> bool:
        """Check if Playwright is available."""
        try:
            from playwright.async_api import async_playwright
            return True
        except ImportError:
            return False

    def parse_output(self, output: str) -> list[ScanFinding]:
        """Parse output (not used for SPA scanner)."""
        return []

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Scan a SPA application.

        Args:
            target: URL of the SPA
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        spa_result = await self.scan_spa(target)
        return spa_result.to_scan_result()

    async def scan_spa(self, url: str) -> SPAScanResult:
        """
        Perform comprehensive SPA security scan.

        Args:
            url: Target URL

        Returns:
            SPAScanResult with findings
        """
        result = SPAScanResult(target=url, started_at=datetime.now())

        if not self.is_available():
            result.errors.append("Playwright not installed. Run: pip install playwright && playwright install")
            return result

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                # Launch browser
                self._browser = await p.chromium.launch(
                    headless=self.config.headless,
                )

                # Create context with settings
                self._context = await self._browser.new_context(
                    viewport={
                        "width": self.config.viewport_width,
                        "height": self.config.viewport_height,
                    },
                    extra_http_headers=self.config.custom_headers,
                )

                # Add cookies if provided
                if self.config.cookies:
                    await self._context.add_cookies(self.config.cookies)

                # Create page
                page = await self._context.new_page()

                # Set up request interception
                if self.config.intercept_requests:
                    await self._setup_request_interception(page, result)

                # Set up error monitoring
                page.on("pageerror", lambda e: result.js_errors.append(str(e)))
                page.on("console", lambda m: self._handle_console(m, result))

                # Navigate to target
                logger.info(f"[SPA] Loading {url}")
                try:
                    await page.goto(url, wait_until="networkidle", timeout=self.config.timeout * 1000)
                except Exception as e:
                    logger.warning(f"Navigation error: {e}")
                    await page.goto(url, wait_until="domcontentloaded", timeout=self.config.timeout * 1000)

                # Wait for SPA to hydrate
                await asyncio.sleep(self.config.wait_for_idle)

                # Detect framework
                result.framework = await self._detect_framework(page)
                logger.info(f"[SPA] Detected framework: {result.framework.value}")

                # Discover routes
                result.routes_discovered = await self._discover_routes(page, url)
                logger.info(f"[SPA] Discovered {len(result.routes_discovered)} routes")

                # Test DOM XSS
                if self.config.test_dom_xss:
                    result.dom_xss_findings = await self._test_dom_xss(page, url)
                    logger.info(f"[SPA] Found {len(result.dom_xss_findings)} DOM XSS issues")

                # Check storage
                if self.config.check_storage:
                    result.storage_findings = await self._check_storage(page)

                # Check source maps
                if self.config.check_source_maps:
                    await self._check_source_maps(page, result)

                # Analyze findings
                self._analyze_findings(result)

                await self._context.close()
                await self._browser.close()

        except Exception as e:
            logger.error(f"SPA scan error: {e}", exc_info=True)
            result.errors.append(str(e))

        result.completed_at = datetime.now()
        return result

    async def _setup_request_interception(self, page, result: SPAScanResult) -> None:
        """Set up request interception."""
        async def handle_request(route, request):
            # Log API requests
            if "/api/" in request.url or "graphql" in request.url.lower():
                result.api_requests.append(
                    InterceptedRequest(
                        method=request.method,
                        url=request.url,
                        headers=dict(request.headers),
                        body=request.post_data,
                    )
                )
            await route.continue_()

        await page.route("**/*", handle_request)

    def _handle_console(self, message, result: SPAScanResult) -> None:
        """Handle console messages."""
        if message.type == "error":
            result.js_errors.append(message.text)

    async def _detect_framework(self, page) -> SPAFramework:
        """Detect the SPA framework."""
        checks = [
            ("window.__REACT_DEVTOOLS_GLOBAL_HOOK__", SPAFramework.REACT),
            ("window.__VUE__", SPAFramework.VUE),
            ("window.ng", SPAFramework.ANGULAR),
            ("window.__NUXT__", SPAFramework.NUXT),
            ("window.__NEXT_DATA__", SPAFramework.NEXT),
            ("window.__svelte", SPAFramework.SVELTE),
        ]

        for check, framework in checks:
            try:
                exists = await page.evaluate(f"typeof {check} !== 'undefined'")
                if exists:
                    return framework
            except Exception:
                pass

        # Check HTML for framework indicators
        html = await page.content()
        if "data-reactroot" in html or "__REACT" in html:
            return SPAFramework.REACT
        if "ng-app" in html or "ng-version" in html:
            return SPAFramework.ANGULAR
        if "data-v-" in html:
            return SPAFramework.VUE

        return SPAFramework.UNKNOWN

    async def _discover_routes(self, page, base_url: str) -> list[str]:
        """Discover client-side routes."""
        routes = set()
        parsed_base = urlparse(base_url)

        # Get all links
        links = await page.evaluate("""
            () => Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(href => href.startsWith(window.location.origin))
        """)

        for link in links:
            parsed = urlparse(link)
            if parsed.netloc == parsed_base.netloc:
                routes.add(parsed.path or "/")

        # Check for React Router links
        router_links = await page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('[data-testid], [to], [href]').forEach(el => {
                    const to = el.getAttribute('to');
                    if (to && to.startsWith('/')) links.push(to);
                });
                return links;
            }
        """)
        routes.update(router_links)

        # Check for Vue Router links
        vue_links = await page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('router-link, [to]').forEach(el => {
                    const to = el.getAttribute('to');
                    if (to) links.push(to);
                });
                return links;
            }
        """)
        routes.update(vue_links)

        return list(routes)[:self.config.max_pages]

    async def _test_dom_xss(self, page, url: str) -> list[DOMXSSFinding]:
        """Test for DOM-based XSS."""
        findings = []

        # DOM XSS test payloads
        xss_payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "\"><img src=x onerror=alert('XSS')>",
        ]

        # Test URL hash-based XSS
        for payload in xss_payloads:
            test_url = f"{url}#/{payload}"
            try:
                await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                await asyncio.sleep(0.5)

                # Check if alert was triggered (via dialog handler)
                triggered = await self._check_xss_triggered(page, payload)

                if triggered:
                    findings.append(
                        DOMXSSFinding(
                            sink=DOMSink.LOCATION_HASH,
                            source="URL hash",
                            payload=payload,
                            triggered=True,
                            url=test_url,
                            evidence=f"XSS triggered via location.hash: {payload}",
                        )
                    )

            except Exception as e:
                logger.debug(f"DOM XSS test error: {e}")

        # Test query parameter XSS
        for payload in xss_payloads:
            test_url = f"{url}?q={payload}"
            try:
                await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                await asyncio.sleep(0.5)

                # Check for payload in DOM
                if await self._payload_in_dom(page, payload):
                    findings.append(
                        DOMXSSFinding(
                            sink=DOMSink.INNER_HTML,
                            source="URL parameter",
                            payload=payload,
                            triggered=False,
                            url=test_url,
                            evidence="Payload reflected in DOM without encoding",
                        )
                    )

            except Exception as e:
                logger.debug(f"DOM XSS test error: {e}")

        # Check for dangerous sinks in JavaScript
        dangerous_patterns = await self._find_dangerous_patterns(page)
        for pattern in dangerous_patterns:
            findings.append(
                DOMXSSFinding(
                    sink=pattern["sink"],
                    source=pattern["source"],
                    payload="",
                    triggered=False,
                    evidence=pattern["code"],
                )
            )

        return findings

    async def _check_xss_triggered(self, page, payload: str) -> bool:
        """Check if XSS payload was triggered."""
        try:
            # Check for alert in page
            triggered = await page.evaluate("""
                () => {
                    // Check if our payload created elements
                    const scripts = document.querySelectorAll('script');
                    for (const s of scripts) {
                        if (s.textContent.includes('alert')) return true;
                    }
                    const imgs = document.querySelectorAll('img[onerror]');
                    if (imgs.length > 0) return true;
                    return false;
                }
            """)
            return triggered
        except Exception:
            return False

    async def _payload_in_dom(self, page, payload: str) -> bool:
        """Check if payload is in DOM."""
        try:
            html = await page.content()
            # Check for unencoded payload
            if payload in html:
                return True
            # Check for partially encoded
            if payload.replace("<", "&lt;") not in html and "<script" in payload.lower():
                return payload.lower() in html.lower()
            return False
        except Exception:
            return False

    async def _find_dangerous_patterns(self, page) -> list[dict]:
        """Find dangerous DOM patterns in JavaScript."""
        patterns = []

        try:
            # Get all script content
            scripts = await page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('script'))
                        .map(s => s.textContent)
                        .join('\\n');
                }
            """)

            # Check for dangerous patterns
            dangerous = [
                (r'\.innerHTML\s*=\s*[^;]*location', DOMSink.INNER_HTML, "location"),
                (r'document\.write\s*\([^)]*location', DOMSink.DOCUMENT_WRITE, "location"),
                (r'eval\s*\([^)]*location', DOMSink.EVAL, "location"),
                (r'\.innerHTML\s*=\s*[^;]*\.hash', DOMSink.INNER_HTML, "location.hash"),
                (r'\.innerHTML\s*=\s*[^;]*\.search', DOMSink.INNER_HTML, "location.search"),
            ]

            for pattern, sink, source in dangerous:
                matches = re.findall(pattern, scripts, re.IGNORECASE)
                for match in matches:
                    patterns.append({
                        "sink": sink,
                        "source": source,
                        "code": match[:200],
                    })

        except Exception as e:
            logger.debug(f"Pattern search error: {e}")

        return patterns

    async def _check_storage(self, page) -> list[dict]:
        """Check localStorage and sessionStorage for sensitive data."""
        findings = []

        try:
            # Get localStorage
            local_storage = await page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }
                    return items;
                }
            """)

            # Get sessionStorage
            session_storage = await page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        items[key] = sessionStorage.getItem(key);
                    }
                    return items;
                }
            """)

            # Check for sensitive data
            sensitive_patterns = [
                (r'(?i)(password|passwd|pwd)', "password"),
                (r'(?i)(token|jwt|bearer)', "token"),
                (r'(?i)(api_key|apikey|api-key)', "api_key"),
                (r'(?i)(secret|private)', "secret"),
                (r'eyJ[A-Za-z0-9_-]+\.eyJ', "jwt_token"),
            ]

            for storage_name, storage_data in [("localStorage", local_storage), ("sessionStorage", session_storage)]:
                for key, value in storage_data.items():
                    for pattern, data_type in sensitive_patterns:
                        if re.search(pattern, key) or (value and re.search(pattern, str(value))):
                            findings.append({
                                "storage": storage_name,
                                "key": key,
                                "data_type": data_type,
                                "severity": "high" if data_type in ["password", "token", "jwt_token"] else "medium",
                            })

        except Exception as e:
            logger.debug(f"Storage check error: {e}")

        return findings

    async def _check_source_maps(self, page, result: SPAScanResult) -> None:
        """Check for exposed source maps."""
        try:
            # Get all script sources
            scripts = await page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
            """)

            for script_url in scripts:
                map_url = f"{script_url}.map"
                try:
                    response = await page.request.get(map_url)
                    if response.status == 200:
                        result.findings.append(
                            ScanFinding(
                                title="Exposed Source Map",
                                severity=ScanSeverity.LOW,
                                description=f"Source map accessible at {map_url}",
                                url=map_url,
                                scanner="spa_scanner",
                                tags=["source_map", "information_disclosure"],
                            )
                        )
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Source map check error: {e}")

    def _analyze_findings(self, result: SPAScanResult) -> None:
        """Analyze and create additional findings."""
        # Check for sensitive data in storage
        for storage_finding in result.storage_findings:
            result.findings.append(
                ScanFinding(
                    title=f"Sensitive Data in {storage_finding['storage']}",
                    severity=ScanSeverity.HIGH if storage_finding["severity"] == "high" else ScanSeverity.MEDIUM,
                    description=f"Sensitive {storage_finding['data_type']} found in {storage_finding['storage']}",
                    evidence=f"Key: {storage_finding['key']}",
                    cwe="CWE-922",
                    scanner="spa_scanner",
                    tags=["storage", "sensitive_data"],
                )
            )

        # Check for API endpoints without auth
        for req in result.api_requests:
            if "authorization" not in [h.lower() for h in req.headers]:
                if req.response_status == 200:
                    result.findings.append(
                        ScanFinding(
                            title="API Endpoint Without Authentication",
                            severity=ScanSeverity.LOW,
                            description=f"API request to {req.url} succeeded without Authorization header",
                            url=req.url,
                            scanner="spa_scanner",
                            tags=["api", "authentication"],
                        )
                    )
