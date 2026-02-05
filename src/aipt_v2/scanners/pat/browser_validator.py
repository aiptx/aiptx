"""
PAT Browser-based PoC Validation for Client-Side Vulnerabilities

Validates PAT findings using headless browser execution for:
- XSS (Reflected, Stored, DOM-based)
- DOM Clobbering
- Prototype Pollution
- Clickjacking
- Tabnabbing
- Client-side path traversal

For XSS and other client-side vulns, simply checking HTTP response
isn't enough - we need to actually execute the JavaScript and verify
the payload triggers.

Features:
- Playwright-based browser execution
- Alert/console capture for XSS validation
- DOM state inspection
- Prototype pollution verification
- Screenshot evidence collection
- Detailed execution logs

Usage:
    from aipt_v2.scanners.pat.browser_validator import PATBrowserValidator

    validator = PATBrowserValidator(headless=True)

    # Validate XSS
    is_vuln, evidence = await validator.validate_xss(
        url="http://target.com/search?q=<script>alert(1)</script>",
        payload="<script>alert(1)</script>",
        context="html_body"
    )

    # Validate Prototype Pollution
    is_vuln, evidence = await validator.validate_prototype_pollution(
        url="http://target.com/app",
        payload='{"__proto__":{"isAdmin":true}}'
    )
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

logger = logging.getLogger(__name__)

# Try to import browser automation
try:
    from aipt_v2.browser.automation import BrowserAutomation, BrowserConfig, PLAYWRIGHT_AVAILABLE
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    BrowserAutomation = None
    BrowserConfig = None


@dataclass
class BrowserValidationResult:
    """Result from browser-based validation."""
    is_vulnerable: bool = False
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    screenshot: Optional[bytes] = None
    screenshot_base64: Optional[str] = None
    console_logs: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    dom_modifications: list[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "has_screenshot": self.screenshot is not None,
            "console_logs_count": len(self.console_logs),
            "alerts_count": len(self.alerts),
            "dom_modifications": self.dom_modifications,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
        }


class PATBrowserValidator:
    """
    Validates PAT findings using headless browser execution.

    For client-side vulnerabilities, the scanner needs to actually
    execute JavaScript in a browser to confirm exploitation.

    This validator uses Playwright to:
    1. Navigate to the vulnerable URL with payload
    2. Listen for alert() calls, console errors, DOM changes
    3. Execute JavaScript to verify exploitation
    4. Capture screenshots as evidence

    Example:
        validator = PATBrowserValidator(headless=True)

        # Single validation
        result = await validator.validate_xss(
            url="http://target.com/search?q=test",
            payload="<script>alert('XSS')</script>",
        )

        if result.is_vulnerable:
            print(f"XSS confirmed! Confidence: {result.confidence:.0%}")
            print(f"Alerts triggered: {result.alerts}")
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        browser_type: str = "chromium",
    ):
        """
        Initialize browser validator.

        Args:
            headless: Run browser in headless mode
            timeout: Page load timeout in seconds
            browser_type: Browser to use (chromium, firefox, webkit)
        """
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not available - browser validation disabled")

        self.headless = headless
        self.timeout = timeout * 1000  # Convert to ms
        self.browser_type = browser_type
        self._browser: Optional[Any] = None

    async def validate_xss(
        self,
        url: str,
        payload: str,
        context: str = "html_body",
        inject_param: Optional[str] = None,
    ) -> BrowserValidationResult:
        """
        Validate XSS by actually executing in browser.

        Args:
            url: Target URL (with or without payload already injected)
            payload: XSS payload that was used
            context: Injection context (html_body, html_attr, js_string, etc.)
            inject_param: Parameter to inject payload into (if not in URL)

        Returns:
            BrowserValidationResult with validation details
        """
        result = BrowserValidationResult()

        if not PLAYWRIGHT_AVAILABLE or not BrowserAutomation:
            result.error = "Playwright not available"
            return result

        import time
        start_time = time.time()

        try:
            config = BrowserConfig(
                headless=self.headless,
                browser_type=self.browser_type,
                timeout=self.timeout,
                ignore_https_errors=True,
            )

            async with BrowserAutomation(config) as browser:
                # Set up alert capture
                alerts = []
                console_logs = []

                # Get the page object
                page = browser._page

                # Set up dialog handler to capture alerts
                async def handle_dialog(dialog):
                    alerts.append(dialog.message)
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Set up console log capture
                def handle_console(msg):
                    console_logs.append(f"{msg.type}: {msg.text}")

                page.on("console", handle_console)

                # Build URL with payload if needed
                test_url = url
                if inject_param:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[inject_param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

                # Navigate to URL
                try:
                    response = await page.goto(test_url, wait_until="networkidle", timeout=self.timeout)
                except Exception as e:
                    # Continue even if timeout - payload might have executed
                    logger.debug(f"Navigation warning: {e}")

                # Wait a bit for any delayed execution
                await asyncio.sleep(1)

                # Check for XSS indicators
                xss_evidence = await page.evaluate("""
                    () => {
                        return {
                            // Check for script injection
                            scriptTags: document.querySelectorAll('script').length,
                            inlineScripts: document.querySelectorAll('script:not([src])').length,

                            // Check for event handlers
                            eventHandlers: document.querySelectorAll('[onerror],[onload],[onclick],[onmouseover]').length,

                            // Check for javascript: URIs
                            jsLinks: document.querySelectorAll('a[href^="javascript:"]').length,

                            // Check if payload appears in dangerous contexts
                            bodyHTML: document.body ? document.body.innerHTML.substring(0, 2000) : '',

                            // Check for common XSS canaries
                            hasAlert: typeof window._xss_triggered !== 'undefined',
                        };
                    }
                """)

                # Analyze results
                result.alerts = alerts
                result.console_logs = console_logs
                result.evidence = xss_evidence

                # Determine vulnerability
                if alerts:
                    # Alert was triggered - definite XSS
                    result.is_vulnerable = True
                    result.confidence = 0.98
                    result.dom_modifications.append(f"Alert triggered: {alerts[0]}")

                elif xss_evidence.get("eventHandlers", 0) > 0:
                    # Event handlers injected
                    result.is_vulnerable = True
                    result.confidence = 0.90
                    result.dom_modifications.append("Event handlers injected into DOM")

                elif payload.lower() in xss_evidence.get("bodyHTML", "").lower():
                    # Payload reflected without encoding
                    if any(x in payload.lower() for x in ["<script", "onerror", "javascript:"]):
                        result.is_vulnerable = True
                        result.confidence = 0.85
                        result.dom_modifications.append("Unencoded payload in HTML")
                    else:
                        result.confidence = 0.5
                        result.dom_modifications.append("Payload reflected (may be encoded)")

                # Take screenshot as evidence
                try:
                    result.screenshot = await page.screenshot()
                    import base64
                    result.screenshot_base64 = base64.b64encode(result.screenshot).decode()
                except Exception as e:
                    logger.debug(f"Screenshot failed: {e}")

        except Exception as e:
            result.error = str(e)
            logger.warning(f"XSS validation error: {e}")

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result

    async def validate_dom_xss(
        self,
        url: str,
        source: str = "location.hash",
        payload: str = "",
    ) -> BrowserValidationResult:
        """
        Validate DOM-based XSS via source-to-sink flow.

        Args:
            url: Target URL
            source: DOM source (location.hash, location.search, etc.)
            payload: XSS payload

        Returns:
            BrowserValidationResult
        """
        result = BrowserValidationResult()

        if not PLAYWRIGHT_AVAILABLE or not BrowserAutomation:
            result.error = "Playwright not available"
            return result

        import time
        start_time = time.time()

        try:
            config = BrowserConfig(
                headless=self.headless,
                browser_type=self.browser_type,
                timeout=self.timeout,
            )

            async with BrowserAutomation(config) as browser:
                alerts = []
                page = browser._page

                async def handle_dialog(dialog):
                    alerts.append(dialog.message)
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Build URL with payload in source
                test_url = url
                if source == "location.hash":
                    test_url = f"{url}#{payload}"
                elif source == "location.search":
                    test_url = f"{url}?q={payload}"

                await page.goto(test_url, wait_until="networkidle", timeout=self.timeout)
                await asyncio.sleep(1)

                # Check for DOM XSS sinks
                dom_xss_check = await page.evaluate("""
                    () => {
                        const sinks = [];

                        // Check innerHTML usage
                        const observer = new MutationObserver((mutations) => {
                            mutations.forEach(m => sinks.push(m.type));
                        });

                        return {
                            alertTriggered: window._domXssTriggered || false,
                            documentWrite: document.body.innerHTML.includes('document.write'),
                            innerHTML: document.querySelectorAll('[data-xss-sink]').length,
                        };
                    }
                """)

                result.alerts = alerts
                result.evidence = dom_xss_check

                if alerts:
                    result.is_vulnerable = True
                    result.confidence = 0.95
                    result.dom_modifications.append("DOM XSS triggered alert")

        except Exception as e:
            result.error = str(e)

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result

    async def validate_prototype_pollution(
        self,
        url: str,
        payload: str,
    ) -> BrowserValidationResult:
        """
        Validate Prototype Pollution by checking if pollution succeeded.

        Args:
            url: Target URL with prototype pollution payload
            payload: The pollution payload used

        Returns:
            BrowserValidationResult
        """
        result = BrowserValidationResult()

        if not PLAYWRIGHT_AVAILABLE or not BrowserAutomation:
            result.error = "Playwright not available"
            return result

        import time
        start_time = time.time()

        try:
            config = BrowserConfig(
                headless=self.headless,
                browser_type=self.browser_type,
                timeout=self.timeout,
            )

            async with BrowserAutomation(config) as browser:
                page = browser._page

                await page.goto(url, wait_until="networkidle", timeout=self.timeout)
                await asyncio.sleep(0.5)

                # Check for prototype pollution
                pollution_check = await page.evaluate("""
                    () => {
                        const checks = {
                            // Check Object.prototype pollution
                            objectPolluted: Object.prototype.polluted === true,
                            isAdmin: Object.prototype.isAdmin === true,
                            admin: Object.prototype.admin === true,
                            role: Object.prototype.role === 'admin',

                            // Check Array.prototype pollution
                            arrayPolluted: Array.prototype.polluted === true,

                            // Check for common gadgets
                            hasOwnProperty: {}.hasOwnProperty !== Object.prototype.hasOwnProperty,

                            // Get polluted properties
                            pollutedProps: Object.keys(Object.prototype).filter(k =>
                                !['constructor', 'toString', 'valueOf', 'hasOwnProperty',
                                 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString',
                                 '__defineGetter__', '__defineSetter__', '__lookupGetter__',
                                 '__lookupSetter__', '__proto__'].includes(k)
                            ),
                        };

                        return checks;
                    }
                """)

                result.evidence = pollution_check

                # Check if pollution succeeded
                polluted_props = pollution_check.get("pollutedProps", [])
                if polluted_props:
                    result.is_vulnerable = True
                    result.confidence = 0.95
                    result.dom_modifications.append(f"Object.prototype polluted: {polluted_props}")

                elif any([
                    pollution_check.get("objectPolluted"),
                    pollution_check.get("isAdmin"),
                    pollution_check.get("admin"),
                ]):
                    result.is_vulnerable = True
                    result.confidence = 0.90
                    result.dom_modifications.append("Prototype pollution confirmed")

                # Take screenshot
                try:
                    result.screenshot = await page.screenshot()
                except Exception:
                    pass

        except Exception as e:
            result.error = str(e)

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result

    async def validate_dom_clobbering(
        self,
        url: str,
        payload: str,
        target_id: str = "",
    ) -> BrowserValidationResult:
        """
        Validate DOM Clobbering attack.

        Args:
            url: Target URL with DOM clobbering payload
            payload: The clobbering payload
            target_id: Expected clobbered ID/name

        Returns:
            BrowserValidationResult
        """
        result = BrowserValidationResult()

        if not PLAYWRIGHT_AVAILABLE or not BrowserAutomation:
            result.error = "Playwright not available"
            return result

        import time
        start_time = time.time()

        try:
            config = BrowserConfig(
                headless=self.headless,
                browser_type=self.browser_type,
                timeout=self.timeout,
            )

            async with BrowserAutomation(config) as browser:
                page = browser._page

                await page.goto(url, wait_until="networkidle", timeout=self.timeout)

                # Check for DOM clobbering
                clobbering_check = await page.evaluate(f"""
                    () => {{
                        const checks = {{
                            // Check if global variables were clobbered
                            windowClobbered: false,
                            documentClobbered: false,
                            targetClobbered: false,
                        }};

                        // Check specific target if provided
                        const targetId = '{target_id}';
                        if (targetId && window[targetId]) {{
                            checks.targetClobbered = true;
                            checks.targetValue = String(window[targetId]).substring(0, 100);
                        }}

                        // Check for common clobbered names
                        ['x', 'cid', 'config', 'settings', 'data'].forEach(name => {{
                            if (window[name] instanceof HTMLElement) {{
                                checks.windowClobbered = true;
                            }}
                        }});

                        return checks;
                    }}
                """)

                result.evidence = clobbering_check

                if clobbering_check.get("targetClobbered") or clobbering_check.get("windowClobbered"):
                    result.is_vulnerable = True
                    result.confidence = 0.85
                    result.dom_modifications.append("DOM clobbering successful")

        except Exception as e:
            result.error = str(e)

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result

    async def validate_clickjacking(
        self,
        url: str,
    ) -> BrowserValidationResult:
        """
        Check if page is vulnerable to clickjacking.

        Args:
            url: Target URL to check

        Returns:
            BrowserValidationResult
        """
        result = BrowserValidationResult()

        if not PLAYWRIGHT_AVAILABLE or not BrowserAutomation:
            result.error = "Playwright not available"
            return result

        import time
        start_time = time.time()

        try:
            config = BrowserConfig(
                headless=self.headless,
                browser_type=self.browser_type,
                timeout=self.timeout,
            )

            async with BrowserAutomation(config) as browser:
                page = browser._page

                # Create an iframe containing the target
                iframe_html = f"""
                <html>
                <body style="margin:0">
                <iframe src="{url}" style="width:100%;height:100%;border:none;"></iframe>
                </body>
                </html>
                """

                import base64
                data_url = f"data:text/html;base64,{base64.b64encode(iframe_html.encode()).decode()}"

                await page.goto(data_url, timeout=self.timeout)
                await asyncio.sleep(1)

                # Check if iframe loaded successfully
                frame_check = await page.evaluate("""
                    () => {
                        const iframe = document.querySelector('iframe');
                        if (!iframe) return { loaded: false };

                        try {
                            // If we can access contentDocument, there's no X-Frame-Options
                            const doc = iframe.contentDocument || iframe.contentWindow.document;
                            return {
                                loaded: true,
                                hasContent: doc.body && doc.body.innerHTML.length > 0,
                                title: doc.title || '',
                            };
                        } catch (e) {
                            // Cross-origin restriction
                            return {
                                loaded: true,
                                crossOrigin: true,
                                hasContent: false,
                            };
                        }
                    }
                """)

                result.evidence = frame_check

                # Check response headers for frame protection
                response = await page.goto(url, timeout=self.timeout)
                headers = response.headers if response else {}

                x_frame = headers.get("x-frame-options", "").lower()
                csp = headers.get("content-security-policy", "").lower()
                frame_ancestors = "frame-ancestors" in csp

                result.evidence["headers"] = {
                    "x_frame_options": x_frame,
                    "has_frame_ancestors": frame_ancestors,
                }

                # Vulnerable if no frame protection
                if not x_frame and not frame_ancestors:
                    result.is_vulnerable = True
                    result.confidence = 0.90
                    result.dom_modifications.append("No clickjacking protection headers")
                elif x_frame in ["deny", "sameorigin"]:
                    result.is_vulnerable = False
                    result.confidence = 0.95

                result.screenshot = await page.screenshot()

        except Exception as e:
            result.error = str(e)

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result

    async def validate_client_path_traversal(
        self,
        url: str,
        payload: str,
    ) -> BrowserValidationResult:
        """
        Validate client-side path traversal.

        Args:
            url: Target URL
            payload: Path traversal payload

        Returns:
            BrowserValidationResult
        """
        result = BrowserValidationResult()

        if not PLAYWRIGHT_AVAILABLE or not BrowserAutomation:
            result.error = "Playwright not available"
            return result

        import time
        start_time = time.time()

        try:
            config = BrowserConfig(
                headless=self.headless,
                browser_type=self.browser_type,
                timeout=self.timeout,
            )

            async with BrowserAutomation(config) as browser:
                page = browser._page

                # Track fetch/XHR requests
                traversal_requests = []

                async def handle_request(request):
                    if ".." in request.url or "%2e%2e" in request.url.lower():
                        traversal_requests.append(request.url)

                page.on("request", handle_request)

                await page.goto(url, wait_until="networkidle", timeout=self.timeout)
                await asyncio.sleep(1)

                result.evidence = {
                    "traversal_requests": traversal_requests,
                    "request_count": len(traversal_requests),
                }

                if traversal_requests:
                    result.is_vulnerable = True
                    result.confidence = 0.80
                    result.dom_modifications.append(f"Path traversal requests: {len(traversal_requests)}")

        except Exception as e:
            result.error = str(e)

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result


# Convenience functions

async def validate_xss_in_browser(
    url: str,
    payload: str,
    headless: bool = True,
) -> tuple[bool, dict]:
    """
    Quick function to validate XSS in browser.

    Args:
        url: URL with XSS payload
        payload: The XSS payload used
        headless: Run headless

    Returns:
        Tuple of (is_vulnerable, evidence_dict)
    """
    validator = PATBrowserValidator(headless=headless)
    result = await validator.validate_xss(url, payload)
    return result.is_vulnerable, result.to_dict()


async def validate_prototype_pollution_in_browser(
    url: str,
    payload: str,
    headless: bool = True,
) -> tuple[bool, dict]:
    """
    Quick function to validate Prototype Pollution.

    Args:
        url: URL with prototype pollution
        payload: The pollution payload
        headless: Run headless

    Returns:
        Tuple of (is_vulnerable, evidence_dict)
    """
    validator = PATBrowserValidator(headless=headless)
    result = await validator.validate_prototype_pollution(url, payload)
    return result.is_vulnerable, result.to_dict()
