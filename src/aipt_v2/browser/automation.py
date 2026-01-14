"""
AIPT Browser Automation

Playwright-based browser automation for security testing.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Playwright import with fallback
try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed. Install with: pip install playwright && playwright install")


@dataclass
class BrowserConfig:
    """Browser automation configuration"""
    headless: bool = True
    browser_type: str = "chromium"  # chromium, firefox, webkit
    viewport_width: int = 1920
    viewport_height: int = 1080
    timeout: float = 30000  # milliseconds
    user_agent: Optional[str] = None

    # Proxy settings
    proxy_server: Optional[str] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None

    # Security testing options
    ignore_https_errors: bool = True
    disable_javascript: bool = False

    # Performance
    slow_mo: int = 0  # Slow down actions (ms)


@dataclass
class PageResult:
    """Result of a page interaction"""
    url: str
    status_code: int = 0
    content: str = ""
    title: str = ""
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    screenshot_base64: Optional[str] = None
    console_logs: list[str] = field(default_factory=list)
    network_requests: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    load_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "cookies_count": len(self.cookies),
            "forms_count": len(self.forms),
            "links_count": len(self.links),
            "load_time_ms": self.load_time_ms,
            "error": self.error,
        }


class BrowserAutomation:
    """
    Browser automation for penetration testing.

    Features:
    - Headless browser control
    - Screenshot capture
    - Form submission
    - JavaScript execution
    - Cookie/session management
    - Network request interception
    - DOM analysis

    Example:
        async with BrowserAutomation() as browser:
            result = await browser.navigate("https://target.com/login")
            await browser.fill_form({
                "username": "admin",
                "password": "password123"
            })
            await browser.click("button[type=submit]")
            await browser.screenshot("login_result.png")
    """

    def __init__(self, config: Optional[BrowserConfig] = None):
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright is required. Install with: pip install playwright && playwright install")

        self.config = config or BrowserConfig()
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._console_logs: list[str] = []
        self._network_requests: list[dict] = []

    async def __aenter__(self) -> "BrowserAutomation":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self) -> None:
        """Start browser instance"""
        self._playwright = await async_playwright().start()

        # Select browser type
        if self.config.browser_type == "firefox":
            browser_launcher = self._playwright.firefox
        elif self.config.browser_type == "webkit":
            browser_launcher = self._playwright.webkit
        else:
            browser_launcher = self._playwright.chromium

        # Launch options
        launch_options = {
            "headless": self.config.headless,
            "slow_mo": self.config.slow_mo,
        }

        if self.config.proxy_server:
            launch_options["proxy"] = {
                "server": self.config.proxy_server,
            }
            if self.config.proxy_username:
                launch_options["proxy"]["username"] = self.config.proxy_username
                launch_options["proxy"]["password"] = self.config.proxy_password or ""

        self._browser = await browser_launcher.launch(**launch_options)

        # Create context
        context_options = {
            "viewport": {
                "width": self.config.viewport_width,
                "height": self.config.viewport_height,
            },
            "ignore_https_errors": self.config.ignore_https_errors,
        }

        if self.config.user_agent:
            context_options["user_agent"] = self.config.user_agent

        self._context = await self._browser.new_context(**context_options)

        # Create page
        self._page = await self._context.new_page()
        self._page.set_default_timeout(self.config.timeout)

        # Set up event listeners
        self._page.on("console", self._on_console)
        self._page.on("request", self._on_request)

        if self.config.disable_javascript:
            await self._context.route("**/*", lambda route: route.fulfill(body="") if route.request.resource_type == "script" else route.continue_())

        logger.info(f"Browser started: {self.config.browser_type}")

    async def close(self) -> None:
        """Close browser"""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser closed")

    async def navigate(self, url: str, wait_until: str = "networkidle") -> PageResult:
        """
        Navigate to URL and analyze page.

        Args:
            url: Target URL
            wait_until: load, domcontentloaded, networkidle

        Returns:
            PageResult with page analysis
        """
        self._console_logs.clear()
        self._network_requests.clear()

        result = PageResult(url=url)
        start_time = datetime.utcnow()

        try:
            response = await self._page.goto(url, wait_until=wait_until)

            if response:
                result.status_code = response.status
                result.headers = dict(response.headers)

            result.content = await self._page.content()
            result.title = await self._page.title()
            result.cookies = await self._context.cookies()
            result.console_logs = self._console_logs.copy()
            result.network_requests = self._network_requests.copy()

            # Extract forms
            result.forms = await self._extract_forms()

            # Extract links
            result.links = await self._extract_links()

            # Extract scripts
            result.scripts = await self._extract_scripts()

        except Exception as e:
            result.error = str(e)
            logger.error(f"Navigation error: {e}")
        finally:
            result.load_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        return result

    async def screenshot(
        self,
        path: Optional[str] = None,
        full_page: bool = False,
    ) -> Optional[str]:
        """
        Take screenshot.

        Args:
            path: Save path (optional)
            full_page: Capture full scrollable page

        Returns:
            Base64 encoded screenshot if no path specified
        """
        try:
            screenshot_bytes = await self._page.screenshot(
                path=path,
                full_page=full_page,
            )
            if not path:
                return base64.b64encode(screenshot_bytes).decode()
            return path
        except Exception as e:
            logger.error(f"Screenshot error: {e}")
            return None

    async def fill_form(
        self,
        form_data: dict[str, str],
        form_selector: Optional[str] = None,
    ) -> bool:
        """
        Fill form fields.

        Args:
            form_data: Field name/id -> value mapping
            form_selector: Optional form selector

        Returns:
            True if successful
        """
        try:
            for field_name, value in form_data.items():
                # Try multiple selector strategies
                selectors = [
                    f'[name="{field_name}"]',
                    f'#{field_name}',
                    f'[id="{field_name}"]',
                    f'[placeholder*="{field_name}" i]',
                ]

                if form_selector:
                    selectors = [f'{form_selector} {s}' for s in selectors]

                for selector in selectors:
                    try:
                        element = await self._page.query_selector(selector)
                        if element:
                            await element.fill(value)
                            break
                    except Exception:
                        continue

            return True
        except Exception as e:
            logger.error(f"Form fill error: {e}")
            return False

    async def click(self, selector: str) -> bool:
        """Click element"""
        try:
            await self._page.click(selector)
            return True
        except Exception as e:
            logger.error(f"Click error: {e}")
            return False

    async def execute_js(self, script: str) -> Any:
        """Execute JavaScript and return result"""
        try:
            return await self._page.evaluate(script)
        except Exception as e:
            logger.error(f"JS execution error: {e}")
            return None

    async def inject_script(self, script: str) -> bool:
        """Inject script into page"""
        try:
            await self._page.add_script_tag(content=script)
            return True
        except Exception as e:
            logger.error(f"Script injection error: {e}")
            return False

    async def set_cookies(self, cookies: list[dict]) -> None:
        """Set cookies"""
        await self._context.add_cookies(cookies)

    async def get_cookies(self) -> list[dict]:
        """Get all cookies"""
        return await self._context.cookies()

    async def clear_cookies(self) -> None:
        """Clear all cookies"""
        await self._context.clear_cookies()

    async def wait_for_selector(self, selector: str, timeout: float = 30000) -> bool:
        """Wait for element to appear"""
        try:
            await self._page.wait_for_selector(selector, timeout=timeout)
            return True
        except Exception:
            return False

    async def get_text(self, selector: str) -> Optional[str]:
        """Get text content of element"""
        try:
            element = await self._page.query_selector(selector)
            if element:
                return await element.text_content()
        except Exception:
            pass
        return None

    async def get_attribute(self, selector: str, attribute: str) -> Optional[str]:
        """Get element attribute"""
        try:
            element = await self._page.query_selector(selector)
            if element:
                return await element.get_attribute(attribute)
        except Exception:
            pass
        return None

    async def _extract_forms(self) -> list[dict]:
        """Extract all forms from page"""
        forms = []
        try:
            form_elements = await self._page.query_selector_all("form")
            for form in form_elements:
                form_data = {
                    "action": await form.get_attribute("action") or "",
                    "method": await form.get_attribute("method") or "GET",
                    "id": await form.get_attribute("id") or "",
                    "inputs": [],
                }

                inputs = await form.query_selector_all("input, textarea, select")
                for input_elem in inputs:
                    input_data = {
                        "name": await input_elem.get_attribute("name") or "",
                        "type": await input_elem.get_attribute("type") or "text",
                        "value": await input_elem.get_attribute("value") or "",
                    }
                    form_data["inputs"].append(input_data)

                forms.append(form_data)
        except Exception as e:
            logger.debug(f"Form extraction error: {e}")

        return forms

    async def _extract_links(self) -> list[str]:
        """Extract all links from page"""
        links = []
        try:
            anchors = await self._page.query_selector_all("a[href]")
            base_url = self._page.url

            for anchor in anchors:
                href = await anchor.get_attribute("href")
                if href:
                    # Resolve relative URLs
                    full_url = urljoin(base_url, href)
                    if full_url not in links:
                        links.append(full_url)
        except Exception as e:
            logger.debug(f"Link extraction error: {e}")

        return links

    async def _extract_scripts(self) -> list[str]:
        """Extract script sources from page"""
        scripts = []
        try:
            script_elements = await self._page.query_selector_all("script[src]")
            for script in script_elements:
                src = await script.get_attribute("src")
                if src:
                    scripts.append(urljoin(self._page.url, src))

            # Also get inline scripts
            inline_scripts = await self._page.query_selector_all("script:not([src])")
            for script in inline_scripts:
                content = await script.text_content()
                if content and len(content) > 10:
                    scripts.append(f"[inline:{len(content)} chars]")
        except Exception:
            pass

        return scripts

    def _on_console(self, message) -> None:
        """Handle console messages"""
        self._console_logs.append(f"[{message.type}] {message.text}")

    def _on_request(self, request) -> None:
        """Handle network requests"""
        self._network_requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
        })

    @property
    def page(self) -> Optional[Page]:
        """Get underlying Playwright page"""
        return self._page

    @property
    def current_url(self) -> str:
        """Get current page URL"""
        return self._page.url if self._page else ""
