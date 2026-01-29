"""
AIPT Web Crawler

Intelligent web crawling for security assessment.
"""
from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class CrawlConfig:
    """Web crawler configuration"""
    max_depth: int = 3
    max_pages: int = 100
    max_concurrent: int = 5
    timeout: float = 30.0
    delay_between_requests: float = 0.5

    # Scope
    stay_in_scope: bool = True
    allowed_domains: list[str] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=lambda: [
        r"\.(jpg|jpeg|png|gif|svg|ico|css|js|woff|woff2|ttf|eot)$",
        r"/logout",
        r"/signout",
        r"#",
    ])

    # Authentication
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    # User agent
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # Content
    follow_redirects: bool = True
    parse_forms: bool = True
    parse_scripts: bool = True


@dataclass
class CrawledPage:
    """Information about a crawled page"""
    url: str
    status_code: int
    content_type: str = ""
    title: str = ""
    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    parameters: list[dict] = field(default_factory=list)  # GET/POST params found
    depth: int = 0
    parent_url: str = ""
    crawl_time: float = 0.0
    error: Optional[str] = None


@dataclass
class CrawlResult:
    """Complete crawl results"""
    target: str
    pages: list[CrawledPage] = field(default_factory=list)
    total_urls_found: int = 0
    total_forms_found: int = 0
    total_parameters_found: int = 0
    unique_domains: set = field(default_factory=set)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    def get_all_urls(self) -> list[str]:
        """Get all discovered URLs"""
        return [p.url for p in self.pages]

    def get_all_forms(self) -> list[dict]:
        """Get all discovered forms"""
        forms = []
        for page in self.pages:
            for form in page.forms:
                forms.append({"page": page.url, **form})
        return forms

    def get_all_parameters(self) -> list[dict]:
        """Get all discovered parameters"""
        params = []
        for page in self.pages:
            for param in page.parameters:
                params.append({"page": page.url, **param})
        return params

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "pages_crawled": len(self.pages),
            "total_urls_found": self.total_urls_found,
            "total_forms_found": self.total_forms_found,
            "total_parameters_found": self.total_parameters_found,
            "unique_domains": list(self.unique_domains),
            "duration_seconds": self.duration_seconds,
        }


class WebCrawler:
    """
    Web crawler for security assessment.

    Features:
    - Breadth-first crawling
    - Concurrent requests
    - Form/parameter discovery
    - Scope enforcement
    - Rate limiting

    Example:
        crawler = WebCrawler(CrawlConfig(max_depth=3))
        result = await crawler.crawl("https://target.com")

        # Get all forms for testing
        for form in result.get_all_forms():
            print(f"Form at {form['page']}: {form['action']}")
    """

    def __init__(self, config: Optional[CrawlConfig] = None):
        self.config = config or CrawlConfig()
        self._visited: Set[str] = set()
        self._queue: deque = deque()
        self._results: list[CrawledPage] = []
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._callback: Optional[Callable[[CrawledPage], None]] = None

    async def crawl(
        self,
        start_url: str,
        callback: Optional[Callable[[CrawledPage], None]] = None,
    ) -> CrawlResult:
        """
        Start crawling from URL.

        Args:
            start_url: Starting URL
            callback: Optional callback for each crawled page

        Returns:
            CrawlResult with all discoveries
        """
        self._callback = callback
        self._visited.clear()
        self._results.clear()

        result = CrawlResult(target=start_url)
        result.start_time = datetime.utcnow()

        # Parse start URL for domain
        parsed = urlparse(start_url)
        base_domain = parsed.netloc

        if not self.config.allowed_domains:
            self.config.allowed_domains = [base_domain]

        # Initialize client
        headers = {"User-Agent": self.config.user_agent}
        headers.update(self.config.headers)

        self._client = httpx.AsyncClient(
            timeout=self.config.timeout,
            follow_redirects=self.config.follow_redirects,
            headers=headers,
            cookies=self.config.cookies,
            verify=False,  # For testing sites with self-signed certs
        )

        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)

        # Add start URL to queue
        self._queue.append((start_url, 0, ""))

        try:
            # Process queue
            while self._queue and len(self._results) < self.config.max_pages:
                # Get batch of URLs
                batch = []
                while self._queue and len(batch) < self.config.max_concurrent:
                    url, depth, parent = self._queue.popleft()
                    normalized = self._normalize_url(url)

                    if normalized not in self._visited and depth <= self.config.max_depth:
                        self._visited.add(normalized)
                        batch.append((url, depth, parent))

                if not batch:
                    break

                # Crawl batch concurrently
                tasks = [
                    self._crawl_page(url, depth, parent)
                    for url, depth, parent in batch
                ]
                await asyncio.gather(*tasks)

                # Rate limiting
                if self.config.delay_between_requests > 0:
                    await asyncio.sleep(self.config.delay_between_requests)

        finally:
            await self._client.aclose()

        # Compile results
        result.pages = self._results
        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        for page in self._results:
            result.total_urls_found += len(page.links)
            result.total_forms_found += len(page.forms)
            result.total_parameters_found += len(page.parameters)
            result.unique_domains.add(urlparse(page.url).netloc)

        logger.info(
            f"Crawl complete: {len(result.pages)} pages, "
            f"{result.total_forms_found} forms, "
            f"{result.total_parameters_found} parameters"
        )

        return result

    async def _crawl_page(self, url: str, depth: int, parent: str) -> None:
        """Crawl a single page"""
        async with self._semaphore:
            page = CrawledPage(url=url, status_code=0, depth=depth, parent_url=parent)
            start_time = datetime.utcnow()

            try:
                response = await self._client.get(url)
                page.status_code = response.status_code
                page.content_type = response.headers.get("content-type", "")

                # Only parse HTML
                if "text/html" not in page.content_type:
                    self._results.append(page)
                    return

                content = response.text

                # Extract title
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", content, re.IGNORECASE)
                if title_match:
                    page.title = title_match.group(1).strip()

                # Extract links
                page.links = self._extract_links(content, url)

                # Extract forms
                if self.config.parse_forms:
                    page.forms = self._extract_forms(content, url)
                    page.parameters.extend(self._extract_form_params(page.forms))

                # Extract scripts
                if self.config.parse_scripts:
                    page.scripts = self._extract_scripts(content, url)

                # Extract URL parameters
                page.parameters.extend(self._extract_url_params(url))

                # Add new links to queue
                for link in page.links:
                    if self._should_crawl(link):
                        self._queue.append((link, depth + 1, url))

            except httpx.TimeoutException:
                page.error = "Timeout"
            except httpx.RequestError as e:
                page.error = str(e)
            except Exception as e:
                page.error = f"Error: {str(e)}"
            finally:
                page.crawl_time = (datetime.utcnow() - start_time).total_seconds()

            self._results.append(page)

            if self._callback:
                self._callback(page)

            logger.debug(f"Crawled: {url} (depth={depth}, status={page.status_code})")

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract links from HTML"""
        links = []
        # href links
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            href = match.group(1)
            if not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urljoin(base_url, href)
                if full_url not in links:
                    links.append(full_url)

        # src links (for images/scripts that might reveal paths)
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            src = match.group(1)
            if not src.startswith("data:"):
                full_url = urljoin(base_url, src)
                if full_url not in links:
                    links.append(full_url)

        return links

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'

        for form_match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)

            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)

            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"

            # Extract inputs
            inputs = []
            input_pattern = r'<input[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_tag = input_match.group(0)

                name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)

                inputs.append({
                    "name": name_match.group(1) if name_match else "",
                    "type": type_match.group(1) if type_match else "text",
                    "value": value_match.group(1) if value_match else "",
                })

            # Extract textareas
            textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
            for ta_match in re.finditer(textarea_pattern, form_html, re.IGNORECASE):
                inputs.append({
                    "name": ta_match.group(1),
                    "type": "textarea",
                    "value": "",
                })

            # Extract selects
            select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>'
            for sel_match in re.finditer(select_pattern, form_html, re.IGNORECASE):
                inputs.append({
                    "name": sel_match.group(1),
                    "type": "select",
                    "value": "",
                })

            forms.append({
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def _extract_scripts(self, html: str, base_url: str) -> list[str]:
        """Extract script URLs"""
        scripts = []
        pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'

        for match in re.finditer(pattern, html, re.IGNORECASE):
            src = match.group(1)
            full_url = urljoin(base_url, src)
            scripts.append(full_url)

        return scripts

    def _extract_form_params(self, forms: list[dict]) -> list[dict]:
        """Extract parameters from forms"""
        params = []
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name"):
                    params.append({
                        "name": inp["name"],
                        "type": inp["type"],
                        "method": form["method"],
                        "location": form["action"],
                    })
        return params

    def _extract_url_params(self, url: str) -> list[dict]:
        """Extract GET parameters from URL"""
        params = []
        parsed = urlparse(url)
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    name, _ = pair.split("=", 1)
                    params.append({
                        "name": name,
                        "type": "url",
                        "method": "GET",
                        "location": url,
                    })
        return params

    def _should_crawl(self, url: str) -> bool:
        """Check if URL should be crawled"""
        # Check exclusion patterns
        for pattern in self.config.excluded_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False

        # Check scope
        if self.config.stay_in_scope:
            parsed = urlparse(url)
            domain = parsed.netloc

            in_scope = False
            for allowed in self.config.allowed_domains:
                if domain == allowed or domain.endswith("." + allowed):
                    in_scope = True
                    break

            if not in_scope:
                return False

        # Check if already visited
        normalized = self._normalize_url(url)
        if normalized in self._visited:
            return False

        return True

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison"""
        parsed = urlparse(url)
        # Remove fragment and normalize
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()
