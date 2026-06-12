"""
AIPT Browser Module

Browser automation for penetration testing:
- Playwright-based headless browsing
- Screenshot capture
- Form interaction
- JavaScript injection
- Cookie/session management
- DOM analysis
"""

from .automation import (
    BrowserAutomation,
    BrowserConfig,
    PageResult,
)
from .crawler import (
    CrawlConfig,
    CrawlResult,
    WebCrawler,
)

__all__ = [
    "BrowserAutomation",
    "BrowserConfig",
    "PageResult",
    "WebCrawler",
    "CrawlConfig",
    "CrawlResult",
]
