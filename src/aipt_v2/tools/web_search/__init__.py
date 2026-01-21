"""
AIPTX Web Search Tool - Perplexity AI Integration

Provides cybersecurity-focused web search for:
- CVE details and CVSS scores
- Exploit information and PoCs
- Security tools and techniques
- Penetration testing approaches
"""

__version__ = "2.1.0"

from aipt_v2.tools.web_search.web_search_actions import (
    search_cve,
    search_exploit,
    web_search,
)

__all__ = ["web_search", "search_cve", "search_exploit"]
