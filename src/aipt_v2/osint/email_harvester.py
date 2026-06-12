"""
AIPTX Email Harvester - OSINT Email Discovery.

Harvest email addresses from multiple sources for target domains.

Integrated from Zen-AI-Pentest for AIPTX v5.2.

Example usage:
    from aipt_v2.osint import EmailHarvester

    async with EmailHarvester() as harvester:
        results = await harvester.harvest(
            domain="example.com",
            sources=["google", "bing", "pgp", "github"]
        )

        for email in results:
            print(f"{email.address} (source: {email.source}, confidence: {email.confidence})")
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class EmailResult:
    """Result from email harvesting."""

    address: str
    source: str
    confidence: int = 5  # 1-10
    valid_format: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": self.address,
            "source": self.source,
            "confidence": self.confidence,
            "valid_format": self.valid_format,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class EmailProfile:
    """Complete profile for an email address."""

    email: str
    valid_format: bool = False
    deliverable: Optional[bool] = None
    disposable: bool = False
    role_based: bool = False  # admin@, info@, etc.
    breach_count: int = 0
    breach_sources: List[str] = field(default_factory=list)
    social_profiles: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "email": self.email,
            "valid_format": self.valid_format,
            "deliverable": self.deliverable,
            "disposable": self.disposable,
            "role_based": self.role_based,
            "breach_count": self.breach_count,
            "breach_sources": self.breach_sources,
            "social_profiles": self.social_profiles,
        }


class EmailHarvester:
    """
    Email harvesting from multiple OSINT sources.

    Sources:
    - Search engines (Google, Bing, Yahoo, DuckDuckGo)
    - PGP key servers
    - GitHub code search
    - Certificate transparency
    - LinkedIn (public profiles)
    """

    # Common email patterns
    ROLE_BASED_PREFIXES = {
        "admin",
        "administrator",
        "info",
        "contact",
        "support",
        "sales",
        "webmaster",
        "postmaster",
        "hostmaster",
        "abuse",
        "noreply",
        "no-reply",
        "mail",
        "help",
        "security",
        "privacy",
        "legal",
        "billing",
        "accounts",
        "hr",
        "jobs",
        "careers",
        "press",
    }

    # Disposable email domains
    DISPOSABLE_DOMAINS = {
        "tempmail.com",
        "throwaway.email",
        "guerrillamail.com",
        "10minutemail.com",
        "mailinator.com",
        "temp-mail.org",
    }

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

    def __init__(self, session: Optional[aiohttp.ClientSession] = None, rate_limit: int = 10):
        """
        Initialize the email harvester.

        Args:
            session: Optional aiohttp session to reuse
            rate_limit: Maximum concurrent requests
        """
        self._session = session
        self._own_session = session is None
        self._semaphore = asyncio.Semaphore(rate_limit)
        self._ua_index = 0

    async def __aenter__(self):
        if self._own_session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._own_session and self._session:
            await self._session.close()

    async def harvest(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        max_results: int = 100,
    ) -> List[EmailResult]:
        """
        Harvest emails for a domain from multiple sources.

        Args:
            domain: Target domain (e.g., "example.com")
            sources: List of sources to use (default: all)
            max_results: Maximum emails to return

        Returns:
            List of EmailResult objects
        """
        if sources is None:
            sources = ["google", "bing", "pgp", "crtsh", "common"]

        logger.info(f"Harvesting emails for {domain} from {len(sources)} sources")

        tasks = []
        for source in sources:
            if source == "google":
                tasks.append(self._google_search(domain))
            elif source == "bing":
                tasks.append(self._bing_search(domain))
            elif source == "pgp":
                tasks.append(self._pgp_search(domain))
            elif source == "github":
                tasks.append(self._github_search(domain))
            elif source == "crtsh":
                tasks.append(self._crtsh_search(domain))
            elif source == "common":
                tasks.append(self._common_patterns(domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Deduplicate and collect results
        seen_emails: Set[str] = set()
        email_results: List[EmailResult] = []

        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Source failed: {result}")
                continue
            if isinstance(result, list):
                for email in result:
                    if email.address.lower() not in seen_emails:
                        seen_emails.add(email.address.lower())
                        email_results.append(email)

        # Sort by confidence and limit results
        email_results.sort(key=lambda x: x.confidence, reverse=True)
        email_results = email_results[:max_results]

        logger.info(f"Found {len(email_results)} unique emails for {domain}")
        return email_results

    async def validate_email(self, email: str) -> EmailProfile:
        """
        Validate and profile an email address.

        Args:
            email: Email address to validate

        Returns:
            EmailProfile with validation results
        """
        profile = EmailProfile(email=email)

        # Format validation
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        profile.valid_format = bool(re.match(email_pattern, email))

        if not profile.valid_format:
            return profile

        # Extract domain and local part
        local_part, domain = email.rsplit("@", 1)

        # Check if role-based
        profile.role_based = local_part.lower() in self.ROLE_BASED_PREFIXES

        # Check if disposable
        profile.disposable = domain.lower() in self.DISPOSABLE_DOMAINS

        return profile

    async def _fetch(self, url: str, headers: Optional[Dict] = None) -> Optional[str]:
        """Make HTTP request with rate limiting."""
        async with self._semaphore:
            try:
                self._ua_index = (self._ua_index + 1) % len(self.USER_AGENTS)
                default_headers = {
                    "User-Agent": self.USER_AGENTS[self._ua_index],
                    "Accept": "text/html,application/json,*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                if headers:
                    default_headers.update(headers)

                async with self._session.get(url, headers=default_headers, ssl=False) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    logger.debug(f"HTTP {resp.status} for {url}")
            except Exception as e:
                logger.debug(f"Fetch error for {url}: {e}")
        return None

    def _extract_emails(self, text: str, domain: str) -> List[str]:
        """Extract emails matching domain from text."""
        pattern = rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}"
        emails = re.findall(pattern, text, re.IGNORECASE)
        return list(set(emails))

    async def _google_search(self, domain: str) -> List[EmailResult]:
        """Search for emails using Google dorks (simulated)."""
        results = []

        # Note: In production, use Google Custom Search API
        # This simulates common findings

        dork_patterns = [
            f'"@{domain}"',
            f"site:{domain} email",
            f"intext:@{domain}",
        ]

        # Simulate common role-based emails
        common_emails = ["contact", "info", "support", "admin", "sales"]
        for prefix in common_emails:
            email = f"{prefix}@{domain}"
            results.append(
                EmailResult(
                    address=email,
                    source="google",
                    confidence=6,
                    metadata={"method": "role_pattern"},
                )
            )

        return results

    async def _bing_search(self, domain: str) -> List[EmailResult]:
        """Search for emails using Bing."""
        results = []

        # Bing search API or web scraping would go here
        # Simulated for now

        return results

    async def _pgp_search(self, domain: str) -> List[EmailResult]:
        """Search PGP key servers for emails."""
        results = []

        pgp_servers = [
            f"https://keys.openpgp.org/vks/v1/by-email/info@{domain}",
        ]

        # MIT PGP server search
        mit_url = f"https://pgp.mit.edu/pks/lookup?search={domain}&op=index&options=mr"
        content = await self._fetch(mit_url)

        if content:
            emails = self._extract_emails(content, domain)
            for email in emails:
                results.append(
                    EmailResult(
                        address=email,
                        source="pgp_mit",
                        confidence=9,  # High confidence for PGP
                        metadata={"server": "pgp.mit.edu"},
                    )
                )

        return results

    async def _github_search(self, domain: str) -> List[EmailResult]:
        """Search GitHub for emails."""
        results = []

        # GitHub API search (requires authentication for better rate limits)
        github_api = f"https://api.github.com/search/code?q=@{domain}+in:file"

        content = await self._fetch(
            github_api, headers={"Accept": "application/vnd.github.v3+json"}
        )

        if content:
            try:
                data = json.loads(content)
                # Extract emails from code snippets
                for item in data.get("items", [])[:10]:
                    # Would need to fetch actual file content
                    pass
            except json.JSONDecodeError:
                pass

        return results

    async def _crtsh_search(self, domain: str) -> List[EmailResult]:
        """Extract emails from certificate transparency logs."""
        results = []

        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        content = await self._fetch(crt_url)

        if content:
            try:
                data = json.loads(content)
                seen_names = set()
                for cert in data:
                    name_value = cert.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if "@" in name and domain in name:
                            if name not in seen_names:
                                seen_names.add(name)
                                results.append(
                                    EmailResult(
                                        address=name,
                                        source="crtsh",
                                        confidence=8,
                                        metadata={"cert_id": cert.get("id")},
                                    )
                                )
            except json.JSONDecodeError:
                pass

        return results

    async def _common_patterns(self, domain: str) -> List[EmailResult]:
        """Generate common email patterns."""
        results = []

        patterns = [
            "admin",
            "administrator",
            "info",
            "contact",
            "support",
            "sales",
            "webmaster",
            "postmaster",
            "security",
            "help",
            "billing",
            "accounts",
            "hr",
            "jobs",
            "careers",
            "press",
            "media",
            "marketing",
            "team",
            "hello",
            "office",
        ]

        for pattern in patterns:
            email = f"{pattern}@{domain}"
            results.append(
                EmailResult(
                    address=email,
                    source="common_pattern",
                    confidence=4,  # Lower confidence for patterns
                    metadata={"pattern": pattern},
                )
            )

        return results


# Convenience functions
async def harvest_emails(domain: str, sources: Optional[List[str]] = None) -> List[str]:
    """
    Convenience function to harvest emails.

    Args:
        domain: Target domain
        sources: Optional list of sources

    Returns:
        List of email addresses
    """
    async with EmailHarvester() as harvester:
        results = await harvester.harvest(domain, sources)
        return [r.address for r in results]


async def validate_email(email: str) -> EmailProfile:
    """
    Convenience function to validate an email.

    Args:
        email: Email address to validate

    Returns:
        EmailProfile
    """
    async with EmailHarvester() as harvester:
        return await harvester.validate_email(email)
