"""
AIPT OSINT Collector

Open-source intelligence gathering from public sources.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OSINTResult:
    """OSINT collection results"""
    target: str
    target_type: str  # domain, email, ip, username

    # Discovered data
    emails: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    social_profiles: list[dict] = field(default_factory=list)
    breaches: list[dict] = field(default_factory=list)
    related_domains: list[str] = field(default_factory=list)
    ip_info: dict = field(default_factory=dict)
    whois_data: dict = field(default_factory=dict)

    # Metadata
    sources_checked: list[str] = field(default_factory=list)
    collected_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "emails_found": len(self.emails),
            "usernames_found": len(self.usernames),
            "social_profiles": len(self.social_profiles),
            "breaches": len(self.breaches),
            "sources_checked": self.sources_checked,
        }


class OSINTCollector:
    """
    OSINT data collector from public sources.

    Sources:
    - Have I Been Pwned (breach data)
    - Hunter.io (email discovery)
    - Shodan (IP/host info)
    - Social media presence checks

    Example:
        collector = OSINTCollector()
        result = await collector.collect_domain("example.com")

        print(f"Emails found: {result.emails}")
        print(f"Breaches: {len(result.breaches)}")
    """

    # Social media platforms to check
    SOCIAL_PLATFORMS = {
        "twitter": "https://twitter.com/{username}",
        "github": "https://github.com/{username}",
        "linkedin": "https://linkedin.com/in/{username}",
        "instagram": "https://instagram.com/{username}",
        "facebook": "https://facebook.com/{username}",
    }

    def __init__(
        self,
        hibp_api_key: str = "",
        hunter_api_key: str = "",
        shodan_api_key: str = "",
    ):
        self.hibp_api_key = hibp_api_key
        self.hunter_api_key = hunter_api_key
        self.shodan_api_key = shodan_api_key

    async def collect_domain(self, domain: str) -> OSINTResult:
        """
        Collect OSINT for a domain.

        Args:
            domain: Target domain

        Returns:
            OSINTResult with discovered data
        """
        result = OSINTResult(target=domain, target_type="domain")

        async with httpx.AsyncClient(timeout=30.0) as client:
            tasks = [
                self._discover_emails(client, domain, result),
                self._check_related_domains(client, domain, result),
                self._get_whois(client, domain, result),
            ]

            await asyncio.gather(*tasks, return_exceptions=True)

        return result

    async def collect_email(self, email: str) -> OSINTResult:
        """
        Collect OSINT for an email address.

        Args:
            email: Target email

        Returns:
            OSINTResult with discovered data
        """
        result = OSINTResult(target=email, target_type="email")

        async with httpx.AsyncClient(timeout=30.0) as client:
            tasks = [
                self._check_breaches(client, email, result),
            ]

            await asyncio.gather(*tasks, return_exceptions=True)

        return result

    async def collect_username(self, username: str) -> OSINTResult:
        """
        Collect OSINT for a username.

        Args:
            username: Target username

        Returns:
            OSINTResult with social profile checks
        """
        result = OSINTResult(target=username, target_type="username")

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            await self._check_social_profiles(client, username, result)

        return result

    async def collect_ip(self, ip: str) -> OSINTResult:
        """
        Collect OSINT for an IP address.

        Args:
            ip: Target IP address

        Returns:
            OSINTResult with IP intelligence
        """
        result = OSINTResult(target=ip, target_type="ip")

        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._get_ip_info(client, ip, result)

        return result

    async def _discover_emails(
        self,
        client: httpx.AsyncClient,
        domain: str,
        result: OSINTResult,
    ) -> None:
        """Discover emails associated with domain"""
        result.sources_checked.append("email_discovery")

        # Hunter.io if API key available
        if self.hunter_api_key:
            try:
                response = await client.get(
                    "https://api.hunter.io/v2/domain-search",
                    params={
                        "domain": domain,
                        "api_key": self.hunter_api_key,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    for email in data.get("data", {}).get("emails", []):
                        if email.get("value"):
                            result.emails.append(email["value"])

            except Exception as e:
                logger.debug(f"Hunter.io error: {e}")

        # Fallback: search common patterns
        common_prefixes = [
            "info", "contact", "admin", "support", "sales", "hello",
            "mail", "webmaster", "postmaster", "abuse",
        ]
        for prefix in common_prefixes:
            result.emails.append(f"{prefix}@{domain}")

    async def _check_breaches(
        self,
        client: httpx.AsyncClient,
        email: str,
        result: OSINTResult,
    ) -> None:
        """Check for breaches using HIBP"""
        result.sources_checked.append("hibp")

        if not self.hibp_api_key:
            logger.debug("No HIBP API key, skipping breach check")
            return

        try:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": self.hibp_api_key,
                    "User-Agent": "AIPT-Scanner",
                },
            )

            if response.status_code == 200:
                for breach in response.json():
                    result.breaches.append({
                        "name": breach.get("Name"),
                        "date": breach.get("BreachDate"),
                        "domain": breach.get("Domain"),
                        "data_classes": breach.get("DataClasses", []),
                    })

        except Exception as e:
            logger.debug(f"HIBP error: {e}")

    async def _check_social_profiles(
        self,
        client: httpx.AsyncClient,
        username: str,
        result: OSINTResult,
    ) -> None:
        """Check social media presence"""
        result.sources_checked.append("social_media")

        async def check_platform(platform: str, url_template: str) -> Optional[dict]:
            url = url_template.format(username=username)
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    return {
                        "platform": platform,
                        "url": url,
                        "exists": True,
                    }
            except Exception:
                pass
            return None

        tasks = [
            check_platform(platform, url)
            for platform, url in self.SOCIAL_PLATFORMS.items()
        ]

        results = await asyncio.gather(*tasks)
        for profile in results:
            if profile:
                result.social_profiles.append(profile)

    async def _check_related_domains(
        self,
        client: httpx.AsyncClient,
        domain: str,
        result: OSINTResult,
    ) -> None:
        """Find related domains"""
        result.sources_checked.append("related_domains")

        # Check common TLDs
        base = domain.rsplit(".", 1)[0]
        tlds = [".com", ".net", ".org", ".io", ".co", ".app", ".dev"]

        for tld in tlds:
            test_domain = base + tld
            if test_domain != domain:
                try:
                    import socket
                    socket.gethostbyname(test_domain)
                    result.related_domains.append(test_domain)
                except socket.gaierror:
                    pass

    async def _get_ip_info(
        self,
        client: httpx.AsyncClient,
        ip: str,
        result: OSINTResult,
    ) -> None:
        """Get IP intelligence"""
        result.sources_checked.append("ip_info")

        # ipinfo.io (no API key needed for basic info)
        try:
            response = await client.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                result.ip_info = response.json()
        except Exception as e:
            logger.debug(f"ipinfo error: {e}")

        # Shodan if API key available
        if self.shodan_api_key:
            try:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": self.shodan_api_key},
                )
                if response.status_code == 200:
                    shodan_data = response.json()
                    result.ip_info["shodan"] = {
                        "ports": shodan_data.get("ports", []),
                        "os": shodan_data.get("os"),
                        "hostnames": shodan_data.get("hostnames", []),
                    }
            except Exception as e:
                logger.debug(f"Shodan error: {e}")

    async def _get_whois(
        self,
        client: httpx.AsyncClient,
        domain: str,
        result: OSINTResult,
    ) -> None:
        """Get WHOIS information"""
        result.sources_checked.append("whois")

        try:
            import whois
            w = whois.whois(domain)
            result.whois_data = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
            }
        except ImportError:
            logger.debug("python-whois not installed")
        except Exception as e:
            logger.debug(f"WHOIS error: {e}")


# Convenience functions
async def osint_domain(domain: str) -> OSINTResult:
    """Quick OSINT for domain"""
    collector = OSINTCollector()
    return await collector.collect_domain(domain)


async def osint_email(email: str, hibp_key: str = "") -> OSINTResult:
    """Quick OSINT for email"""
    collector = OSINTCollector(hibp_api_key=hibp_key)
    return await collector.collect_email(email)


async def osint_username(username: str) -> OSINTResult:
    """Quick social media presence check"""
    collector = OSINTCollector()
    return await collector.collect_username(username)
