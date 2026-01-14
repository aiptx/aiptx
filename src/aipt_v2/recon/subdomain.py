"""
AIPT Subdomain Enumeration

Subdomain discovery using multiple sources and tools.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Set

import httpx

logger = logging.getLogger(__name__)


@dataclass
class Subdomain:
    """Discovered subdomain"""
    domain: str
    ip: str = ""
    status: str = "unknown"  # alive, dead, unknown
    http_status: int = 0
    https_status: int = 0
    title: str = ""
    source: str = ""
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "status": self.status,
            "http_status": self.http_status,
            "https_status": self.https_status,
            "title": self.title,
            "source": self.source,
        }


@dataclass
class SubdomainConfig:
    """Subdomain enumeration configuration"""
    # Tools to use
    use_subfinder: bool = True
    use_amass: bool = False
    use_crtsh: bool = True
    use_dns_bruteforce: bool = False

    # Verification
    resolve_dns: bool = True
    check_http: bool = True
    timeout: float = 5.0
    concurrent_requests: int = 50

    # Wordlist for bruteforce
    wordlist: list[str] = field(default_factory=lambda: [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "vpn", "gateway", "router", "admin", "administrator",
        "api", "app", "apps", "dev", "development", "staging", "test", "testing",
        "prod", "production", "web", "portal", "secure", "ssl", "cdn", "static",
        "assets", "img", "images", "media", "files", "download", "downloads",
        "blog", "forum", "shop", "store", "support", "help", "docs", "wiki",
        "git", "svn", "repo", "repository", "jenkins", "ci", "build",
        "monitor", "status", "health", "metrics", "grafana", "kibana",
        "db", "database", "mysql", "postgres", "redis", "elastic", "elasticsearch",
        "auth", "login", "sso", "oauth", "identity",
    ])


@dataclass
class SubdomainResult:
    """Subdomain enumeration results"""
    target: str
    subdomains: list[Subdomain] = field(default_factory=list)
    alive_count: int = 0
    total_found: int = 0
    sources_used: list[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    def get_alive(self) -> list[Subdomain]:
        """Get only alive subdomains"""
        return [s for s in self.subdomains if s.status == "alive"]

    def get_by_source(self, source: str) -> list[Subdomain]:
        """Get subdomains from specific source"""
        return [s for s in self.subdomains if s.source == source]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_found": self.total_found,
            "alive_count": self.alive_count,
            "sources_used": self.sources_used,
            "duration_seconds": self.duration_seconds,
            "subdomains": [s.to_dict() for s in self.subdomains],
        }


class SubdomainEnumerator:
    """
    Subdomain enumeration from multiple sources.

    Sources:
    - Subfinder (if installed)
    - Amass (if installed)
    - crt.sh (Certificate Transparency)
    - DNS bruteforce (optional)

    Example:
        enumerator = SubdomainEnumerator(SubdomainConfig(
            use_crtsh=True,
            check_http=True,
        ))
        result = await enumerator.enumerate("example.com")

        for subdomain in result.get_alive():
            print(f"{subdomain.domain} -> {subdomain.ip}")
    """

    def __init__(self, config: Optional[SubdomainConfig] = None):
        self.config = config or SubdomainConfig()
        self._found: Set[str] = set()

    async def enumerate(self, domain: str) -> SubdomainResult:
        """
        Enumerate subdomains for a domain.

        Args:
            domain: Target domain (e.g., example.com)

        Returns:
            SubdomainResult with discovered subdomains
        """
        result = SubdomainResult(target=domain)
        result.start_time = datetime.utcnow()
        self._found.clear()

        # Collect from all sources
        tasks = []

        if self.config.use_crtsh:
            tasks.append(self._from_crtsh(domain))
            result.sources_used.append("crt.sh")

        if self.config.use_subfinder and self._tool_available("subfinder"):
            tasks.append(self._from_subfinder(domain))
            result.sources_used.append("subfinder")

        if self.config.use_amass and self._tool_available("amass"):
            tasks.append(self._from_amass(domain))
            result.sources_used.append("amass")

        if self.config.use_dns_bruteforce:
            tasks.append(self._dns_bruteforce(domain))
            result.sources_used.append("dns_bruteforce")

        # Gather results
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for source_result in results:
            if isinstance(source_result, list):
                for subdomain in source_result:
                    if subdomain.domain not in self._found:
                        self._found.add(subdomain.domain)
                        result.subdomains.append(subdomain)

        result.total_found = len(result.subdomains)

        # Verify subdomains
        if self.config.resolve_dns or self.config.check_http:
            await self._verify_subdomains(result.subdomains)

        result.alive_count = len([s for s in result.subdomains if s.status == "alive"])
        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        logger.info(
            f"Enumeration complete: {result.total_found} found, {result.alive_count} alive"
        )

        return result

    async def _from_crtsh(self, domain: str) -> list[Subdomain]:
        """Query crt.sh certificate transparency logs"""
        subdomains = []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json"
                )

                if response.status_code == 200:
                    data = response.json()

                    for entry in data:
                        name = entry.get("name_value", "")
                        # Split by newlines (can have multiple names)
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            # Clean wildcards
                            sub = sub.replace("*.", "")
                            if sub and sub.endswith(domain) and sub not in self._found:
                                subdomains.append(Subdomain(
                                    domain=sub,
                                    source="crt.sh",
                                ))

        except Exception as e:
            logger.debug(f"crt.sh error: {e}")

        return subdomains

    async def _from_subfinder(self, domain: str) -> list[Subdomain]:
        """Run subfinder"""
        subdomains = []

        try:
            process = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=120.0)

            for line in stdout.decode().strip().split("\n"):
                sub = line.strip().lower()
                if sub and sub not in self._found:
                    subdomains.append(Subdomain(
                        domain=sub,
                        source="subfinder",
                    ))

        except Exception as e:
            logger.debug(f"subfinder error: {e}")

        return subdomains

    async def _from_amass(self, domain: str) -> list[Subdomain]:
        """Run amass"""
        subdomains = []

        try:
            process = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-d", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=300.0)

            for line in stdout.decode().strip().split("\n"):
                sub = line.strip().lower()
                if sub and sub not in self._found:
                    subdomains.append(Subdomain(
                        domain=sub,
                        source="amass",
                    ))

        except Exception as e:
            logger.debug(f"amass error: {e}")

        return subdomains

    async def _dns_bruteforce(self, domain: str) -> list[Subdomain]:
        """Bruteforce subdomains using wordlist"""
        subdomains = []
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)

        async def check_subdomain(word: str) -> Optional[Subdomain]:
            async with semaphore:
                subdomain = f"{word}.{domain}"
                try:
                    socket.setdefaulttimeout(self.config.timeout)
                    ip = socket.gethostbyname(subdomain)
                    return Subdomain(
                        domain=subdomain,
                        ip=ip,
                        status="alive",
                        source="dns_bruteforce",
                    )
                except socket.gaierror:
                    return None

        tasks = [check_subdomain(word) for word in self.config.wordlist]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result and result.domain not in self._found:
                subdomains.append(result)

        return subdomains

    async def _verify_subdomains(self, subdomains: list[Subdomain]) -> None:
        """Verify subdomains are alive"""
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)

        async def verify(subdomain: Subdomain) -> None:
            async with semaphore:
                # DNS resolution
                if self.config.resolve_dns and not subdomain.ip:
                    try:
                        subdomain.ip = socket.gethostbyname(subdomain.domain)
                    except socket.gaierror:
                        subdomain.status = "dead"
                        return

                # HTTP check
                if self.config.check_http:
                    try:
                        async with httpx.AsyncClient(
                            timeout=self.config.timeout,
                            follow_redirects=True,
                            verify=False,
                        ) as client:
                            # Try HTTPS first
                            try:
                                response = await client.get(f"https://{subdomain.domain}")
                                subdomain.https_status = response.status_code
                                subdomain.status = "alive"

                                # Extract title
                                title_match = re.search(
                                    r"<title[^>]*>([^<]+)</title>",
                                    response.text,
                                    re.IGNORECASE,
                                )
                                if title_match:
                                    subdomain.title = title_match.group(1).strip()[:100]

                            except Exception:
                                # Try HTTP
                                try:
                                    response = await client.get(f"http://{subdomain.domain}")
                                    subdomain.http_status = response.status_code
                                    subdomain.status = "alive"
                                except Exception:
                                    pass

                    except Exception:
                        pass

                # Mark as alive if we got an IP
                if subdomain.ip and subdomain.status == "unknown":
                    subdomain.status = "alive"

        await asyncio.gather(*[verify(s) for s in subdomains])

    def _tool_available(self, tool: str) -> bool:
        """Check if tool is available"""
        import shutil
        return shutil.which(tool) is not None


# Convenience function
async def enumerate_subdomains(domain: str, quick: bool = True) -> SubdomainResult:
    """Quick subdomain enumeration"""
    config = SubdomainConfig(
        use_subfinder=not quick,
        use_amass=False,
        use_crtsh=True,
        use_dns_bruteforce=not quick,
        check_http=True,
    )
    enumerator = SubdomainEnumerator(config)
    return await enumerator.enumerate(domain)
