"""
AIPTX Domain Reconnaissance - OSINT Domain Intelligence.

Comprehensive domain reconnaissance including:
- WHOIS information
- DNS records enumeration
- Subdomain discovery
- Technology detection
- IP intelligence

Integrated from Zen-AI-Pentest for AIPTX v5.2.

Example usage:
    from aipt_v2.osint import DomainRecon

    async with DomainRecon() as recon:
        info = await recon.full_recon("example.com")

        print(f"Subdomains: {len(info.subdomains)}")
        print(f"Technologies: {info.technologies}")
"""

import asyncio
import json
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class DomainInfo:
    """Complete domain reconnaissance results."""

    domain: str

    # WHOIS data
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None

    # DNS records
    name_servers: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)

    # Subdomain enumeration
    subdomains: List[str] = field(default_factory=list)

    # Technology detection
    technologies: List[str] = field(default_factory=list)
    web_server: Optional[str] = None
    cms: Optional[str] = None
    frameworks: List[str] = field(default_factory=list)

    # Security
    has_spf: bool = False
    has_dmarc: bool = False
    has_dkim: bool = False
    ssl_grade: Optional[str] = None

    # Metadata
    recon_timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "whois": {
                "registrar": self.registrar,
                "creation_date": self.creation_date,
                "expiration_date": self.expiration_date,
                "registrant_org": self.registrant_org,
                "registrant_country": self.registrant_country,
            },
            "dns": {
                "name_servers": self.name_servers,
                "ip_addresses": self.ip_addresses,
                "ipv6_addresses": self.ipv6_addresses,
                "mx_records": self.mx_records,
                "txt_records": self.txt_records,
                "cname_records": self.cname_records,
            },
            "subdomains": self.subdomains,
            "technologies": {
                "detected": self.technologies,
                "web_server": self.web_server,
                "cms": self.cms,
                "frameworks": self.frameworks,
            },
            "security": {
                "has_spf": self.has_spf,
                "has_dmarc": self.has_dmarc,
                "has_dkim": self.has_dkim,
                "ssl_grade": self.ssl_grade,
            },
            "recon_timestamp": self.recon_timestamp.isoformat(),
        }


@dataclass
class IPInfo:
    """IP address intelligence."""

    ip: str
    hostname: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False
    is_tor: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "geolocation": {
                "country": self.country,
                "region": self.region,
                "city": self.city,
            },
            "network": {
                "isp": self.isp,
                "org": self.org,
                "asn": self.asn,
            },
            "flags": {
                "is_proxy": self.is_proxy,
                "is_hosting": self.is_hosting,
                "is_tor": self.is_tor,
            },
        }


class DomainRecon:
    """
    Domain reconnaissance and enumeration.

    Features:
    - WHOIS lookup
    - DNS enumeration (A, AAAA, MX, TXT, NS, CNAME)
    - Subdomain discovery (crt.sh, DNS brute, wordlists)
    - Technology fingerprinting
    - IP geolocation
    """

    # Common subdomain wordlist
    SUBDOMAIN_WORDLIST = [
        "www",
        "mail",
        "webmail",
        "ftp",
        "admin",
        "portal",
        "api",
        "app",
        "apps",
        "blog",
        "shop",
        "store",
        "dev",
        "development",
        "test",
        "testing",
        "staging",
        "stage",
        "uat",
        "qa",
        "demo",
        "beta",
        "alpha",
        "cdn",
        "static",
        "assets",
        "media",
        "img",
        "images",
        "files",
        "download",
        "downloads",
        "upload",
        "uploads",
        "secure",
        "ssl",
        "vpn",
        "remote",
        "login",
        "signin",
        "auth",
        "sso",
        "oauth",
        "m",
        "mobile",
        "wap",
        "ns1",
        "ns2",
        "ns3",
        "mx",
        "mx1",
        "mx2",
        "smtp",
        "pop",
        "imap",
        "email",
        "dashboard",
        "panel",
        "cpanel",
        "webmin",
        "plesk",
        "git",
        "gitlab",
        "github",
        "bitbucket",
        "svn",
        "repo",
        "jenkins",
        "ci",
        "build",
        "deploy",
        "prod",
        "production",
        "db",
        "database",
        "mysql",
        "postgres",
        "mongo",
        "redis",
        "cache",
        "search",
        "elastic",
        "kibana",
        "grafana",
        "monitor",
        "status",
        "health",
        "metrics",
        "analytics",
        "tracking",
        "support",
        "help",
        "docs",
        "documentation",
        "wiki",
        "kb",
        "forum",
        "community",
        "social",
        "news",
        "press",
        "ir",
        "careers",
        "jobs",
        "hr",
        "internal",
        "intranet",
        "extranet",
    ]

    # Technology signatures
    TECH_SIGNATURES = {
        "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
        "Drupal": [r"Drupal", r"/sites/default/files"],
        "Joomla": [r"Joomla", r"/components/com_"],
        "Magento": [r"Mage.Cookies", r"/skin/frontend/"],
        "Shopify": [r"cdn.shopify.com", r"shopify"],
        "React": [r"_reactRootContainer", r"react-root"],
        "Angular": [r"ng-version", r"ng-app"],
        "Vue.js": [r"__vue__", r"v-cloak"],
        "jQuery": [r"jquery", r"jQuery"],
        "Bootstrap": [r"bootstrap"],
        "Tailwind": [r"tailwindcss"],
        "Laravel": [r"laravel", r"XSRF-TOKEN"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "Rails": [r"X-Rails", r"_rails"],
        "Express": [r"X-Powered-By: Express"],
        "Next.js": [r"_next", r"__NEXT_DATA__"],
        "Nuxt.js": [r"_nuxt", r"__NUXT__"],
        "CloudFlare": [r"cloudflare", r"cf-ray"],
        "AWS": [r"amazonaws.com", r"aws"],
        "Azure": [r"azure", r"azurewebsites"],
        "Google Cloud": [r"googleapis", r"appspot"],
        "Nginx": [r"nginx"],
        "Apache": [r"Apache", r"mod_"],
        "IIS": [r"IIS", r"Microsoft-IIS"],
        "PHP": [r"\.php", r"PHPSESSID"],
        "ASP.NET": [r"\.aspx", r"__VIEWSTATE", r"ASP.NET"],
    }

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        rate_limit: int = 10,
        wordlist: Optional[List[str]] = None,
    ):
        """
        Initialize domain reconnaissance.

        Args:
            session: Optional aiohttp session
            rate_limit: Maximum concurrent requests
            wordlist: Custom subdomain wordlist
        """
        self._session = session
        self._own_session = session is None
        self._semaphore = asyncio.Semaphore(rate_limit)
        self._wordlist = wordlist or self.SUBDOMAIN_WORDLIST
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

    async def full_recon(self, domain: str) -> DomainInfo:
        """
        Perform comprehensive domain reconnaissance.

        Args:
            domain: Target domain

        Returns:
            DomainInfo with all gathered intelligence
        """
        logger.info(f"Starting full recon for {domain}")
        info = DomainInfo(domain=domain)

        # Run all recon tasks concurrently
        tasks = [
            self._get_whois(domain),
            self._enumerate_dns(domain),
            self._enumerate_subdomains(domain),
            self._detect_technologies(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process WHOIS
        if isinstance(results[0], dict):
            info.registrar = results[0].get("registrar")
            info.creation_date = results[0].get("creation_date")
            info.expiration_date = results[0].get("expiration_date")
            info.registrant_org = results[0].get("registrant_org")
            info.registrant_country = results[0].get("registrant_country")
            info.name_servers = results[0].get("name_servers", [])

        # Process DNS
        if isinstance(results[1], dict):
            info.ip_addresses = results[1].get("A", [])
            info.ipv6_addresses = results[1].get("AAAA", [])
            info.mx_records = results[1].get("MX", [])
            info.txt_records = results[1].get("TXT", [])
            info.cname_records = results[1].get("CNAME", [])

            # Check email security
            for txt in info.txt_records:
                if "v=spf1" in txt:
                    info.has_spf = True
                if "_dmarc" in txt.lower():
                    info.has_dmarc = True

        # Process subdomains
        if isinstance(results[2], list):
            info.subdomains = results[2]

        # Process technologies
        if isinstance(results[3], dict):
            info.technologies = results[3].get("technologies", [])
            info.web_server = results[3].get("web_server")
            info.cms = results[3].get("cms")
            info.frameworks = results[3].get("frameworks", [])

        logger.info(
            f"Recon complete for {domain}: "
            f"{len(info.subdomains)} subdomains, "
            f"{len(info.technologies)} technologies"
        )
        return info

    async def enumerate_subdomains(
        self,
        domain: str,
        methods: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Enumerate subdomains using multiple methods.

        Args:
            domain: Target domain
            methods: Methods to use (crtsh, brute, etc.)

        Returns:
            List of discovered subdomains
        """
        if methods is None:
            methods = ["crtsh", "brute"]

        return await self._enumerate_subdomains(domain, methods)

    async def get_ip_info(self, ip: str) -> IPInfo:
        """
        Get intelligence about an IP address.

        Args:
            ip: IP address

        Returns:
            IPInfo with geolocation and network data
        """
        info = IPInfo(ip=ip)

        # Use ip-api.com (free tier)
        geo_url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,regionName,city,isp,org,as,proxy,hosting"
        )

        content = await self._fetch(geo_url)
        if content:
            try:
                data = json.loads(content)
                if data.get("status") == "success":
                    info.country = data.get("country")
                    info.region = data.get("regionName")
                    info.city = data.get("city")
                    info.isp = data.get("isp")
                    info.org = data.get("org")
                    info.asn = data.get("as")
                    info.is_proxy = data.get("proxy", False)
                    info.is_hosting = data.get("hosting", False)
            except json.JSONDecodeError:
                pass

        return info

    async def _fetch(self, url: str, headers: Optional[Dict] = None) -> Optional[str]:
        """Make HTTP request with rate limiting."""
        async with self._semaphore:
            try:
                self._ua_index = (self._ua_index + 1) % len(self.USER_AGENTS)
                default_headers = {
                    "User-Agent": self.USER_AGENTS[self._ua_index],
                    "Accept": "text/html,application/json,*/*",
                }
                if headers:
                    default_headers.update(headers)

                async with self._session.get(url, headers=default_headers, ssl=False) as resp:
                    if resp.status == 200:
                        return await resp.text()
            except Exception as e:
                logger.debug(f"Fetch error for {url}: {e}")
        return None

    async def _get_whois(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information."""
        # In production, use python-whois or RDAP API
        # For now, use a public WHOIS API

        whois_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON"

        # Fallback to basic lookup
        try:
            # Try socket-based resolution for basic info
            ip = socket.gethostbyname(domain)
            return {
                "name_servers": [],
                "resolved_ip": ip,
            }
        except socket.gaierror:
            return {}

    async def _enumerate_dns(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records."""
        records = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "TXT": [],
            "CNAME": [],
            "NS": [],
        }

        # Use DNS over HTTPS (Cloudflare)
        doh_url = "https://cloudflare-dns.com/dns-query"

        for record_type in ["A", "AAAA", "MX", "TXT", "NS"]:
            url = f"{doh_url}?name={domain}&type={record_type}"
            content = await self._fetch(url, headers={"Accept": "application/dns-json"})

            if content:
                try:
                    data = json.loads(content)
                    for answer in data.get("Answer", []):
                        value = answer.get("data", "").strip('"')
                        if value:
                            records[record_type].append(value)
                except json.JSONDecodeError:
                    pass

        # Check for DMARC record
        dmarc_url = f"{doh_url}?name=_dmarc.{domain}&type=TXT"
        content = await self._fetch(dmarc_url, headers={"Accept": "application/dns-json"})
        if content:
            try:
                data = json.loads(content)
                for answer in data.get("Answer", []):
                    records["TXT"].append(answer.get("data", ""))
            except json.JSONDecodeError:
                pass

        return records

    async def _enumerate_subdomains(
        self,
        domain: str,
        methods: Optional[List[str]] = None,
    ) -> List[str]:
        """Enumerate subdomains using multiple methods."""
        if methods is None:
            methods = ["crtsh", "brute"]

        subdomains: Set[str] = set()

        tasks = []
        if "crtsh" in methods:
            tasks.append(self._crtsh_subdomains(domain))
        if "brute" in methods:
            tasks.append(self._brute_subdomains(domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                subdomains.update(result)

        return sorted(list(subdomains))

    async def _crtsh_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from certificate transparency logs."""
        subdomains = []

        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        content = await self._fetch(crt_url)

        if content:
            try:
                data = json.loads(content)
                seen = set()
                for cert in data:
                    name_value = cert.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        # Skip wildcards and the base domain
                        if name.startswith("*"):
                            name = name[2:]  # Remove *.
                        if name.endswith(domain) and name != domain:
                            if name not in seen:
                                seen.add(name)
                                subdomains.append(name)
            except json.JSONDecodeError:
                pass

        return subdomains

    async def _brute_subdomains(self, domain: str) -> List[str]:
        """Brute force subdomains using wordlist."""
        subdomains = []

        # Use DNS over HTTPS for resolution
        doh_url = "https://cloudflare-dns.com/dns-query"

        async def check_subdomain(word: str) -> Optional[str]:
            subdomain = f"{word}.{domain}"
            url = f"{doh_url}?name={subdomain}&type=A"
            content = await self._fetch(url, headers={"Accept": "application/dns-json"})
            if content:
                try:
                    data = json.loads(content)
                    if data.get("Answer"):
                        return subdomain
                except json.JSONDecodeError:
                    pass
            return None

        # Check subdomains in batches
        tasks = [check_subdomain(word) for word in self._wordlist[:50]]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                subdomains.append(result)

        return subdomains

    async def _detect_technologies(self, domain: str) -> Dict[str, Any]:
        """Detect web technologies."""
        result = {
            "technologies": [],
            "web_server": None,
            "cms": None,
            "frameworks": [],
        }

        # Fetch the main page
        for protocol in ["https", "http"]:
            url = f"{protocol}://{domain}"
            try:
                async with self._semaphore:
                    async with self._session.get(
                        url,
                        headers={"User-Agent": self.USER_AGENTS[0]},
                        ssl=False,
                        allow_redirects=True,
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            headers = resp.headers

                            # Check headers
                            server = headers.get("Server", "").lower()
                            if "nginx" in server:
                                result["web_server"] = "Nginx"
                            elif "apache" in server:
                                result["web_server"] = "Apache"
                            elif "iis" in server:
                                result["web_server"] = "IIS"

                            powered_by = headers.get("X-Powered-By", "")
                            if powered_by:
                                result["technologies"].append(powered_by)

                            # Check content for signatures
                            content_lower = content.lower()
                            for tech, patterns in self.TECH_SIGNATURES.items():
                                for pattern in patterns:
                                    if re.search(pattern, content_lower):
                                        if tech not in result["technologies"]:
                                            result["technologies"].append(tech)
                                            # Categorize
                                            if tech in ["WordPress", "Drupal", "Joomla", "Magento"]:
                                                result["cms"] = tech
                                            elif tech in [
                                                "React",
                                                "Angular",
                                                "Vue.js",
                                                "Laravel",
                                                "Django",
                                                "Rails",
                                            ]:
                                                result["frameworks"].append(tech)
                                        break

                            break  # Success, don't try http
            except Exception as e:
                logger.debug(f"Tech detection error for {url}: {e}")

        return result


# Convenience functions
async def recon_domain(domain: str) -> DomainInfo:
    """
    Convenience function for full domain recon.

    Args:
        domain: Target domain

    Returns:
        DomainInfo
    """
    async with DomainRecon() as recon:
        return await recon.full_recon(domain)


async def enumerate_subdomains(domain: str) -> List[str]:
    """
    Convenience function for subdomain enumeration.

    Args:
        domain: Target domain

    Returns:
        List of subdomains
    """
    async with DomainRecon() as recon:
        return await recon.enumerate_subdomains(domain)


async def get_ip_info(ip: str) -> IPInfo:
    """
    Convenience function for IP lookup.

    Args:
        ip: IP address

    Returns:
        IPInfo
    """
    async with DomainRecon() as recon:
        return await recon.get_ip_info(ip)
