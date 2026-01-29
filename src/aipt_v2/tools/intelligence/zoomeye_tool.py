"""
ZoomEye Intelligence Integration for AIPTX

Provides passive reconnaissance through ZoomEye's cyberspace search engine.
Discovers related IPs, domains, services, and infrastructure information.

Environment Variables:
    ZOOMEYE_API_KEY: ZoomEye API key (get from https://www.zoomeye.ai profile)

Usage:
    from aipt_v2.tools.intelligence import get_zoomeye, zoomeye_domain_search

    zoomeye = get_zoomeye()
    if zoomeye.connect():
        # Search by domain
        results = zoomeye.search_domain("example.com")
        for host in results.hosts:
            print(f"{host.ip}:{host.port} - {host.service}")

        # Search by organization
        results = zoomeye.search_org("Example Corp")

References:
    - ZoomEye API: https://www.zoomeye.ai/doc
    - MCP Server: https://github.com/zoomeye-ai/mcp_zoomeye
"""

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ==================== Data Classes ====================

@dataclass
class ZoomEyeConfig:
    """Configuration for ZoomEye connection."""
    api_key: str = field(default_factory=lambda: os.getenv("ZOOMEYE_API_KEY", ""))
    base_url: str = "https://api.zoomeye.ai"
    timeout: int = 30
    max_results: int = 100  # Max results per query
    cache_ttl: int = 3600   # Cache TTL in seconds (1 hour)


@dataclass
class ZoomEyeHost:
    """Represents a discovered host from ZoomEye."""
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    domain: str = ""
    hostname: str = ""
    os: str = ""
    country: str = ""
    city: str = ""
    isp: str = ""
    asn: int = 0
    org: str = ""
    banner: str = ""
    title: str = ""
    app: str = ""
    version: str = ""
    ssl_cert: Dict = field(default_factory=dict)
    last_updated: str = ""
    raw_data: Dict = field(default_factory=dict)


@dataclass
class ZoomEyeResult:
    """Result of a ZoomEye search."""
    query: str
    total: int = 0
    hosts: List[ZoomEyeHost] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    services: Dict[str, int] = field(default_factory=dict)  # service -> count
    countries: Dict[str, int] = field(default_factory=dict)  # country -> count
    ports: Dict[int, int] = field(default_factory=dict)  # port -> count
    error: str = ""
    cached: bool = False
    search_time: float = 0.0


# ==================== Main Tool Class ====================

class ZoomEyeTool:
    """
    ZoomEye Cyberspace Search Engine integration.

    Provides passive reconnaissance capabilities:
    - Domain search: Find all hosts associated with a domain
    - IP search: Find services on specific IPs
    - Organization search: Find assets by organization name
    - Service search: Find specific services/applications
    - Certificate search: Find hosts by SSL certificate info
    """

    def __init__(self, config: Optional[ZoomEyeConfig] = None):
        """Initialize ZoomEye tool with configuration."""
        self.config = config or ZoomEyeConfig()
        self._session = requests.Session()
        self._connected = False
        self._cache: Dict[str, tuple] = {}  # query -> (result, timestamp)
        self._quota_info: Dict = {}

        # Set headers
        self._session.headers.update({
            "API-KEY": self.config.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _encode_query(self, query: str) -> str:
        """Base64 encode a query string for the API."""
        return base64.b64encode(query.encode()).decode()

    def _decode_query(self, encoded: str) -> str:
        """Decode a base64 query string."""
        return base64.b64decode(encoded.encode()).decode()

    def _get_cached(self, query: str) -> Optional[ZoomEyeResult]:
        """Check cache for a query result."""
        if query in self._cache:
            result, timestamp = self._cache[query]
            if time.time() - timestamp < self.config.cache_ttl:
                result.cached = True
                return result
            else:
                del self._cache[query]
        return None

    def _set_cache(self, query: str, result: ZoomEyeResult):
        """Cache a query result."""
        self._cache[query] = (result, time.time())

    def _request(self, endpoint: str, params: dict = None) -> dict:
        """Make authenticated request to ZoomEye API."""
        url = f"{self.config.base_url}{endpoint}"
        try:
            response = self._session.get(
                url,
                params=params,
                timeout=self.config.timeout
            )

            # Handle rate limiting
            if response.status_code == 429:
                logger.warning("ZoomEye rate limit reached")
                return {"error": "Rate limit exceeded. Please wait."}

            # Handle auth errors
            if response.status_code == 401:
                logger.error("ZoomEye authentication failed")
                return {"error": "Invalid API key"}

            if response.status_code == 403:
                logger.error("ZoomEye access forbidden")
                return {"error": "Access forbidden - check API key permissions"}

            # Handle server errors (5xx)
            if response.status_code >= 500:
                logger.warning(f"ZoomEye server error: {response.status_code}")
                return {"error": f"ZoomEye server error ({response.status_code}) - service may be temporarily unavailable"}

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            logger.error("ZoomEye request timed out")
            return {"error": "Request timed out"}
        except requests.exceptions.RequestException as e:
            logger.error(f"ZoomEye API error: {e}")
            return {"error": str(e)}

    # ==================== Connection ====================

    def connect(self) -> bool:
        """Test connection and verify API key."""
        if not self.config.api_key:
            logger.error("ZoomEye API key not configured")
            return False

        try:
            # Use resources/info endpoint to verify credentials
            result = self._request("/resources-info")
            if "error" in result:
                logger.error(f"ZoomEye connection failed: {result['error']}")
                return False

            self._connected = True
            self._quota_info = result

            # Log quota info
            resources = result.get("resources", {})
            logger.info(f"Connected to ZoomEye - Quota: {resources.get('search', 'N/A')} searches remaining")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to ZoomEye: {e}")
            self._connected = False
            return False

    def is_connected(self) -> bool:
        """Check if connected to ZoomEye."""
        return self._connected

    def get_quota(self) -> Dict:
        """Get current API quota information."""
        if not self._connected:
            self.connect()
        return self._quota_info

    # ==================== Search Methods ====================

    def search(
        self,
        query: str,
        page: int = 1,
        pagesize: int = 20,
        sub_type: str = "v4",
        fields: str = None,
        use_cache: bool = True
    ) -> ZoomEyeResult:
        """
        Execute a ZoomEye search query.

        Args:
            query: ZoomEye query string (e.g., 'hostname:"example.com"')
            page: Page number (1-based)
            pagesize: Results per page (max 1000)
            sub_type: Data type - 'v4' (IPv4), 'v6' (IPv6), 'web' (websites)
            fields: Comma-separated field names to return
            use_cache: Whether to use cached results

        Returns:
            ZoomEyeResult with discovered hosts and aggregated data

        Query Syntax Examples:
            - hostname:"example.com"
            - site:"example.com"
            - ip:"1.2.3.4"
            - cidr:"192.168.1.0/24"
            - org:"Example Corp"
            - app:"Apache"
            - port:443
            - ssl.cert.subject.cn:"example.com"
        """
        # Check cache first
        cache_key = f"{query}:{page}:{pagesize}:{sub_type}"
        if use_cache:
            cached = self._get_cached(cache_key)
            if cached:
                logger.debug(f"ZoomEye cache hit for: {query}")
                return cached

        start_time = time.time()

        # Build request parameters
        params = {
            "qbase64": self._encode_query(query),
            "page": page,
            "pagesize": min(pagesize, 1000),
            "sub_type": sub_type,
        }
        if fields:
            params["fields"] = fields

        # Make request
        response = self._request("/host/search", params)

        if "error" in response:
            return ZoomEyeResult(
                query=query,
                error=response["error"],
                search_time=time.time() - start_time
            )

        # Parse results
        result = self._parse_search_results(query, response)
        result.search_time = time.time() - start_time

        # Cache the result
        if use_cache and not result.error:
            self._set_cache(cache_key, result)

        logger.info(f"ZoomEye search '{query}' returned {result.total} results")
        return result

    def _parse_search_results(self, query: str, response: dict) -> ZoomEyeResult:
        """Parse ZoomEye API response into structured result."""
        result = ZoomEyeResult(query=query)
        result.total = response.get("total", 0)

        hosts = []
        domains_set = set()
        ips_set = set()
        services_count: Dict[str, int] = {}
        countries_count: Dict[str, int] = {}
        ports_count: Dict[int, int] = {}

        for match in response.get("matches", []):
            # Parse host data
            portinfo = match.get("portinfo", {})
            geoinfo = match.get("geoinfo", {})

            host = ZoomEyeHost(
                ip=match.get("ip", ""),
                port=portinfo.get("port", 0),
                protocol=portinfo.get("protocol", "tcp"),
                service=portinfo.get("service", ""),
                domain=portinfo.get("hostname", "") or match.get("rdns", ""),
                hostname=match.get("rdns", ""),
                os=portinfo.get("os", ""),
                country=geoinfo.get("country", {}).get("names", {}).get("en", ""),
                city=geoinfo.get("city", {}).get("names", {}).get("en", ""),
                isp=geoinfo.get("isp", ""),
                asn=geoinfo.get("asn", 0),
                org=geoinfo.get("organization", ""),
                banner=portinfo.get("banner", "")[:500],  # Truncate banner
                title=portinfo.get("title", ""),
                app=portinfo.get("app", ""),
                version=portinfo.get("version", ""),
                ssl_cert=match.get("ssl", {}),
                last_updated=match.get("timestamp", ""),
                raw_data=match,
            )
            hosts.append(host)

            # Aggregate data
            if host.ip:
                ips_set.add(host.ip)
            if host.domain:
                domains_set.add(host.domain)
            if host.service:
                services_count[host.service] = services_count.get(host.service, 0) + 1
            if host.country:
                countries_count[host.country] = countries_count.get(host.country, 0) + 1
            if host.port:
                ports_count[host.port] = ports_count.get(host.port, 0) + 1

        result.hosts = hosts
        result.domains = sorted(domains_set)
        result.ips = sorted(ips_set)
        result.services = dict(sorted(services_count.items(), key=lambda x: -x[1]))
        result.countries = dict(sorted(countries_count.items(), key=lambda x: -x[1]))
        result.ports = dict(sorted(ports_count.items(), key=lambda x: -x[1]))

        return result

    # ==================== Convenience Search Methods ====================

    def search_domain(self, domain: str, include_subdomains: bool = True) -> ZoomEyeResult:
        """
        Search for all hosts associated with a domain.

        Args:
            domain: Target domain (e.g., "example.com")
            include_subdomains: Include subdomains in search

        Returns:
            ZoomEyeResult with discovered hosts
        """
        if include_subdomains:
            # Use site: to include subdomains
            query = f'site:"{domain}"'
        else:
            query = f'hostname:"{domain}"'

        return self.search(query, pagesize=100)

    def search_ip(self, ip: str) -> ZoomEyeResult:
        """
        Search for all services on a specific IP.

        Args:
            ip: Target IP address

        Returns:
            ZoomEyeResult with discovered services
        """
        query = f'ip:"{ip}"'
        return self.search(query, pagesize=100)

    def search_cidr(self, cidr: str) -> ZoomEyeResult:
        """
        Search for hosts in a CIDR range.

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            ZoomEyeResult with discovered hosts
        """
        query = f'cidr:"{cidr}"'
        return self.search(query, pagesize=100)

    def search_org(self, organization: str) -> ZoomEyeResult:
        """
        Search for hosts by organization name.

        Args:
            organization: Organization name

        Returns:
            ZoomEyeResult with discovered hosts
        """
        query = f'org:"{organization}"'
        return self.search(query, pagesize=100)

    def search_asn(self, asn: int) -> ZoomEyeResult:
        """
        Search for hosts by ASN number.

        Args:
            asn: Autonomous System Number

        Returns:
            ZoomEyeResult with discovered hosts
        """
        query = f'asn:{asn}'
        return self.search(query, pagesize=100)

    def search_service(self, service: str, domain: str = None) -> ZoomEyeResult:
        """
        Search for specific services, optionally filtered by domain.

        Args:
            service: Service name (e.g., "nginx", "apache", "ssh")
            domain: Optional domain filter

        Returns:
            ZoomEyeResult with discovered services
        """
        if domain:
            query = f'app:"{service}" site:"{domain}"'
        else:
            query = f'app:"{service}"'
        return self.search(query, pagesize=100)

    def search_ssl_cert(self, cn: str) -> ZoomEyeResult:
        """
        Search for hosts by SSL certificate Common Name.

        Args:
            cn: Certificate Common Name (domain in cert)

        Returns:
            ZoomEyeResult with discovered hosts
        """
        query = f'ssl.cert.subject.cn:"{cn}"'
        return self.search(query, pagesize=100)

    def search_favicon(self, favicon_hash: str) -> ZoomEyeResult:
        """
        Search for hosts by favicon hash.

        Useful for finding related infrastructure using the same favicon.

        Args:
            favicon_hash: Favicon hash (can be computed from favicon.ico)

        Returns:
            ZoomEyeResult with discovered hosts
        """
        query = f'iconhash:"{favicon_hash}"'
        return self.search(query, pagesize=100)

    # ==================== AIPTX Integration ====================

    def to_findings(self, result: ZoomEyeResult) -> List[Dict]:
        """
        Convert ZoomEye results to AIPTX finding format.

        Args:
            result: ZoomEyeResult to convert

        Returns:
            List of AIPTX findings
        """
        findings = []

        # Add discovered IPs as findings
        for host in result.hosts:
            findings.append({
                "type": "discovered_host",
                "value": f"{host.ip}:{host.port}",
                "description": f"{host.service or 'Unknown'} service on {host.ip}:{host.port}",
                "severity": "info",
                "phase": "recon",
                "tool": "zoomeye",
                "target": host.domain or host.ip,
                "metadata": {
                    "ip": host.ip,
                    "port": host.port,
                    "protocol": host.protocol,
                    "service": host.service,
                    "app": host.app,
                    "version": host.version,
                    "os": host.os,
                    "country": host.country,
                    "city": host.city,
                    "org": host.org,
                    "asn": host.asn,
                    "title": host.title,
                    "banner_preview": host.banner[:200] if host.banner else "",
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        # Add discovered subdomains as findings
        for domain in result.domains:
            if domain:
                findings.append({
                    "type": "subdomain",
                    "value": domain,
                    "description": f"Subdomain discovered via ZoomEye: {domain}",
                    "severity": "info",
                    "phase": "recon",
                    "tool": "zoomeye",
                    "target": domain,
                    "metadata": {"source": "zoomeye"},
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })

        return findings

    def get_recon_summary(self, result: ZoomEyeResult) -> Dict:
        """
        Generate a reconnaissance summary from ZoomEye results.

        Args:
            result: ZoomEyeResult to summarize

        Returns:
            Summary dict with aggregated intelligence
        """
        return {
            "query": result.query,
            "total_results": result.total,
            "unique_ips": len(result.ips),
            "unique_domains": len(result.domains),
            "top_services": dict(list(result.services.items())[:10]),
            "top_ports": dict(list(result.ports.items())[:10]),
            "countries": result.countries,
            "search_time": f"{result.search_time:.2f}s",
            "cached": result.cached,
        }


# ==================== Global Instance & Helper Functions ====================

_zoomeye: Optional[ZoomEyeTool] = None


def get_zoomeye(config: Optional[ZoomEyeConfig] = None) -> ZoomEyeTool:
    """Get or create global ZoomEye instance."""
    global _zoomeye
    if _zoomeye is None or config is not None:
        _zoomeye = ZoomEyeTool(config)
    return _zoomeye


def zoomeye_search(query: str, pagesize: int = 20) -> ZoomEyeResult:
    """Quick search using ZoomEye dorks."""
    zoomeye = get_zoomeye()
    if not zoomeye.connect():
        return ZoomEyeResult(query=query, error="Connection failed")
    return zoomeye.search(query, pagesize=pagesize)


def zoomeye_domain_search(domain: str) -> ZoomEyeResult:
    """Search for all hosts related to a domain."""
    zoomeye = get_zoomeye()
    if not zoomeye.connect():
        return ZoomEyeResult(query=f"site:{domain}", error="Connection failed")
    return zoomeye.search_domain(domain)


def zoomeye_ip_search(ip: str) -> ZoomEyeResult:
    """Search for services on a specific IP."""
    zoomeye = get_zoomeye()
    if not zoomeye.connect():
        return ZoomEyeResult(query=f"ip:{ip}", error="Connection failed")
    return zoomeye.search_ip(ip)


def zoomeye_org_search(org: str) -> ZoomEyeResult:
    """Search for hosts by organization name."""
    zoomeye = get_zoomeye()
    if not zoomeye.connect():
        return ZoomEyeResult(query=f"org:{org}", error="Connection failed")
    return zoomeye.search_org(org)


# ==================== CLI Testing ====================

if __name__ == "__main__":
    import sys

    print("ZoomEye Intelligence Tool Test")
    print("=" * 50)

    zoomeye = get_zoomeye()

    if zoomeye.connect():
        print(f"[+] Connected to ZoomEye")
        quota = zoomeye.get_quota()
        print(f"    Quota: {quota.get('resources', {})}")

        if len(sys.argv) > 1:
            target = sys.argv[1]
            print(f"\n[*] Searching for: {target}")

            # Search by domain
            result = zoomeye.search_domain(target)

            if result.error:
                print(f"[-] Error: {result.error}")
            else:
                print(f"[+] Total results: {result.total}")
                print(f"[+] Unique IPs: {len(result.ips)}")
                print(f"[+] Unique domains: {len(result.domains)}")
                print(f"[+] Top services: {dict(list(result.services.items())[:5])}")
                print(f"[+] Top ports: {dict(list(result.ports.items())[:5])}")

                print(f"\n[*] Sample hosts:")
                for host in result.hosts[:5]:
                    print(f"    {host.ip}:{host.port} - {host.service} ({host.country})")
        else:
            print("\nUsage: python zoomeye_tool.py <domain>")
    else:
        print("[-] Failed to connect to ZoomEye")
        print("    Set ZOOMEYE_API_KEY environment variable")
