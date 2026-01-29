"""
API Endpoint Discovery

Automatic API endpoint detection and enumeration:
- OpenAPI/Swagger spec detection
- GraphQL endpoint detection
- Common API path fuzzing
- Version enumeration
- Documentation discovery
- Hidden endpoint detection

Usage:
    from aipt_v2.tools.api_security import APIDiscovery

    discovery = APIDiscovery("https://target.com")
    endpoints = await discovery.discover()
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse

from aipt_v2.core.event_loop_manager import current_time

try:
    import aiohttp
except ImportError:
    aiohttp = None


@dataclass
class DiscoveredEndpoint:
    """Discovered API endpoint."""
    url: str
    method: str
    status_code: int
    endpoint_type: str  # rest, graphql, swagger, soap, grpc
    content_type: str
    response_size: int
    auth_required: bool
    documentation_url: str = ""
    version: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class APIDiscoveryConfig:
    """API discovery configuration."""
    base_url: str

    # Discovery options
    discover_swagger: bool = True
    discover_graphql: bool = True
    discover_common_paths: bool = True
    discover_versions: bool = True

    # Authentication
    auth_token: str = ""
    api_key: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    # Performance
    max_concurrent: int = 10
    timeout: int = 10
    delay_ms: int = 50


@dataclass
class APIDiscoveryResult:
    """Result of API discovery."""
    base_url: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    endpoints: List[DiscoveredEndpoint]
    swagger_specs: List[str]
    graphql_endpoints: List[str]
    api_versions: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class APIDiscovery:
    """
    API Endpoint Discovery Tool.

    Automatically discovers and enumerates API endpoints
    through various techniques including spec detection,
    common path fuzzing, and version enumeration.
    """

    # OpenAPI/Swagger spec locations
    SWAGGER_PATHS = [
        "/openapi.json", "/openapi.yaml",
        "/swagger.json", "/swagger.yaml",
        "/api-docs", "/api-docs.json",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/swagger-resources",
        "/api/swagger.json", "/api/openapi.json",
        "/.well-known/openapi.json",
        "/docs", "/docs/", "/redoc",
        "/api/docs", "/api/documentation"
    ]

    # GraphQL common endpoints
    GRAPHQL_PATHS = [
        "/graphql", "/graphiql", "/graphql/console",
        "/api/graphql", "/v1/graphql",
        "/gql", "/query",
        "/graphql/v1", "/graphql/v2"
    ]

    # Common API paths to enumerate
    COMMON_API_PATHS = [
        # Authentication
        "/api/auth", "/api/login", "/api/logout", "/api/register",
        "/api/oauth", "/api/token", "/api/refresh",
        "/auth/login", "/auth/token", "/oauth/token",

        # User management
        "/api/users", "/api/user", "/api/me", "/api/profile",
        "/api/account", "/api/accounts",
        "/users", "/user", "/me", "/profile",

        # Common resources
        "/api/items", "/api/products", "/api/orders",
        "/api/customers", "/api/data", "/api/resources",

        # Admin endpoints
        "/api/admin", "/admin/api", "/api/internal",
        "/api/management", "/api/config", "/api/settings",

        # Health/Status
        "/api/health", "/api/status", "/api/ping",
        "/health", "/healthz", "/ready", "/status",
        "/_health", "/_status",

        # Info/Debug
        "/api/info", "/api/version", "/api/debug",
        "/info", "/version", "/debug",
        "/actuator", "/actuator/health", "/actuator/info",

        # SOAP/Legacy
        "/soap", "/wsdl", "/service", "/services",
        "/ws", "/webservice"
    ]

    # API version patterns
    VERSION_PATTERNS = [
        "/v1", "/v2", "/v3", "/v4",
        "/api/v1", "/api/v2", "/api/v3",
        "/api/1.0", "/api/2.0", "/api/3.0",
        "/1.0", "/2.0", "/3.0"
    ]

    # GraphQL introspection query
    GRAPHQL_INTROSPECTION = """
    query { __schema { queryType { name } } }
    """

    def __init__(self, base_url: str, config: Optional[APIDiscoveryConfig] = None):
        """
        Initialize API discovery.

        Args:
            base_url: Target base URL
            config: Discovery configuration
        """
        self.base_url = base_url.rstrip("/")
        self.config = config or APIDiscoveryConfig(base_url=base_url)
        self.discovered: Set[str] = set()
        self.endpoints: List[DiscoveredEndpoint] = []
        self.swagger_specs: List[str] = []
        self.graphql_endpoints: List[str] = []
        self.api_versions: List[str] = []

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "User-Agent": "AIPTX-API-Discovery/1.0",
            "Accept": "application/json, text/html, */*"
        }
        headers.update(self.config.headers)

        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"

        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key

        return headers

    async def _check_url(self, path: str, method: str = "GET") -> Optional[DiscoveredEndpoint]:
        """Check if URL exists and is accessible."""
        if aiohttp is None:
            raise ImportError("aiohttp required. Install with: pip install aiohttp")

        url = urljoin(self.base_url, path)

        if url in self.discovered:
            return None

        try:
            await asyncio.sleep(self.config.delay_ms / 1000)

            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    if response.status in [200, 201, 301, 302, 401, 403]:
                        self.discovered.add(url)

                        content_type = response.headers.get("Content-Type", "")
                        body = await response.text()

                        # Determine endpoint type
                        endpoint_type = self._detect_endpoint_type(path, content_type, body)

                        # Check if auth required
                        auth_required = response.status in [401, 403]

                        return DiscoveredEndpoint(
                            url=url,
                            method=method,
                            status_code=response.status,
                            endpoint_type=endpoint_type,
                            content_type=content_type,
                            response_size=len(body),
                            auth_required=auth_required
                        )

        except Exception:
            pass

        return None

    def _detect_endpoint_type(self, path: str, content_type: str, body: str) -> str:
        """Detect the type of API endpoint."""
        path_lower = path.lower()
        content_lower = content_type.lower()
        body_lower = body.lower()

        # GraphQL detection
        if "graphql" in path_lower or "graphiql" in path_lower:
            return "graphql"
        if '"data"' in body and '"__schema"' in body:
            return "graphql"

        # OpenAPI/Swagger detection
        if "swagger" in path_lower or "openapi" in path_lower or "api-docs" in path_lower:
            return "swagger"
        if '"openapi"' in body_lower or '"swagger"' in body_lower:
            return "swagger"

        # SOAP detection
        if "soap" in path_lower or "wsdl" in path_lower:
            return "soap"
        if "xml" in content_lower and ("<wsdl:" in body_lower or "<soap:" in body_lower):
            return "soap"

        # gRPC detection
        if "grpc" in path_lower or "application/grpc" in content_lower:
            return "grpc"

        # Default REST
        return "rest"

    async def discover_swagger(self) -> List[str]:
        """Discover OpenAPI/Swagger specifications."""
        specs = []

        tasks = [self._check_url(path) for path in self.SWAGGER_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, DiscoveredEndpoint):
                if result.endpoint_type == "swagger":
                    specs.append(result.url)
                    self.endpoints.append(result)

        self.swagger_specs = specs
        return specs

    async def discover_graphql(self) -> List[str]:
        """Discover GraphQL endpoints."""
        graphql_eps = []

        for path in self.GRAPHQL_PATHS:
            # Try GET request
            endpoint = await self._check_url(path)
            if endpoint:
                self.endpoints.append(endpoint)
                if endpoint.endpoint_type == "graphql":
                    graphql_eps.append(endpoint.url)
                    continue

            # Try POST with introspection
            url = urljoin(self.base_url, path)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json={"query": self.GRAPHQL_INTROSPECTION},
                        headers={"Content-Type": "application/json", **self._get_headers()},
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            body = await response.text()
                            if "__schema" in body or "queryType" in body:
                                graphql_eps.append(url)
                                self.discovered.add(url)
                                self.endpoints.append(DiscoveredEndpoint(
                                    url=url,
                                    method="POST",
                                    status_code=200,
                                    endpoint_type="graphql",
                                    content_type="application/json",
                                    response_size=len(body),
                                    auth_required=False
                                ))
            except Exception:
                pass

        self.graphql_endpoints = graphql_eps
        return graphql_eps

    async def discover_common_paths(self) -> List[DiscoveredEndpoint]:
        """Discover common API paths."""
        found = []

        # Batch requests with semaphore for rate limiting
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def check_with_limit(path: str):
            async with semaphore:
                return await self._check_url(path)

        tasks = [check_with_limit(path) for path in self.COMMON_API_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, DiscoveredEndpoint):
                found.append(result)
                self.endpoints.append(result)

        return found

    async def discover_versions(self) -> List[str]:
        """Discover API versions."""
        versions = []

        for version_path in self.VERSION_PATTERNS:
            # Test version root
            endpoint = await self._check_url(version_path)
            if endpoint:
                versions.append(version_path)
                self.endpoints.append(endpoint)

            # Test version with common endpoints
            for suffix in ["/users", "/health", "/status", "/info"]:
                full_path = f"{version_path}{suffix}"
                endpoint = await self._check_url(full_path)
                if endpoint:
                    if version_path not in versions:
                        versions.append(version_path)
                    self.endpoints.append(endpoint)

        self.api_versions = versions
        return versions

    async def discover_from_html(self) -> List[DiscoveredEndpoint]:
        """Extract API endpoints from HTML/JavaScript."""
        found = []

        try:
            async with aiohttp.ClientSession() as session:
                # Fetch main page
                async with session.get(
                    self.base_url,
                    headers=self._get_headers(),
                    ssl=False
                ) as response:
                    body = await response.text()

                    # Extract URLs from HTML/JS
                    url_patterns = [
                        r'["\'](/api/[^"\']+)["\']',
                        r'["\'](/v\d+/[^"\']+)["\']',
                        r'["\'](https?://[^"\']*api[^"\']*)["\']',
                        r'fetch\(["\']([^"\']+)["\']',
                        r'axios\.\w+\(["\']([^"\']+)["\']'
                    ]

                    extracted_urls = set()
                    for pattern in url_patterns:
                        matches = re.findall(pattern, body)
                        extracted_urls.update(matches)

                    for url in extracted_urls:
                        # Normalize URL
                        if url.startswith("/"):
                            url = urljoin(self.base_url, url)
                        elif not url.startswith("http"):
                            continue

                        # Only check URLs from same domain
                        if urlparse(url).netloc == urlparse(self.base_url).netloc:
                            endpoint = await self._check_url(urlparse(url).path)
                            if endpoint:
                                found.append(endpoint)
                                self.endpoints.append(endpoint)

        except Exception:
            pass

        return found

    async def discover_from_robots(self) -> List[str]:
        """Check robots.txt for API paths."""
        paths = []

        try:
            url = urljoin(self.base_url, "/robots.txt")
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        body = await response.text()

                        # Extract Disallow paths
                        for line in body.split("\n"):
                            if line.lower().startswith("disallow:"):
                                path = line.split(":", 1)[1].strip()
                                if "/api" in path.lower() or "/v" in path:
                                    paths.append(path)
                                    endpoint = await self._check_url(path)
                                    if endpoint:
                                        self.endpoints.append(endpoint)

        except Exception:
            pass

        return paths

    async def discover_from_sitemap(self) -> List[str]:
        """Check sitemap for API paths."""
        paths = []

        try:
            for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
                url = urljoin(self.base_url, sitemap_path)
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, ssl=False) as response:
                        if response.status == 200:
                            body = await response.text()

                            # Extract URLs from sitemap
                            urls = re.findall(r"<loc>([^<]+)</loc>", body)
                            for found_url in urls:
                                if "/api" in found_url.lower() or "/v" in found_url:
                                    parsed = urlparse(found_url)
                                    paths.append(parsed.path)
                                    endpoint = await self._check_url(parsed.path)
                                    if endpoint:
                                        self.endpoints.append(endpoint)

        except Exception:
            pass

        return paths

    async def discover(self) -> APIDiscoveryResult:
        """
        Run full API discovery.

        Returns:
            APIDiscoveryResult with all discovered endpoints
        """
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = current_time()

        # Run discovery tasks
        if self.config.discover_swagger:
            await self.discover_swagger()

        if self.config.discover_graphql:
            await self.discover_graphql()

        if self.config.discover_common_paths:
            await self.discover_common_paths()

        if self.config.discover_versions:
            await self.discover_versions()

        # Additional discovery
        await self.discover_from_html()
        await self.discover_from_robots()
        await self.discover_from_sitemap()

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = current_time() - start_time

        # Deduplicate endpoints
        seen = set()
        unique_endpoints = []
        for ep in self.endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)

        return APIDiscoveryResult(
            base_url=self.base_url,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            endpoints=unique_endpoints,
            swagger_specs=self.swagger_specs,
            graphql_endpoints=self.graphql_endpoints,
            api_versions=self.api_versions,
            metadata={
                "urls_checked": len(self.discovered),
                "endpoints_found": len(unique_endpoints)
            }
        )


# Convenience function
async def discover_api(
    base_url: str,
    auth_token: Optional[str] = None,
    full_scan: bool = True
) -> APIDiscoveryResult:
    """
    Quick API discovery.

    Args:
        base_url: Target base URL
        auth_token: Optional bearer token
        full_scan: Run comprehensive discovery

    Returns:
        APIDiscoveryResult
    """
    config = APIDiscoveryConfig(
        base_url=base_url,
        auth_token=auth_token or "",
        discover_swagger=True,
        discover_graphql=True,
        discover_common_paths=full_scan,
        discover_versions=full_scan
    )

    discovery = APIDiscovery(base_url, config)
    return await discovery.discover()


async def quick_api_check(base_url: str) -> Dict[str, Any]:
    """
    Quick check for API presence.

    Args:
        base_url: Target URL

    Returns:
        Dict with API detection results
    """
    discovery = APIDiscovery(base_url)

    result = {
        "has_swagger": False,
        "has_graphql": False,
        "has_api": False,
        "swagger_url": None,
        "graphql_url": None,
        "api_version": None
    }

    # Quick checks
    swagger = await discovery.discover_swagger()
    if swagger:
        result["has_swagger"] = True
        result["swagger_url"] = swagger[0]

    graphql = await discovery.discover_graphql()
    if graphql:
        result["has_graphql"] = True
        result["graphql_url"] = graphql[0]

    versions = await discovery.discover_versions()
    if versions:
        result["has_api"] = True
        result["api_version"] = versions[0]

    return result
