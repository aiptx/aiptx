"""
AIPTX Target Analyzer - Zero-Config Target Detection

Automatically analyzes targets to determine:
- Target type (web app, API, SPA, repo, etc.)
- Technology stack
- Features (auth, forms, WebSocket, GraphQL)
- Recommended scan approach
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class TargetType(str, Enum):
    """Types of scan targets."""
    WEB_APP = "web_app"
    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    SPA = "spa"
    WEBSOCKET = "websocket"
    GITHUB_REPO = "github_repo"
    GITLAB_REPO = "gitlab_repo"
    LOCAL_DIRECTORY = "local_directory"
    UNKNOWN = "unknown"


class Technology(str, Enum):
    """Detected technologies."""
    # Frontend
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    JQUERY = "jquery"
    NEXT_JS = "next.js"
    NUXT = "nuxt"

    # Backend
    DJANGO = "django"
    FLASK = "flask"
    FASTAPI = "fastapi"
    EXPRESS = "express"
    SPRING = "spring"
    RAILS = "rails"
    LARAVEL = "laravel"
    ASP_NET = "asp.net"

    # Servers
    NGINX = "nginx"
    APACHE = "apache"
    IIS = "iis"
    CLOUDFLARE = "cloudflare"

    # Languages
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    PHP = "php"
    RUBY = "ruby"
    CSHARP = "csharp"

    # Databases
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    REDIS = "redis"

    # Other
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"


@dataclass
class TargetProfile:
    """Complete profile of a scan target."""
    target: str
    target_type: TargetType
    technologies: list[Technology] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)

    # Web-specific
    url: Optional[str] = None
    base_url: Optional[str] = None
    has_auth: bool = False
    has_forms: bool = False
    has_api: bool = False
    has_graphql: bool = False
    has_websocket: bool = False
    has_file_upload: bool = False

    # Source-specific
    source_path: Optional[str] = None
    languages: dict[str, int] = field(default_factory=dict)

    # Metadata
    server: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    sitemap: list[str] = field(default_factory=list)

    # Recommendations
    recommended_agents: list[str] = field(default_factory=list)
    recommended_scans: list[str] = field(default_factory=list)
    scan_priority: str = "medium"

    def __str__(self) -> str:
        techs = ", ".join(t.value for t in self.technologies[:5])
        return f"TargetProfile({self.target_type.value}, techs=[{techs}])"


class TargetAnalyzer:
    """
    Automatic target analyzer for zero-config scanning.

    Analyzes targets to determine:
    - Type (web, API, SPA, repo, local)
    - Technology stack
    - Security-relevant features
    - Recommended scan approach

    Usage:
        analyzer = TargetAnalyzer()
        profile = await analyzer.analyze("https://example.com")
        print(f"Type: {profile.target_type}")
        print(f"Technologies: {profile.technologies}")
    """

    def __init__(self, timeout: float = 15.0):
        """
        Initialize analyzer.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout

    async def analyze(self, target: str) -> TargetProfile:
        """
        Analyze a target and create a profile.

        Args:
            target: URL, path, or repository URL

        Returns:
            TargetProfile with detected information
        """
        profile = TargetProfile(target=target, target_type=TargetType.UNKNOWN)

        # Determine target type
        if os.path.exists(target):
            profile.target_type = TargetType.LOCAL_DIRECTORY
            profile.source_path = os.path.abspath(target)
            await self._analyze_local_directory(profile)

        elif "github.com" in target:
            profile.target_type = TargetType.GITHUB_REPO
            await self._analyze_github_repo(profile)

        elif "gitlab.com" in target or "gitlab" in target.lower():
            profile.target_type = TargetType.GITLAB_REPO
            await self._analyze_gitlab_repo(profile)

        elif target.startswith(("http://", "https://")):
            profile.url = target
            profile.base_url = self._get_base_url(target)
            await self._analyze_web_target(profile)

        else:
            # Try as URL
            if not target.startswith("http"):
                target = f"https://{target}"
            profile.url = target
            profile.base_url = self._get_base_url(target)
            try:
                await self._analyze_web_target(profile)
            except Exception:
                profile.target_type = TargetType.UNKNOWN

        # Generate recommendations
        self._generate_recommendations(profile)

        return profile

    def _get_base_url(self, url: str) -> str:
        """Extract base URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _analyze_web_target(self, profile: TargetProfile) -> None:
        """Analyze a web target."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    profile.url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    allow_redirects=True,
                ) as response:
                    html = await response.text()
                    headers = dict(response.headers)
                    profile.headers = headers

                    # Detect server
                    profile.server = headers.get("Server", "").split("/")[0]

                    # Detect technologies from headers
                    self._detect_from_headers(profile, headers)

                    # Detect technologies from HTML
                    self._detect_from_html(profile, html)

                    # Detect features
                    self._detect_features(profile, html)

                    # Determine target type
                    self._determine_target_type(profile, html)

                    # Extract endpoints from HTML
                    self._extract_endpoints(profile, html)

        except Exception as e:
            logger.warning(f"Error analyzing web target: {e}")
            profile.target_type = TargetType.WEB_APP

    def _detect_from_headers(self, profile: TargetProfile, headers: dict) -> None:
        """Detect technologies from HTTP headers."""
        header_str = str(headers).lower()

        # Server detection
        server = headers.get("Server", "").lower()
        if "nginx" in server:
            profile.technologies.append(Technology.NGINX)
        if "apache" in server:
            profile.technologies.append(Technology.APACHE)
        if "iis" in server:
            profile.technologies.append(Technology.IIS)

        # Framework detection
        powered_by = headers.get("X-Powered-By", "").lower()
        if "express" in powered_by:
            profile.technologies.append(Technology.EXPRESS)
        if "php" in powered_by:
            profile.technologies.append(Technology.PHP)
        if "asp.net" in powered_by:
            profile.technologies.append(Technology.ASP_NET)

        # CDN/WAF detection
        if "cloudflare" in header_str:
            profile.technologies.append(Technology.CLOUDFLARE)

        # Cookie-based detection
        set_cookie = headers.get("Set-Cookie", "")
        if "csrftoken" in set_cookie.lower():
            profile.technologies.append(Technology.DJANGO)
        if "laravel_session" in set_cookie.lower():
            profile.technologies.append(Technology.LARAVEL)
        if "PHPSESSID" in set_cookie:
            profile.technologies.append(Technology.PHP)

        # Extract cookie names
        profile.cookies = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", set_cookie)

    def _detect_from_html(self, profile: TargetProfile, html: str) -> None:
        """Detect technologies from HTML content."""
        html_lower = html.lower()

        # Frontend frameworks
        if "__NEXT_DATA__" in html or "next.js" in html_lower:
            profile.technologies.append(Technology.NEXT_JS)
            profile.technologies.append(Technology.REACT)
        elif "data-reactroot" in html or "__REACT" in html:
            profile.technologies.append(Technology.REACT)

        if "__VUE__" in html or "v-app" in html or "vue.js" in html_lower:
            profile.technologies.append(Technology.VUE)

        if "ng-app" in html or "ng-version" in html or "angular" in html_lower:
            profile.technologies.append(Technology.ANGULAR)

        if "jquery" in html_lower:
            profile.technologies.append(Technology.JQUERY)

        # Backend frameworks
        if "csrfmiddlewaretoken" in html:
            profile.technologies.append(Technology.DJANGO)

        # CMS detection
        if "wp-content" in html or "wp-includes" in html:
            profile.technologies.append(Technology.WORDPRESS)

        if "drupal" in html_lower:
            profile.technologies.append(Technology.DRUPAL)

        # Remove duplicates
        profile.technologies = list(set(profile.technologies))

    def _detect_features(self, profile: TargetProfile, html: str) -> None:
        """Detect security-relevant features."""
        html_lower = html.lower()

        # Authentication
        auth_indicators = [
            "login", "signin", "sign-in", "password",
            "username", "email", "authenticate"
        ]
        profile.has_auth = any(ind in html_lower for ind in auth_indicators)

        # Forms
        profile.has_forms = "<form" in html_lower

        # File upload
        profile.has_file_upload = (
            'type="file"' in html_lower or
            'enctype="multipart/form-data"' in html_lower
        )

        # API indicators
        api_indicators = ["/api/", "swagger", "openapi", "rest"]
        profile.has_api = any(ind in html_lower for ind in api_indicators)

        # GraphQL
        graphql_indicators = ["graphql", "__schema", "query {", "mutation {"]
        profile.has_graphql = any(ind in html_lower for ind in graphql_indicators)

        # WebSocket
        ws_indicators = ["websocket", "socket.io", "sockjs", "ws://", "wss://"]
        profile.has_websocket = any(ind in html_lower for ind in ws_indicators)

        if profile.has_graphql:
            profile.technologies.append(Technology.GRAPHQL)
        if profile.has_websocket:
            profile.technologies.append(Technology.WEBSOCKET)

    def _determine_target_type(self, profile: TargetProfile, html: str) -> None:
        """Determine the target type based on analysis."""
        if profile.has_graphql:
            profile.target_type = TargetType.GRAPHQL_API
        elif profile.has_websocket:
            profile.target_type = TargetType.WEBSOCKET
        elif self._is_spa(html, profile):
            profile.target_type = TargetType.SPA
        elif profile.has_api and not profile.has_forms:
            profile.target_type = TargetType.REST_API
        else:
            profile.target_type = TargetType.WEB_APP

    def _is_spa(self, html: str, profile: TargetProfile) -> bool:
        """Check if target is a Single-Page Application."""
        spa_frameworks = [
            Technology.REACT, Technology.VUE, Technology.ANGULAR, Technology.NEXT_JS
        ]

        # Has SPA framework
        if any(f in profile.technologies for f in spa_frameworks):
            # And minimal HTML (SPA signature)
            body_match = re.search(r"<body[^>]*>(.*?)</body>", html, re.DOTALL | re.IGNORECASE)
            if body_match:
                body_content = body_match.group(1).strip()
                # SPAs typically have minimal body content
                if len(body_content) < 1000 and ("id=\"root\"" in html or "id=\"app\"" in html):
                    return True

        return False

    def _extract_endpoints(self, profile: TargetProfile, html: str) -> None:
        """Extract endpoints from HTML."""
        # Find href links
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)

        # Find action attributes
        actions = re.findall(r'action=["\']([^"\']+)["\']', html)

        # Find API endpoints in JavaScript
        api_endpoints = re.findall(r'["\']/(api|v\d+)/[^"\']+["\']', html)

        all_endpoints = hrefs + actions + [f"/{e}" for e in api_endpoints]

        # Filter and normalize
        base = urlparse(profile.url)
        for endpoint in all_endpoints:
            if endpoint.startswith("/"):
                profile.endpoints.append(endpoint)
            elif endpoint.startswith(profile.base_url):
                profile.endpoints.append(urlparse(endpoint).path)

        profile.endpoints = list(set(profile.endpoints))[:50]  # Limit

    async def _analyze_local_directory(self, profile: TargetProfile) -> None:
        """Analyze a local directory."""
        profile.languages = {}

        ext_to_lang = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "jsx": "javascript",
            "tsx": "typescript",
            "java": "java",
            "go": "go",
            "rb": "ruby",
            "php": "php",
            "cs": "csharp",
        }

        for root, _, files in os.walk(profile.source_path):
            # Skip common non-source directories
            if any(d in root for d in [".git", "node_modules", "vendor", "__pycache__"]):
                continue

            for filename in files:
                ext = filename.split(".")[-1].lower() if "." in filename else ""
                if ext in ext_to_lang:
                    lang = ext_to_lang[ext]
                    profile.languages[lang] = profile.languages.get(lang, 0) + 1

        # Detect technologies from files
        if os.path.exists(os.path.join(profile.source_path, "package.json")):
            profile.technologies.append(Technology.JAVASCRIPT)
        if os.path.exists(os.path.join(profile.source_path, "requirements.txt")):
            profile.technologies.append(Technology.PYTHON)
        if os.path.exists(os.path.join(profile.source_path, "go.mod")):
            profile.technologies.append(Technology.GO)
        if os.path.exists(os.path.join(profile.source_path, "pom.xml")):
            profile.technologies.append(Technology.JAVA)
        if os.path.exists(os.path.join(profile.source_path, "Gemfile")):
            profile.technologies.append(Technology.RUBY)

    async def _analyze_github_repo(self, profile: TargetProfile) -> None:
        """Analyze a GitHub repository URL."""
        # Extract repo info from URL
        parsed = urlparse(profile.target)
        path_parts = parsed.path.strip("/").split("/")

        if len(path_parts) >= 2:
            owner, repo = path_parts[0], path_parts[1]
            profile.source_path = f"https://github.com/{owner}/{repo}"

    async def _analyze_gitlab_repo(self, profile: TargetProfile) -> None:
        """Analyze a GitLab repository URL."""
        profile.source_path = profile.target

    def _generate_recommendations(self, profile: TargetProfile) -> None:
        """Generate scan recommendations based on profile."""
        agents = []
        scans = []

        # Always recommend recon for web targets
        if profile.target_type not in [TargetType.LOCAL_DIRECTORY, TargetType.GITHUB_REPO]:
            agents.append("ReconAgent")
            scans.append("subdomain_enumeration")
            scans.append("directory_bruteforce")

        # SAST for source code
        if profile.source_path or profile.target_type in [
            TargetType.LOCAL_DIRECTORY, TargetType.GITHUB_REPO
        ]:
            agents.append("SASTAgent")
            scans.append("sast_analysis")
            scans.append("secret_detection")

        # DAST for web targets
        if profile.target_type in [
            TargetType.WEB_APP, TargetType.SPA, TargetType.REST_API
        ]:
            agents.append("DASTAgent")
            scans.append("xss_scan")
            scans.append("sqli_scan")

        # GraphQL specific
        if profile.has_graphql or profile.target_type == TargetType.GRAPHQL_API:
            scans.append("graphql_introspection")
            scans.append("graphql_injection")

        # WebSocket specific
        if profile.has_websocket or profile.target_type == TargetType.WEBSOCKET:
            agents.append("WebSocketAgent")
            scans.append("websocket_injection")

        # Business logic for authenticated apps
        if profile.has_auth:
            agents.append("BusinessLogicAgent")
            scans.append("auth_bypass")
            scans.append("idor_scan")

        # File upload testing
        if profile.has_file_upload:
            scans.append("file_upload_scan")

        # Set priority
        if profile.has_auth or profile.has_api:
            profile.scan_priority = "high"
        elif profile.has_forms or profile.has_file_upload:
            profile.scan_priority = "high"
        else:
            profile.scan_priority = "medium"

        profile.recommended_agents = agents
        profile.recommended_scans = scans


# Convenience function
async def analyze_target(target: str) -> TargetProfile:
    """
    Convenience function to analyze a target.

    Args:
        target: URL, path, or repository URL

    Returns:
        TargetProfile
    """
    analyzer = TargetAnalyzer()
    return await analyzer.analyze(target)
