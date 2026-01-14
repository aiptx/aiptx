"""
AIPT Technology Detection

Web technology fingerprinting and stack detection.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """Detected technology"""
    name: str
    category: str  # frontend, backend, framework, cms, server, etc.
    version: str = ""
    confidence: int = 100  # 0-100
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
        }


@dataclass
class TechStack:
    """Complete technology stack"""
    url: str
    technologies: list[Technology] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.utcnow)

    def get_by_category(self, category: str) -> list[Technology]:
        """Get technologies by category"""
        return [t for t in self.technologies if t.category == category]

    def has_tech(self, name: str) -> bool:
        """Check if specific technology is present"""
        return any(t.name.lower() == name.lower() for t in self.technologies)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "technologies": [t.to_dict() for t in self.technologies],
            "categories": list(set(t.category for t in self.technologies)),
        }


class TechDetector:
    """
    Web technology fingerprinting.

    Detects:
    - Web servers (nginx, Apache, IIS)
    - Frameworks (React, Vue, Angular, Django, Rails)
    - CMS (WordPress, Drupal, Joomla)
    - JavaScript libraries
    - Security tools (WAF, CDN)

    Example:
        detector = TechDetector()
        stack = await detector.detect("https://example.com")

        for tech in stack.technologies:
            print(f"{tech.category}: {tech.name} {tech.version}")
    """

    # Technology fingerprints
    FINGERPRINTS = {
        # Headers
        "headers": {
            "Server": {
                "nginx": ("nginx", "server"),
                "Apache": ("Apache", "server"),
                "Microsoft-IIS": ("IIS", "server"),
                "cloudflare": ("Cloudflare", "cdn"),
                "AmazonS3": ("Amazon S3", "storage"),
                "Varnish": ("Varnish", "cache"),
                "gunicorn": ("Gunicorn", "server"),
                "uvicorn": ("Uvicorn", "server"),
            },
            "X-Powered-By": {
                "PHP": ("PHP", "language"),
                "ASP.NET": ("ASP.NET", "framework"),
                "Express": ("Express.js", "framework"),
                "Next.js": ("Next.js", "framework"),
                "Nuxt": ("Nuxt.js", "framework"),
            },
            "X-Generator": {
                "WordPress": ("WordPress", "cms"),
                "Drupal": ("Drupal", "cms"),
                "Joomla": ("Joomla", "cms"),
            },
        },
        # HTML patterns
        "html": [
            # Frameworks
            (r"react", "React", "frontend"),
            (r"ng-app|angular", "Angular", "frontend"),
            (r"vue\.js|v-cloak|v-bind", "Vue.js", "frontend"),
            (r"svelte", "Svelte", "frontend"),
            (r"ember", "Ember.js", "frontend"),

            # CMS
            (r"wp-content|wp-includes", "WordPress", "cms"),
            (r"drupal\.js|drupal\.settings", "Drupal", "cms"),
            (r"joomla", "Joomla", "cms"),
            (r"shopify", "Shopify", "ecommerce"),
            (r"magento", "Magento", "ecommerce"),
            (r"woocommerce", "WooCommerce", "ecommerce"),

            # JavaScript libraries
            (r"jquery[\.-]?\d|jquery\.min\.js", "jQuery", "javascript"),
            (r"bootstrap[\.-]?\d|bootstrap\.min", "Bootstrap", "css"),
            (r"tailwind", "Tailwind CSS", "css"),
            (r"lodash", "Lodash", "javascript"),
            (r"moment\.js|moment\.min", "Moment.js", "javascript"),
            (r"axios", "Axios", "javascript"),

            # Analytics
            (r"google-analytics|gtag|ga\.js", "Google Analytics", "analytics"),
            (r"googletagmanager", "Google Tag Manager", "analytics"),
            (r"facebook.*pixel|fbq\(", "Facebook Pixel", "analytics"),
            (r"hotjar", "Hotjar", "analytics"),
            (r"segment\.io|analytics\.js", "Segment", "analytics"),

            # Security
            (r"recaptcha", "reCAPTCHA", "security"),
            (r"hcaptcha", "hCaptcha", "security"),
            (r"cloudflare", "Cloudflare", "cdn"),
            (r"akamai", "Akamai", "cdn"),
            (r"fastly", "Fastly", "cdn"),

            # Other
            (r"webpack", "Webpack", "build"),
            (r"vite", "Vite", "build"),
            (r"graphql", "GraphQL", "api"),
            (r"socket\.io", "Socket.IO", "websocket"),
        ],
        # Cookie patterns
        "cookies": {
            "PHPSESSID": ("PHP", "language"),
            "ASP.NET_SessionId": ("ASP.NET", "framework"),
            "JSESSIONID": ("Java", "language"),
            "rack.session": ("Ruby/Rack", "framework"),
            "express.sid": ("Express.js", "framework"),
            "connect.sid": ("Connect.js", "framework"),
            "laravel_session": ("Laravel", "framework"),
            "django": ("Django", "framework"),
            "wordpress": ("WordPress", "cms"),
            "wp-settings": ("WordPress", "cms"),
            "__cf_bm": ("Cloudflare", "cdn"),
        },
    }

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def detect(self, url: str) -> TechStack:
        """
        Detect technologies used by a website.

        Args:
            url: Target URL

        Returns:
            TechStack with detected technologies
        """
        stack = TechStack(url=url)

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.get(url)

                # Store headers
                stack.headers = dict(response.headers)

                # Store cookies
                stack.cookies = [c for c in response.cookies.keys()]

                # Detect from headers
                self._detect_from_headers(response.headers, stack)

                # Detect from cookies
                self._detect_from_cookies(response.cookies, stack)

                # Detect from HTML
                self._detect_from_html(response.text, stack)

                # Extract versions where possible
                self._extract_versions(response.text, stack)

        except Exception as e:
            logger.error(f"Tech detection error: {e}")

        # Deduplicate
        seen = set()
        unique = []
        for tech in stack.technologies:
            key = (tech.name, tech.category)
            if key not in seen:
                seen.add(key)
                unique.append(tech)
        stack.technologies = unique

        logger.info(f"Detected {len(stack.technologies)} technologies")
        return stack

    def _detect_from_headers(self, headers: httpx.Headers, stack: TechStack) -> None:
        """Detect technologies from HTTP headers"""
        for header, patterns in self.FINGERPRINTS["headers"].items():
            value = headers.get(header, "")
            if value:
                for pattern, (name, category) in patterns.items():
                    if pattern.lower() in value.lower():
                        # Extract version if present
                        version = ""
                        version_match = re.search(rf"{pattern}[/\s]*([\d.]+)", value, re.I)
                        if version_match:
                            version = version_match.group(1)

                        stack.technologies.append(Technology(
                            name=name,
                            category=category,
                            version=version,
                            confidence=100,
                            evidence=f"Header: {header}: {value}",
                        ))

    def _detect_from_cookies(self, cookies: httpx.Cookies, stack: TechStack) -> None:
        """Detect technologies from cookies"""
        for cookie_name in cookies.keys():
            for pattern, (name, category) in self.FINGERPRINTS["cookies"].items():
                if pattern.lower() in cookie_name.lower():
                    stack.technologies.append(Technology(
                        name=name,
                        category=category,
                        confidence=90,
                        evidence=f"Cookie: {cookie_name}",
                    ))

    def _detect_from_html(self, html: str, stack: TechStack) -> None:
        """Detect technologies from HTML content"""
        html_lower = html.lower()

        for pattern, name, category in self.FINGERPRINTS["html"]:
            if re.search(pattern, html_lower):
                stack.technologies.append(Technology(
                    name=name,
                    category=category,
                    confidence=80,
                    evidence=f"HTML pattern: {pattern}",
                ))

        # Check meta generator
        generator_match = re.search(
            r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
            html,
            re.I,
        )
        if generator_match:
            generator = generator_match.group(1)
            stack.technologies.append(Technology(
                name=generator.split()[0],
                category="cms",
                version=generator.split()[1] if len(generator.split()) > 1 else "",
                confidence=100,
                evidence=f"Meta generator: {generator}",
            ))

    def _extract_versions(self, html: str, stack: TechStack) -> None:
        """Try to extract version numbers"""
        # Version patterns for common technologies
        version_patterns = {
            "jQuery": r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)",
            "Bootstrap": r"bootstrap[.-]?(\d+\.\d+(?:\.\d+)?)",
            "React": r"react[.-]?(\d+\.\d+(?:\.\d+)?)",
            "Vue.js": r"vue[.-]?(\d+\.\d+(?:\.\d+)?)",
            "Angular": r"angular[.-]?(\d+\.\d+(?:\.\d+)?)",
        }

        for tech in stack.technologies:
            if not tech.version and tech.name in version_patterns:
                pattern = version_patterns[tech.name]
                match = re.search(pattern, html, re.I)
                if match:
                    tech.version = match.group(1)


# Convenience function
async def detect_tech(url: str) -> TechStack:
    """Quick technology detection"""
    detector = TechDetector()
    return await detector.detect(url)
