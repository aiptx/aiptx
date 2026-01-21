"""
AIPTX Beast Mode - Context Analyzer
===================================

Analyze target context to optimize payload selection and mutation.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class TargetContext:
    """Analyzed context of a target."""
    target_url: str
    technology_stack: list[str] = field(default_factory=list)
    web_server: str | None = None
    backend_language: str | None = None
    framework: str | None = None
    database: str | None = None
    waf: str | None = None
    cms: str | None = None
    cdn: str | None = None
    cloud_provider: str | None = None
    response_patterns: dict[str, str] = field(default_factory=dict)
    headers_of_interest: dict[str, str] = field(default_factory=dict)
    cookies_of_interest: list[str] = field(default_factory=list)
    confidence_scores: dict[str, float] = field(default_factory=dict)

    def context_hash(self) -> str:
        """Generate a hash representing this context."""
        context_str = f"{self.web_server}:{self.backend_language}:{self.database}:{self.waf}"
        return hashlib.sha256(context_str.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target_url": self.target_url,
            "technology_stack": self.technology_stack,
            "web_server": self.web_server,
            "backend_language": self.backend_language,
            "framework": self.framework,
            "database": self.database,
            "waf": self.waf,
            "cms": self.cms,
            "cdn": self.cdn,
            "cloud_provider": self.cloud_provider,
            "response_patterns": self.response_patterns,
            "headers_of_interest": self.headers_of_interest,
            "cookies_of_interest": self.cookies_of_interest,
            "confidence_scores": self.confidence_scores,
        }

    def get_summary(self) -> str:
        """Get a human-readable summary."""
        parts = []
        if self.web_server:
            parts.append(f"Server: {self.web_server}")
        if self.backend_language:
            parts.append(f"Backend: {self.backend_language}")
        if self.framework:
            parts.append(f"Framework: {self.framework}")
        if self.database:
            parts.append(f"DB: {self.database}")
        if self.waf:
            parts.append(f"WAF: {self.waf}")
        if self.cms:
            parts.append(f"CMS: {self.cms}")

        return " | ".join(parts) if parts else "Unknown context"


# Technology detection patterns
TECH_PATTERNS = {
    # Web servers
    "server": {
        "nginx": [r"nginx", r"server:\s*nginx"],
        "apache": [r"apache", r"server:\s*apache"],
        "iis": [r"microsoft-iis", r"iis", r"asp\.net"],
        "cloudflare": [r"cloudflare"],
        "litespeed": [r"litespeed"],
        "tomcat": [r"tomcat", r"coyote"],
    },

    # Backend languages
    "backend": {
        "php": [
            r"\.php[?#]?",
            r"x-powered-by:\s*php",
            r"phpsessid",
            r"<?php",
        ],
        "python": [
            r"x-powered-by:\s*python",
            r"wsgi",
            r"django",
            r"flask",
        ],
        "java": [
            r"\.jsp[?#]?",
            r"\.do[?#]?",
            r"jsessionid",
            r"x-powered-by:\s*servlet",
        ],
        "nodejs": [
            r"x-powered-by:\s*express",
            r"connect\.sid",
        ],
        "ruby": [
            r"x-powered-by:\s*phusion passenger",
            r"_session_id",
            r"rails",
        ],
        "aspnet": [
            r"\.aspx?[?#]?",
            r"asp\.net",
            r"__viewstate",
            r"\.ashx",
        ],
    },

    # Frameworks
    "framework": {
        "django": [r"csrfmiddlewaretoken", r"django"],
        "flask": [r"werkzeug", r"flask"],
        "laravel": [r"laravel_session", r"xsrf-token"],
        "rails": [r"rails", r"_rails_"],
        "spring": [r"spring", r"jsessionid"],
        "express": [r"express", r"connect\.sid"],
        "angular": [r"ng-", r"angular"],
        "react": [r"react", r"__react"],
        "vue": [r"vue", r"data-v-"],
    },

    # Databases (from errors/patterns)
    "database": {
        "mysql": [
            r"mysql",
            r"you have an error in your sql syntax",
            r"mysqli?_",
            r"mariadb",
        ],
        "postgres": [
            r"postgres",
            r"pg_",
            r"pgsql",
        ],
        "mssql": [
            r"microsoft sql server",
            r"mssql",
            r"sqlserver",
            r"unclosed quotation mark",
        ],
        "oracle": [
            r"oracle",
            r"ora-\d+",
        ],
        "sqlite": [
            r"sqlite",
        ],
        "mongodb": [
            r"mongodb",
            r"bson",
        ],
    },

    # CMS
    "cms": {
        "wordpress": [
            r"wp-content",
            r"wp-includes",
            r"wordpress",
        ],
        "drupal": [
            r"drupal",
            r"sites/all",
        ],
        "joomla": [
            r"joomla",
            r"option=com_",
        ],
        "magento": [
            r"magento",
            r"mage",
        ],
        "shopify": [
            r"shopify",
            r"cdn\.shopify",
        ],
    },

    # WAF patterns
    "waf": {
        "cloudflare": [
            r"cf-ray",
            r"__cfduid",
            r"cloudflare",
        ],
        "aws_waf": [
            r"x-amzn-",
            r"awselb",
        ],
        "akamai": [
            r"akamai",
            r"ak_bmsc",
        ],
        "imperva": [
            r"incap_ses",
            r"incapsula",
        ],
        "modsecurity": [
            r"mod_security",
            r"modsecurity",
        ],
        "sucuri": [
            r"sucuri",
            r"x-sucuri",
        ],
    },

    # Cloud providers
    "cloud": {
        "aws": [
            r"amazonaws",
            r"x-amz-",
            r"aws",
        ],
        "azure": [
            r"azure",
            r"microsoft",
            r"windows\.net",
        ],
        "gcp": [
            r"google",
            r"gcp",
            r"googleapis",
        ],
        "cloudflare": [
            r"cloudflare",
            r"cf-ray",
        ],
    },
}


class ContextAnalyzer:
    """
    Analyze target responses to determine technology context.

    This information is used to optimize payload selection.
    """

    def __init__(self):
        """Initialize the context analyzer."""
        self._patterns = TECH_PATTERNS
        self._compiled_patterns: dict[str, dict[str, list[re.Pattern]]] = {}

        # Pre-compile patterns
        for category, techs in self._patterns.items():
            self._compiled_patterns[category] = {}
            for tech, patterns in techs.items():
                self._compiled_patterns[category][tech] = [
                    re.compile(p, re.IGNORECASE) for p in patterns
                ]

    def analyze(
        self,
        target_url: str,
        responses: list[dict[str, Any]],
    ) -> TargetContext:
        """
        Analyze target based on HTTP responses.

        Args:
            target_url: The target URL
            responses: List of HTTP responses with headers, body, cookies

        Returns:
            TargetContext with detected technologies
        """
        context = TargetContext(target_url=target_url)

        # Combine all response data for analysis
        all_headers: dict[str, str] = {}
        all_cookies: list[str] = []
        all_bodies: list[str] = []

        for response in responses:
            headers = response.get("headers", {})
            for k, v in headers.items():
                all_headers[k.lower()] = v

            cookies = response.get("cookies", {})
            all_cookies.extend(cookies.keys())

            body = response.get("body", "")
            if body:
                all_bodies.append(body)

        # Create combined search text
        header_text = " ".join(f"{k}: {v}" for k, v in all_headers.items())
        cookie_text = " ".join(all_cookies)
        body_text = " ".join(all_bodies)
        combined_text = f"{header_text} {cookie_text} {body_text} {target_url}"

        # Detect technologies
        context.web_server = self._detect_best_match("server", combined_text, context)
        context.backend_language = self._detect_best_match("backend", combined_text, context)
        context.framework = self._detect_best_match("framework", combined_text, context)
        context.database = self._detect_best_match("database", combined_text, context)
        context.cms = self._detect_best_match("cms", combined_text, context)
        context.waf = self._detect_best_match("waf", combined_text, context)
        context.cloud_provider = self._detect_best_match("cloud", combined_text, context)

        # Build technology stack list
        stack = []
        if context.web_server:
            stack.append(context.web_server)
        if context.backend_language:
            stack.append(context.backend_language)
        if context.framework:
            stack.append(context.framework)
        if context.database:
            stack.append(context.database)
        if context.cms:
            stack.append(context.cms)
        context.technology_stack = stack

        # Store interesting headers
        interesting_headers = [
            "server", "x-powered-by", "x-aspnet-version",
            "x-generator", "x-drupal-cache", "x-varnish",
        ]
        for header in interesting_headers:
            if header in all_headers:
                context.headers_of_interest[header] = all_headers[header]

        # Store interesting cookies
        interesting_cookies = [
            "phpsessid", "jsessionid", "asp.net_sessionid",
            "laravel_session", "wordpress_logged_in",
        ]
        for cookie in all_cookies:
            cookie_lower = cookie.lower()
            for interesting in interesting_cookies:
                if interesting in cookie_lower:
                    context.cookies_of_interest.append(cookie)
                    break

        logger.info(f"Context analysis: {context.get_summary()}")

        return context

    def _detect_best_match(
        self,
        category: str,
        text: str,
        context: TargetContext,
    ) -> str | None:
        """Detect the best matching technology for a category."""
        if category not in self._compiled_patterns:
            return None

        matches: dict[str, int] = {}

        for tech, patterns in self._compiled_patterns[category].items():
            match_count = 0
            for pattern in patterns:
                if pattern.search(text):
                    match_count += 1

            if match_count > 0:
                matches[tech] = match_count

        if not matches:
            return None

        # Get best match (most pattern matches)
        best_tech = max(matches, key=matches.get)
        confidence = min(1.0, matches[best_tech] / len(self._compiled_patterns[category][best_tech]))
        context.confidence_scores[f"{category}_{best_tech}"] = confidence

        return best_tech

    def get_payload_recommendations(
        self,
        context: TargetContext,
    ) -> dict[str, list[str]]:
        """
        Get payload recommendations based on context.

        Args:
            context: The analyzed target context

        Returns:
            Dict mapping payload_type to recommended mutations/techniques
        """
        recommendations: dict[str, list[str]] = {
            "sqli": [],
            "xss": [],
            "cmdi": [],
        }

        # Database-specific SQL recommendations
        if context.database:
            db = context.database.lower()
            if db in ("mysql", "mariadb"):
                recommendations["sqli"].extend([
                    "version_comments",
                    "hex_encode_strings",
                    "space_to_comment",
                ])
            elif db in ("mssql", "sqlserver"):
                recommendations["sqli"].extend([
                    "concat_strings",
                    "unicode_encode",
                ])
            elif db in ("postgres", "postgresql"):
                recommendations["sqli"].extend([
                    "double_quotes",
                    "dollar_quotes",
                ])
            elif db == "oracle":
                recommendations["sqli"].extend([
                    "concat_pipes",
                    "chr_function",
                ])

        # WAF-specific recommendations
        if context.waf:
            waf = context.waf.lower()
            recommendations["sqli"].append(f"waf_bypass_{waf}")
            recommendations["xss"].append(f"waf_bypass_{waf}")

        # Backend-specific XSS recommendations
        if context.backend_language:
            lang = context.backend_language.lower()
            if lang == "php":
                recommendations["xss"].extend([
                    "php_wrapper_xss",
                    "svg_onload",
                ])
            elif lang in ("nodejs", "javascript"):
                recommendations["xss"].extend([
                    "template_injection",
                    "prototype_pollution",
                ])

        # CMS-specific recommendations
        if context.cms:
            cms = context.cms.lower()
            if cms == "wordpress":
                recommendations["sqli"].append("wp_prefix")
                recommendations["xss"].append("wp_hooks")
            elif cms == "drupal":
                recommendations["sqli"].append("drupal_specific")

        return recommendations


def analyze_context(
    target_url: str,
    responses: list[dict[str, Any]],
) -> TargetContext:
    """Convenience function to analyze target context."""
    analyzer = ContextAnalyzer()
    return analyzer.analyze(target_url, responses)


__all__ = [
    "TargetContext",
    "ContextAnalyzer",
    "analyze_context",
    "TECH_PATTERNS",
]
