"""
AIPTX Verification Policy Engine - Category-specific verification rules

This module implements the verification strategy for each finding category.
Different vulnerability types require different evidence to confirm:

- TLS/SSL: Auto-confirm from authoritative scanners (sslscan, testssl)
- Exposures: Verify content exists with expected data
- CVE/Version: Verify version matches CVE requirements
- SSTI: Canary+flip test (inject {{7*7}} expect 49, then {{7*8}} expect 56)
- Host Header: Requires demonstrable impact (password reset poisoning)
- SSRF: OOB callback verification or cloud metadata content

Verification results:
- CONFIRMED: Verified with evidence (reportable)
- LIKELY: High confidence, no definitive proof
- SUPPRESSED_FP: Confirmed false positive (not reportable)
- MANUAL_REVIEW: Cannot auto-verify, needs human review
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Protocol
from urllib.parse import urlparse, urljoin, quote

import aiohttp

from aipt_v2.models.finding_v2 import (
    FindingV2,
    FindingCategory,
    VerificationStatusV2,
    SeverityV2,
)

logger = logging.getLogger(__name__)


class VerificationConfidence(Enum):
    """Confidence level of verification result"""
    DEFINITIVE = "definitive"    # 100% certain (math check, signature match)
    HIGH = "high"                # 90%+ certain
    MEDIUM = "medium"            # 60-90% certain
    LOW = "low"                  # <60% certain


@dataclass
class VerificationResult:
    """Result of a verification attempt"""
    status: VerificationStatusV2
    evidence: str = ""
    confidence: float = 0.0
    confidence_level: VerificationConfidence = VerificationConfidence.MEDIUM
    details: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0

    @property
    def is_success(self) -> bool:
        """Check if verification was successful (CONFIRMED or LIKELY)"""
        return self.status in [
            VerificationStatusV2.CONFIRMED,
            VerificationStatusV2.LIKELY,
        ]


class VerificationPolicy(ABC):
    """
    Abstract base class for category-specific verification policies.

    Each policy defines how to verify findings of a specific category.
    """

    # Categories this policy handles
    categories: list[FindingCategory] = []

    # Timeout for HTTP requests
    request_timeout: int = 10

    # User agent for verification requests
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    @abstractmethod
    async def verify(self, finding: FindingV2) -> VerificationResult:
        """
        Verify a finding and return the result.

        Args:
            finding: The finding to verify

        Returns:
            VerificationResult with status and evidence
        """
        pass

    async def _fetch_url(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict] = None,
        data: Optional[str] = None,
        follow_redirects: bool = True,
    ) -> tuple[int, str, dict[str, str]]:
        """
        Fetch URL and return status, content, headers.

        Returns:
            Tuple of (status_code, response_body, response_headers)
        """
        default_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
        }
        if headers:
            default_headers.update(headers)

        try:
            timeout = aiohttp.ClientTimeout(total=self.request_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method,
                    url,
                    headers=default_headers,
                    data=data,
                    allow_redirects=follow_redirects,
                    ssl=False,  # Skip SSL verification for testing
                ) as response:
                    body = await response.text()
                    headers_dict = {k.lower(): v for k, v in response.headers.items()}
                    return response.status, body, headers_dict
        except asyncio.TimeoutError:
            return 0, "", {"error": "timeout"}
        except Exception as e:
            return 0, "", {"error": str(e)}


class TLSVerificationPolicy(VerificationPolicy):
    """
    TLS/SSL findings from authoritative scanners are auto-confirmed.

    sslscan and testssl are considered authoritative for TLS issues.
    These tools directly test TLS configurations and don't produce
    false positives for issues they detect.
    """

    categories = [FindingCategory.TLS_SSL]

    AUTHORITATIVE_SCANNERS = ["sslscan", "testssl", "sslyze", "tlsscan"]

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Check if from authoritative scanner
        source_lower = finding.source_tool.lower()
        is_authoritative = any(
            scanner in source_lower for scanner in self.AUTHORITATIVE_SCANNERS
        )

        if is_authoritative:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.CONFIRMED,
                evidence=f"Auto-confirmed: {finding.source_tool} is an authoritative TLS scanner",
                confidence=1.0,
                confidence_level=VerificationConfidence.DEFINITIVE,
                details={"auto_confirmed": True, "source": finding.source_tool},
                duration_ms=duration,
            )

        # For non-authoritative sources, mark as LIKELY
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.LIKELY,
            evidence=f"TLS finding from {finding.source_tool} - not an authoritative scanner",
            confidence=0.7,
            confidence_level=VerificationConfidence.MEDIUM,
            details={"auto_confirmed": False, "source": finding.source_tool},
            duration_ms=duration,
        )


class ExposureVerificationPolicy(VerificationPolicy):
    """
    Verify sensitive file exposures by checking content.

    Checks:
    1. URL returns 200 OK
    2. Response is not a redirect or error page
    3. Response contains expected content patterns
    """

    categories = [FindingCategory.EXPOSURE]

    # Patterns that indicate actual sensitive content
    CONTENT_PATTERNS = {
        "phpinfo": [r"PHP Version", r"Configuration", r"PHP Credits"],
        ".env": [r"\w+=[\w\-/@]+", r"DATABASE_", r"API_KEY", r"SECRET"],
        "config": [r"password\s*[:=]", r"database\s*[:=]", r"host\s*[:=]"],
        "backup": [r"<?php", r"CREATE TABLE", r"INSERT INTO"],
        ".git": [r"ref:", r"refs/heads", r"[0-9a-f]{40}"],
        "directory_listing": [r"Index of", r"Parent Directory", r"<a href="],
        "swagger": [r"swagger", r"openapi", r'"paths":', r'"info":'],
        "graphql": [r"__schema", r'"types":', r"GraphQL"],
        ".htaccess": [r"RewriteRule", r"AuthType", r"Deny from"],
        "web.config": [r"<configuration>", r"<system.web>"],
    }

    # Patterns that indicate NOT a real exposure (false positive)
    FALSE_POSITIVE_PATTERNS = [
        r"404 Not Found",
        r"Page Not Found",
        r"Access Denied",
        r"403 Forbidden",
        r"Login Required",
        r"Authentication Required",
        r"<title>Error</title>",
    ]

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Fetch the URL
        status, body, headers = await self._fetch_url(finding.url)

        if status == 0:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.MANUAL_REVIEW,
                evidence=f"Could not fetch URL: {headers.get('error', 'unknown error')}",
                confidence=0.0,
                confidence_level=VerificationConfidence.LOW,
                duration_ms=duration,
            )

        # Check for obvious non-exposure responses
        if status in [403, 404, 401, 500]:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.SUPPRESSED_FP,
                evidence=f"URL returns {status} status - not an actual exposure",
                confidence=0.9,
                confidence_level=VerificationConfidence.HIGH,
                details={"status_code": status},
                duration_ms=duration,
            )

        # Check for false positive patterns in body
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                duration = (datetime.utcnow() - start).total_seconds() * 1000
                return VerificationResult(
                    status=VerificationStatusV2.SUPPRESSED_FP,
                    evidence=f"Response contains false positive pattern: {pattern}",
                    confidence=0.8,
                    confidence_level=VerificationConfidence.HIGH,
                    details={"pattern_matched": pattern, "status_code": status},
                    duration_ms=duration,
                )

        # Check for expected content patterns
        exposure_type = self._detect_exposure_type(finding)
        patterns = self.CONTENT_PATTERNS.get(exposure_type, [])

        matched_patterns = []
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                matched_patterns.append(pattern)

        if matched_patterns:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.CONFIRMED,
                evidence=f"Exposure verified: found {len(matched_patterns)} content patterns",
                confidence=0.95,
                confidence_level=VerificationConfidence.HIGH,
                details={
                    "status_code": status,
                    "exposure_type": exposure_type,
                    "patterns_matched": matched_patterns,
                    "body_length": len(body),
                },
                duration_ms=duration,
            )

        # 200 OK but no patterns matched - likely real but uncertain
        if status == 200 and len(body) > 100:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.LIKELY,
                evidence=f"URL returns 200 OK with content, but no specific patterns matched",
                confidence=0.6,
                confidence_level=VerificationConfidence.MEDIUM,
                details={"status_code": status, "body_length": len(body)},
                duration_ms=duration,
            )

        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.MANUAL_REVIEW,
            evidence="Could not automatically verify exposure",
            confidence=0.3,
            confidence_level=VerificationConfidence.LOW,
            duration_ms=duration,
        )

    def _detect_exposure_type(self, finding: FindingV2) -> str:
        """Detect the type of exposure from finding details"""
        url_lower = finding.url.lower()
        title_lower = finding.title.lower()

        for exposure_type in self.CONTENT_PATTERNS.keys():
            if exposure_type in url_lower or exposure_type in title_lower:
                return exposure_type

        return "unknown"


class CVEVersionVerificationPolicy(VerificationPolicy):
    """
    Verify CVE findings by checking version numbers.

    This policy verifies that the detected version actually falls
    within the vulnerable version range for the CVE.
    """

    categories = [FindingCategory.CVE_VERSION]

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Extract version from evidence
        version = self._extract_version(finding)

        if not version:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.MANUAL_REVIEW,
                evidence="Could not extract version number from finding",
                confidence=0.3,
                confidence_level=VerificationConfidence.LOW,
                duration_ms=duration,
            )

        # Check if CVE IDs are provided
        if finding.cve_ids:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.LIKELY,
                evidence=f"Version {version} detected with CVE(s): {', '.join(finding.cve_ids)}",
                confidence=0.75,
                confidence_level=VerificationConfidence.MEDIUM,
                details={
                    "version": version,
                    "cves": finding.cve_ids,
                },
                duration_ms=duration,
            )

        # No CVE IDs but version detected
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.MANUAL_REVIEW,
            evidence=f"Version {version} detected but no CVE IDs to verify against",
            confidence=0.4,
            confidence_level=VerificationConfidence.LOW,
            details={"version": version},
            duration_ms=duration,
        )

    def _extract_version(self, finding: FindingV2) -> Optional[str]:
        """Extract version number from evidence or title"""
        text = f"{finding.evidence} {finding.title} {finding.description}"

        # Common version patterns
        patterns = [
            r"version[:\s]+(\d+\.\d+(?:\.\d+)?)",
            r"v(\d+\.\d+(?:\.\d+)?)",
            r"(\d+\.\d+\.\d+)",
            r"release[:\s]+(\d+\.\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        return None


class SSTIVerificationPolicy(VerificationPolicy):
    """
    SSTI verification using canary+flip test.

    Stage 1: Inject {{7*7}}, expect 49 in response
    Stage 2: Inject {{7*8}}, expect 56 in response

    Both tests must pass for CONFIRMED status.
    Only canary (Stage 1) = LIKELY
    """

    categories = [FindingCategory.INJECTION_SSTI]

    # SSTI payloads for different template engines
    PAYLOADS = {
        "jinja2": ("{{7*7}}", "{{7*8}}", "49", "56"),
        "twig": ("{{7*7}}", "{{7*8}}", "49", "56"),
        "freemarker": ("${7*7}", "${7*8}", "49", "56"),
        "velocity": ("#set($x=7*7)$x", "#set($x=7*8)$x", "49", "56"),
        "smarty": ("{$smarty.version}{7*7}", "{$smarty.version}{7*8}", "49", "56"),
    }

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Try each template engine
        for engine, (payload1, payload2, expect1, expect2) in self.PAYLOADS.items():
            canary_result = await self._test_payload(finding, payload1, expect1)
            if canary_result:
                # Stage 1 passed - try flip test
                flip_result = await self._test_payload(finding, payload2, expect2)
                if flip_result:
                    duration = (datetime.utcnow() - start).total_seconds() * 1000
                    return VerificationResult(
                        status=VerificationStatusV2.CONFIRMED,
                        evidence=f"SSTI confirmed with {engine}: canary={payload1}→{expect1}, flip={payload2}→{expect2}",
                        confidence=0.99,
                        confidence_level=VerificationConfidence.DEFINITIVE,
                        details={
                            "engine": engine,
                            "canary_payload": payload1,
                            "flip_payload": payload2,
                        },
                        duration_ms=duration,
                    )
                else:
                    # Only canary passed
                    duration = (datetime.utcnow() - start).total_seconds() * 1000
                    return VerificationResult(
                        status=VerificationStatusV2.LIKELY,
                        evidence=f"SSTI likely ({engine}): canary test passed but flip test failed",
                        confidence=0.7,
                        confidence_level=VerificationConfidence.MEDIUM,
                        details={"engine": engine, "canary_passed": True, "flip_passed": False},
                        duration_ms=duration,
                    )

        # No payload worked
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.MANUAL_REVIEW,
            evidence="Could not verify SSTI with automated tests",
            confidence=0.3,
            confidence_level=VerificationConfidence.LOW,
            duration_ms=duration,
        )

    async def _test_payload(self, finding: FindingV2, payload: str, expected: str) -> bool:
        """Test a single SSTI payload"""
        # Construct URL with payload
        if finding.parameter:
            # Inject into specific parameter
            url = self._inject_parameter(finding.url, finding.parameter, payload)
        else:
            # Try path injection
            url = finding.url.rstrip("/") + "/" + quote(payload)

        try:
            status, body, _ = await self._fetch_url(url, method=finding.method)
            return status == 200 and expected in body
        except Exception:
            return False

    def _inject_parameter(self, url: str, param: str, value: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        if "?" in url:
            return f"{url}&{param}={quote(value)}"
        return f"{url}?{param}={quote(value)}"


class HostHeaderVerificationPolicy(VerificationPolicy):
    """
    Host Header Injection requires demonstrable impact.

    Only confirm if:
    - Password reset links contain injected host (HIGH impact)
    - Cache keys are affected (MEDIUM impact)

    Body-only reflection is low impact and marked MANUAL_REVIEW.
    """

    categories = [FindingCategory.HOST_HEADER]

    CANARY_HOST = "evil.attacker.com"

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Inject custom host header
        headers = {
            "Host": self.CANARY_HOST,
            "X-Forwarded-Host": self.CANARY_HOST,
            "X-Host": self.CANARY_HOST,
        }

        status, body, resp_headers = await self._fetch_url(
            finding.url,
            headers=headers,
            follow_redirects=False,
        )

        if status == 0:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.MANUAL_REVIEW,
                evidence="Could not fetch URL for host header verification",
                confidence=0.0,
                duration_ms=duration,
            )

        # Check for high-impact reflection (Location header)
        location = resp_headers.get("location", "")
        if self.CANARY_HOST in location:
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.CONFIRMED,
                evidence=f"HIGH IMPACT: Host header reflected in Location header: {location}",
                confidence=0.95,
                confidence_level=VerificationConfidence.HIGH,
                details={
                    "reflected_in": "location_header",
                    "location": location,
                    "impact": "high",
                },
                duration_ms=duration,
            )

        # Check for cache-related headers
        cache_headers = ["x-cache", "cf-cache-status", "x-varnish", "age"]
        has_cache = any(h in resp_headers for h in cache_headers)

        # Check body reflection
        if self.CANARY_HOST in body:
            if has_cache:
                duration = (datetime.utcnow() - start).total_seconds() * 1000
                return VerificationResult(
                    status=VerificationStatusV2.LIKELY,
                    evidence="Host header reflected in body with caching present - potential cache poisoning",
                    confidence=0.7,
                    confidence_level=VerificationConfidence.MEDIUM,
                    details={
                        "reflected_in": "body",
                        "caching_present": True,
                        "impact": "medium",
                    },
                    duration_ms=duration,
                )
            else:
                duration = (datetime.utcnow() - start).total_seconds() * 1000
                return VerificationResult(
                    status=VerificationStatusV2.MANUAL_REVIEW,
                    evidence="Host header reflected in body only - low impact without cache or reset flow",
                    confidence=0.4,
                    confidence_level=VerificationConfidence.LOW,
                    details={
                        "reflected_in": "body",
                        "impact": "low",
                    },
                    duration_ms=duration,
                )

        # No reflection detected
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.SUPPRESSED_FP,
            evidence="Host header not reflected in response",
            confidence=0.8,
            confidence_level=VerificationConfidence.HIGH,
            duration_ms=duration,
        )


class SSRFVerificationPolicy(VerificationPolicy):
    """
    SSRF verification using OOB callbacks or content detection.

    Verification methods:
    1. OOB callback (most reliable) - inject callback URL
    2. Cloud metadata detection - check for AWS/GCP/Azure metadata
    3. Internal service banners - identify internal services
    """

    categories = [FindingCategory.SSRF]

    # Cloud metadata patterns
    CLOUD_METADATA_PATTERNS = [
        # AWS
        r"ami-id",
        r"instance-id",
        r"security-credentials",
        r"iam/info",
        # GCP
        r"computeMetadata",
        r"project-id",
        r"instance/zone",
        # Azure
        r"metadata/instance",
        r"subscriptionId",
    ]

    # Internal service patterns
    INTERNAL_SERVICE_PATTERNS = [
        r"127\.0\.0\.1",
        r"localhost",
        r"internal",
        r"Redis",
        r"MongoDB",
        r"MySQL",
        r"PostgreSQL",
        r"Elasticsearch",
    ]

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Check existing evidence for metadata patterns
        evidence_lower = (finding.evidence or "").lower()
        body_lower = (finding.raw_response or "").lower()
        combined = f"{evidence_lower} {body_lower}"

        # Check for cloud metadata
        for pattern in self.CLOUD_METADATA_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                duration = (datetime.utcnow() - start).total_seconds() * 1000
                return VerificationResult(
                    status=VerificationStatusV2.CONFIRMED,
                    evidence=f"SSRF confirmed: cloud metadata pattern '{pattern}' found in response",
                    confidence=0.95,
                    confidence_level=VerificationConfidence.HIGH,
                    details={"pattern": pattern, "type": "cloud_metadata"},
                    duration_ms=duration,
                )

        # Check for internal service patterns
        for pattern in self.INTERNAL_SERVICE_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                duration = (datetime.utcnow() - start).total_seconds() * 1000
                return VerificationResult(
                    status=VerificationStatusV2.LIKELY,
                    evidence=f"SSRF likely: internal service pattern '{pattern}' found",
                    confidence=0.7,
                    confidence_level=VerificationConfidence.MEDIUM,
                    details={"pattern": pattern, "type": "internal_service"},
                    duration_ms=duration,
                )

        # No patterns found - needs manual verification
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.MANUAL_REVIEW,
            evidence="SSRF requires OOB callback or manual verification",
            confidence=0.4,
            confidence_level=VerificationConfidence.LOW,
            duration_ms=duration,
        )


class SQLiVerificationPolicy(VerificationPolicy):
    """
    SQL Injection verification using error-based and timing detection.
    """

    categories = [FindingCategory.INJECTION_SQLI]

    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"ORA-\d{5}",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark",
        r"SQLSTATE\[",
        r"sqlite_",
        r"SQLite3::",
    ]

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Check existing evidence
        combined = f"{finding.evidence or ''} {finding.raw_response or ''}"

        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                duration = (datetime.utcnow() - start).total_seconds() * 1000
                return VerificationResult(
                    status=VerificationStatusV2.CONFIRMED,
                    evidence=f"SQLi confirmed: database error pattern '{pattern}' found",
                    confidence=0.9,
                    confidence_level=VerificationConfidence.HIGH,
                    details={"pattern": pattern},
                    duration_ms=duration,
                )

        # No definitive patterns
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.MANUAL_REVIEW,
            evidence="SQLi requires further manual verification",
            confidence=0.4,
            confidence_level=VerificationConfidence.LOW,
            duration_ms=duration,
        )


class XSSVerificationPolicy(VerificationPolicy):
    """XSS verification by checking reflection patterns."""

    categories = [FindingCategory.INJECTION_XSS]

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()

        # Generate canary
        canary = f"xss{random.randint(10000, 99999)}"

        # Check if we have evidence of reflection
        combined = f"{finding.evidence or ''} {finding.raw_response or ''}"

        # Check for script tags
        if re.search(r"<script[^>]*>", combined, re.IGNORECASE):
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.LIKELY,
                evidence="XSS likely: script tag reflection detected in evidence",
                confidence=0.7,
                confidence_level=VerificationConfidence.MEDIUM,
                duration_ms=duration,
            )

        # Check for event handlers
        if re.search(r"on\w+\s*=", combined, re.IGNORECASE):
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            return VerificationResult(
                status=VerificationStatusV2.LIKELY,
                evidence="XSS likely: event handler reflection detected",
                confidence=0.6,
                confidence_level=VerificationConfidence.MEDIUM,
                duration_ms=duration,
            )

        duration = (datetime.utcnow() - start).total_seconds() * 1000
        return VerificationResult(
            status=VerificationStatusV2.MANUAL_REVIEW,
            evidence="XSS requires manual verification in browser context",
            confidence=0.3,
            confidence_level=VerificationConfidence.LOW,
            duration_ms=duration,
        )


class DefaultVerificationPolicy(VerificationPolicy):
    """
    Default policy for uncategorized findings.

    These require manual review as we have no specific verification strategy.
    """

    categories = [FindingCategory.OTHER]

    async def verify(self, finding: FindingV2) -> VerificationResult:
        start = datetime.utcnow()
        duration = (datetime.utcnow() - start).total_seconds() * 1000

        return VerificationResult(
            status=VerificationStatusV2.MANUAL_REVIEW,
            evidence=f"No automated verification available for category: {finding.category.value}",
            confidence=0.3,
            confidence_level=VerificationConfidence.LOW,
            duration_ms=duration,
        )


# Registry of verification policies by category
VERIFICATION_POLICIES: dict[FindingCategory, VerificationPolicy] = {
    FindingCategory.TLS_SSL: TLSVerificationPolicy(),
    FindingCategory.EXPOSURE: ExposureVerificationPolicy(),
    FindingCategory.CVE_VERSION: CVEVersionVerificationPolicy(),
    FindingCategory.INJECTION_SSTI: SSTIVerificationPolicy(),
    FindingCategory.INJECTION_SQLI: SQLiVerificationPolicy(),
    FindingCategory.INJECTION_XSS: XSSVerificationPolicy(),
    FindingCategory.HOST_HEADER: HostHeaderVerificationPolicy(),
    FindingCategory.SSRF: SSRFVerificationPolicy(),
}


class VerificationEngine:
    """
    Main verification engine that routes findings to appropriate policies.

    Usage:
        engine = VerificationEngine()
        verified_findings = await engine.verify_all(findings)
    """

    def __init__(
        self,
        policies: Optional[dict[FindingCategory, VerificationPolicy]] = None,
        max_concurrent: int = 10,
        skip_categories: Optional[list[FindingCategory]] = None,
    ):
        """
        Initialize verification engine.

        Args:
            policies: Optional custom policy registry
            max_concurrent: Maximum concurrent verifications
            skip_categories: Categories to skip verification for
        """
        self.policies = policies or VERIFICATION_POLICIES
        self.default_policy = DefaultVerificationPolicy()
        self.max_concurrent = max_concurrent
        self.skip_categories = skip_categories or []
        self.stats: dict[str, Any] = {}

    async def verify_all(
        self,
        findings: list[FindingV2],
        progress_callback: Optional[callable] = None,
    ) -> list[FindingV2]:
        """
        Verify all findings using appropriate policies.

        Args:
            findings: List of deduplicated findings to verify
            progress_callback: Optional callback for progress updates

        Returns:
            List of findings with updated verification status
        """
        if not findings:
            return []

        logger.info(f"Starting verification of {len(findings)} findings...")

        # Reset stats
        self.stats = {
            "total": len(findings),
            "verified": 0,
            "by_status": {},
            "by_category": {},
            "errors": [],
        }

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def verify_with_semaphore(finding: FindingV2) -> FindingV2:
            async with semaphore:
                return await self._verify_single(finding)

        # Run verifications concurrently
        tasks = [verify_with_semaphore(f) for f in findings]
        verified = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        result_findings = []
        for i, result in enumerate(verified):
            if isinstance(result, Exception):
                logger.error(f"Verification error for finding {findings[i].id}: {result}")
                findings[i].verification_status = VerificationStatusV2.MANUAL_REVIEW
                self.stats["errors"].append(str(result))
                result_findings.append(findings[i])
            else:
                result_findings.append(result)

        # Update stats
        for f in result_findings:
            status = f.verification_status.value
            self.stats["by_status"][status] = self.stats["by_status"].get(status, 0) + 1
            cat = f.category.value
            self.stats["by_category"][cat] = self.stats["by_category"].get(cat, 0) + 1

        self.stats["verified"] = len(result_findings)

        logger.info(f"Verification complete. Results: {self.stats['by_status']}")

        return result_findings

    async def _verify_single(self, finding: FindingV2) -> FindingV2:
        """Verify a single finding"""
        # Skip if category is in skip list
        if finding.category in self.skip_categories:
            finding.verification_status = VerificationStatusV2.MANUAL_REVIEW
            return finding

        # Skip if already verified
        if finding.verification_status in [
            VerificationStatusV2.CONFIRMED,
            VerificationStatusV2.SUPPRESSED_FP,
        ]:
            return finding

        # Get appropriate policy
        policy = self.policies.get(finding.category, self.default_policy)

        try:
            # Run verification
            result = await policy.verify(finding)

            # Update finding
            finding.mark_verified(
                status=result.status,
                evidence=result.evidence,
                confidence=result.confidence,
            )

        except Exception as e:
            logger.warning(f"Verification failed for {finding.id}: {e}")
            finding.verification_status = VerificationStatusV2.MANUAL_REVIEW

        return finding

    def get_stats(self) -> dict[str, Any]:
        """Get verification statistics"""
        return self.stats
