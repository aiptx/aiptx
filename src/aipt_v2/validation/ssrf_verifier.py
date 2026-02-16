"""
AIPTX SSRF Verification Module

Provides real SSRF verification to eliminate false positives by:
1. OOB Callback verification - Most reliable, proves server-side request
2. Content analysis - Detects cloud metadata, internal services
3. Timing analysis - For blind SSRF without content/callback

This module ONLY verifies existing findings - it does not change
the attack payloads or scanning capabilities.

Usage:
    from aipt_v2.validation.ssrf_verifier import SSRFVerifier

    async with SSRFVerifier() as verifier:
        result = await verifier.verify(finding, session)
        finding.mark_verified(result.status, result.evidence)
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from aipt_v2.models.findings import Finding, VerificationStatus, VulnerabilityType

logger = logging.getLogger(__name__)

# Try to import aiohttp
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None


class SSRFType(Enum):
    """Type of SSRF vulnerability for targeted verification."""
    BASIC = "basic"                    # Standard URL fetch
    CLOUD_METADATA = "cloud_metadata"  # AWS/GCP/Azure metadata
    INTERNAL_SERVICE = "internal"      # Internal services (redis, mysql, etc.)
    BLIND = "blind"                    # No content returned, needs callback
    FILE_READ = "file_read"            # file:// protocol abuse


@dataclass
class VerificationResult:
    """Result of SSRF verification attempt."""
    status: VerificationStatus
    ssrf_type: SSRFType = SSRFType.BASIC
    evidence: str = ""
    confidence: float = 0.0
    callback_received: bool = False
    callback_id: str | None = None
    callback_data: dict[str, Any] = field(default_factory=dict)
    response_content: str | None = None
    timing_ms: float | None = None
    detected_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "ssrf_type": self.ssrf_type.value,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "callback_received": self.callback_received,
            "callback_id": self.callback_id,
            "callback_data": self.callback_data,
            "timing_ms": self.timing_ms,
            "detected_patterns": self.detected_patterns,
        }


# Content patterns for SSRF verification
# These patterns indicate successful SSRF exploitation

AWS_METADATA_PATTERNS = [
    # EC2 Instance identity
    (r"ami-[a-f0-9]{8,17}", "AWS AMI ID"),
    (r"i-[a-f0-9]{8,17}", "AWS Instance ID"),
    (r"arn:aws:iam::\d+:", "AWS IAM ARN"),
    (r"AKIA[A-Z0-9]{16}", "AWS Access Key ID"),
    (r'"region"\s*:\s*"[a-z]{2}-[a-z]+-\d+"', "AWS Region"),
    (r'"availabilityZone"\s*:\s*"[a-z]{2}-[a-z]+-\d+[a-z]"', "AWS Availability Zone"),
    (r'"instanceType"\s*:\s*"[a-z0-9]+\.[a-z0-9]+"', "AWS Instance Type"),
    (r'"privateIp"\s*:\s*"10\.\d+\.\d+\.\d+"', "AWS Private IP"),
    (r'"accountId"\s*:\s*"\d{12}"', "AWS Account ID"),
    # IAM credentials
    (r'"AccessKeyId"\s*:\s*"ASIA[A-Z0-9]{16}"', "AWS Temp Access Key"),
    (r'"SecretAccessKey"\s*:', "AWS Secret Key (response key)"),
    (r'"Token"\s*:\s*"[A-Za-z0-9/+=]{100,}"', "AWS Session Token"),
    # Specific metadata endpoints
    (r"169\.254\.169\.254", "AWS Metadata IP in response"),
]

GCP_METADATA_PATTERNS = [
    (r"projects/\d+/", "GCP Project reference"),
    (r'"project-id"\s*:\s*"[a-z][a-z0-9-]+"', "GCP Project ID"),
    (r"computeMetadata", "GCP Compute Metadata"),
    (r'"access_token"\s*:\s*"ya29\.[A-Za-z0-9_-]+"', "GCP Access Token"),
    (r'"instance-id"\s*:\s*"\d+"', "GCP Instance ID"),
    (r'"zone"\s*:\s*"[a-z]+-[a-z]+-[a-z]+"', "GCP Zone"),
    (r"metadata\.google\.internal", "GCP Metadata Domain"),
]

AZURE_METADATA_PATTERNS = [
    (r'"subscriptionId"\s*:\s*"[a-f0-9-]{36}"', "Azure Subscription ID"),
    (r'"resourceGroupName"\s*:', "Azure Resource Group"),
    (r'"vmId"\s*:\s*"[a-f0-9-]{36}"', "Azure VM ID"),
    (r'"access_token"\s*:\s*"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\."', "Azure Access Token (JWT)"),
    (r"169\.254\.169\.254.*?metadata", "Azure Metadata Request"),
]

INTERNAL_SERVICE_PATTERNS = [
    # SSH banners
    (r"SSH-\d+\.\d+-OpenSSH", "OpenSSH Banner"),
    (r"SSH-\d+\.\d+-dropbear", "Dropbear SSH Banner"),
    # Redis
    (r"\$\d+\r\nredis_version:", "Redis Server Response"),
    (r"redis_version:\d+\.\d+", "Redis Version"),
    # MySQL
    (r"mysql_native_password", "MySQL Auth Response"),
    (r"\x00\x00\x00\x0a[5-8]\.\d+\.\d+", "MySQL Banner"),
    # PostgreSQL
    (r"PostgreSQL \d+\.\d+", "PostgreSQL Version"),
    # MongoDB
    (r'"ismaster"\s*:\s*true', "MongoDB Primary"),
    (r'"maxBsonObjectSize"', "MongoDB Response"),
    # Elasticsearch
    (r'"cluster_name"\s*:', "Elasticsearch Cluster"),
    (r'"cluster_uuid"\s*:', "Elasticsearch UUID"),
    # Memcached
    (r"STAT version \d+\.\d+", "Memcached Stats"),
    # Docker
    (r'"ApiVersion"\s*:\s*"\d+\.\d+"', "Docker API Version"),
    (r"/var/run/docker\.sock", "Docker Socket Path"),
    # Kubernetes
    (r'"kind"\s*:\s*"(Pod|Service|Namespace)"', "Kubernetes Resource"),
    (r'"apiVersion"\s*:\s*"v\d+"', "Kubernetes API Version"),
]

FILE_CONTENT_PATTERNS = [
    # /etc/passwd
    (r"root:x?:0:0:", "Unix /etc/passwd root entry"),
    (r"daemon:x?:\d+:\d+:", "Unix /etc/passwd daemon entry"),
    (r"nobody:x?:\d+:\d+:", "Unix /etc/passwd nobody entry"),
    # /etc/hosts
    (r"127\.0\.0\.1\s+localhost", "Unix /etc/hosts localhost"),
    # /etc/shadow (extremely critical if accessible)
    (r"root:\$\d+\$", "Unix /etc/shadow (CRITICAL!)"),
    # Windows
    (r"\[boot loader\]", "Windows boot.ini"),
    (r"\\Windows\\System32", "Windows System Path"),
    # AWS credentials file
    (r"\[default\]\s*aws_access_key_id", "AWS Credentials File"),
    # SSH keys
    (r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----", "SSH Private Key"),
    (r"-----BEGIN CERTIFICATE-----", "SSL Certificate"),
    # Environment files
    (r"(DATABASE_URL|DB_PASSWORD|SECRET_KEY)\s*=", "Environment Variables"),
]

# Headers that indicate SSRF-able services
SSRF_INDICATOR_HEADERS = [
    "x-amz-",
    "x-goog-",
    "x-ms-",
    "server: apache/",
    "server: nginx/",
    "x-powered-by:",
]


class SSRFVerifier:
    """
    SSRF Verification Engine

    Provides multi-stage verification for SSRF findings:
    1. OOB Callback verification (most reliable)
    2. Response content analysis (cloud metadata, internal services)
    3. Timing-based analysis (for blind SSRF)

    Does NOT modify attack payloads or change scanning behavior.
    Only VERIFIES existing findings to separate true positives from false positives.
    """

    def __init__(
        self,
        callback_manager: Optional[Any] = None,
        callback_timeout: float = 30.0,
        request_timeout: float = 15.0,
        enable_timing_analysis: bool = True,
        min_timing_delay_ms: float = 3000.0,
    ):
        """
        Initialize SSRF verifier.

        Args:
            callback_manager: Optional CallbackManager for OOB verification
            callback_timeout: Time to wait for OOB callback
            request_timeout: HTTP request timeout
            enable_timing_analysis: Enable timing-based blind SSRF detection
            min_timing_delay_ms: Minimum delay to consider as timing indicator
        """
        self.callback_manager = callback_manager
        self.callback_timeout = callback_timeout
        self.request_timeout = request_timeout
        self.enable_timing_analysis = enable_timing_analysis
        self.min_timing_delay_ms = min_timing_delay_ms
        self._owned_callback_manager = False

    async def __aenter__(self):
        """Async context manager entry."""
        if self.callback_manager is None:
            # Create our own callback manager
            from aipt_v2.validation.callback_server import CallbackManager
            self.callback_manager = CallbackManager()
            await self.callback_manager.start()
            self._owned_callback_manager = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._owned_callback_manager and self.callback_manager:
            await self.callback_manager.stop()

    async def verify(
        self,
        finding: Finding,
        session: Optional[aiohttp.ClientSession] = None,
        retry_count: int = 2,
    ) -> VerificationResult:
        """
        Verify an SSRF finding using multiple techniques.

        Verification stages:
        1. Analyze existing evidence/response for content patterns
        2. If blind/no content, attempt OOB callback verification
        3. If still uncertain, use timing analysis

        Args:
            finding: The SSRF finding to verify
            session: Optional aiohttp session for making requests
            retry_count: Number of verification attempts

        Returns:
            VerificationResult with status, evidence, and confidence
        """
        if finding.vuln_type not in [VulnerabilityType.SSRF, VulnerabilityType.RFI]:
            return VerificationResult(
                status=VerificationStatus.MANUAL_REVIEW,
                evidence="Finding is not SSRF type",
                confidence=0.0,
            )

        # Stage 1: Analyze existing evidence/response content
        content_result = self._analyze_content(finding)
        if content_result.status == VerificationStatus.CONFIRMED:
            logger.info(f"SSRF confirmed via content analysis: {finding.url}")
            return content_result

        # Stage 2: OOB callback verification (if callback manager available)
        if self.callback_manager and session:
            callback_result = await self._verify_with_callback(finding, session)
            if callback_result.status == VerificationStatus.CONFIRMED:
                logger.info(f"SSRF confirmed via OOB callback: {finding.url}")
                return callback_result

        # Stage 3: Timing analysis for blind SSRF
        if self.enable_timing_analysis and session:
            timing_result = await self._verify_with_timing(finding, session)
            if timing_result.status in [VerificationStatus.CONFIRMED, VerificationStatus.LIKELY]:
                logger.info(f"SSRF detected via timing: {finding.url} ({timing_result.timing_ms}ms)")
                return timing_result

        # If we have partial evidence from content analysis, return that
        if content_result.confidence > 0.3:
            return content_result

        # Cannot verify - mark for manual review
        return VerificationResult(
            status=VerificationStatus.MANUAL_REVIEW,
            evidence="Automated verification inconclusive. Manual testing recommended.",
            confidence=0.2,
        )

    def _analyze_content(self, finding: Finding) -> VerificationResult:
        """
        Analyze finding's evidence/response for SSRF confirmation patterns.

        Looks for:
        - Cloud metadata (AWS/GCP/Azure)
        - Internal service banners
        - File contents (passwd, hosts, etc.)
        """
        content = ""
        if finding.evidence:
            content += finding.evidence + "\n"
        if finding.response:
            content += finding.response + "\n"

        if not content.strip():
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                evidence="No content to analyze",
                confidence=0.0,
            )

        detected_patterns = []
        ssrf_type = SSRFType.BASIC
        max_confidence = 0.0

        # Check AWS metadata patterns
        for pattern, name in AWS_METADATA_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns.append(f"AWS: {name}")
                ssrf_type = SSRFType.CLOUD_METADATA
                max_confidence = max(max_confidence, 0.95)

        # Check GCP metadata patterns
        for pattern, name in GCP_METADATA_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns.append(f"GCP: {name}")
                ssrf_type = SSRFType.CLOUD_METADATA
                max_confidence = max(max_confidence, 0.95)

        # Check Azure metadata patterns
        for pattern, name in AZURE_METADATA_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns.append(f"Azure: {name}")
                ssrf_type = SSRFType.CLOUD_METADATA
                max_confidence = max(max_confidence, 0.95)

        # Check internal service patterns
        for pattern, name in INTERNAL_SERVICE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns.append(f"Internal: {name}")
                ssrf_type = SSRFType.INTERNAL_SERVICE
                max_confidence = max(max_confidence, 0.9)

        # Check file content patterns
        for pattern, name in FILE_CONTENT_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns.append(f"File: {name}")
                ssrf_type = SSRFType.FILE_READ
                max_confidence = max(max_confidence, 0.95)

        if detected_patterns:
            # Multiple patterns = higher confidence
            if len(detected_patterns) >= 3:
                max_confidence = min(max_confidence + 0.05, 1.0)

            status = VerificationStatus.CONFIRMED if max_confidence >= 0.9 else VerificationStatus.LIKELY

            return VerificationResult(
                status=status,
                ssrf_type=ssrf_type,
                evidence=f"Content analysis detected: {', '.join(detected_patterns)}",
                confidence=max_confidence,
                detected_patterns=detected_patterns,
                response_content=content[:1000] if len(content) > 1000 else content,
            )

        return VerificationResult(
            status=VerificationStatus.UNVERIFIED,
            evidence="No SSRF indicators found in content",
            confidence=0.1,
        )

    async def _verify_with_callback(
        self,
        finding: Finding,
        session: aiohttp.ClientSession,
    ) -> VerificationResult:
        """
        Verify SSRF using OOB callback.

        This is the most reliable verification method:
        1. Generate unique callback URL
        2. Inject callback URL via the vulnerable parameter
        3. Wait for callback
        4. If callback received, SSRF is CONFIRMED
        """
        if not self.callback_manager:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                evidence="Callback manager not available",
                confidence=0.0,
            )

        try:
            # Generate callback URL with unique ID
            callback_url, callback_id = self.callback_manager.generate_callback_url(
                vuln_type="ssrf",
                finding_id=finding.fingerprint,
            )

            logger.debug(f"Generated callback URL for SSRF verification: {callback_url}")

            # Build the verification request
            # We need to inject the callback URL into the vulnerable parameter
            target_url = finding.url
            param = finding.parameter

            if param:
                # Parameter-based SSRF
                import urllib.parse
                parsed = urllib.parse.urlparse(target_url)
                query_params = urllib.parse.parse_qs(parsed.query)
                query_params[param] = [callback_url]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                target_url = urllib.parse.urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                ))
            else:
                # URL might already contain the payload - can't inject
                logger.debug("No parameter specified, cannot inject callback URL")
                return VerificationResult(
                    status=VerificationStatus.UNVERIFIED,
                    evidence="No vulnerable parameter identified for callback injection",
                    confidence=0.0,
                )

            # Send the request
            try:
                async with session.request(
                    finding.method or "GET",
                    target_url,
                    timeout=aiohttp.ClientTimeout(total=self.request_timeout),
                    allow_redirects=True,
                    ssl=False,
                ) as response:
                    # We don't care much about the response - the callback is what matters
                    _ = await response.text()
            except Exception as e:
                logger.debug(f"Request error during callback verification: {e}")
                # Request failed, but callback might still come

            # Wait for callback
            result = await self.callback_manager.wait_for_callback(
                callback_id,
                timeout=self.callback_timeout,
            )

            if result:
                return VerificationResult(
                    status=VerificationStatus.CONFIRMED,
                    ssrf_type=SSRFType.BLIND,
                    evidence=f"OOB callback received from {result.source_ip}. "
                             f"Callback ID: {callback_id}. "
                             f"Time: {result.received_at.isoformat()}",
                    confidence=1.0,
                    callback_received=True,
                    callback_id=callback_id,
                    callback_data=result.to_dict(),
                )

            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                evidence=f"No callback received within {self.callback_timeout}s",
                confidence=0.1,
                callback_id=callback_id,
            )

        except Exception as e:
            logger.error(f"Callback verification error: {e}")
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                evidence=f"Callback verification failed: {str(e)}",
                confidence=0.0,
            )

    async def _verify_with_timing(
        self,
        finding: Finding,
        session: aiohttp.ClientSession,
    ) -> VerificationResult:
        """
        Verify blind SSRF using timing analysis.

        For blind SSRF where no content is returned and callbacks aren't possible,
        we can use timing differences to infer server-side requests:
        1. Measure baseline response time
        2. Inject URL to slow/unreachable host
        3. If response time increases significantly, SSRF is LIKELY
        """
        try:
            # Baseline measurement (request without SSRF)
            baseline_times = []
            for _ in range(3):
                start = time.perf_counter()
                try:
                    async with session.request(
                        finding.method or "GET",
                        finding.url,
                        timeout=aiohttp.ClientTimeout(total=5.0),
                        allow_redirects=True,
                        ssl=False,
                    ) as response:
                        _ = await response.text()
                        elapsed = (time.perf_counter() - start) * 1000
                        baseline_times.append(elapsed)
                except asyncio.TimeoutError:
                    baseline_times.append(5000)
                except Exception:
                    pass

            if not baseline_times:
                return VerificationResult(
                    status=VerificationStatus.UNVERIFIED,
                    evidence="Could not establish baseline timing",
                    confidence=0.0,
                )

            avg_baseline = sum(baseline_times) / len(baseline_times)

            # Now test with a slow/timeout target
            # Use a non-routable IP that will cause delay
            slow_targets = [
                "http://10.255.255.1:65535/",  # Non-routable
                "http://192.0.2.1:1/",  # TEST-NET, won't respond
            ]

            param = finding.parameter
            if not param:
                return VerificationResult(
                    status=VerificationStatus.UNVERIFIED,
                    evidence="No parameter for timing analysis",
                    confidence=0.0,
                )

            for slow_target in slow_targets:
                import urllib.parse
                parsed = urllib.parse.urlparse(finding.url)
                query_params = urllib.parse.parse_qs(parsed.query)
                query_params[param] = [slow_target]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                target_url = urllib.parse.urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                ))

                start = time.perf_counter()
                try:
                    async with session.request(
                        finding.method or "GET",
                        target_url,
                        timeout=aiohttp.ClientTimeout(total=15.0),
                        allow_redirects=True,
                        ssl=False,
                    ) as response:
                        _ = await response.text()
                        elapsed = (time.perf_counter() - start) * 1000
                except asyncio.TimeoutError:
                    elapsed = 15000
                except Exception:
                    continue

                # Check if there's significant timing difference
                timing_diff = elapsed - avg_baseline
                if timing_diff >= self.min_timing_delay_ms:
                    confidence = min(0.7 + (timing_diff / 10000) * 0.2, 0.85)
                    return VerificationResult(
                        status=VerificationStatus.LIKELY,
                        ssrf_type=SSRFType.BLIND,
                        evidence=f"Timing analysis suggests SSRF. "
                                 f"Baseline: {avg_baseline:.0f}ms, "
                                 f"With slow target: {elapsed:.0f}ms, "
                                 f"Difference: {timing_diff:.0f}ms",
                        confidence=confidence,
                        timing_ms=timing_diff,
                    )

            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                evidence=f"No significant timing difference detected. Baseline: {avg_baseline:.0f}ms",
                confidence=0.1,
                timing_ms=avg_baseline,
            )

        except Exception as e:
            logger.error(f"Timing analysis error: {e}")
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                evidence=f"Timing analysis failed: {str(e)}",
                confidence=0.0,
            )

    def analyze_response_for_ssrf(
        self,
        response_body: str,
        response_headers: dict[str, str] | None = None,
    ) -> VerificationResult:
        """
        Analyze an HTTP response for SSRF indicators.

        Standalone method that can be used outside of finding verification.

        Args:
            response_body: The response body text
            response_headers: Optional response headers dict

        Returns:
            VerificationResult with analysis results
        """
        content = response_body
        if response_headers:
            content += "\n" + str(response_headers)

        # Create a temporary finding for analysis
        temp_finding = Finding(
            title="Response Analysis",
            severity=Severity.HIGH,
            vuln_type=VulnerabilityType.SSRF,
            url="",
            evidence=content,
        )

        return self._analyze_content(temp_finding)

    @staticmethod
    def get_verification_payloads(callback_url: str) -> list[tuple[str, str, float]]:
        """
        Generate SSRF verification payloads with callback URL.

        Returns list of (payload, description, expected_confidence) tuples.
        This supplements (not replaces) existing attack payloads.
        """
        payloads = [
            # Direct callback
            (callback_url, "direct_callback", 1.0),

            # URL with path
            (f"{callback_url}/ssrf-verify", "callback_with_path", 1.0),

            # Bypass techniques with callback
            (f"http://localhost@{callback_url.replace('http://', '')}", "userinfo_bypass", 0.9),

            # Double encoding
            (callback_url.replace(":", "%3A").replace("/", "%2F"), "url_encoded", 0.8),

            # With port confusion
            (f"{callback_url}:80", "port_suffix", 0.9),
        ]
        return payloads


# Import Severity for the standalone method
from aipt_v2.models.findings import Severity
