"""
PAT Parallel Executor

Executes HTTP requests in parallel with rate limiting,
WAF detection, and adaptive backoff.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Callable, Optional

import httpx

from .config import EnhancedPATScanConfig, ExecutorConfig
from .request_generator import InjectionRequest

# Lazy imports for WAF detection/bypass modules
_advanced_waf_detector = None
_payload_engine = None


def _get_advanced_waf_detector():
    """Lazy-load advanced WAF detector from exploitation module."""
    global _advanced_waf_detector
    if _advanced_waf_detector is None:
        try:
            from aipt_v2.exploitation.waf_detector import WAFDetector as AdvancedWAFDetector

            _advanced_waf_detector = AdvancedWAFDetector
        except ImportError:
            return None
    return _advanced_waf_detector()


def _get_payload_engine():
    """Lazy-load payload engine from exploitation module."""
    global _payload_engine
    if _payload_engine is None:
        try:
            from aipt_v2.exploitation.payload_engine import PayloadEngine

            _payload_engine = PayloadEngine
        except ImportError:
            return None
    return _payload_engine()


logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of executing a single request."""

    request: InjectionRequest
    response: Optional[httpx.Response] = None

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    elapsed_ms: float = 0.0

    # Status
    success: bool = False
    error: Optional[str] = None
    retry_count: int = 0

    # WAF detection
    waf_detected: bool = False
    waf_type: Optional[str] = None

    @property
    def status_code(self) -> int:
        """Get response status code."""
        return self.response.status_code if self.response else 0

    @property
    def response_body(self) -> str:
        """Get response body as text."""
        if self.response:
            try:
                return self.response.text
            except Exception:
                return ""
        return ""

    @property
    def response_headers(self) -> dict[str, str]:
        """Get response headers."""
        if self.response:
            return dict(self.response.headers)
        return {}


class RateLimiter:
    """Token bucket rate limiter for HTTP requests."""

    def __init__(self, requests_per_second: float):
        """
        Initialize rate limiter.

        Args:
            requests_per_second: Maximum requests per second
        """
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class WAFDetector:
    """Detects Web Application Firewall responses."""

    # WAF signature patterns
    WAF_SIGNATURES = {
        "cloudflare": [
            "cloudflare",
            "cf-ray",
            "attention required",
            "__cfduid",
        ],
        "akamai": [
            "akamai",
            "ghost",
            "akamaighost",
            "x-akamai",
        ],
        "aws_waf": [
            "awselb",
            "x-amz-cf",
            "x-amzn-requestid",
        ],
        "imperva": [
            "incapsula",
            "visid_incap",
            "incap_ses",
            "imperva",
        ],
        "f5_bigip": [
            "bigipserver",
            "x-cnection",
            "f5-bigip",
        ],
        "modsecurity": [
            "mod_security",
            "modsecurity",
            "nyob",
        ],
        "sucuri": [
            "sucuri",
            "x-sucuri",
        ],
        "barracuda": [
            "barra_counter_session",
            "barracuda",
        ],
        "generic": [
            "blocked",
            "access denied",
            "forbidden",
            "request blocked",
            "security violation",
            "suspicious activity",
            "your request has been blocked",
        ],
    }

    # Status codes that often indicate WAF blocking
    WAF_STATUS_CODES = {403, 406, 429, 503, 999}

    @classmethod
    def detect(cls, response: httpx.Response) -> tuple[bool, Optional[str]]:
        """
        Detect if response indicates WAF blocking.

        Args:
            response: HTTP response

        Returns:
            Tuple of (is_waf, waf_type)
        """
        # Check status code
        is_waf_status = response.status_code in cls.WAF_STATUS_CODES

        # Check headers and body
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        body_lower = response.text.lower()[:5000] if response.text else ""

        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                # Check headers
                for header_val in headers_lower.values():
                    if sig_lower in header_val:
                        return True, waf_name
                # Check body
                if sig_lower in body_lower:
                    return True, waf_name

        # Status code alone might indicate WAF
        if is_waf_status and response.status_code == 403:
            return True, "generic"

        return False, None


class ScopeEnforcer:
    """Enforces scope restrictions on targets."""

    def __init__(self, allowed_patterns: list[str]):
        """
        Initialize scope enforcer.

        Args:
            allowed_patterns: List of allowed URL patterns (glob-like)
        """
        self.allowed_patterns = allowed_patterns
        self._compiled = [self._compile_pattern(p) for p in allowed_patterns]

    def _compile_pattern(self, pattern: str) -> str:
        """Convert glob pattern to regex."""
        import re

        # Escape special chars except * and ?
        escaped = re.escape(pattern)
        # Convert glob wildcards
        escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")
        return f"^{escaped}$"

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope."""
        import re

        if not self.allowed_patterns:
            return True  # No restrictions

        for pattern in self._compiled:
            if re.match(pattern, url, re.IGNORECASE):
                return True

        return False


class ParallelExecutor:
    """
    Executes HTTP requests in parallel with safety controls.

    Features:
    - Configurable concurrency
    - Rate limiting (token bucket)
    - WAF detection and adaptation
    - Scope enforcement
    - Retry with exponential backoff
    - Timeout handling
    """

    def __init__(self, config: Optional[ExecutorConfig] = None):
        """
        Initialize executor.

        Args:
            config: Executor configuration
        """
        self.config = config or ExecutorConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter = RateLimiter(self.config.requests_per_second)
        self._scope_enforcer: Optional[ScopeEnforcer] = None
        self._waf_backoff = 1.0
        self._request_count = 0
        self._waf_count = 0

    async def __aenter__(self) -> "ParallelExecutor":
        """Async context manager entry."""
        await self._create_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    async def _create_client(self) -> None:
        """Create HTTP client."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=self.config.follow_redirects,
            max_redirects=self.config.max_redirects,
            verify=self.config.verify_ssl,
            headers={"User-Agent": self.config.user_agent},
            proxy=self.config.proxy,
        )

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def set_scope(self, patterns: list[str]) -> None:
        """Set allowed URL patterns for scope enforcement."""
        self._scope_enforcer = ScopeEnforcer(patterns)

    async def execute(self, request: InjectionRequest) -> ExecutionResult:
        """
        Execute a single request.

        Args:
            request: Request to execute

        Returns:
            ExecutionResult with response or error
        """
        result = ExecutionResult(
            request=request,
            start_time=datetime.now(timezone.utc),
        )

        # Scope check
        if self._scope_enforcer and not self._scope_enforcer.is_in_scope(request.url):
            result.error = f"URL out of scope: {request.url}"
            result.end_time = datetime.now(timezone.utc)
            return result

        # Rate limiting
        await self._rate_limiter.acquire()

        # WAF backoff
        if self._waf_backoff > 1.0:
            await asyncio.sleep(self._waf_backoff - 1.0)

        if not self._client:
            await self._create_client()

        # Execute with retry
        for attempt in range(self.config.retry_count + 1):
            try:
                start_time = time.monotonic()

                # Build httpx request
                response = await self._client.request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    content=request.body,
                    cookies=request.cookies,
                )

                elapsed = (time.monotonic() - start_time) * 1000
                result.response = response
                result.elapsed_ms = elapsed
                result.success = True
                result.retry_count = attempt

                # WAF detection
                if self.config.waf_detection:
                    is_waf, waf_type = WAFDetector.detect(response)
                    if is_waf:
                        result.waf_detected = True
                        result.waf_type = waf_type
                        self._waf_count += 1
                        # Increase backoff
                        self._waf_backoff = min(
                            self._waf_backoff * self.config.waf_backoff_multiplier, 30.0
                        )
                        logger.warning(
                            f"WAF detected ({waf_type}), backoff: {self._waf_backoff:.1f}s"
                        )
                    else:
                        # Gradually reduce backoff
                        self._waf_backoff = max(1.0, self._waf_backoff * 0.9)

                self._request_count += 1
                break

            except httpx.TimeoutException:
                result.error = "Request timeout"
                if attempt < self.config.retry_count:
                    await asyncio.sleep(self.config.retry_backoff**attempt)

            except httpx.RequestError as e:
                result.error = str(e)
                if attempt < self.config.retry_count:
                    await asyncio.sleep(self.config.retry_backoff**attempt)

            except Exception as e:
                result.error = f"Unexpected error: {e}"
                break

        result.end_time = datetime.now(timezone.utc)
        return result

    async def execute_batch(
        self,
        requests: list[InjectionRequest],
        on_result: Optional[Callable[[ExecutionResult], None]] = None,
        stop_on_waf: bool = False,
    ) -> list[ExecutionResult]:
        """
        Execute multiple requests in parallel.

        Args:
            requests: List of requests to execute
            on_result: Callback for each result
            stop_on_waf: Stop if WAF is consistently detected

        Returns:
            List of execution results
        """
        if not self._client:
            await self._create_client()

        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        results: list[ExecutionResult] = []
        consecutive_waf = 0

        async def execute_with_semaphore(request: InjectionRequest) -> ExecutionResult:
            nonlocal consecutive_waf

            async with semaphore:
                # Check for WAF threshold
                if stop_on_waf and consecutive_waf >= 5:
                    return ExecutionResult(
                        request=request,
                        error="Stopped due to consecutive WAF detections",
                    )

                result = await self.execute(request)

                if result.waf_detected:
                    consecutive_waf += 1
                else:
                    consecutive_waf = 0

                if on_result:
                    on_result(result)

                return result

        # Execute all requests
        tasks = [execute_with_semaphore(req) for req in requests]
        results = await asyncio.gather(*tasks)

        return list(results)

    async def execute_stream(
        self,
        requests: list[InjectionRequest],
    ) -> AsyncIterator[ExecutionResult]:
        """
        Execute requests and yield results as they complete.

        Args:
            requests: List of requests

        Yields:
            ExecutionResult as each completes
        """
        if not self._client:
            await self._create_client()

        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def execute_with_semaphore(request: InjectionRequest) -> ExecutionResult:
            async with semaphore:
                return await self.execute(request)

        # Create tasks
        tasks = {asyncio.create_task(execute_with_semaphore(req)): req for req in requests}

        # Yield results as they complete
        while tasks:
            done, _ = await asyncio.wait(
                tasks.keys(),
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in done:
                result = await task
                del tasks[task]
                yield result

    @property
    def stats(self) -> dict:
        """Get execution statistics."""
        return {
            "requests_executed": self._request_count,
            "waf_detections": self._waf_count,
            "current_backoff": self._waf_backoff,
        }

    def reset_stats(self) -> None:
        """Reset execution statistics."""
        self._request_count = 0
        self._waf_count = 0
        self._waf_backoff = 1.0


async def execute_requests(
    requests: list[InjectionRequest],
    config: Optional[ExecutorConfig] = None,
    scope_patterns: Optional[list[str]] = None,
) -> list[ExecutionResult]:
    """
    Convenience function to execute requests.

    Args:
        requests: Requests to execute
        config: Executor configuration
        scope_patterns: Allowed URL patterns

    Returns:
        List of execution results
    """
    async with ParallelExecutor(config) as executor:
        if scope_patterns:
            executor.set_scope(scope_patterns)
        return await executor.execute_batch(requests)


@dataclass
class WAFProbeResult:
    """Result of WAF fingerprinting probe."""

    detected: bool = False
    waf_type: Optional[str] = None
    waf_name: str = "None"
    confidence: float = 0.0
    bypass_recommendations: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class WAFAwareExecutor(ParallelExecutor):
    """
    Enhanced executor with proactive WAF fingerprinting and bypass.

    Extends ParallelExecutor with:
    - WAF fingerprinting probe before scan
    - Automatic WAF-specific payload mutations
    - Technique switching on block detection
    - Learning from blocked requests

    Example:
        config = EnhancedPATScanConfig(
            waf_aware=True,
            waf_probe_first=True,
            authorized=True,
        )
        async with WAFAwareExecutor(config) as executor:
            waf_result = await executor.probe_waf("http://example.com")
            if waf_result.detected:
                print(f"WAF detected: {waf_result.waf_name}")
            results = await executor.execute_with_waf_adaptation(requests)
    """

    # Probe payloads designed to trigger WAF responses
    WAF_PROBE_PAYLOADS = [
        "' OR '1'='1",  # SQLi
        "<script>alert(1)</script>",  # XSS
        "; cat /etc/passwd",  # CMDi
        "../../../etc/passwd",  # LFI
    ]

    def __init__(self, config: Optional[EnhancedPATScanConfig] = None):
        """
        Initialize WAF-aware executor.

        Args:
            config: Enhanced PAT scanner configuration
        """
        executor_config = config.executor if config else ExecutorConfig()
        super().__init__(executor_config)
        self.enhanced_config = config or EnhancedPATScanConfig()
        self._waf_probe_result: Optional[WAFProbeResult] = None
        self._advanced_detector = None
        self._payload_engine = None
        self._blocked_techniques: set[str] = set()
        self._successful_mutations: list[str] = []

    async def probe_waf(self, target_url: str) -> WAFProbeResult:
        """
        Probe target to fingerprint WAF.

        Sends benign probe requests followed by attack patterns
        to detect and fingerprint WAF.

        Args:
            target_url: Target URL to probe

        Returns:
            WAFProbeResult with detection details
        """
        result = WAFProbeResult()

        if not self._client:
            await self._create_client()

        # Initialize advanced detector
        self._advanced_detector = _get_advanced_waf_detector()

        # Step 1: Send benign request as baseline
        try:
            baseline_response = await self._client.get(target_url)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
        except Exception as e:
            logger.warning(f"WAF probe baseline failed: {e}")
            return result

        # Step 2: Send attack probes
        for probe_payload in self.WAF_PROBE_PAYLOADS:
            try:
                # Append payload to URL parameter
                probe_url = f"{target_url}{'&' if '?' in target_url else '?'}test={probe_payload}"
                probe_response = await self._client.get(probe_url)

                # Check for WAF indicators
                if self._advanced_detector:
                    # Use advanced detector
                    cookies = {k: v for k, v in probe_response.cookies.items()}
                    detection = self._advanced_detector.detect(
                        status_code=probe_response.status_code,
                        headers=dict(probe_response.headers),
                        body=probe_response.text[:5000],
                        cookies=cookies,
                    )

                    if detection.detected and detection.confidence > result.confidence:
                        result.detected = True
                        result.waf_type = detection.waf_type.value
                        result.waf_name = detection.waf_name
                        result.confidence = detection.confidence
                        result.bypass_recommendations = detection.bypass_recommendations
                        result.evidence = detection.evidence

                else:
                    # Fall back to basic WAF detector
                    is_waf, waf_type = WAFDetector.detect(probe_response)
                    if is_waf:
                        result.detected = True
                        result.waf_type = waf_type
                        result.waf_name = waf_type or "generic"
                        result.confidence = 0.7

                # Check for significant response difference
                status_diff = probe_response.status_code != baseline_status
                length_diff = abs(len(probe_response.text) - baseline_length) > 500

                if (status_diff or length_diff) and probe_response.status_code in {
                    403,
                    406,
                    429,
                    503,
                }:
                    if not result.detected:
                        result.detected = True
                        result.waf_type = "generic"
                        result.waf_name = "Unknown WAF"
                        result.confidence = 0.5
                        result.evidence.append(
                            f"Status changed: {baseline_status} -> {probe_response.status_code}"
                        )

            except Exception as e:
                logger.debug(f"WAF probe with payload failed: {e}")
                continue

        self._waf_probe_result = result

        if result.detected:
            logger.info(
                f"WAF detected: {result.waf_name} " f"(confidence: {result.confidence:.0%})"
            )
            # Set WAF type in payload engine
            self._payload_engine = _get_payload_engine()
            if self._payload_engine and result.waf_type:
                self._payload_engine.set_waf(result.waf_type)

        return result

    async def execute_with_waf_adaptation(
        self,
        requests: list[InjectionRequest],
        on_result: Optional[Callable[[ExecutionResult], None]] = None,
    ) -> list[ExecutionResult]:
        """
        Execute requests with WAF-adaptive behavior.

        If WAF is detected, applies bypass mutations and technique switching.

        Args:
            requests: Requests to execute
            on_result: Callback for each result

        Returns:
            List of execution results
        """
        # Probe WAF if enabled and not already done
        if self.enhanced_config.waf_probe_first and not self._waf_probe_result:
            if requests:
                target_url = requests[0].url.split("?")[0]
                await self.probe_waf(target_url)

        # If WAF detected, apply mutations to requests
        if self._waf_probe_result and self._waf_probe_result.detected:
            requests = self._apply_waf_mutations(requests)

        # Execute with adaptive behavior
        results = []
        consecutive_blocks = 0
        max_consecutive_blocks = 10

        for request in requests:
            # Check if technique is blocked
            technique = self._get_technique(request)
            if technique and technique in self._blocked_techniques:
                logger.debug(f"Skipping blocked technique: {technique}")
                continue

            result = await self.execute(request)

            # Track blocked requests for technique switching
            if result.waf_detected:
                consecutive_blocks += 1
                if technique:
                    self._blocked_techniques.add(technique)
                    logger.info(f"Technique blocked, adding to blocklist: {technique}")

                # If too many consecutive blocks, apply more aggressive mutations
                if consecutive_blocks >= max_consecutive_blocks:
                    logger.warning("Too many consecutive WAF blocks, applying aggressive evasion")
                    self._apply_aggressive_evasion()
                    consecutive_blocks = 0
            else:
                consecutive_blocks = 0
                # Track successful mutations
                if result.request.payload and result.request.payload.source_file:
                    if "+" in result.request.payload.source_file:
                        mutation = result.request.payload.source_file.split("+")[-1]
                        if mutation not in self._successful_mutations:
                            self._successful_mutations.append(mutation)

            results.append(result)

            if on_result:
                on_result(result)

        return results

    def _apply_waf_mutations(
        self,
        requests: list[InjectionRequest],
    ) -> list[InjectionRequest]:
        """Apply WAF-specific mutations to request payloads."""
        if not self._payload_engine or not self._waf_probe_result:
            return requests

        from .config import VulnerabilityType
        from .payload_parser import ParsedPayload

        waf_type = self._waf_probe_result.waf_type
        mutated_requests = []

        for request in requests:
            if not request.payload:
                mutated_requests.append(request)
                continue

            # Map VulnerabilityType to PayloadType
            vuln_type = request.payload.category
            payload_type_map = {
                VulnerabilityType.SQL_INJECTION: "sqli",
                VulnerabilityType.XSS: "xss",
                VulnerabilityType.COMMAND_INJECTION: "cmdi",
            }
            payload_type = payload_type_map.get(vuln_type)

            if not payload_type:
                mutated_requests.append(request)
                continue

            # Get WAF bypass mutations
            try:
                from aipt_v2.exploitation.payload_engine import WAF_BYPASS_MUTATIONS, MutationType

                waf_lower = waf_type.lower() if waf_type else ""
                if waf_lower in WAF_BYPASS_MUTATIONS:
                    type_mutations = WAF_BYPASS_MUTATIONS.get(waf_lower, {}).get(payload_type, [])

                    if type_mutations:
                        # Apply mutations to payload content
                        mutated_content = request.payload.content
                        applied_mutations = []

                        for original, replacement in type_mutations:
                            if original in mutated_content:
                                mutated_content = mutated_content.replace(original, replacement)
                                applied_mutations.append(f"{original}->{replacement[:20]}")

                        if mutated_content != request.payload.content:
                            # Create new request with mutated payload
                            mutated_payload = ParsedPayload(
                                content=mutated_content,
                                category=request.payload.category,
                                subcategory=request.payload.subcategory,
                                technique=request.payload.technique,
                                source_file=f"{request.payload.source_file}+waf_bypass_{waf_type}",
                                tags=request.payload.tags + [f"waf:{waf_type}"],
                            )

                            # Create copy of request with mutated payload
                            from dataclasses import replace

                            mutated_request = replace(request, payload=mutated_payload)
                            mutated_requests.append(mutated_request)
                            logger.debug(f"Applied WAF bypass: {applied_mutations}")
                            continue

            except ImportError:
                pass

            # Keep original if no mutation applied
            mutated_requests.append(request)

        return mutated_requests

    def _get_technique(self, request: InjectionRequest) -> Optional[str]:
        """Extract technique identifier from request."""
        if request.payload and request.payload.technique:
            return request.payload.technique.value
        return None

    def _apply_aggressive_evasion(self) -> None:
        """Apply more aggressive evasion when standard mutations fail."""
        # Increase backoff significantly
        self._waf_backoff = min(self._waf_backoff * 2, 60.0)

        # Add random delays

        self._rate_limiter.rate = max(1.0, self._rate_limiter.rate * 0.5)

        logger.info(
            f"Aggressive evasion: backoff={self._waf_backoff:.1f}s, "
            f"rate={self._rate_limiter.rate:.1f}rps"
        )

    @property
    def waf_probe_result(self) -> Optional[WAFProbeResult]:
        """Get WAF probe result."""
        return self._waf_probe_result

    @property
    def blocked_techniques(self) -> set[str]:
        """Get set of blocked techniques."""
        return self._blocked_techniques

    @property
    def successful_mutations(self) -> list[str]:
        """Get list of successful mutations."""
        return self._successful_mutations

    @property
    def waf_stats(self) -> dict:
        """Get WAF-related statistics."""
        return {
            **self.stats,
            "waf_detected": self._waf_probe_result.detected if self._waf_probe_result else False,
            "waf_type": self._waf_probe_result.waf_type if self._waf_probe_result else None,
            "blocked_techniques": list(self._blocked_techniques),
            "successful_mutations": self._successful_mutations,
        }
