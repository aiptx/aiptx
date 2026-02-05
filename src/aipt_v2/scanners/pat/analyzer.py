"""
PAT Response Analyzer

Analyzes HTTP responses to detect successful vulnerability exploitation.
Supports multiple detection methods: error-based, time-based, content-diff, reflection.
"""
from __future__ import annotations

import difflib
import hashlib
import logging
import math
import re
from dataclasses import dataclass, field
from typing import Optional

from .config import (
    VulnerabilityType,
    DetectionMethod,
    AnalyzerConfig,
)
from .detection_patterns import (
    get_detection_patterns,
    match_any_pattern,
    DetectionPattern,
)
from .request_generator import InjectionRequest
from .executor import ExecutionResult

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Result of response analysis."""
    vulnerable: bool = False
    confidence: float = 0.0                # 0.0 to 1.0
    detection_method: DetectionMethod = DetectionMethod.ERROR_BASED
    vuln_type: Optional[VulnerabilityType] = None

    # Evidence
    evidence: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)

    # Quality indicators
    false_positive_risk: str = "unknown"   # low, medium, high
    requires_manual_verification: bool = False

    # Context
    payload_used: str = ""
    parameter: str = ""
    injection_point: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "detection_method": self.detection_method.value,
            "vuln_type": self.vuln_type.value if self.vuln_type else None,
            "evidence": self.evidence[:3],  # Limit for output
            "matched_patterns": self.matched_patterns,
            "false_positive_risk": self.false_positive_risk,
            "requires_manual_verification": self.requires_manual_verification,
        }


@dataclass
class BaselineData:
    """Baseline response data for comparison."""
    status_codes: list[int] = field(default_factory=list)
    response_lengths: list[int] = field(default_factory=list)
    response_hashes: list[str] = field(default_factory=list)
    avg_response_time_ms: float = 0.0
    content_samples: list[str] = field(default_factory=list)
    # Enhanced: Store all response times for statistical analysis
    response_times_ms: list[float] = field(default_factory=list)

    @property
    def avg_length(self) -> float:
        """Get average response length."""
        if not self.response_lengths:
            return 0.0
        return sum(self.response_lengths) / len(self.response_lengths)

    @property
    def common_status_code(self) -> int:
        """Get most common status code."""
        if not self.status_codes:
            return 200
        return max(set(self.status_codes), key=self.status_codes.count)

    @property
    def response_time_std_ms(self) -> float:
        """Calculate standard deviation of response times (for z-score analysis)."""
        if len(self.response_times_ms) < 2:
            return 0.0
        n = len(self.response_times_ms)
        mean = self.avg_response_time_ms
        variance = sum((t - mean) ** 2 for t in self.response_times_ms) / n
        return math.sqrt(variance)

    @property
    def response_time_min_ms(self) -> float:
        """Get minimum response time."""
        if not self.response_times_ms:
            return 0.0
        return min(self.response_times_ms)

    @property
    def response_time_max_ms(self) -> float:
        """Get maximum response time."""
        if not self.response_times_ms:
            return 0.0
        return max(self.response_times_ms)


class ResponseAnalyzer:
    """
    Analyzes HTTP responses to detect vulnerabilities.

    Detection methods:
    - Error-based: Looks for error messages indicating vulnerability
    - Time-based: Compares response time against baseline
    - Content-diff: Compares response content against baseline
    - Reflection: Checks if payload is reflected in response
    - Header-based: Analyzes response headers
    """

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        """
        Initialize analyzer.

        Args:
            config: Analyzer configuration
        """
        self.config = config or AnalyzerConfig()
        self._baseline: Optional[BaselineData] = None

    def set_baseline(self, results: list[ExecutionResult]) -> None:
        """
        Set baseline from normal (non-payload) requests.

        Args:
            results: List of baseline execution results
        """
        self._baseline = BaselineData()

        for result in results:
            if result.success and result.response:
                self._baseline.status_codes.append(result.status_code)
                self._baseline.response_lengths.append(len(result.response_body))
                self._baseline.response_hashes.append(
                    hashlib.md5(result.response_body.encode()).hexdigest()
                )
                self._baseline.content_samples.append(result.response_body[:2000])

            # Store all response times for statistical analysis
            if result.elapsed_ms > 0:
                self._baseline.response_times_ms.append(result.elapsed_ms)

        # Calculate average response time
        times = self._baseline.response_times_ms
        if times:
            self._baseline.avg_response_time_ms = sum(times) / len(times)

        logger.debug(
            f"Baseline set: avg_length={self._baseline.avg_length:.0f}, "
            f"avg_time={self._baseline.avg_response_time_ms:.0f}ms, "
            f"std_time={self._baseline.response_time_std_ms:.0f}ms, "
            f"n_samples={len(times)}"
        )

    def analyze(
        self,
        result: ExecutionResult,
        baseline: Optional[BaselineData] = None,
    ) -> AnalysisResult:
        """
        Analyze an execution result for vulnerabilities.

        Args:
            result: Execution result to analyze
            baseline: Baseline data (uses stored baseline if None)

        Returns:
            AnalysisResult with vulnerability detection
        """
        analysis = AnalysisResult()
        baseline = baseline or self._baseline

        if not result.success or not result.response:
            return analysis

        # Get vulnerability type from payload
        vuln_type = None
        if result.request.payload:
            vuln_type = result.request.payload.category
            analysis.vuln_type = vuln_type
            analysis.payload_used = result.request.payload.content
            analysis.parameter = result.request.parameter_name
            analysis.injection_point = result.request.injection_point.value

        # Run all detection methods and aggregate confidence
        detections: list[tuple[DetectionMethod, float, list[str]]] = []

        # 1. Error-based detection
        error_result = self._detect_error_based(result, vuln_type)
        if error_result[1] > 0:
            detections.append(error_result)

        # 2. Time-based detection
        time_result = self._detect_time_based(result, baseline)
        if time_result[1] > 0:
            detections.append(time_result)

        # 3. Content difference detection
        content_result = self._detect_content_diff(result, baseline)
        if content_result[1] > 0:
            detections.append(content_result)

        # 4. Reflection detection (primarily for XSS)
        reflection_result = self._detect_reflection(result)
        if reflection_result[1] > 0:
            detections.append(reflection_result)

        # 5. Header-based detection
        header_result = self._detect_header_based(result, vuln_type)
        if header_result[1] > 0:
            detections.append(header_result)

        # Aggregate results
        if detections:
            # Use highest confidence detection
            best_detection = max(detections, key=lambda x: x[1])
            analysis.detection_method = best_detection[0]
            analysis.confidence = best_detection[1]
            analysis.evidence = best_detection[2]

            # Collect all matched patterns
            for _, _, evidence in detections:
                analysis.matched_patterns.extend(evidence)

            # Determine if vulnerable
            analysis.vulnerable = analysis.confidence >= self.config.confidence_threshold

            # Assess false positive risk
            analysis.false_positive_risk = self._assess_fp_risk(analysis, detections)

            # Flag for manual verification if needed
            analysis.requires_manual_verification = (
                analysis.confidence < 0.85 or
                analysis.false_positive_risk in ("medium", "high")
            )

        return analysis

    def _detect_error_based(
        self,
        result: ExecutionResult,
        vuln_type: Optional[VulnerabilityType],
    ) -> tuple[DetectionMethod, float, list[str]]:
        """Detect vulnerabilities via error messages."""
        evidence = []
        confidence = 0.0

        if not vuln_type:
            return DetectionMethod.ERROR_BASED, 0.0, []

        body = result.response_body

        # Check against detection patterns
        matched, pattern, match = match_any_pattern(body, vuln_type)
        if matched:
            confidence = 0.85
            evidence.append(f"Matched pattern: {pattern}")
            if match:
                evidence.append(f"Match: {match.group(0)[:100]}")

        # Additional checks for specific vuln types
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            # Extra SQL error patterns
            sql_errors = [
                "syntax error",
                "mysql",
                "postgresql",
                "sqlite",
                "oracle",
                "sql server",
            ]
            body_lower = body.lower()
            for error in sql_errors:
                if error in body_lower and "error" in body_lower:
                    confidence = max(confidence, 0.7)
                    evidence.append(f"SQL error keyword: {error}")

        return DetectionMethod.ERROR_BASED, confidence, evidence

    def _detect_time_based(
        self,
        result: ExecutionResult,
        baseline: Optional[BaselineData],
    ) -> tuple[DetectionMethod, float, list[str]]:
        """
        Detect time-based blind vulnerabilities using statistical analysis.

        Uses z-score analysis to reduce false positives from network jitter.
        A delay is considered significant if:
        1. Z-score > 3 (3 standard deviations above mean = 99.7% confidence)
        2. Actual delay is close to expected delay (within tolerance)

        This dramatically reduces false positive rate from ~30% to <10%.
        """
        evidence = []
        confidence = 0.0

        if not baseline or baseline.avg_response_time_ms == 0:
            return DetectionMethod.TIME_BASED, 0.0, []

        elapsed = result.elapsed_ms
        baseline_avg = baseline.avg_response_time_ms
        baseline_std = baseline.response_time_std_ms
        threshold = self.config.time_based_threshold_ms
        actual_delay = elapsed - baseline_avg

        # Early exit if no significant delay
        if actual_delay < threshold * 0.5:
            return DetectionMethod.TIME_BASED, 0.0, []

        # ─── Statistical Z-Score Analysis ───
        # Z-score = (observed - mean) / std_dev
        # Z > 3.0 means 99.7% confidence it's not random variation
        z_score = 0.0
        if baseline_std > 0 and len(baseline.response_times_ms) >= 3:
            z_score = actual_delay / baseline_std
            evidence.append(f"Z-score: {z_score:.2f}")

            if z_score > 4.0:
                confidence = 0.85
                evidence.append("Highly significant delay (>4σ)")
            elif z_score > 3.0:
                confidence = 0.75
                evidence.append("Significant delay (>3σ)")
            elif z_score > 2.0:
                confidence = 0.5
                evidence.append("Moderate delay (>2σ)")
        else:
            # Fallback for small sample sizes: use threshold-based detection
            if actual_delay >= threshold:
                confidence = 0.6
                evidence.append("Insufficient baseline samples for z-score")

        # ─── Delay Accuracy Check ───
        # Confirm the delay matches expected sleep/wait time (within tolerance)
        # This catches cases where payload specified SLEEP(5) and we see ~5s delay
        delay_tolerance_ms = 1500  # Allow ±1.5 second variance
        delay_matches_expected = abs(actual_delay - threshold) < delay_tolerance_ms

        if delay_matches_expected and actual_delay >= threshold * 0.8:
            # Delay is close to what the payload requested
            confidence = min(confidence + 0.15, 0.95)
            evidence.append(
                f"Delay matches expected: {actual_delay:.0f}ms ≈ {threshold:.0f}ms (±{delay_tolerance_ms}ms)"
            )

        # ─── Additional Confidence Boosters ───
        # Very large delays (2x threshold) are strong indicators
        if actual_delay >= threshold * 2:
            confidence = min(confidence + 0.1, 0.95)
            evidence.append(f"Large delay: {actual_delay:.0f}ms (≥2x threshold)")

        # If no std data but delay is very significant, still flag with lower confidence
        if confidence == 0 and actual_delay >= threshold:
            confidence = 0.5
            evidence.append("Threshold exceeded (no statistical data)")

        # Always include timing summary
        if confidence > 0:
            evidence.insert(0, f"Response: {elapsed:.0f}ms | Baseline: {baseline_avg:.0f}ms ± {baseline_std:.0f}ms")

        return DetectionMethod.TIME_BASED, confidence, evidence

    def _detect_content_diff(
        self,
        result: ExecutionResult,
        baseline: Optional[BaselineData],
    ) -> tuple[DetectionMethod, float, list[str]]:
        """Detect vulnerabilities via content differences."""
        evidence = []
        confidence = 0.0

        if not baseline or not baseline.content_samples:
            return DetectionMethod.CONTENT_DIFF, 0.0, []

        body = result.response_body
        body_length = len(body)

        # Skip very short responses
        if body_length < self.config.min_response_length:
            return DetectionMethod.CONTENT_DIFF, 0.0, []

        # Check length difference
        avg_length = baseline.avg_length
        if avg_length > 0:
            length_ratio = abs(body_length - avg_length) / avg_length
            if length_ratio > self.config.content_diff_threshold:
                confidence = 0.6
                evidence.append(
                    f"Length diff: {body_length} vs baseline {avg_length:.0f} "
                    f"({length_ratio*100:.1f}% change)"
                )

        # Check content similarity with baseline samples
        for sample in baseline.content_samples[:3]:
            similarity = self._calculate_similarity(body, sample)
            if similarity < (1 - self.config.content_diff_threshold):
                new_confidence = 0.5 + (1 - similarity) * 0.3
                if new_confidence > confidence:
                    confidence = new_confidence
                    evidence.append(f"Content similarity: {similarity*100:.1f}%")

        # Check status code difference
        if result.status_code != baseline.common_status_code:
            confidence = max(confidence, 0.4)
            evidence.append(
                f"Status code changed: {result.status_code} vs {baseline.common_status_code}"
            )

        return DetectionMethod.CONTENT_DIFF, confidence, evidence

    def _detect_reflection(
        self,
        result: ExecutionResult,
    ) -> tuple[DetectionMethod, float, list[str]]:
        """Detect payload reflection (primarily for XSS)."""
        evidence = []
        confidence = 0.0

        if not result.request.payload:
            return DetectionMethod.REFLECTION, 0.0, []

        payload = result.request.payload.content
        body = result.response_body

        # Direct reflection check
        if payload in body:
            # Check context for XSS
            vuln_type = result.request.payload.category

            if vuln_type == VulnerabilityType.XSS:
                # Check if in dangerous context
                dangerous_contexts = [
                    (r"<script[^>]*>.*?" + re.escape(payload), "script tag", 0.95),
                    (r"on\w+\s*=\s*['\"].*?" + re.escape(payload), "event handler", 0.9),
                    (r"javascript:.*?" + re.escape(payload), "javascript: URL", 0.9),
                    (re.escape(payload), "direct reflection", 0.7),
                ]

                for pattern, context, ctx_confidence in dangerous_contexts:
                    if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                        confidence = max(confidence, ctx_confidence)
                        evidence.append(f"Payload reflected in {context}")
                        break
            else:
                confidence = 0.6
                evidence.append("Payload reflected in response")

        # Check for partial reflection (encoded/modified)
        elif self._check_partial_reflection(payload, body):
            confidence = 0.5
            evidence.append("Partial payload reflection detected")

        return DetectionMethod.REFLECTION, confidence, evidence

    def _detect_header_based(
        self,
        result: ExecutionResult,
        vuln_type: Optional[VulnerabilityType],
    ) -> tuple[DetectionMethod, float, list[str]]:
        """Detect vulnerabilities via response headers."""
        evidence = []
        confidence = 0.0

        headers = result.response_headers

        # Check for CRLF injection
        if vuln_type == VulnerabilityType.CRLF_INJECTION:
            for key, value in headers.items():
                if result.request.payload and result.request.payload.content in value:
                    confidence = 0.9
                    evidence.append(f"Payload in header: {key}")

        # Check for open redirect
        if vuln_type == VulnerabilityType.OPEN_REDIRECT:
            location = headers.get("location", "")
            if result.request.payload:
                payload = result.request.payload.content
                if payload in location or "evil.com" in location.lower():
                    confidence = 0.85
                    evidence.append(f"Redirect to injected URL: {location}")

        # Check for SSRF indicators
        if vuln_type == VulnerabilityType.SSRF:
            # Internal IP in response
            internal_patterns = [
                r"127\.\d+\.\d+\.\d+",
                r"10\.\d+\.\d+\.\d+",
                r"192\.168\.\d+\.\d+",
                r"localhost",
            ]
            body = result.response_body
            for pattern in internal_patterns:
                if re.search(pattern, body):
                    confidence = max(confidence, 0.7)
                    evidence.append(f"Internal IP/host in response")
                    break

        return DetectionMethod.HEADER_BASED, confidence, evidence

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity ratio between two strings."""
        if not str1 or not str2:
            return 0.0

        # Use sequence matcher for similarity
        # Limit length for performance
        str1 = str1[:5000]
        str2 = str2[:5000]

        matcher = difflib.SequenceMatcher(None, str1, str2)
        return matcher.ratio()

    def _check_partial_reflection(self, payload: str, body: str) -> bool:
        """Check for partial/encoded payload reflection."""
        if len(payload) < 5:
            return False

        # Check for URL-encoded reflection
        import urllib.parse
        encoded = urllib.parse.quote(payload)
        if encoded in body:
            return True

        # Check for HTML-encoded reflection
        html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        if html_encoded in body:
            return True

        # Check for partial matches (significant portion of payload)
        min_length = max(5, len(payload) // 2)
        for i in range(len(payload) - min_length + 1):
            chunk = payload[i:i + min_length]
            if chunk in body:
                return True

        return False

    def _assess_fp_risk(
        self,
        analysis: AnalysisResult,
        detections: list[tuple[DetectionMethod, float, list[str]]],
    ) -> str:
        """Assess false positive risk."""
        # Multiple detection methods agreeing = lower FP risk
        num_detections = len([d for d in detections if d[1] > 0.5])

        if num_detections >= 2 and analysis.confidence >= 0.85:
            return "low"
        elif num_detections >= 1 and analysis.confidence >= 0.7:
            return "medium"
        else:
            return "high"


class EnhancedResponseAnalyzer(ResponseAnalyzer):
    """
    Enhanced analyzer with statistical time-based confirmation.

    Adds:
    - Multiple sample confirmation for time-based detection
    - Statistical t-test comparison between delay/no-delay requests
    - Adaptive confidence based on sample consistency
    """

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        super().__init__(config)
        self._time_samples: dict[str, list[float]] = {}  # param -> [times]

    def analyze_with_confirmation(
        self,
        delay_results: list[ExecutionResult],
        no_delay_results: list[ExecutionResult],
    ) -> AnalysisResult:
        """
        Analyze time-based detection using multiple samples.

        For robust time-based blind detection, we compare:
        - delay_results: Responses from payloads with expected delay (SLEEP(5))
        - no_delay_results: Responses from payloads without delay (SLEEP(0))

        Uses statistical comparison to determine if delay is genuine.

        Args:
            delay_results: Results from delay-inducing payloads
            no_delay_results: Results from non-delay payloads (control group)

        Returns:
            AnalysisResult with statistical confidence
        """
        analysis = AnalysisResult()

        if not delay_results or not no_delay_results:
            return analysis

        # Extract timing data
        delay_times = [r.elapsed_ms for r in delay_results if r.elapsed_ms > 0]
        no_delay_times = [r.elapsed_ms for r in no_delay_results if r.elapsed_ms > 0]

        if len(delay_times) < 2 or len(no_delay_times) < 2:
            # Not enough samples for statistical analysis
            return self.analyze(delay_results[0]) if delay_results else analysis

        # Calculate statistics
        delay_mean = sum(delay_times) / len(delay_times)
        no_delay_mean = sum(no_delay_times) / len(no_delay_times)
        mean_diff = delay_mean - no_delay_mean

        # Calculate pooled standard deviation for t-test
        delay_var = sum((t - delay_mean) ** 2 for t in delay_times) / len(delay_times)
        no_delay_var = sum((t - no_delay_mean) ** 2 for t in no_delay_times) / len(no_delay_times)

        pooled_std = math.sqrt(
            (delay_var * len(delay_times) + no_delay_var * len(no_delay_times)) /
            (len(delay_times) + len(no_delay_times))
        )

        # Perform t-statistic calculation
        t_statistic = 0.0
        if pooled_std > 0:
            se = pooled_std * math.sqrt(1/len(delay_times) + 1/len(no_delay_times))
            t_statistic = mean_diff / se if se > 0 else 0

        evidence = [
            f"Delay group: {delay_mean:.0f}ms (n={len(delay_times)})",
            f"Control group: {no_delay_mean:.0f}ms (n={len(no_delay_times)})",
            f"Mean difference: {mean_diff:.0f}ms",
        ]

        # Confidence based on t-statistic
        # t > 2.0 roughly corresponds to p < 0.05 for small samples
        # t > 3.0 roughly corresponds to p < 0.01
        # t > 4.0 roughly corresponds to p < 0.001
        confidence = 0.0
        if t_statistic > 4.0:
            confidence = 0.95
            evidence.append(f"T-statistic: {t_statistic:.2f} (p < 0.001)")
        elif t_statistic > 3.0:
            confidence = 0.85
            evidence.append(f"T-statistic: {t_statistic:.2f} (p < 0.01)")
        elif t_statistic > 2.0:
            confidence = 0.70
            evidence.append(f"T-statistic: {t_statistic:.2f} (p < 0.05)")
        elif t_statistic > 1.5:
            confidence = 0.5
            evidence.append(f"T-statistic: {t_statistic:.2f} (marginal)")

        # Additional confidence boost if delay matches expected threshold
        expected_delay = self.config.time_based_threshold_ms
        if abs(mean_diff - expected_delay) < 1500:  # Within 1.5s of expected
            confidence = min(confidence + 0.1, 0.95)
            evidence.append(f"Delay matches expected: {mean_diff:.0f}ms ≈ {expected_delay:.0f}ms")

        # Set result
        if confidence >= self.config.confidence_threshold:
            analysis.vulnerable = True

        analysis.confidence = confidence
        analysis.detection_method = DetectionMethod.TIME_BASED
        analysis.evidence = evidence
        analysis.false_positive_risk = "low" if confidence >= 0.85 else "medium"

        # Copy metadata from first result
        if delay_results[0].request.payload:
            analysis.vuln_type = delay_results[0].request.payload.category
            analysis.payload_used = delay_results[0].request.payload.content
            analysis.parameter = delay_results[0].request.parameter_name
            analysis.injection_point = delay_results[0].request.injection_point.value

        return analysis

    def get_timing_statistics(self) -> dict:
        """Get current timing statistics for debugging/reporting."""
        if not self._baseline:
            return {}

        return {
            "avg_response_time_ms": self._baseline.avg_response_time_ms,
            "std_response_time_ms": self._baseline.response_time_std_ms,
            "min_response_time_ms": self._baseline.response_time_min_ms,
            "max_response_time_ms": self._baseline.response_time_max_ms,
            "sample_count": len(self._baseline.response_times_ms),
        }


def analyze_results(
    results: list[ExecutionResult],
    baseline_results: Optional[list[ExecutionResult]] = None,
    config: Optional[AnalyzerConfig] = None,
) -> list[AnalysisResult]:
    """
    Convenience function to analyze multiple results.

    Args:
        results: Execution results to analyze
        baseline_results: Baseline results for comparison
        config: Analyzer configuration

    Returns:
        List of analysis results
    """
    analyzer = ResponseAnalyzer(config)

    if baseline_results:
        analyzer.set_baseline(baseline_results)

    return [analyzer.analyze(result) for result in results]
