"""
AIPT Real-Time Adaptation Engine

Adapts scanning strategy in real-time based on target responses:
- Detects WAF/rate limiting and adjusts accordingly
- Modifies payloads when blocked
- Adjusts timing to avoid detection
- Switches techniques based on feedback

This provides intelligent, adaptive scanning that responds to defenses.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class DefenseType(Enum):
    """Types of defenses that can be detected."""
    WAF = "waf"
    RATE_LIMIT = "rate_limit"
    IP_BLOCK = "ip_block"
    GEO_BLOCK = "geo_block"
    CAPTCHA = "captcha"
    HONEYPOT = "honeypot"
    TARPIT = "tarpit"


class AdaptationAction(Enum):
    """Actions that can be taken in response to defenses."""
    SLOW_DOWN = "slow_down"
    CHANGE_PAYLOAD = "change_payload"
    USE_PROXY = "use_proxy"
    WAIT_AND_RETRY = "wait_and_retry"
    SKIP_ENDPOINT = "skip_endpoint"
    SWITCH_TECHNIQUE = "switch_technique"
    ABORT = "abort"


@dataclass
class DefenseDetection:
    """Detection of a defensive measure."""
    defense_type: DefenseType
    confidence: float  # 0.0 to 1.0
    evidence: str
    detected_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdaptationStrategy:
    """Strategy for adapting to detected defenses."""
    action: AdaptationAction
    parameters: dict[str, Any]
    reason: str
    expected_outcome: str


@dataclass
class RequestResult:
    """Result of a request for adaptation analysis."""
    url: str
    status_code: int
    response_time_ms: int
    response_size: int
    blocked: bool = False
    error: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AdaptationState:
    """Current state of the adaptation engine."""
    request_count: int = 0
    blocked_count: int = 0
    success_count: int = 0
    current_delay_ms: int = 100
    detected_defenses: list[DefenseDetection] = field(default_factory=list)
    payload_failures: dict[str, int] = field(default_factory=dict)
    last_request_time: Optional[datetime] = None
    is_rate_limited: bool = False
    is_blocked: bool = False


class RealTimeAdapter:
    """
    Real-time adaptation engine for security scanning.

    Monitors request/response patterns and adapts scanning strategy
    to avoid detection and maximize effectiveness.

    Example:
        adapter = RealTimeAdapter()

        # Register defense handlers
        adapter.on_waf_detected(lambda d: print(f"WAF: {d.evidence}"))

        # Process results and adapt
        for url in urls:
            result = await send_request(url)
            strategy = adapter.analyze_result(result)

            if strategy.action == AdaptationAction.SLOW_DOWN:
                await asyncio.sleep(strategy.parameters["delay_ms"] / 1000)
            elif strategy.action == AdaptationAction.CHANGE_PAYLOAD:
                payload = strategy.parameters["new_payload"]
    """

    def __init__(
        self,
        base_delay_ms: int = 100,
        max_delay_ms: int = 5000,
        block_threshold: int = 5,
        rate_limit_threshold: int = 10,
    ):
        self.base_delay_ms = base_delay_ms
        self.max_delay_ms = max_delay_ms
        self.block_threshold = block_threshold
        self.rate_limit_threshold = rate_limit_threshold

        self.state = AdaptationState(current_delay_ms=base_delay_ms)
        self._handlers: dict[DefenseType, list[Callable]] = {}
        self._recent_responses: list[RequestResult] = []
        self._max_recent = 50

    def analyze_result(self, result: RequestResult) -> AdaptationStrategy:
        """
        Analyze a request result and determine adaptation strategy.

        Args:
            result: The request result to analyze

        Returns:
            AdaptationStrategy with recommended action
        """
        self._record_result(result)

        # Check for various defense indicators
        defenses = self._detect_defenses(result)
        for defense in defenses:
            self._record_defense(defense)
            self._trigger_handlers(defense)

        # Determine strategy based on detected defenses
        return self._determine_strategy(result, defenses)

    def _detect_defenses(self, result: RequestResult) -> list[DefenseDetection]:
        """Detect defensive measures from a response."""
        detections = []

        # Check for WAF signatures
        waf_detection = self._detect_waf(result)
        if waf_detection:
            detections.append(waf_detection)

        # Check for rate limiting
        rate_limit = self._detect_rate_limit(result)
        if rate_limit:
            detections.append(rate_limit)

        # Check for IP blocking
        ip_block = self._detect_ip_block(result)
        if ip_block:
            detections.append(ip_block)

        # Check for captcha
        captcha = self._detect_captcha(result)
        if captcha:
            detections.append(captcha)

        return detections

    def _detect_waf(self, result: RequestResult) -> Optional[DefenseDetection]:
        """Detect Web Application Firewall signatures."""
        waf_indicators = {
            # Status codes
            "status_403": result.status_code == 403,
            "status_406": result.status_code == 406,
            "status_429": result.status_code == 429,
            "status_503": result.status_code == 503,

            # Headers
            "cloudflare": any("cloudflare" in v.lower() for v in result.headers.values()),
            "akamai": any("akamai" in v.lower() for v in result.headers.values()),
            "aws_waf": "x-amzn-requestid" in result.headers,
            "mod_security": "mod_security" in str(result.headers).lower(),

            # Response patterns
            "blocked_keyword": result.blocked,
        }

        active_indicators = [k for k, v in waf_indicators.items() if v]

        if active_indicators:
            # Determine WAF name from indicators
            waf_name = "Unknown WAF"
            if "cloudflare" in active_indicators:
                waf_name = "Cloudflare"
            elif "akamai" in active_indicators:
                waf_name = "Akamai"
            elif "aws_waf" in active_indicators:
                waf_name = "AWS WAF"
            elif "mod_security" in active_indicators:
                waf_name = "ModSecurity"

            return DefenseDetection(
                defense_type=DefenseType.WAF,
                confidence=min(len(active_indicators) * 0.3, 1.0),
                evidence=f"{waf_name} detected via: {', '.join(active_indicators)}",
                metadata={"waf_name": waf_name, "indicators": active_indicators},
            )

        return None

    def _detect_rate_limit(self, result: RequestResult) -> Optional[DefenseDetection]:
        """Detect rate limiting."""
        # Check status code
        if result.status_code == 429:
            retry_after = result.headers.get("retry-after", "unknown")
            return DefenseDetection(
                defense_type=DefenseType.RATE_LIMIT,
                confidence=0.95,
                evidence=f"HTTP 429 received, Retry-After: {retry_after}",
                metadata={"retry_after": retry_after},
            )

        # Check for consistent slow responses indicating throttling
        recent_times = [r.response_time_ms for r in self._recent_responses[-10:]]
        if len(recent_times) >= 5:
            avg_time = sum(recent_times) / len(recent_times)
            if avg_time > 2000:  # > 2 seconds average
                return DefenseDetection(
                    defense_type=DefenseType.RATE_LIMIT,
                    confidence=0.6,
                    evidence=f"Throttling suspected: avg response time {avg_time:.0f}ms",
                    metadata={"avg_response_time": avg_time},
                )

        # Check for repeated blocks
        recent_blocks = sum(1 for r in self._recent_responses[-10:] if r.blocked)
        if recent_blocks >= self.rate_limit_threshold:
            return DefenseDetection(
                defense_type=DefenseType.RATE_LIMIT,
                confidence=0.7,
                evidence=f"{recent_blocks} blocks in last 10 requests",
                metadata={"block_count": recent_blocks},
            )

        return None

    def _detect_ip_block(self, result: RequestResult) -> Optional[DefenseDetection]:
        """Detect IP-based blocking."""
        # Consistent 403s or connection resets suggest IP block
        recent_403s = sum(1 for r in self._recent_responses[-10:] if r.status_code == 403)

        if recent_403s >= 8:
            return DefenseDetection(
                defense_type=DefenseType.IP_BLOCK,
                confidence=0.8,
                evidence=f"{recent_403s}/10 recent requests returned 403",
                metadata={"consecutive_403s": recent_403s},
            )

        return None

    def _detect_captcha(self, result: RequestResult) -> Optional[DefenseDetection]:
        """Detect CAPTCHA challenges."""
        captcha_indicators = [
            "captcha" in str(result.headers).lower(),
            result.status_code == 503,  # Often used with challenges
        ]

        if any(captcha_indicators):
            return DefenseDetection(
                defense_type=DefenseType.CAPTCHA,
                confidence=0.7,
                evidence="CAPTCHA challenge detected",
            )

        return None

    def _determine_strategy(
        self,
        result: RequestResult,
        defenses: list[DefenseDetection],
    ) -> AdaptationStrategy:
        """Determine the best adaptation strategy."""
        # Priority: IP Block > Rate Limit > WAF > Continue

        # Check for IP block - most severe
        ip_blocks = [d for d in defenses if d.defense_type == DefenseType.IP_BLOCK]
        if ip_blocks and ip_blocks[0].confidence > 0.7:
            return AdaptationStrategy(
                action=AdaptationAction.USE_PROXY,
                parameters={"reason": "IP appears blocked"},
                reason="IP blocking detected with high confidence",
                expected_outcome="Requests should succeed from new IP",
            )

        # Check for rate limiting
        rate_limits = [d for d in defenses if d.defense_type == DefenseType.RATE_LIMIT]
        if rate_limits:
            rl = rate_limits[0]
            new_delay = min(self.state.current_delay_ms * 2, self.max_delay_ms)

            # Check for Retry-After header
            retry_after = rl.metadata.get("retry_after")
            if retry_after and retry_after != "unknown":
                try:
                    new_delay = int(retry_after) * 1000
                except ValueError:
                    pass

            self.state.current_delay_ms = new_delay
            self.state.is_rate_limited = True

            return AdaptationStrategy(
                action=AdaptationAction.SLOW_DOWN,
                parameters={"delay_ms": new_delay},
                reason=f"Rate limiting detected: {rl.evidence}",
                expected_outcome=f"Delay increased to {new_delay}ms between requests",
            )

        # Check for WAF blocking
        wafs = [d for d in defenses if d.defense_type == DefenseType.WAF]
        if wafs and result.blocked:
            waf = wafs[0]
            waf_name = waf.metadata.get("waf_name", "Unknown")

            return AdaptationStrategy(
                action=AdaptationAction.CHANGE_PAYLOAD,
                parameters={
                    "waf_name": waf_name,
                    "bypass_techniques": self._get_waf_bypass_techniques(waf_name),
                },
                reason=f"WAF blocking detected: {waf_name}",
                expected_outcome="Payload modified to bypass WAF",
            )

        # Check for CAPTCHA
        captchas = [d for d in defenses if d.defense_type == DefenseType.CAPTCHA]
        if captchas:
            return AdaptationStrategy(
                action=AdaptationAction.SKIP_ENDPOINT,
                parameters={"reason": "CAPTCHA required"},
                reason="CAPTCHA challenge cannot be bypassed automatically",
                expected_outcome="Endpoint skipped, manual testing recommended",
            )

        # No defenses - check if we can speed up
        if (self.state.is_rate_limited and
            self.state.blocked_count == 0 and
            len(self._recent_responses) >= 10):

            # No blocks in recent requests, try reducing delay
            new_delay = max(self.base_delay_ms, self.state.current_delay_ms // 2)
            self.state.current_delay_ms = new_delay

            if new_delay == self.base_delay_ms:
                self.state.is_rate_limited = False

        # Default: continue with current settings
        return AdaptationStrategy(
            action=AdaptationAction.SLOW_DOWN,
            parameters={"delay_ms": self.state.current_delay_ms},
            reason="Maintaining current pace",
            expected_outcome="Continue scanning",
        )

    def _get_waf_bypass_techniques(self, waf_name: str) -> list[str]:
        """Get recommended WAF bypass techniques."""
        techniques = {
            "Cloudflare": [
                "double_url_encode",
                "unicode_normalization",
                "case_variation",
                "comment_injection",
            ],
            "Akamai": [
                "unicode_normalization",
                "parameter_pollution",
                "json_payload",
            ],
            "AWS WAF": [
                "double_url_encode",
                "null_byte_injection",
            ],
            "ModSecurity": [
                "comment_injection",
                "case_variation",
                "chunked_encoding",
            ],
        }
        return techniques.get(waf_name, ["encoding_variation", "case_variation"])

    def _record_result(self, result: RequestResult):
        """Record a request result for analysis."""
        self._recent_responses.append(result)
        if len(self._recent_responses) > self._max_recent:
            self._recent_responses.pop(0)

        self.state.request_count += 1
        if result.blocked:
            self.state.blocked_count += 1
        elif result.status_code == 200:
            self.state.success_count += 1

        self.state.last_request_time = datetime.utcnow()

    def _record_defense(self, defense: DefenseDetection):
        """Record a detected defense."""
        self.state.detected_defenses.append(defense)

    def on_waf_detected(self, handler: Callable[[DefenseDetection], None]):
        """Register handler for WAF detection."""
        self._register_handler(DefenseType.WAF, handler)

    def on_rate_limit(self, handler: Callable[[DefenseDetection], None]):
        """Register handler for rate limit detection."""
        self._register_handler(DefenseType.RATE_LIMIT, handler)

    def on_ip_block(self, handler: Callable[[DefenseDetection], None]):
        """Register handler for IP block detection."""
        self._register_handler(DefenseType.IP_BLOCK, handler)

    def _register_handler(self, defense_type: DefenseType, handler: Callable):
        """Register a handler for a defense type."""
        if defense_type not in self._handlers:
            self._handlers[defense_type] = []
        self._handlers[defense_type].append(handler)

    def _trigger_handlers(self, defense: DefenseDetection):
        """Trigger handlers for a detected defense."""
        handlers = self._handlers.get(defense.defense_type, [])
        for handler in handlers:
            try:
                handler(defense)
            except Exception as e:
                logger.warning(f"Handler error: {e}")

    def get_current_delay(self) -> int:
        """Get the current recommended delay in milliseconds."""
        return self.state.current_delay_ms

    def get_statistics(self) -> dict[str, Any]:
        """Get adaptation statistics."""
        return {
            "total_requests": self.state.request_count,
            "blocked_requests": self.state.blocked_count,
            "successful_requests": self.state.success_count,
            "block_rate": self.state.blocked_count / max(1, self.state.request_count),
            "current_delay_ms": self.state.current_delay_ms,
            "is_rate_limited": self.state.is_rate_limited,
            "detected_defenses": [
                {
                    "type": d.defense_type.value,
                    "confidence": d.confidence,
                    "evidence": d.evidence,
                }
                for d in self.state.detected_defenses[-10:]
            ],
        }

    def reset(self):
        """Reset adaptation state."""
        self.state = AdaptationState(current_delay_ms=self.base_delay_ms)
        self._recent_responses.clear()
