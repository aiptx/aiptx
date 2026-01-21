"""
AIPTX Beast Mode - Timing Engine
================================

Timing-based evasion and jitter functionality.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TimingProfile(str, Enum):
    """Pre-defined timing profiles."""
    AGGRESSIVE = "aggressive"   # Fast, more detectable
    NORMAL = "normal"           # Balanced
    CAUTIOUS = "cautious"       # Slower, less detectable
    PARANOID = "paranoid"       # Very slow, minimal footprint
    BUSINESS_HOURS = "business_hours"  # Mimic normal work patterns


@dataclass
class TimingConfig:
    """Timing configuration."""
    min_delay: float
    max_delay: float
    jitter_factor: float
    burst_size: int = 1
    burst_delay: float = 0.0

    def get_delay(self) -> float:
        """Calculate delay with jitter."""
        base = random.uniform(self.min_delay, self.max_delay)
        jitter = base * self.jitter_factor * random.uniform(-1, 1)
        return max(0, base + jitter)


# Pre-defined timing profiles
TIMING_PROFILES = {
    TimingProfile.AGGRESSIVE: TimingConfig(
        min_delay=0.0,
        max_delay=0.1,
        jitter_factor=0.1,
        burst_size=10,
        burst_delay=0.5,
    ),
    TimingProfile.NORMAL: TimingConfig(
        min_delay=0.5,
        max_delay=2.0,
        jitter_factor=0.3,
        burst_size=5,
        burst_delay=3.0,
    ),
    TimingProfile.CAUTIOUS: TimingConfig(
        min_delay=2.0,
        max_delay=5.0,
        jitter_factor=0.5,
        burst_size=3,
        burst_delay=10.0,
    ),
    TimingProfile.PARANOID: TimingConfig(
        min_delay=10.0,
        max_delay=60.0,
        jitter_factor=0.7,
        burst_size=1,
        burst_delay=0.0,
    ),
    TimingProfile.BUSINESS_HOURS: TimingConfig(
        min_delay=1.0,
        max_delay=10.0,
        jitter_factor=0.5,
        burst_size=3,
        burst_delay=30.0,
    ),
}


class TimingEngine:
    """
    Manage timing for stealthy operations.

    Provides jitter, delays, and timing-based evasion.
    """

    def __init__(self, profile: TimingProfile = TimingProfile.NORMAL):
        """
        Initialize timing engine.

        Args:
            profile: Timing profile to use
        """
        self.profile = profile
        self.config = TIMING_PROFILES[profile]
        self._request_count = 0
        self._burst_count = 0
        self._last_request_time = 0.0

    def wait(self) -> float:
        """
        Wait for appropriate delay.

        Returns:
            Actual delay used
        """
        delay = self.get_next_delay()
        if delay > 0:
            time.sleep(delay)
        return delay

    def get_next_delay(self) -> float:
        """
        Calculate next delay based on profile.

        Returns:
            Delay in seconds
        """
        self._request_count += 1
        self._burst_count += 1

        # Check if burst limit reached
        if self._burst_count >= self.config.burst_size and self.config.burst_delay > 0:
            self._burst_count = 0
            return self.config.burst_delay + self.config.get_delay()

        return self.config.get_delay()

    def reset(self):
        """Reset timing counters."""
        self._request_count = 0
        self._burst_count = 0
        self._last_request_time = 0.0

    def is_business_hours(self) -> bool:
        """
        Check if current time is business hours.

        Returns:
            True if during business hours
        """
        current_hour = time.localtime().tm_hour
        return 9 <= current_hour <= 17

    def get_optimal_timing(self) -> dict[str, Any]:
        """
        Get optimal timing recommendations.

        Returns:
            Timing recommendations
        """
        return {
            "is_business_hours": self.is_business_hours(),
            "recommended_profile": TimingProfile.BUSINESS_HOURS.value if self.is_business_hours() else TimingProfile.CAUTIOUS.value,
            "current_profile": self.profile.value,
            "current_config": {
                "min_delay": self.config.min_delay,
                "max_delay": self.config.max_delay,
                "jitter_factor": self.config.jitter_factor,
                "burst_size": self.config.burst_size,
            },
            "requests_sent": self._request_count,
        }


def add_jitter(
    value: float,
    percentage: float = 0.3,
    min_val: float = 0.0,
    max_val: float | None = None,
) -> float:
    """
    Add jitter to a value.

    Args:
        value: Base value
        percentage: Jitter percentage (0-1)
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        Value with jitter applied
    """
    jitter = value * percentage * random.uniform(-1, 1)
    result = value + jitter

    result = max(min_val, result)
    if max_val is not None:
        result = min(max_val, result)

    return result


def get_timing_profile(profile_name: str) -> TimingConfig:
    """
    Get a timing profile by name.

    Args:
        profile_name: Profile name

    Returns:
        TimingConfig for the profile
    """
    profile = TimingProfile(profile_name)
    return TIMING_PROFILES[profile]


def calculate_scan_duration(
    total_targets: int,
    operations_per_target: int,
    profile: TimingProfile = TimingProfile.NORMAL,
) -> dict[str, Any]:
    """
    Calculate estimated scan duration.

    Args:
        total_targets: Number of targets
        operations_per_target: Operations per target
        profile: Timing profile

    Returns:
        Duration estimates
    """
    config = TIMING_PROFILES[profile]
    total_operations = total_targets * operations_per_target

    # Calculate average delay
    avg_delay = (config.min_delay + config.max_delay) / 2

    # Account for bursts
    if config.burst_size > 0:
        bursts = total_operations // config.burst_size
        burst_time = bursts * config.burst_delay
    else:
        burst_time = 0

    # Total time
    base_time = total_operations * avg_delay
    total_time = base_time + burst_time

    return {
        "total_operations": total_operations,
        "average_delay": avg_delay,
        "estimated_seconds": total_time,
        "estimated_minutes": total_time / 60,
        "estimated_hours": total_time / 3600,
        "human_readable": _format_duration(total_time),
        "profile": profile.value,
    }


def _format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    else:
        return f"{seconds / 3600:.1f} hours"


def get_rate_limiting_bypass_techniques() -> list[dict[str, str]]:
    """
    Get techniques for bypassing rate limiting.

    Returns:
        List of bypass techniques
    """
    return [
        {
            "name": "distributed_requests",
            "description": "Spread requests across multiple source IPs",
            "implementation": "Use multiple proxies or pivot points",
        },
        {
            "name": "slow_rate",
            "description": "Stay under rate limit threshold",
            "implementation": "Use cautious or paranoid timing profile",
        },
        {
            "name": "header_rotation",
            "description": "Rotate identifying headers",
            "implementation": "Change User-Agent, X-Forwarded-For per request",
        },
        {
            "name": "session_rotation",
            "description": "Use new sessions periodically",
            "implementation": "Clear cookies, get new session tokens",
        },
        {
            "name": "ip_rotation",
            "description": "Rotate source IP addresses",
            "implementation": "Use rotating proxies or VPN endpoints",
        },
        {
            "name": "time_spacing",
            "description": "Space requests over longer periods",
            "implementation": "Run over multiple days during business hours",
        },
    ]


__all__ = [
    "TimingProfile",
    "TimingConfig",
    "TimingEngine",
    "TIMING_PROFILES",
    "add_jitter",
    "get_timing_profile",
    "calculate_scan_duration",
]
