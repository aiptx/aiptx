"""
AIPTX Beast Mode - Stealth Module
==================================

Evasion, anti-detection, and stealthy operation techniques.

Components:
- stealth_engine: Main stealth coordinator
- timing: Jitter, delays, and timing evasion
- traffic_mimicry: Blend with normal traffic patterns
- lolbins: Living-off-the-land binary database
- obfuscation: Command and payload obfuscation
"""

from __future__ import annotations

from aipt_v2.stealth.stealth_engine import (
    StealthEngine,
    StealthConfig,
    StealthLevel,
)
from aipt_v2.stealth.timing import (
    TimingEngine,
    add_jitter,
    get_timing_profile,
)
from aipt_v2.stealth.lolbins import (
    LOLBinDatabase,
    get_lolbin_alternative,
)

__all__ = [
    # Engine
    "StealthEngine",
    "StealthConfig",
    "StealthLevel",
    # Timing
    "TimingEngine",
    "add_jitter",
    "get_timing_profile",
    # LOLBins
    "LOLBinDatabase",
    "get_lolbin_alternative",
]
