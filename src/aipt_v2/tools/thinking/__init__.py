"""
AIPTX Thinking Tool
===================

Provides structured reasoning for complex decisions.
Helps agents think through multi-step problems systematically.

Integrated from Strix's thinking tool.

Usage:
    from aipt_v2.tools.thinking import think, analyze_options

    # Think through a decision
    result = think(
        reasoning="The target has an exposed API endpoint at /api/users...",
        decision="Test for IDOR vulnerability by modifying user IDs",
        confidence=0.85,
    )

    # Analyze multiple options
    result = analyze_options(
        context="Found potential SQL injection point",
        options=[
            "Use sqlmap for automated testing",
            "Manual testing with custom payloads",
            "Check for WAF before proceeding",
        ],
    )
"""

from .thinking_actions import (
    think,
    analyze_options,
    plan_attack,
    ThinkingResult,
)

__all__ = [
    "think",
    "analyze_options",
    "plan_attack",
    "ThinkingResult",
]
