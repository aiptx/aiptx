"""
AIPTX Business Logic Test Patterns

Defines patterns for common business logic vulnerabilities.
"""

from aipt_v2.business_logic.patterns.base import (
    TestPattern,
    PatternCategory,
    TestCase,
    TestResult,
    TestSeverity,
)
from aipt_v2.business_logic.patterns.race_conditions import RACE_CONDITION_PATTERNS
from aipt_v2.business_logic.patterns.price_manipulation import PRICE_MANIPULATION_PATTERNS
from aipt_v2.business_logic.patterns.workflow import WORKFLOW_PATTERNS
from aipt_v2.business_logic.patterns.access_control import ACCESS_CONTROL_PATTERNS
from aipt_v2.business_logic.patterns.rate_limiting import RATE_LIMIT_PATTERNS

__all__ = [
    # Base classes
    "TestPattern",
    "PatternCategory",
    "TestCase",
    "TestResult",
    "TestSeverity",
    # Pattern sets
    "RACE_CONDITION_PATTERNS",
    "PRICE_MANIPULATION_PATTERNS",
    "WORKFLOW_PATTERNS",
    "ACCESS_CONTROL_PATTERNS",
    "RATE_LIMIT_PATTERNS",
]


def get_all_patterns() -> list["TestPattern"]:
    """Get all defined test patterns."""
    return (
        RACE_CONDITION_PATTERNS +
        PRICE_MANIPULATION_PATTERNS +
        WORKFLOW_PATTERNS +
        ACCESS_CONTROL_PATTERNS +
        RATE_LIMIT_PATTERNS
    )


def get_patterns_by_category(category: PatternCategory) -> list["TestPattern"]:
    """Get patterns for a specific category."""
    return [p for p in get_all_patterns() if p.category == category]
