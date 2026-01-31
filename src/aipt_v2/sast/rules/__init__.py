"""
AIPTX SAST Rules - Security Rules Engine

Defines security rules that are matched against parsed code.
Rules are language-specific and cover common vulnerability patterns.

Rule Categories:
- Injection (SQL, Command, LDAP, etc.)
- XSS (DOM, Reflected, Stored)
- Cryptography (Weak algorithms, hardcoded secrets)
- Configuration (Insecure settings)
- Authentication/Authorization
"""

from aipt_v2.sast.rules.base import (
    Rule,
    RuleMatch,
    RuleSeverity,
    RuleCategory,
    RuleSet,
)
from aipt_v2.sast.rules.secrets import SecretDetectionRules
from aipt_v2.sast.rules.python_rules import PythonSecurityRules
from aipt_v2.sast.rules.javascript_rules import JavaScriptSecurityRules
from aipt_v2.sast.rules.java_rules import JavaSecurityRules
from aipt_v2.sast.rules.go_rules import GoSecurityRules

__all__ = [
    # Base
    "Rule",
    "RuleMatch",
    "RuleSeverity",
    "RuleCategory",
    "RuleSet",
    # Language-specific rules
    "SecretDetectionRules",
    "PythonSecurityRules",
    "JavaScriptSecurityRules",
    "JavaSecurityRules",
    "GoSecurityRules",
]


def get_rules_for_language(language: str) -> RuleSet:
    """
    Get security rules for a specific language.

    Args:
        language: Language name (python, javascript, java, go)

    Returns:
        RuleSet for the language
    """
    rules_map = {
        "python": PythonSecurityRules,
        "javascript": JavaScriptSecurityRules,
        "typescript": JavaScriptSecurityRules,
        "java": JavaSecurityRules,
        "go": GoSecurityRules,
    }

    rule_class = rules_map.get(language.lower())
    if rule_class:
        return rule_class()

    # Return empty ruleset for unknown languages
    return RuleSet(language="unknown", rules=[])


def get_all_rules() -> list[RuleSet]:
    """Get all available rule sets."""
    return [
        SecretDetectionRules(),
        PythonSecurityRules(),
        JavaScriptSecurityRules(),
        JavaSecurityRules(),
        GoSecurityRules(),
    ]
