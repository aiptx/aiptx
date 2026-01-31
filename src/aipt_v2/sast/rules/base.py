"""
AIPTX SAST Rules Base - Rule Definition Framework

Provides the base classes for defining security rules
that can be matched against parsed code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from aipt_v2.sast.parsers.base import ParsedFile, CodeLocation


class RuleSeverity(str, Enum):
    """Severity levels for security rules."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleCategory(str, Enum):
    """Categories of security rules."""
    INJECTION = "injection"          # SQL, Command, LDAP, etc.
    XSS = "xss"                       # Cross-site scripting
    CRYPTO = "crypto"                 # Cryptography issues
    AUTH = "auth"                     # Authentication/Authorization
    CONFIG = "config"                 # Configuration issues
    SECRETS = "secrets"               # Hardcoded secrets
    SSRF = "ssrf"                     # Server-side request forgery
    PATH_TRAVERSAL = "path_traversal" # Path traversal/LFI
    DESERIALIZATION = "deserialization"
    XXE = "xxe"                       # XML external entities
    LOGGING = "logging"               # Logging sensitive data
    ERROR_HANDLING = "error_handling"
    RACE_CONDITION = "race_condition"
    MISCELLANEOUS = "misc"


@dataclass
class Rule:
    """
    Security rule definition.

    A rule defines a pattern that indicates a security issue.
    Rules can match against:
    - Raw code (regex patterns)
    - Parsed structures (AST patterns)
    - Data flows (source to sink)
    """
    id: str
    name: str
    description: str
    severity: RuleSeverity
    category: RuleCategory
    languages: list[str]  # Languages this rule applies to

    # Matching patterns (use one or more)
    pattern: Optional[str] = None  # Regex pattern
    patterns: list[str] = field(default_factory=list)  # Multiple patterns
    negative_patterns: list[str] = field(default_factory=list)  # Patterns that negate match

    # CWE/OWASP mappings
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)

    # Remediation
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    # Advanced matching
    source_patterns: list[str] = field(default_factory=list)  # For taint tracking
    sink_patterns: list[str] = field(default_factory=list)

    # Metadata
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    def matches_line(self, line: str) -> bool:
        """
        Check if rule matches a line of code.

        Args:
            line: Line of code to check

        Returns:
            True if rule matches
        """
        # Check negative patterns first
        for neg_pattern in self.negative_patterns:
            if re.search(neg_pattern, line, re.IGNORECASE):
                return False

        # Check main pattern
        if self.pattern:
            if re.search(self.pattern, line, re.IGNORECASE):
                return True

        # Check multiple patterns
        for pattern in self.patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        return False


@dataclass
class RuleMatch:
    """
    A match of a rule against code.

    Contains all information needed to report the finding.
    """
    rule: Rule
    file_path: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    code_snippet: str = ""
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    matched_text: str = ""
    confidence: float = 0.8
    metadata: dict = field(default_factory=dict)

    @property
    def location(self) -> CodeLocation:
        return CodeLocation(
            file_path=self.file_path,
            line=self.line,
            column=self.column,
            end_line=self.end_line,
        )

    def to_finding_dict(self) -> dict:
        """Convert to finding dictionary."""
        return {
            "rule_id": self.rule.id,
            "title": self.rule.name,
            "description": self.rule.description,
            "severity": self.rule.severity.value,
            "category": self.rule.category.value,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "remediation": self.rule.remediation,
            "cwe_ids": self.rule.cwe_ids,
            "owasp_ids": self.rule.owasp_ids,
            "confidence": self.confidence,
            "references": self.rule.references,
        }


class RuleSet:
    """
    Collection of security rules for a language or category.

    Provides efficient matching against parsed files.
    """

    def __init__(
        self,
        language: str,
        rules: Optional[list[Rule]] = None,
        name: str = "",
    ):
        """
        Initialize rule set.

        Args:
            language: Target language
            rules: List of rules
            name: Optional name for the rule set
        """
        self.language = language
        self.name = name or f"{language}_rules"
        self._rules: list[Rule] = rules or []

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the set."""
        self._rules.append(rule)

    def get_rules(self, enabled_only: bool = True) -> list[Rule]:
        """Get all rules."""
        if enabled_only:
            return [r for r in self._rules if r.enabled]
        return self._rules

    def get_rules_by_category(self, category: RuleCategory) -> list[Rule]:
        """Get rules by category."""
        return [r for r in self._rules if r.category == category and r.enabled]

    def get_rules_by_severity(self, severity: RuleSeverity) -> list[Rule]:
        """Get rules by severity."""
        return [r for r in self._rules if r.severity == severity and r.enabled]

    def match_file(self, parsed: ParsedFile) -> list[RuleMatch]:
        """
        Match all rules against a parsed file.

        Args:
            parsed: Parsed file to check

        Returns:
            List of rule matches
        """
        matches = []

        for rule in self.get_rules():
            # Check language compatibility
            if self.language.lower() not in [l.lower() for l in rule.languages]:
                continue

            # Match against each line
            for i, line in enumerate(parsed.lines, 1):
                if rule.matches_line(line):
                    # Get context
                    context_before = parsed.lines[max(0, i-4):i-1]
                    context_after = parsed.lines[i:min(len(parsed.lines), i+3)]

                    match = RuleMatch(
                        rule=rule,
                        file_path=parsed.file_path,
                        line=i,
                        code_snippet=line.strip(),
                        context_before=context_before,
                        context_after=context_after,
                        matched_text=line.strip(),
                    )
                    matches.append(match)

        return matches

    def match_content(
        self, content: str, file_path: str
    ) -> list[RuleMatch]:
        """
        Match rules against raw content.

        Args:
            content: Source code content
            file_path: File path for reporting

        Returns:
            List of rule matches
        """
        matches = []
        lines = content.split("\n")

        for rule in self.get_rules():
            for i, line in enumerate(lines, 1):
                if rule.matches_line(line):
                    context_before = lines[max(0, i-4):i-1]
                    context_after = lines[i:min(len(lines), i+3)]

                    match = RuleMatch(
                        rule=rule,
                        file_path=file_path,
                        line=i,
                        code_snippet=line.strip(),
                        context_before=context_before,
                        context_after=context_after,
                    )
                    matches.append(match)

        return matches

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self):
        return iter(self._rules)
