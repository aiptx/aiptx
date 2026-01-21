"""
PoC (Proof of Concept) Validator
================================

Validates vulnerability proofs-of-concept to ensure they meet quality standards
and can be reproduced. Helps achieve zero false positives.

Integrated from Strix's reporting system.

Example:
    from aipt_v2.tools.reporting import validate_poc

    poc_data = {
        "title": "SQL Injection in Login",
        "description": "The login form is vulnerable to SQL injection...",
        "steps": [
            "Navigate to /login",
            "Enter username: admin' OR '1'='1",
            "Observe authentication bypass",
        ],
        "evidence": "HTTP response showing authentication success without valid credentials",
        "impact": "Authentication bypass allowing unauthorized access",
        "script_code": "curl -X POST http://target/login -d 'user=admin\\' OR \\'1\\'=\\'1&pass=x'",
    }

    is_valid, errors = validate_poc(poc_data)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


class PoCValidationError(Exception):
    """Raised when PoC validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"PoC validation failed: {'; '.join(errors)}")


@dataclass
class PoCRequirements:
    """
    Requirements for a valid PoC.

    Can be customized per vulnerability type.
    """

    # Required text fields
    required_fields: list[str] = field(
        default_factory=lambda: [
            "title",
            "description",
            "impact",
            "target",
            "technical_analysis",
            "poc_description",
            "poc_script_code",
            "remediation_steps",
        ]
    )

    # Minimum lengths for fields
    min_lengths: dict[str, int] = field(
        default_factory=lambda: {
            "title": 10,
            "description": 50,
            "impact": 20,
            "technical_analysis": 50,
            "poc_description": 30,
            "poc_script_code": 10,
            "remediation_steps": 20,
        }
    )

    # Fields that should contain code/commands
    code_fields: list[str] = field(default_factory=lambda: ["poc_script_code"])

    # Fields that should contain URLs or paths
    target_fields: list[str] = field(default_factory=lambda: ["target", "endpoint"])

    # Whether steps are required
    require_steps: bool = False
    min_steps: int = 1


def validate_poc(
    poc_data: dict[str, Any],
    requirements: PoCRequirements | None = None,
) -> tuple[bool, list[str]]:
    """
    Validate a PoC against requirements.

    Args:
        poc_data: Dictionary containing PoC fields.
        requirements: Optional custom requirements. Uses defaults if not provided.

    Returns:
        Tuple of (is_valid, error_messages).
    """
    req = requirements or PoCRequirements()
    errors: list[str] = []

    # Check required fields
    for field_name in req.required_fields:
        value = poc_data.get(field_name)
        if not value or not str(value).strip():
            errors.append(f"{field_name.replace('_', ' ').title()} cannot be empty")
            continue

        # Check minimum length
        if field_name in req.min_lengths:
            min_len = req.min_lengths[field_name]
            if len(str(value).strip()) < min_len:
                errors.append(
                    f"{field_name.replace('_', ' ').title()} too short "
                    f"(minimum {min_len} characters)"
                )

    # Check code fields have actual code
    for field_name in req.code_fields:
        value = poc_data.get(field_name)
        if value:
            # Basic check for code-like content
            value_str = str(value).strip()
            if not _looks_like_code(value_str):
                errors.append(
                    f"{field_name.replace('_', ' ').title()} does not appear to contain "
                    "valid code, commands, or exploit payload"
                )

    # Check steps if required
    if req.require_steps:
        steps = poc_data.get("steps", [])
        if not steps:
            errors.append("Reproduction steps are required")
        elif len(steps) < req.min_steps:
            errors.append(f"At least {req.min_steps} reproduction steps required")

    # Check for false positive indicators
    false_positive_indicators = _check_false_positive_indicators(poc_data)
    errors.extend(false_positive_indicators)

    is_valid = len(errors) == 0
    return is_valid, errors


def _looks_like_code(text: str) -> bool:
    """
    Check if text appears to contain code or commands.

    This is a heuristic check looking for common code patterns.
    """
    # Common code indicators
    code_indicators = [
        # Commands/scripts
        "curl ",
        "wget ",
        "python ",
        "node ",
        "bash ",
        "sh ",
        "#!/",
        # HTTP
        "http://",
        "https://",
        "GET ",
        "POST ",
        "PUT ",
        "DELETE ",
        # Code syntax
        "import ",
        "from ",
        "def ",
        "function ",
        "const ",
        "let ",
        "var ",
        "class ",
        # SQL
        "SELECT ",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "UNION ",
        "' OR ",
        "\" OR ",
        # Payloads
        "<script",
        "javascript:",
        "${",
        "{{",
        "eval(",
        # Command injection
        "; ",
        "| ",
        "` ",
        "$(",
        # Path traversal
        "../",
        "..\\",
    ]

    text_lower = text.lower()
    for indicator in code_indicators:
        if indicator.lower() in text_lower:
            return True

    # Check for special characters common in code
    special_chars = ["=", "(", ")", "{", "}", "[", "]", "<", ">", "&", "|", ";"]
    char_count = sum(1 for c in text if c in special_chars)
    if char_count >= 3:
        return True

    return False


def _check_false_positive_indicators(poc_data: dict[str, Any]) -> list[str]:
    """
    Check for indicators that suggest a false positive.

    Returns list of warning messages for potential false positives.
    """
    warnings: list[str] = []

    description = str(poc_data.get("description", "")).lower()
    poc_description = str(poc_data.get("poc_description", "")).lower()
    poc_code = str(poc_data.get("poc_script_code", "")).lower()

    # Check for speculative language
    speculative_phrases = [
        "might be vulnerable",
        "could be vulnerable",
        "may be vulnerable",
        "possibly vulnerable",
        "potential vulnerability",
        "needs further testing",
        "requires confirmation",
        "unconfirmed",
    ]

    for phrase in speculative_phrases:
        if phrase in description or phrase in poc_description:
            warnings.append(
                f"PoC contains speculative language ('{phrase}'). "
                "Ensure the vulnerability is confirmed before reporting."
            )
            break

    # Check for missing evidence
    if "error" not in poc_code and "response" not in poc_description:
        if "evidence" not in poc_data or not poc_data.get("evidence"):
            warnings.append(
                "PoC lacks clear evidence of exploitation. "
                "Include server response, error messages, or other observable impact."
            )

    # Check for generic placeholder content
    placeholder_indicators = [
        "example.com",
        "target.com",
        "localhost",
        "127.0.0.1",
        "[target]",
        "<target>",
        "{target}",
        "xxx",
        "placeholder",
    ]

    target = str(poc_data.get("target", "")).lower()
    for indicator in placeholder_indicators:
        if indicator in target:
            warnings.append(
                f"Target appears to be a placeholder ('{indicator}'). "
                "Replace with actual target for valid PoC."
            )
            break

    return warnings


def validate_vulnerability_report(
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    **kwargs: Any,
) -> tuple[bool, list[str]]:
    """
    Validate a complete vulnerability report.

    Convenience function that wraps validate_poc with standard fields.

    Args:
        title: Vulnerability title.
        description: Detailed description.
        impact: Business/security impact.
        target: Target URL/endpoint.
        technical_analysis: Technical explanation.
        poc_description: PoC explanation.
        poc_script_code: Actual exploit code/commands.
        remediation_steps: How to fix.
        **kwargs: Additional fields.

    Returns:
        Tuple of (is_valid, error_messages).
    """
    poc_data = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        **kwargs,
    }

    return validate_poc(poc_data)
