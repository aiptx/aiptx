"""
Thinking Tool Actions
=====================

Structured thinking for complex decisions during penetration testing.
Provides transparency into agent reasoning for audit and review.

Integrated from Strix's thinking tool.

Example:
    # Think through a decision
    result = think(
        reasoning="The login form doesn't appear to have CSRF protection...",
        decision="Attempt CSRF attack on password change functionality",
        confidence=0.75,
    )

    # Plan an attack
    result = plan_attack(
        vulnerability_type="SQL Injection",
        target="https://example.com/api/search",
        context="GET parameter 'q' appears to be injectable",
    )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class ThinkingResult:
    """Result of a thinking operation."""

    reasoning: str
    decision: str
    confidence: float
    timestamp: str
    context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "reasoning": self.reasoning,
            "decision": self.decision,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "context": self.context,
        }


def think(
    reasoning: str,
    decision: str,
    confidence: float,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Record structured thinking for a decision.

    This tool helps agents think through complex decisions systematically.
    It provides transparency into the reasoning process for audit and review.

    Args:
        reasoning: Step-by-step thought process explaining the analysis.
        decision: The decision or action to take.
        confidence: Confidence level from 0.0 to 1.0.
        context: Optional additional context.

    Returns:
        Dict with the thinking result and status.

    Example:
        result = think(
            reasoning='''
            1. The target form submits to /api/login via POST
            2. The username field appears to be concatenated into SQL
            3. Single quote causes a 500 error, indicating potential SQLi
            4. The error message reveals MySQL backend
            ''',
            decision="Proceed with SQL injection testing using MySQL-specific payloads",
            confidence=0.85,
        )
    """
    # Validate confidence
    if not 0.0 <= confidence <= 1.0:
        return {
            "success": False,
            "message": f"Confidence must be between 0.0 and 1.0, got {confidence}",
            "error": "invalid_confidence",
        }

    # Validate reasoning
    if not reasoning or len(reasoning.strip()) < 10:
        return {
            "success": False,
            "message": "Reasoning must be at least 10 characters",
            "error": "invalid_reasoning",
        }

    # Validate decision
    if not decision or len(decision.strip()) < 5:
        return {
            "success": False,
            "message": "Decision must be at least 5 characters",
            "error": "invalid_decision",
        }

    result = ThinkingResult(
        reasoning=reasoning.strip(),
        decision=decision.strip(),
        confidence=confidence,
        timestamp=datetime.utcnow().isoformat(),
        context=context,
    )

    # Log to tracer if available
    try:
        from aipt_v2.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer and hasattr(tracer, "log_thinking"):
            tracer.log_thinking(result.to_dict())
    except (ImportError, AttributeError):
        pass

    logger.info(f"Thinking: {decision} (confidence: {confidence:.0%})")

    return {
        "success": True,
        "message": "Thinking recorded",
        **result.to_dict(),
    }


def analyze_options(
    context: str,
    options: list[str],
    criteria: list[str] | None = None,
) -> dict[str, Any]:
    """
    Analyze multiple options for a decision.

    Helps agents compare different approaches systematically.

    Args:
        context: The situation or problem being analyzed.
        options: List of possible actions/approaches.
        criteria: Optional evaluation criteria.

    Returns:
        Dict with analysis framework.

    Example:
        result = analyze_options(
            context="Found potential command injection in search parameter",
            options=[
                "Test with simple command like 'id'",
                "Use time-based blind injection",
                "Check for WAF before testing",
            ],
            criteria=["Stealth", "Reliability", "Speed"],
        )
    """
    if not context:
        return {
            "success": False,
            "message": "Context is required",
            "error": "missing_context",
        }

    if not options or len(options) < 2:
        return {
            "success": False,
            "message": "At least 2 options are required",
            "error": "insufficient_options",
        }

    default_criteria = [
        "Effectiveness",
        "Risk",
        "Stealth",
        "Time required",
    ]

    return {
        "success": True,
        "message": "Options analysis framework ready",
        "context": context,
        "options": [
            {"id": i + 1, "description": opt}
            for i, opt in enumerate(options)
        ],
        "criteria": criteria or default_criteria,
        "instructions": (
            "Evaluate each option against the criteria. "
            "Consider trade-offs and recommend the best approach. "
            "Use the think() function to record your final decision."
        ),
    }


def plan_attack(
    vulnerability_type: str,
    target: str,
    context: str,
    constraints: list[str] | None = None,
) -> dict[str, Any]:
    """
    Create a structured attack plan.

    Helps agents plan multi-step attacks systematically.

    Args:
        vulnerability_type: Type of vulnerability (e.g., "SQL Injection").
        target: Target URL/endpoint.
        context: Current knowledge about the target.
        constraints: Optional constraints (e.g., "No automated tools").

    Returns:
        Dict with attack planning framework.

    Example:
        result = plan_attack(
            vulnerability_type="SQL Injection",
            target="https://example.com/api/search?q=",
            context="GET parameter appears injectable, MySQL backend",
            constraints=["Stay under WAF radar", "No data modification"],
        )
    """
    if not vulnerability_type:
        return {
            "success": False,
            "message": "Vulnerability type is required",
            "error": "missing_vulnerability_type",
        }

    if not target:
        return {
            "success": False,
            "message": "Target is required",
            "error": "missing_target",
        }

    # Standard attack phases
    attack_phases = [
        {
            "phase": 1,
            "name": "Reconnaissance",
            "description": "Gather information about the target and vulnerability",
        },
        {
            "phase": 2,
            "name": "Validation",
            "description": "Confirm the vulnerability exists and is exploitable",
        },
        {
            "phase": 3,
            "name": "Exploitation",
            "description": "Exploit the vulnerability to demonstrate impact",
        },
        {
            "phase": 4,
            "name": "Documentation",
            "description": "Document findings with PoC and evidence",
        },
    ]

    return {
        "success": True,
        "message": "Attack plan framework ready",
        "vulnerability_type": vulnerability_type,
        "target": target,
        "context": context,
        "constraints": constraints or [],
        "phases": attack_phases,
        "instructions": (
            "Execute each phase systematically. "
            "Use think() to record reasoning at each step. "
            "Create vulnerability report with create_vulnerability_report() when complete."
        ),
    }
