"""
AIPTX Beast Mode - Business Logic Analyzer
==========================================

Analyze application business logic for vulnerabilities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BusinessLogicFlaw:
    """A discovered business logic vulnerability."""
    name: str
    category: str
    description: str
    impact: str
    exploitation: str
    test_cases: list[dict[str, str]] = field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "impact": self.impact,
            "exploitation": self.exploitation,
            "test_cases": self.test_cases,
            "severity": self.severity,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


# Business logic flaw categories
BL_CATEGORIES = {
    "authentication": {
        "name": "Authentication Flaws",
        "flaws": [
            {
                "name": "Password Reset Poisoning",
                "description": "Manipulate host header to hijack password reset",
                "test": "Modify Host header in reset request",
            },
            {
                "name": "Account Enumeration",
                "description": "Different responses reveal valid accounts",
                "test": "Compare error messages for valid/invalid users",
            },
            {
                "name": "Brute Force Bypass",
                "description": "Rate limiting can be bypassed",
                "test": "Test IP rotation, X-Forwarded-For manipulation",
            },
            {
                "name": "Multi-factor Bypass",
                "description": "2FA can be skipped or bypassed",
                "test": "Try direct access to authenticated pages",
            },
        ],
    },
    "authorization": {
        "name": "Authorization Flaws",
        "flaws": [
            {
                "name": "Horizontal Privilege Escalation",
                "description": "Access other users' resources",
                "test": "Modify user IDs in requests",
            },
            {
                "name": "Vertical Privilege Escalation",
                "description": "Access admin functions as regular user",
                "test": "Test admin endpoints as regular user",
            },
            {
                "name": "Missing Function-Level Access Control",
                "description": "Sensitive functions lack authorization",
                "test": "Access admin functions directly",
            },
        ],
    },
    "session_management": {
        "name": "Session Management Flaws",
        "flaws": [
            {
                "name": "Session Fixation",
                "description": "Session ID not regenerated after login",
                "test": "Check if session ID changes post-auth",
            },
            {
                "name": "Insufficient Session Expiration",
                "description": "Sessions don't timeout properly",
                "test": "Test session validity after logout/timeout",
            },
            {
                "name": "Concurrent Session Handling",
                "description": "Multiple sessions allowed when shouldn't be",
                "test": "Login from multiple devices",
            },
        ],
    },
    "workflow": {
        "name": "Workflow Flaws",
        "flaws": [
            {
                "name": "Process Bypass",
                "description": "Skip steps in multi-step process",
                "test": "Jump directly to later steps",
            },
            {
                "name": "State Manipulation",
                "description": "Modify workflow state",
                "test": "Tamper with state parameters",
            },
            {
                "name": "Race Condition",
                "description": "Concurrent requests cause issues",
                "test": "Send simultaneous requests",
            },
        ],
    },
    "payment_cart": {
        "name": "E-commerce Flaws",
        "flaws": [
            {
                "name": "Price Manipulation",
                "description": "Modify product prices",
                "test": "Tamper with price parameters",
            },
            {
                "name": "Quantity Manipulation",
                "description": "Negative quantities or overflow",
                "test": "Test negative and extreme quantities",
            },
            {
                "name": "Discount Abuse",
                "description": "Reuse or stack discount codes",
                "test": "Apply same code multiple times",
            },
            {
                "name": "Cart Manipulation",
                "description": "Add items without proper validation",
                "test": "Modify cart between selection and checkout",
            },
        ],
    },
    "data_validation": {
        "name": "Data Validation Flaws",
        "flaws": [
            {
                "name": "Mass Assignment",
                "description": "Set unintended object properties",
                "test": "Add extra fields to requests",
            },
            {
                "name": "Type Juggling",
                "description": "Weak type comparison issues",
                "test": "Send different data types",
            },
            {
                "name": "Integer Overflow",
                "description": "Large numbers cause overflow",
                "test": "Test with MAX_INT values",
            },
        ],
    },
}


class BusinessLogicAnalyzer:
    """
    Analyze application business logic for vulnerabilities.

    Goes beyond technical vulnerabilities to find logical flaws
    in application workflows and processes.
    """

    def __init__(self):
        """Initialize business logic analyzer."""
        self._findings: list[BusinessLogicFlaw] = []
        self._application_context: dict[str, Any] = {}

    def set_context(self, context: dict[str, Any]):
        """
        Set application context for analysis.

        Args:
            context: Application information
        """
        self._application_context = context

    def get_test_cases(
        self,
        categories: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get business logic test cases.

        Args:
            categories: Specific categories to test

        Returns:
            List of test cases
        """
        if categories is None:
            categories = list(BL_CATEGORIES.keys())

        test_cases = []

        for cat_name in categories:
            if cat_name in BL_CATEGORIES:
                category = BL_CATEGORIES[cat_name]
                for flaw in category["flaws"]:
                    test_cases.append({
                        "category": cat_name,
                        "name": flaw["name"],
                        "description": flaw["description"],
                        "test": flaw["test"],
                        "commands": self._get_test_commands(cat_name, flaw["name"]),
                    })

        return test_cases

    def _get_test_commands(self, category: str, flaw_name: str) -> list[dict[str, str]]:
        """Get specific test commands for a flaw."""
        commands = {
            ("authentication", "Password Reset Poisoning"): [
                {
                    "name": "Host Header Injection",
                    "command": "curl -X POST -H 'Host: attacker.com' <reset_url> -d 'email=victim@example.com'",
                },
                {
                    "name": "X-Forwarded-Host",
                    "command": "curl -X POST -H 'X-Forwarded-Host: attacker.com' <reset_url> -d 'email=victim@example.com'",
                },
            ],
            ("authorization", "Horizontal Privilege Escalation"): [
                {
                    "name": "IDOR Test",
                    "command": "# Replace user_id with another user's ID in requests",
                },
                {
                    "name": "Parameter Tampering",
                    "command": "# Modify userId, accountId, customerId parameters",
                },
            ],
            ("workflow", "Race Condition"): [
                {
                    "name": "Turbo Intruder",
                    "command": "# Use Burp Turbo Intruder for race conditions",
                },
                {
                    "name": "Concurrent Requests",
                    "command": "for i in {1..10}; do curl -s <url> & done; wait",
                },
            ],
            ("payment_cart", "Price Manipulation"): [
                {
                    "name": "Intercept Price",
                    "command": "# Intercept request and modify price parameter",
                },
                {
                    "name": "Negative Price",
                    "command": "# Set price to negative value",
                },
            ],
        }

        return commands.get(
            (category, flaw_name),
            [{"name": "Manual Test", "command": "# Perform manual testing"}],
        )

    def analyze_workflow(
        self,
        workflow_steps: list[str],
        endpoints: list[dict[str, str]],
    ) -> list[BusinessLogicFlaw]:
        """
        Analyze a multi-step workflow for flaws.

        Args:
            workflow_steps: Steps in the workflow
            endpoints: Endpoint information

        Returns:
            List of potential flaws
        """
        findings = []

        # Check for process bypass
        if len(workflow_steps) > 2:
            findings.append(BusinessLogicFlaw(
                name="Potential Process Bypass",
                category="workflow",
                description=f"Multi-step workflow ({len(workflow_steps)} steps) may allow step skipping",
                impact="Bypass required validation or approval steps",
                exploitation="Access later steps directly without completing earlier ones",
                test_cases=[
                    {"step": i + 1, "test": f"Try accessing step {i + 1} directly"}
                    for i in range(1, len(workflow_steps))
                ],
                severity="medium",
                confidence=0.6,
            ))

        # Check for state manipulation
        findings.append(BusinessLogicFlaw(
            name="State Manipulation",
            category="workflow",
            description="Workflow state parameters may be tamperable",
            impact="Modify workflow outcome or skip validation",
            exploitation="Modify state/status parameters in requests",
            severity="medium",
            confidence=0.5,
        ))

        self._findings.extend(findings)
        return findings

    def analyze_ecommerce(
        self,
        has_cart: bool = True,
        has_discounts: bool = True,
        has_payments: bool = True,
    ) -> list[BusinessLogicFlaw]:
        """
        Analyze e-commerce specific logic.

        Args:
            has_cart: Application has shopping cart
            has_discounts: Application supports discounts
            has_payments: Application processes payments

        Returns:
            List of potential flaws
        """
        findings = []

        if has_cart:
            findings.extend([
                BusinessLogicFlaw(
                    name="Cart Tampering",
                    category="payment_cart",
                    description="Shopping cart may be vulnerable to manipulation",
                    impact="Add items at wrong prices, modify quantities",
                    exploitation="Intercept and modify cart requests",
                    severity="high",
                    confidence=0.7,
                ),
                BusinessLogicFlaw(
                    name="Negative Quantity",
                    category="payment_cart",
                    description="Negative quantities may not be validated",
                    impact="Negative total leading to refund/credit",
                    exploitation="Set item quantity to negative values",
                    severity="high",
                    confidence=0.6,
                ),
            ])

        if has_discounts:
            findings.append(BusinessLogicFlaw(
                name="Discount Code Abuse",
                category="payment_cart",
                description="Discount codes may be reusable or stackable",
                impact="Apply discounts multiple times or combine",
                exploitation="Reuse single-use codes, apply multiple codes",
                severity="medium",
                confidence=0.6,
            ))

        if has_payments:
            findings.extend([
                BusinessLogicFlaw(
                    name="Price Manipulation",
                    category="payment_cart",
                    description="Prices may be modifiable in requests",
                    impact="Purchase items at arbitrary prices",
                    exploitation="Intercept and modify price parameters",
                    severity="critical",
                    confidence=0.5,
                ),
                BusinessLogicFlaw(
                    name="Currency Confusion",
                    category="payment_cart",
                    description="Currency handling may have flaws",
                    impact="Pay in weaker currency at same numeric value",
                    exploitation="Modify currency parameters",
                    severity="high",
                    confidence=0.4,
                ),
            ])

        self._findings.extend(findings)
        return findings

    def analyze_authentication(
        self,
        has_password_reset: bool = True,
        has_2fa: bool = False,
        has_social_login: bool = False,
    ) -> list[BusinessLogicFlaw]:
        """
        Analyze authentication logic.

        Args:
            has_password_reset: Has password reset functionality
            has_2fa: Has two-factor authentication
            has_social_login: Has social login options

        Returns:
            List of potential flaws
        """
        findings = []

        if has_password_reset:
            findings.extend([
                BusinessLogicFlaw(
                    name="Password Reset Poisoning",
                    category="authentication",
                    description="Host header may influence reset link",
                    impact="Hijack password reset of any user",
                    exploitation="Inject attacker domain in Host header",
                    severity="critical",
                    confidence=0.6,
                ),
                BusinessLogicFlaw(
                    name="Token Reuse",
                    category="authentication",
                    description="Reset tokens may not be invalidated",
                    impact="Reuse tokens for repeated access",
                    exploitation="Save and reuse reset tokens",
                    severity="medium",
                    confidence=0.5,
                ),
            ])

        if has_2fa:
            findings.extend([
                BusinessLogicFlaw(
                    name="2FA Bypass",
                    category="authentication",
                    description="Two-factor authentication may be bypassable",
                    impact="Access accounts without 2FA verification",
                    exploitation="Direct navigation, parameter manipulation",
                    severity="critical",
                    confidence=0.5,
                ),
                BusinessLogicFlaw(
                    name="2FA Brute Force",
                    category="authentication",
                    description="2FA codes may not have attempt limits",
                    impact="Brute force 2FA codes",
                    exploitation="Automated code guessing",
                    severity="high",
                    confidence=0.5,
                ),
            ])

        if has_social_login:
            findings.append(BusinessLogicFlaw(
                name="OAuth Misconfiguration",
                category="authentication",
                description="OAuth implementation may have flaws",
                impact="Account takeover via OAuth abuse",
                exploitation="State parameter manipulation, redirect URI issues",
                severity="high",
                confidence=0.4,
            ))

        self._findings.extend(findings)
        return findings

    def get_llm_analysis_prompt(
        self,
        app_description: str,
        features: list[str],
    ) -> str:
        """
        Generate prompt for LLM business logic analysis.

        Args:
            app_description: Description of the application
            features: List of application features

        Returns:
            LLM prompt
        """
        features_str = "\n".join(f"- {f}" for f in features)

        return f"""As a security consultant, analyze this application for business logic vulnerabilities:

Application: {app_description}

Features:
{features_str}

Identify potential business logic flaws in:
1. Authentication flows (login, registration, password reset)
2. Authorization (access control, privilege management)
3. Workflows (multi-step processes, state management)
4. Financial operations (payments, refunds, discounts)
5. Rate limiting and abuse prevention

For each potential flaw:
- Describe the vulnerability
- Explain the business impact
- Provide test methodology
- Rate severity (critical/high/medium/low)

Focus on flaws that automated scanners typically miss."""

    def get_findings(self) -> list[BusinessLogicFlaw]:
        """Get all findings."""
        return self._findings.copy()


def analyze_business_logic(
    app_type: str,
    features: list[str] | None = None,
) -> list[BusinessLogicFlaw]:
    """Convenience function for business logic analysis."""
    analyzer = BusinessLogicAnalyzer()

    if app_type == "ecommerce":
        return analyzer.analyze_ecommerce()
    elif app_type == "auth":
        return analyzer.analyze_authentication()
    else:
        return analyzer.get_test_cases()


__all__ = [
    "BusinessLogicFlaw",
    "BusinessLogicAnalyzer",
    "BL_CATEGORIES",
    "analyze_business_logic",
]
