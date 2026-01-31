"""
AI-Powered Business Logic Test Generator

Uses LLM to generate creative, context-aware business logic tests
based on application analysis and known vulnerability patterns.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aipt_v2.business_logic.patterns import (
    TestPattern,
    TestCase,
    PatternCategory,
    TestSeverity,
    get_all_patterns,
)
from aipt_v2.business_logic.analyzer import Workflow


@dataclass
class GeneratedTest:
    """An AI-generated test case."""
    name: str
    description: str
    category: str
    attack_vector: str
    method: str
    endpoint: str
    payload: Dict[str, Any]
    expected_behavior: str
    success_criteria: List[str]
    risk_level: str
    reasoning: str
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_test_case(self) -> TestCase:
        """Convert to executable TestCase."""
        return TestCase(
            name=self.name,
            description=self.description,
            method=self.method,
            endpoint_pattern=self.endpoint,
            body_template=self.payload,
            success_indicators=self.success_criteria,
        )


@dataclass
class GenerationContext:
    """Context for test generation."""
    target_url: str
    workflows: List[Workflow]
    discovered_endpoints: List[str]
    parameters: Dict[str, List[str]]
    application_type: str  # e-commerce, banking, social, etc.
    technology_stack: List[str]
    authentication_type: str
    existing_patterns: List[str]


class AITestGenerator:
    """
    Generates business logic tests using AI analysis.

    The generator:
    1. Analyzes application context and workflows
    2. Identifies potential business logic attack surfaces
    3. Generates creative test cases beyond predefined patterns
    4. Prioritizes tests by potential impact
    """

    # Templates for common business logic attacks
    ATTACK_TEMPLATES = {
        "race_condition": {
            "description": "Test for TOCTOU vulnerabilities with concurrent requests",
            "vectors": [
                "simultaneous_transactions",
                "concurrent_state_updates",
                "parallel_resource_claims",
            ],
            "indicators": ["multiple_successes", "inconsistent_state", "duplicate_records"],
        },
        "parameter_tampering": {
            "description": "Modify parameters to bypass business rules",
            "vectors": [
                "price_modification",
                "quantity_manipulation",
                "role_elevation",
                "id_enumeration",
            ],
            "indicators": ["accepted_invalid_value", "unauthorized_access", "privilege_escalation"],
        },
        "workflow_bypass": {
            "description": "Skip required steps in multi-step processes",
            "vectors": [
                "step_skipping",
                "state_manipulation",
                "direct_final_action",
            ],
            "indicators": ["completed_without_steps", "state_inconsistency"],
        },
        "mass_assignment": {
            "description": "Set unintended fields via API",
            "vectors": [
                "role_injection",
                "status_override",
                "internal_field_setting",
            ],
            "indicators": ["field_accepted", "privilege_change"],
        },
        "time_manipulation": {
            "description": "Exploit time-based restrictions",
            "vectors": [
                "deadline_bypass",
                "early_access",
                "expiry_circumvention",
            ],
            "indicators": ["accepted_outside_window", "accessed_restricted_content"],
        },
    }

    # Common vulnerable parameter patterns
    SENSITIVE_PARAMS = {
        "financial": ["amount", "price", "total", "balance", "credit", "fee", "discount"],
        "identity": ["user_id", "account_id", "owner_id", "customer_id"],
        "access": ["role", "permission", "is_admin", "level", "group"],
        "state": ["status", "state", "step", "stage", "approved", "verified"],
        "quantity": ["quantity", "count", "limit", "max", "min"],
    }

    def __init__(self, context: Optional[GenerationContext] = None):
        """
        Initialize generator.

        Args:
            context: Application context for generation
        """
        self.context = context
        self.generated_tests: List[GeneratedTest] = []

    def analyze_attack_surface(
        self,
        workflows: List[Workflow],
        endpoints: List[str],
    ) -> Dict[str, List[str]]:
        """
        Analyze potential attack surface from discovered elements.

        Returns mapping of attack categories to potential targets.
        """
        attack_surface = {
            "race_conditions": [],
            "parameter_tampering": [],
            "workflow_bypass": [],
            "access_control": [],
            "data_validation": [],
        }

        # Analyze endpoints
        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()

            # Race condition targets
            if any(kw in endpoint_lower for kw in ["payment", "transfer", "order", "checkout", "claim", "redeem"]):
                attack_surface["race_conditions"].append(endpoint)

            # Parameter tampering targets
            if any(kw in endpoint_lower for kw in ["update", "edit", "modify", "create", "price", "quantity"]):
                attack_surface["parameter_tampering"].append(endpoint)

            # Workflow targets
            if any(kw in endpoint_lower for kw in ["step", "wizard", "process", "checkout", "verify"]):
                attack_surface["workflow_bypass"].append(endpoint)

            # Access control targets
            if any(kw in endpoint_lower for kw in ["admin", "user", "profile", "settings", "manage"]):
                attack_surface["access_control"].append(endpoint)

        # Analyze workflow parameters
        for workflow in workflows:
            for endpoint, params in workflow.parameters.items():
                for param in params:
                    param_lower = param.lower()

                    # Check against sensitive param patterns
                    for category, keywords in self.SENSITIVE_PARAMS.items():
                        if any(kw in param_lower for kw in keywords):
                            attack_surface["data_validation"].append(f"{endpoint}:{param}")

        return attack_surface

    def generate_tests_for_endpoint(
        self,
        endpoint: str,
        method: str,
        parameters: List[str],
        application_type: str = "web_app",
    ) -> List[GeneratedTest]:
        """
        Generate tests for a specific endpoint.

        Args:
            endpoint: The API endpoint
            method: HTTP method
            parameters: Known parameters
            application_type: Type of application

        Returns:
            List of generated tests
        """
        tests = []
        endpoint_lower = endpoint.lower()

        # Determine relevant attack categories
        relevant_attacks = []

        if any(kw in endpoint_lower for kw in ["payment", "transfer", "checkout"]):
            relevant_attacks.extend(["race_condition", "parameter_tampering"])

        if any(kw in endpoint_lower for kw in ["user", "profile", "account"]):
            relevant_attacks.extend(["parameter_tampering", "mass_assignment"])

        if any(kw in endpoint_lower for kw in ["step", "wizard", "process"]):
            relevant_attacks.append("workflow_bypass")

        if any(kw in endpoint_lower for kw in ["coupon", "promo", "discount"]):
            relevant_attacks.extend(["race_condition", "parameter_tampering"])

        # Generate tests for each relevant attack
        for attack_type in set(relevant_attacks):
            template = self.ATTACK_TEMPLATES.get(attack_type, {})

            for vector in template.get("vectors", [])[:2]:  # Limit to 2 vectors per attack
                test = self._generate_test_for_vector(
                    endpoint,
                    method,
                    parameters,
                    attack_type,
                    vector,
                    template,
                )
                if test:
                    tests.append(test)

        return tests

    def _generate_test_for_vector(
        self,
        endpoint: str,
        method: str,
        parameters: List[str],
        attack_type: str,
        vector: str,
        template: Dict[str, Any],
    ) -> Optional[GeneratedTest]:
        """Generate a single test for an attack vector."""

        # Build payload based on attack vector
        payload = {}
        success_criteria = template.get("indicators", [])

        if attack_type == "race_condition":
            # For race conditions, use standard payload but mark for concurrent execution
            for param in parameters:
                payload[param] = f"{{{{test_{param}}}}}"

            return GeneratedTest(
                name=f"Race_{vector}_{endpoint.replace('/', '_')}",
                description=f"Test {vector.replace('_', ' ')} on {endpoint}",
                category="race_condition",
                attack_vector=vector,
                method=method,
                endpoint=endpoint,
                payload=payload,
                expected_behavior="Only one request should succeed",
                success_criteria=success_criteria,
                risk_level="high",
                reasoning=f"Endpoint {endpoint} handles {vector.replace('_', ' ')} which may be vulnerable to race conditions",
            )

        elif attack_type == "parameter_tampering":
            # Generate manipulation payloads
            for param in parameters:
                param_lower = param.lower()

                if any(kw in param_lower for kw in ["price", "amount", "total"]):
                    payload[param] = -100
                elif any(kw in param_lower for kw in ["quantity", "count"]):
                    payload[param] = 999999
                elif any(kw in param_lower for kw in ["role", "admin"]):
                    payload[param] = "admin"
                elif any(kw in param_lower for kw in ["id"]):
                    payload[param] = "1"
                else:
                    payload[param] = f"{{{{test_{param}}}}}"

            return GeneratedTest(
                name=f"Tamper_{vector}_{endpoint.replace('/', '_')}",
                description=f"Test {vector.replace('_', ' ')} via parameter tampering",
                category="parameter_tampering",
                attack_vector=vector,
                method=method,
                endpoint=endpoint,
                payload=payload,
                expected_behavior="Server should validate and reject invalid values",
                success_criteria=["accepted", "success", "updated"],
                risk_level="high" if "price" in str(parameters).lower() else "medium",
                reasoning=f"Parameters {parameters} may be vulnerable to {vector.replace('_', ' ')}",
            )

        elif attack_type == "workflow_bypass":
            # Try to skip to final step
            payload["step"] = 99
            payload["complete"] = True
            payload["skip_validation"] = True

            return GeneratedTest(
                name=f"Bypass_{vector}_{endpoint.replace('/', '_')}",
                description=f"Attempt to {vector.replace('_', ' ')} on workflow",
                category="workflow_bypass",
                attack_vector=vector,
                method=method,
                endpoint=endpoint,
                payload=payload,
                expected_behavior="Server should enforce workflow sequence",
                success_criteria=["completed", "success"],
                risk_level="medium",
                reasoning=f"Multi-step workflow at {endpoint} may allow {vector.replace('_', ' ')}",
            )

        elif attack_type == "mass_assignment":
            # Try to set internal fields
            payload.update({
                "role": "admin",
                "is_admin": True,
                "verified": True,
                "approved": True,
            })
            for param in parameters:
                payload[param] = f"{{{{test_{param}}}}}"

            return GeneratedTest(
                name=f"MassAssign_{vector}_{endpoint.replace('/', '_')}",
                description=f"Test mass assignment via {vector.replace('_', ' ')}",
                category="mass_assignment",
                attack_vector=vector,
                method=method,
                endpoint=endpoint,
                payload=payload,
                expected_behavior="Server should whitelist allowed fields",
                success_criteria=["admin", "elevated", "updated"],
                risk_level="critical" if "role" in str(parameters).lower() else "high",
                reasoning=f"API endpoint may accept unintended fields via {vector.replace('_', ' ')}",
            )

        return None

    def generate_from_workflows(
        self,
        workflows: List[Workflow],
    ) -> List[GeneratedTest]:
        """
        Generate tests from discovered workflows.

        Args:
            workflows: List of discovered workflows

        Returns:
            List of generated tests
        """
        all_tests = []

        for workflow in workflows:
            for endpoint in workflow.endpoints:
                params = workflow.parameters.get(endpoint, [])

                for method in workflow.methods:
                    tests = self.generate_tests_for_endpoint(
                        endpoint,
                        method,
                        params,
                    )
                    all_tests.extend(tests)

        self.generated_tests = all_tests
        return all_tests

    def generate_creative_tests(
        self,
        context: GenerationContext,
    ) -> List[GeneratedTest]:
        """
        Generate creative tests based on full context.

        Uses application type and technology stack to generate
        context-aware tests.
        """
        tests = []

        # E-commerce specific tests
        if context.application_type in ["e-commerce", "marketplace"]:
            tests.extend(self._generate_ecommerce_tests(context))

        # Banking/Finance specific tests
        if context.application_type in ["banking", "finance", "payment"]:
            tests.extend(self._generate_finance_tests(context))

        # Social/User-generated content tests
        if context.application_type in ["social", "forum", "cms"]:
            tests.extend(self._generate_social_tests(context))

        # Generate from workflows
        tests.extend(self.generate_from_workflows(context.workflows))

        return tests

    def _generate_ecommerce_tests(self, context: GenerationContext) -> List[GeneratedTest]:
        """Generate e-commerce specific tests."""
        tests = []

        # Price manipulation tests
        for endpoint in context.discovered_endpoints:
            if any(kw in endpoint.lower() for kw in ["cart", "checkout", "order"]):
                tests.append(GeneratedTest(
                    name=f"NegativePrice_{endpoint.replace('/', '_')}",
                    description="Submit negative price to get credit",
                    category="price_manipulation",
                    attack_vector="negative_value_injection",
                    method="POST",
                    endpoint=endpoint,
                    payload={"price": -100, "quantity": 1},
                    expected_behavior="Reject negative prices",
                    success_criteria=["added", "cart", "total"],
                    risk_level="critical",
                    reasoning="E-commerce endpoint may not validate price sign",
                ))

                tests.append(GeneratedTest(
                    name=f"QuantityOverflow_{endpoint.replace('/', '_')}",
                    description="Submit very large quantity for overflow",
                    category="price_manipulation",
                    attack_vector="integer_overflow",
                    method="POST",
                    endpoint=endpoint,
                    payload={"quantity": 2147483647},
                    expected_behavior="Validate quantity range",
                    success_criteria=["added", "total"],
                    risk_level="high",
                    reasoning="Large quantities may cause integer overflow in total calculation",
                ))

        return tests

    def _generate_finance_tests(self, context: GenerationContext) -> List[GeneratedTest]:
        """Generate finance/banking specific tests."""
        tests = []

        for endpoint in context.discovered_endpoints:
            if any(kw in endpoint.lower() for kw in ["transfer", "payment", "withdraw"]):
                tests.append(GeneratedTest(
                    name=f"DoubleSpend_{endpoint.replace('/', '_')}",
                    description="Concurrent withdrawal to double-spend",
                    category="race_condition",
                    attack_vector="concurrent_withdrawal",
                    method="POST",
                    endpoint=endpoint,
                    payload={"amount": 100},
                    expected_behavior="Only one withdrawal should succeed",
                    success_criteria=["success", "completed"],
                    risk_level="critical",
                    reasoning="Financial transactions vulnerable to race conditions",
                ))

        return tests

    def _generate_social_tests(self, context: GenerationContext) -> List[GeneratedTest]:
        """Generate social platform specific tests."""
        tests = []

        for endpoint in context.discovered_endpoints:
            if any(kw in endpoint.lower() for kw in ["vote", "like", "follow"]):
                tests.append(GeneratedTest(
                    name=f"VoteBombing_{endpoint.replace('/', '_')}",
                    description="Submit multiple votes via race condition",
                    category="race_condition",
                    attack_vector="concurrent_votes",
                    method="POST",
                    endpoint=endpoint,
                    payload={"target_id": "1", "direction": "up"},
                    expected_behavior="One vote per user enforced",
                    success_criteria=["voted", "success"],
                    risk_level="medium",
                    reasoning="Voting endpoints may allow duplicate votes via race condition",
                ))

        return tests

    def to_json(self) -> str:
        """Export generated tests as JSON."""
        return json.dumps(
            [
                {
                    "name": t.name,
                    "description": t.description,
                    "category": t.category,
                    "attack_vector": t.attack_vector,
                    "method": t.method,
                    "endpoint": t.endpoint,
                    "payload": t.payload,
                    "expected_behavior": t.expected_behavior,
                    "success_criteria": t.success_criteria,
                    "risk_level": t.risk_level,
                    "reasoning": t.reasoning,
                }
                for t in self.generated_tests
            ],
            indent=2,
        )
