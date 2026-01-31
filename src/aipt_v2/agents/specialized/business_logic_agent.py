"""
AIPTX Business Logic Agent - Business Logic Flaw Testing

Tests for vulnerabilities that automated scanners miss:
- Race conditions
- Price/amount manipulation
- Workflow bypasses
- Privilege escalation
- Rate limiting bypasses
- Promo code abuse
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urljoin

from aipt_v2.agents.specialized.base_specialized import (
    SpecializedAgent,
    AgentCapability,
    AgentConfig,
)
from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    VulnerabilityType,
    Evidence,
)

logger = logging.getLogger(__name__)


# Business logic test patterns
BL_TEST_PATTERNS = {
    "race_condition": {
        "description": "Tests for race condition vulnerabilities",
        "endpoints": ["checkout", "transfer", "apply", "redeem", "vote", "like"],
        "tests": [
            ("concurrent_requests", "Send multiple concurrent requests"),
            ("double_submit", "Submit same request twice rapidly"),
        ],
    },
    "price_manipulation": {
        "description": "Tests for price/amount manipulation",
        "endpoints": ["cart", "checkout", "order", "payment"],
        "params": ["price", "amount", "quantity", "total", "discount"],
        "tests": [
            ("negative_values", "Use negative values"),
            ("zero_amount", "Use zero amount"),
            ("large_amount", "Use extremely large amounts"),
            ("float_precision", "Use float precision issues"),
        ],
    },
    "workflow_bypass": {
        "description": "Tests for workflow/step bypasses",
        "endpoints": ["checkout", "verify", "confirm", "submit"],
        "tests": [
            ("skip_steps", "Skip intermediate steps"),
            ("direct_access", "Access final step directly"),
            ("state_manipulation", "Manipulate state tokens"),
        ],
    },
    "access_control": {
        "description": "Tests for horizontal/vertical privilege escalation",
        "endpoints": ["profile", "account", "user", "admin", "settings"],
        "params": ["id", "user_id", "account_id", "uid"],
        "tests": [
            ("idor", "Access other users' resources"),
            ("role_escalation", "Change user role"),
            ("admin_access", "Access admin functions"),
        ],
    },
}


class BusinessLogicAgent(SpecializedAgent):
    """
    Business Logic testing agent.

    Tests for flaws that traditional scanners miss:
    - Race conditions (double-spend, double-vote)
    - Price manipulation
    - Workflow bypasses
    - IDOR and privilege escalation
    - Rate limiting bypasses
    """

    name = "BusinessLogicAgent"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._workflows: list[dict] = []
        self._auth_tokens: dict = {}

    def get_capabilities(self) -> list[AgentCapability]:
        return [
            AgentCapability.WORKFLOW_ANALYSIS,
            AgentCapability.RACE_CONDITION,
            AgentCapability.PRICE_MANIPULATION,
            AgentCapability.ACCESS_CONTROL,
        ]

    async def run(self) -> dict[str, Any]:
        """Execute business logic testing."""
        await self.initialize()
        self._progress.status = "running"

        results = {
            "tests_run": 0,
            "workflows_tested": 0,
            "findings_count": 0,
            "success": True,
        }

        try:
            # Phase 1: Analyze application workflows (20%)
            await self.update_progress("Analyzing workflows", 0)
            workflows = await self._analyze_workflows()
            results["workflows_tested"] = len(workflows)

            # Phase 2: Test race conditions (40%)
            self.check_cancelled()
            await self.update_progress("Testing race conditions", 20)
            await self._test_race_conditions(workflows)
            results["tests_run"] += len(workflows)

            # Phase 3: Test price manipulation (55%)
            self.check_cancelled()
            await self.update_progress("Testing price manipulation", 40)
            await self._test_price_manipulation(workflows)

            # Phase 4: Test workflow bypasses (70%)
            self.check_cancelled()
            await self.update_progress("Testing workflow bypasses", 55)
            await self._test_workflow_bypasses(workflows)

            # Phase 5: Test access control (85%)
            self.check_cancelled()
            await self.update_progress("Testing access control", 70)
            await self._test_access_control(workflows)

            # Phase 6: AI-generated tests (100%)
            self.check_cancelled()
            await self.update_progress("Running AI-generated tests", 85)
            await self._run_ai_generated_tests(workflows)

            await self.update_progress("Complete", 100)
            results["findings_count"] = self._findings_count

        except asyncio.CancelledError:
            logger.info("BusinessLogicAgent cancelled")
            results["success"] = False
            results["error"] = "Cancelled"
        except Exception as e:
            logger.error(f"BusinessLogicAgent error: {e}", exc_info=True)
            results["success"] = False
            results["error"] = str(e)
        finally:
            await self.cleanup()

        return results

    async def _analyze_workflows(self) -> list[dict]:
        """Analyze application to identify workflows."""
        workflows = []

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                # Fetch homepage to analyze structure
                async with session.get(self.target, timeout=10) as resp:
                    html = await resp.text()
                    workflows = self._extract_workflows_from_html(html)

        except Exception as e:
            logger.warning(f"Workflow analysis error: {e}")

        # Add common workflow patterns if not found
        if not workflows:
            workflows = self._get_common_workflows()

        return workflows

    def _extract_workflows_from_html(self, html: str) -> list[dict]:
        """Extract potential workflows from HTML."""
        import re

        workflows = []

        # Find forms
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']'
        for match in re.finditer(form_pattern, html, re.IGNORECASE):
            action = match.group(1)
            method = match.group(2).upper()

            # Identify workflow type
            workflow_type = "unknown"
            if any(word in action.lower() for word in ["login", "auth", "signin"]):
                workflow_type = "authentication"
            elif any(word in action.lower() for word in ["cart", "checkout", "order"]):
                workflow_type = "ecommerce"
            elif any(word in action.lower() for word in ["transfer", "payment"]):
                workflow_type = "financial"
            elif any(word in action.lower() for word in ["register", "signup"]):
                workflow_type = "registration"

            workflows.append({
                "url": urljoin(self.target, action),
                "method": method,
                "type": workflow_type,
                "params": self._extract_form_params(html, action),
            })

        return workflows

    def _extract_form_params(self, html: str, form_action: str) -> list[dict]:
        """Extract parameters from a form."""
        import re
        params = []

        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*'
        for match in re.finditer(input_pattern, html):
            params.append({"name": match.group(1), "type": "input"})

        return params

    def _get_common_workflows(self) -> list[dict]:
        """Get common workflow patterns to test."""
        base_url = self.target
        return [
            {
                "url": urljoin(base_url, "/api/checkout"),
                "method": "POST",
                "type": "ecommerce",
                "params": [{"name": "cart_id"}, {"name": "total"}],
            },
            {
                "url": urljoin(base_url, "/api/transfer"),
                "method": "POST",
                "type": "financial",
                "params": [{"name": "amount"}, {"name": "to_account"}],
            },
            {
                "url": urljoin(base_url, "/api/profile"),
                "method": "GET",
                "type": "profile",
                "params": [{"name": "user_id"}],
            },
        ]

    async def _test_race_conditions(self, workflows: list[dict]) -> None:
        """Test for race condition vulnerabilities."""
        import aiohttp

        for workflow in workflows:
            self.check_cancelled()

            # Only test relevant endpoints
            if not any(word in workflow["url"].lower()
                       for word in BL_TEST_PATTERNS["race_condition"]["endpoints"]):
                continue

            try:
                async def make_request(session: aiohttp.ClientSession):
                    if workflow["method"] == "POST":
                        async with session.post(workflow["url"], timeout=10) as resp:
                            return resp.status, await resp.text()
                    else:
                        async with session.get(workflow["url"], timeout=10) as resp:
                            return resp.status, await resp.text()

                # Send multiple concurrent requests
                async with aiohttp.ClientSession() as session:
                    tasks = [make_request(session) for _ in range(10)]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)

                    # Analyze responses for race condition indicators
                    success_count = sum(1 for r in responses
                                        if isinstance(r, tuple) and r[0] in [200, 201])

                    # If more than expected succeeded, might be race condition
                    if success_count > 1:
                        # Check for duplicate processing indicators
                        response_bodies = [r[1] for r in responses if isinstance(r, tuple)]
                        unique_responses = set(response_bodies)

                        if len(unique_responses) < len(response_bodies):
                            finding = Finding(
                                vuln_type=VulnerabilityType.RACE_CONDITION,
                                title=f"Potential race condition in {workflow['url']}",
                                description="Multiple concurrent requests succeeded when only one should",
                                severity=FindingSeverity.HIGH,
                                target=self.target,
                                url=workflow["url"],
                                evidence=Evidence(
                                    notes=f"Sent 10 concurrent requests, {success_count} succeeded"
                                ),
                                tags=["business-logic", "race-condition"],
                            )
                            await self.add_finding(finding)

            except Exception as e:
                logger.warning(f"Race condition test error: {e}")

    async def _test_price_manipulation(self, workflows: list[dict]) -> None:
        """Test for price/amount manipulation vulnerabilities."""
        import aiohttp

        manipulation_tests = [
            (-1, "negative value"),
            (0, "zero value"),
            (0.001, "tiny amount"),
            (99999999, "extremely large value"),
            (-0.01, "negative decimal"),
        ]

        for workflow in workflows:
            self.check_cancelled()

            # Only test relevant endpoints
            if not any(word in workflow["url"].lower()
                       for word in BL_TEST_PATTERNS["price_manipulation"]["endpoints"]):
                continue

            async with aiohttp.ClientSession() as session:
                for param in workflow.get("params", []):
                    # Only test likely numeric parameters
                    if not any(word in param["name"].lower()
                               for word in BL_TEST_PATTERNS["price_manipulation"]["params"]):
                        continue

                    for test_value, description in manipulation_tests:
                        try:
                            test_data = {param["name"]: test_value}

                            if workflow["method"] == "POST":
                                async with session.post(
                                    workflow["url"],
                                    json=test_data,
                                    timeout=10
                                ) as resp:
                                    if resp.status == 200:
                                        body = await resp.text()
                                        # Check if manipulation was accepted
                                        if "success" in body.lower() or "accepted" in body.lower():
                                            finding = Finding(
                                                vuln_type=VulnerabilityType.BUSINESS_LOGIC,
                                                title=f"Price manipulation: {description} accepted",
                                                description=f"Parameter {param['name']} accepts {description}",
                                                severity=FindingSeverity.HIGH,
                                                target=self.target,
                                                url=workflow["url"],
                                                parameter=param["name"],
                                                payload=str(test_value),
                                                evidence=Evidence(response=body[:500]),
                                                tags=["business-logic", "price-manipulation"],
                                            )
                                            await self.add_finding(finding)

                        except Exception as e:
                            logger.debug(f"Price test error: {e}")

    async def _test_workflow_bypasses(self, workflows: list[dict]) -> None:
        """Test for workflow/step bypass vulnerabilities."""
        import aiohttp

        # Try to access final steps directly
        final_step_patterns = ["confirm", "complete", "finish", "success", "done"]

        async with aiohttp.ClientSession() as session:
            for pattern in final_step_patterns:
                self.check_cancelled()

                test_url = urljoin(self.target, f"/api/{pattern}")

                try:
                    async with session.get(test_url, timeout=10) as resp:
                        if resp.status == 200:
                            body = await resp.text()

                            # Check if we got a success page without completing steps
                            if any(word in body.lower() for word in
                                   ["order", "confirmed", "complete", "success", "thank"]):
                                finding = Finding(
                                    vuln_type=VulnerabilityType.BUSINESS_LOGIC,
                                    title=f"Workflow bypass: Direct access to {pattern}",
                                    description="Final step accessible without completing workflow",
                                    severity=FindingSeverity.HIGH,
                                    target=self.target,
                                    url=test_url,
                                    evidence=Evidence(response=body[:500]),
                                    tags=["business-logic", "workflow-bypass"],
                                )
                                await self.add_finding(finding)

                except Exception:
                    pass

    async def _test_access_control(self, workflows: list[dict]) -> None:
        """Test for access control vulnerabilities (IDOR)."""
        import aiohttp

        # Test IDOR by trying different IDs
        idor_tests = ["1", "2", "0", "-1", "admin", "test"]

        async with aiohttp.ClientSession() as session:
            for workflow in workflows:
                self.check_cancelled()

                for param in workflow.get("params", []):
                    # Only test ID-like parameters
                    if not any(word in param["name"].lower()
                               for word in BL_TEST_PATTERNS["access_control"]["params"]):
                        continue

                    baseline_response = None

                    for test_id in idor_tests:
                        try:
                            test_params = {param["name"]: test_id}
                            test_url = workflow["url"]

                            async with session.get(
                                test_url,
                                params=test_params,
                                timeout=10
                            ) as resp:
                                body = await resp.text()

                                if baseline_response is None:
                                    baseline_response = body
                                    continue

                                # Check if we got different user data
                                if (resp.status == 200 and body != baseline_response and
                                        any(word in body.lower() for word in
                                            ["email", "name", "address", "phone", "profile"])):
                                    finding = Finding(
                                        vuln_type=VulnerabilityType.IDOR,
                                        title=f"IDOR in {param['name']}",
                                        description=f"Can access different resources by changing {param['name']}",
                                        severity=FindingSeverity.HIGH,
                                        target=self.target,
                                        url=test_url,
                                        parameter=param["name"],
                                        payload=test_id,
                                        evidence=Evidence(
                                            notes=f"Different response for ID: {test_id}"
                                        ),
                                        tags=["business-logic", "idor"],
                                    )
                                    await self.add_finding(finding)
                                    break

                        except Exception:
                            pass

    async def _run_ai_generated_tests(self, workflows: list[dict]) -> None:
        """Use LLM to generate creative business logic tests."""
        try:
            from aipt_v2.llm import get_completion

            # Generate test cases for each workflow
            for workflow in workflows[:5]:  # Limit to prevent overload
                self.check_cancelled()

                prompt = f"""Analyze this API endpoint and generate business logic test cases:

URL: {workflow['url']}
Method: {workflow['method']}
Type: {workflow['type']}
Parameters: {[p['name'] for p in workflow.get('params', [])]}

Generate 3 creative test cases for potential business logic flaws.
Format as JSON: {{"tests": [{{"name": "...", "description": "...", "payload": {{...}}}}]}}
"""

                try:
                    response = await get_completion(prompt)

                    # Parse and execute generated tests
                    import json
                    test_data = json.loads(response)

                    for test in test_data.get("tests", []):
                        await self._execute_generated_test(workflow, test)

                except Exception as e:
                    logger.debug(f"AI test generation failed: {e}")

        except ImportError:
            logger.debug("LLM not available for AI-generated tests")

    async def _execute_generated_test(self, workflow: dict, test: dict) -> None:
        """Execute an AI-generated test case."""
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                if workflow["method"] == "POST":
                    async with session.post(
                        workflow["url"],
                        json=test.get("payload", {}),
                        timeout=10
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text()

                            # If we got a success response, might be a flaw
                            if "success" in body.lower():
                                finding = Finding(
                                    vuln_type=VulnerabilityType.BUSINESS_LOGIC,
                                    title=f"AI-detected: {test.get('name', 'Business logic flaw')}",
                                    description=test.get("description", ""),
                                    severity=FindingSeverity.MEDIUM,
                                    target=self.target,
                                    url=workflow["url"],
                                    evidence=Evidence(notes=str(test.get("payload"))),
                                    tags=["business-logic", "ai-generated"],
                                )
                                await self.add_finding(finding)

        except Exception as e:
            logger.debug(f"Generated test execution failed: {e}")
