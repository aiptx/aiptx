"""
Business Logic Analyzer

Analyzes web applications to identify business logic vulnerabilities
by matching discovered workflows against known vulnerability patterns.
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from aipt_v2.business_logic.patterns import (
    TestPattern,
    PatternCategory,
    TestCase,
    TestResult,
    get_all_patterns,
    get_patterns_by_category,
)

try:
    import aiohttp
except ImportError:
    aiohttp = None


@dataclass
class Workflow:
    """A discovered workflow in the application."""
    name: str
    endpoints: List[str]
    methods: List[str]
    parameters: Dict[str, List[str]]
    requires_auth: bool = False
    description: str = ""


@dataclass
class BusinessLogicFinding:
    """A business logic vulnerability finding."""
    pattern_id: str
    pattern_name: str
    category: str
    severity: str
    description: str
    endpoint: str
    evidence: str
    remediation: str
    cwe_ids: List[str] = field(default_factory=list)
    test_results: List[TestResult] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class BusinessLogicScanResult:
    """Result of business logic analysis."""
    target: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    workflows_discovered: int
    patterns_tested: int
    findings: List[BusinessLogicFinding]
    workflows: List[Workflow] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BusinessLogicAnalyzer:
    """
    Analyzes web applications for business logic vulnerabilities.

    The analyzer:
    1. Discovers workflows by crawling the application
    2. Matches workflows against known vulnerability patterns
    3. Generates and executes test cases
    4. Validates findings with actual exploitation
    """

    def __init__(
        self,
        target: str,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        max_concurrent: int = 5,
    ):
        """
        Initialize analyzer.

        Args:
            target: Base URL of the application
            auth_headers: Authentication headers
            cookies: Session cookies
            timeout: Request timeout in seconds
            max_concurrent: Max concurrent requests
        """
        self.target = target.rstrip("/")
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.max_concurrent = max_concurrent

        self.workflows: List[Workflow] = []
        self.findings: List[BusinessLogicFinding] = []
        self.patterns = get_all_patterns()

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "User-Agent": "AIPTX-BusinessLogic-Analyzer/4.0",
            "Accept": "application/json, text/html, */*",
        }
        headers.update(self.auth_headers)
        return headers

    async def _send_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Dict[str, Any], str]:
        """
        Send HTTP request and return status, headers, body.
        """
        if aiohttp is None:
            raise ImportError("aiohttp required: pip install aiohttp")

        req_headers = self._get_headers()
        if headers:
            req_headers.update(headers)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    headers=req_headers,
                    cookies=self.cookies,
                    data=data,
                    json=json_data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                ) as response:
                    body = await response.text()
                    return response.status, dict(response.headers), body
        except Exception as e:
            return 0, {}, str(e)

    async def discover_workflows(self) -> List[Workflow]:
        """
        Discover workflows in the application.

        Analyzes common patterns to identify:
        - Authentication flows (login, register, reset)
        - E-commerce flows (cart, checkout, payment)
        - User management (profile, settings)
        - Admin functions
        """
        workflows = []

        # Common workflow endpoint patterns
        workflow_patterns = {
            "authentication": {
                "endpoints": ["/login", "/signin", "/auth", "/register", "/signup", "/logout"],
                "methods": ["GET", "POST"],
                "params": ["username", "password", "email", "remember"]
            },
            "password_reset": {
                "endpoints": ["/forgot", "/reset", "/recover", "/password"],
                "methods": ["GET", "POST"],
                "params": ["email", "token", "new_password"]
            },
            "user_profile": {
                "endpoints": ["/profile", "/account", "/settings", "/user"],
                "methods": ["GET", "PUT", "POST", "PATCH"],
                "params": ["name", "email", "phone", "avatar"]
            },
            "e-commerce_cart": {
                "endpoints": ["/cart", "/basket", "/bag"],
                "methods": ["GET", "POST", "DELETE"],
                "params": ["item_id", "quantity", "remove"]
            },
            "e-commerce_checkout": {
                "endpoints": ["/checkout", "/payment", "/order", "/purchase"],
                "methods": ["GET", "POST"],
                "params": ["address", "payment_method", "card", "total"]
            },
            "search": {
                "endpoints": ["/search", "/find", "/query", "/lookup"],
                "methods": ["GET", "POST"],
                "params": ["q", "query", "term", "filter"]
            },
            "admin": {
                "endpoints": ["/admin", "/dashboard", "/manage", "/control"],
                "methods": ["GET", "POST", "PUT", "DELETE"],
                "params": ["action", "user_id", "role"]
            },
            "api_resources": {
                "endpoints": ["/api/users", "/api/orders", "/api/products"],
                "methods": ["GET", "POST", "PUT", "DELETE"],
                "params": ["id", "limit", "offset", "filter"]
            }
        }

        # Check which workflows exist
        for workflow_name, config in workflow_patterns.items():
            discovered_endpoints = []

            for endpoint in config["endpoints"]:
                url = urljoin(self.target, endpoint)
                status, _, body = await self._send_request("GET", url)

                if status in [200, 201, 301, 302, 401, 403]:
                    discovered_endpoints.append(endpoint)

            if discovered_endpoints:
                workflows.append(Workflow(
                    name=workflow_name,
                    endpoints=discovered_endpoints,
                    methods=config["methods"],
                    parameters={ep: config["params"] for ep in discovered_endpoints},
                    requires_auth=workflow_name in ["user_profile", "admin", "e-commerce_checkout"],
                    description=f"Discovered {workflow_name} workflow"
                ))

        self.workflows = workflows
        return workflows

    def match_patterns(self, workflows: List[Workflow]) -> List[Tuple[Workflow, TestPattern]]:
        """
        Match discovered workflows against vulnerability patterns.

        Returns list of (workflow, pattern) pairs to test.
        """
        matches = []

        for workflow in workflows:
            for endpoint in workflow.endpoints:
                for pattern in self.patterns:
                    if pattern.matches_endpoint(endpoint):
                        matches.append((workflow, pattern))
                        break  # One match per pattern per workflow

        return matches

    async def test_pattern(
        self,
        workflow: Workflow,
        pattern: TestPattern,
    ) -> List[BusinessLogicFinding]:
        """
        Test a specific pattern against a workflow.
        """
        findings = []

        for test_case in pattern.test_cases:
            # Find matching endpoint
            matching_endpoint = None
            for endpoint in workflow.endpoints:
                if test_case.endpoint_pattern:
                    if re.search(test_case.endpoint_pattern, endpoint, re.I):
                        matching_endpoint = endpoint
                        break
                else:
                    matching_endpoint = endpoint
                    break

            if not matching_endpoint:
                continue

            url = urljoin(self.target, matching_endpoint)

            # Handle concurrent requests (for race conditions)
            if test_case.concurrent_requests > 1:
                results = await self._test_concurrent(url, test_case)
            else:
                results = await self._test_single(url, test_case)

            # Check for vulnerability indicators
            vulnerability_found = False
            evidence_parts = []

            for result in results:
                response_text = str(result.get("body", "")).lower()

                # Check success indicators
                success_matches = [
                    ind for ind in test_case.success_indicators
                    if ind.lower() in response_text
                ]

                # Check failure indicators
                failure_matches = [
                    ind for ind in test_case.failure_indicators
                    if ind.lower() in response_text
                ]

                # Vulnerability found if success without failure indicators
                if success_matches and not failure_matches:
                    vulnerability_found = True
                    evidence_parts.append(
                        f"Success indicators found: {success_matches}, "
                        f"Status: {result.get('status')}"
                    )

            if vulnerability_found:
                findings.append(BusinessLogicFinding(
                    pattern_id=pattern.id,
                    pattern_name=pattern.name,
                    category=pattern.category.value,
                    severity=pattern.severity.value,
                    description=f"{pattern.description}. Test case: {test_case.name}",
                    endpoint=url,
                    evidence="; ".join(evidence_parts),
                    remediation=pattern.remediation,
                    cwe_ids=pattern.cwe_ids,
                ))

        return findings

    async def _test_single(
        self,
        url: str,
        test_case: TestCase,
    ) -> List[Dict[str, Any]]:
        """Execute a single test request."""
        results = []

        # Handle manipulations
        if test_case.manipulation:
            for param, values in test_case.manipulation.items():
                for value in values[:3]:  # Limit variations
                    body = dict(test_case.body_template)
                    body[param] = value

                    status, headers, body_text = await self._send_request(
                        test_case.method,
                        url,
                        headers=test_case.headers,
                        json_data=body if test_case.method in ["POST", "PUT", "PATCH"] else None,
                    )

                    results.append({
                        "status": status,
                        "headers": headers,
                        "body": body_text,
                        "payload": body,
                    })
        else:
            status, headers, body_text = await self._send_request(
                test_case.method,
                url,
                headers=test_case.headers,
                json_data=test_case.body_template if test_case.method in ["POST", "PUT", "PATCH"] else None,
            )

            results.append({
                "status": status,
                "headers": headers,
                "body": body_text,
                "payload": test_case.body_template,
            })

        return results

    async def _test_concurrent(
        self,
        url: str,
        test_case: TestCase,
    ) -> List[Dict[str, Any]]:
        """Execute concurrent test requests for race condition testing."""
        results = []

        async def send_one():
            return await self._send_request(
                test_case.method,
                url,
                headers=test_case.headers,
                json_data=test_case.body_template,
            )

        # Send concurrent requests
        tasks = [send_one() for _ in range(test_case.concurrent_requests)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = 0
        for resp in responses:
            if isinstance(resp, tuple):
                status, headers, body = resp
                results.append({
                    "status": status,
                    "headers": headers,
                    "body": body,
                })
                if status in [200, 201]:
                    success_count += 1

        # For race conditions, multiple successes indicate vulnerability
        if success_count > 1:
            results[0]["race_condition_indicator"] = f"{success_count} successful concurrent requests"

        return results

    async def analyze(
        self,
        categories: Optional[List[PatternCategory]] = None,
    ) -> BusinessLogicScanResult:
        """
        Run full business logic analysis.

        Args:
            categories: Specific categories to test (None = all)

        Returns:
            BusinessLogicScanResult with all findings
        """
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = asyncio.get_event_loop().time()

        # Discover workflows
        workflows = await self.discover_workflows()

        # Filter patterns by category if specified
        if categories:
            patterns_to_use = []
            for cat in categories:
                patterns_to_use.extend(get_patterns_by_category(cat))
            self.patterns = patterns_to_use

        # Match workflows to patterns
        matches = self.match_patterns(workflows)

        # Test each match
        all_findings = []
        patterns_tested = set()

        for workflow, pattern in matches:
            patterns_tested.add(pattern.id)
            findings = await self.test_pattern(workflow, pattern)
            all_findings.extend(findings)

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = asyncio.get_event_loop().time() - start_time

        self.findings = all_findings

        return BusinessLogicScanResult(
            target=self.target,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            workflows_discovered=len(workflows),
            patterns_tested=len(patterns_tested),
            findings=all_findings,
            workflows=workflows,
            metadata={
                "patterns_available": len(self.patterns),
                "categories_tested": list(set(f.category for f in all_findings)) if all_findings else [],
            }
        )


async def analyze_business_logic(
    target: str,
    auth_headers: Optional[Dict[str, str]] = None,
    categories: Optional[List[str]] = None,
) -> BusinessLogicScanResult:
    """
    Quick business logic analysis.

    Args:
        target: Target URL
        auth_headers: Authentication headers
        categories: Categories to test (e.g., ["race_condition", "price_manipulation"])

    Returns:
        BusinessLogicScanResult
    """
    analyzer = BusinessLogicAnalyzer(target, auth_headers=auth_headers)

    # Convert string categories to enum
    cat_enums = None
    if categories:
        cat_enums = [PatternCategory(c) for c in categories if c in [e.value for e in PatternCategory]]

    return await analyzer.analyze(categories=cat_enums)
