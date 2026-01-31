"""
Business Logic Test Executor

Executes generated business logic tests against target applications
with concurrent support, evidence collection, and result analysis.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from aipt_v2.business_logic.patterns import TestCase, TestResult
from aipt_v2.business_logic.test_generator import GeneratedTest

try:
    import aiohttp
except ImportError:
    aiohttp = None


@dataclass
class ExecutionResult:
    """Result of a single test execution."""
    test_name: str
    test_category: str
    endpoint: str
    method: str

    # Execution details
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    request_payload: Dict[str, Any]

    # Timing
    started_at: str
    finished_at: str
    duration_ms: float

    # Analysis
    vulnerability_detected: bool = False
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    matched_indicators: List[str] = field(default_factory=list)

    # For concurrent tests
    concurrent_successes: int = 0
    concurrent_total: int = 1


@dataclass
class ExecutionReport:
    """Full execution report for all tests."""
    target: str
    total_tests: int
    executed_tests: int
    vulnerabilities_found: int
    execution_started: str
    execution_finished: str
    total_duration: float
    results: List[ExecutionResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


class TestExecutor:
    """
    Executes business logic tests against target applications.

    Features:
    - Concurrent test execution
    - Race condition testing with simultaneous requests
    - Evidence collection
    - Result analysis and confidence scoring
    """

    def __init__(
        self,
        target: str,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        max_concurrent: int = 10,
        delay_between_tests: float = 0.1,
    ):
        """
        Initialize executor.

        Args:
            target: Base URL of target application
            auth_headers: Authentication headers
            cookies: Session cookies
            timeout: Request timeout in seconds
            max_concurrent: Max concurrent requests for race conditions
            delay_between_tests: Delay between sequential tests
        """
        self.target = target.rstrip("/")
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.delay_between_tests = delay_between_tests

        self.results: List[ExecutionResult] = []

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "User-Agent": "AIPTX-TestExecutor/4.0",
            "Accept": "application/json, text/html, */*",
            "Content-Type": "application/json",
        }
        headers.update(self.auth_headers)
        return headers

    async def _send_request(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, str], str, float]:
        """
        Send HTTP request and return status, headers, body, duration.
        """
        if aiohttp is None:
            raise ImportError("aiohttp required: pip install aiohttp")

        req_headers = self._get_headers()
        if headers:
            req_headers.update(headers)

        start_time = time.time()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    headers=req_headers,
                    cookies=self.cookies,
                    json=payload if method in ["POST", "PUT", "PATCH"] else None,
                    params=payload if method == "GET" else None,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                ) as response:
                    body = await response.text()
                    duration = (time.time() - start_time) * 1000  # Convert to ms
                    return response.status, dict(response.headers), body, duration

        except asyncio.TimeoutError:
            return 0, {}, "Request timed out", (time.time() - start_time) * 1000
        except Exception as e:
            return 0, {}, str(e), (time.time() - start_time) * 1000

    def _analyze_response(
        self,
        test: GeneratedTest,
        status_code: int,
        body: str,
        headers: Dict[str, str],
    ) -> Tuple[bool, float, List[str], List[str]]:
        """
        Analyze response to determine if vulnerability was detected.

        Returns: (vulnerability_detected, confidence, evidence, matched_indicators)
        """
        vulnerability_detected = False
        confidence = 0.0
        evidence = []
        matched_indicators = []

        body_lower = body.lower()

        # Check success criteria
        for criterion in test.success_criteria:
            if criterion.lower() in body_lower:
                matched_indicators.append(criterion)

        # Calculate confidence based on matches
        if test.success_criteria:
            match_ratio = len(matched_indicators) / len(test.success_criteria)
            confidence = match_ratio * 0.7  # Max 70% from indicator matching

        # Adjust based on status code
        if status_code in [200, 201]:
            confidence += 0.2
            evidence.append(f"Successful status code: {status_code}")
        elif status_code in [400, 401, 403]:
            confidence -= 0.3  # Likely rejected

        # Check for error indicators (reduces confidence)
        error_indicators = ["error", "invalid", "denied", "forbidden", "unauthorized", "failed"]
        for error in error_indicators:
            if error in body_lower:
                confidence -= 0.1
                break

        # Vulnerability threshold
        if confidence >= 0.5 and matched_indicators:
            vulnerability_detected = True
            evidence.append(f"Matched indicators: {matched_indicators}")

        return vulnerability_detected, max(0, min(1, confidence)), evidence, matched_indicators

    async def execute_test(
        self,
        test: GeneratedTest,
    ) -> ExecutionResult:
        """
        Execute a single test.

        Args:
            test: The test to execute

        Returns:
            ExecutionResult with findings
        """
        started_at = datetime.now(timezone.utc).isoformat()
        url = urljoin(self.target, test.endpoint)

        # Execute request
        status, headers, body, duration = await self._send_request(
            test.method,
            url,
            test.payload,
        )

        finished_at = datetime.now(timezone.utc).isoformat()

        # Analyze response
        vuln_detected, confidence, evidence, matched = self._analyze_response(
            test, status, body, headers
        )

        return ExecutionResult(
            test_name=test.name,
            test_category=test.category,
            endpoint=url,
            method=test.method,
            status_code=status,
            response_body=body[:2000],  # Truncate long responses
            response_headers=headers,
            request_payload=test.payload,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration,
            vulnerability_detected=vuln_detected,
            confidence=confidence,
            evidence=evidence,
            matched_indicators=matched,
        )

    async def execute_race_condition_test(
        self,
        test: GeneratedTest,
        concurrent_count: int = 10,
    ) -> ExecutionResult:
        """
        Execute a race condition test with concurrent requests.

        Args:
            test: The test to execute
            concurrent_count: Number of concurrent requests

        Returns:
            ExecutionResult with race condition analysis
        """
        started_at = datetime.now(timezone.utc).isoformat()
        url = urljoin(self.target, test.endpoint)

        # Send concurrent requests
        async def send_one():
            return await self._send_request(test.method, url, test.payload)

        start_time = time.time()
        tasks = [send_one() for _ in range(concurrent_count)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        total_duration = (time.time() - start_time) * 1000

        finished_at = datetime.now(timezone.utc).isoformat()

        # Analyze results
        success_count = 0
        all_bodies = []
        first_status = 0
        first_headers: Dict[str, str] = {}

        for i, resp in enumerate(responses):
            if isinstance(resp, tuple):
                status, headers, body, _ = resp
                all_bodies.append(body)

                if i == 0:
                    first_status = status
                    first_headers = headers

                if status in [200, 201]:
                    success_count += 1

        # Race condition detected if multiple successes
        vulnerability_detected = success_count > 1
        confidence = min(1.0, success_count / concurrent_count) if success_count > 1 else 0

        evidence = []
        if vulnerability_detected:
            evidence.append(f"Race condition: {success_count}/{concurrent_count} requests succeeded")
            evidence.append("Multiple concurrent requests achieved success state")

        return ExecutionResult(
            test_name=test.name,
            test_category=test.category,
            endpoint=url,
            method=test.method,
            status_code=first_status,
            response_body=all_bodies[0][:1000] if all_bodies else "",
            response_headers=first_headers,
            request_payload=test.payload,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=total_duration,
            vulnerability_detected=vulnerability_detected,
            confidence=confidence,
            evidence=evidence,
            matched_indicators=[],
            concurrent_successes=success_count,
            concurrent_total=concurrent_count,
        )

    async def execute_all(
        self,
        tests: List[GeneratedTest],
        parallel: bool = False,
    ) -> ExecutionReport:
        """
        Execute all tests and generate report.

        Args:
            tests: List of tests to execute
            parallel: Execute tests in parallel (use with caution)

        Returns:
            ExecutionReport with all results
        """
        execution_started = datetime.now(timezone.utc).isoformat()
        start_time = time.time()

        results = []

        if parallel:
            # Execute in parallel batches
            batch_size = 5
            for i in range(0, len(tests), batch_size):
                batch = tests[i:i + batch_size]
                tasks = []

                for test in batch:
                    if test.category == "race_condition":
                        tasks.append(self.execute_race_condition_test(test))
                    else:
                        tasks.append(self.execute_test(test))

                batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in batch_results:
                    if isinstance(result, ExecutionResult):
                        results.append(result)

        else:
            # Execute sequentially
            for test in tests:
                if test.category == "race_condition":
                    result = await self.execute_race_condition_test(test)
                else:
                    result = await self.execute_test(test)

                results.append(result)

                # Delay between tests
                await asyncio.sleep(self.delay_between_tests)

        execution_finished = datetime.now(timezone.utc).isoformat()
        total_duration = time.time() - start_time

        self.results = results

        # Build summary
        vulnerabilities = [r for r in results if r.vulnerability_detected]
        by_category = {}
        for r in results:
            if r.test_category not in by_category:
                by_category[r.test_category] = {"total": 0, "vulnerable": 0}
            by_category[r.test_category]["total"] += 1
            if r.vulnerability_detected:
                by_category[r.test_category]["vulnerable"] += 1

        return ExecutionReport(
            target=self.target,
            total_tests=len(tests),
            executed_tests=len(results),
            vulnerabilities_found=len(vulnerabilities),
            execution_started=execution_started,
            execution_finished=execution_finished,
            total_duration=total_duration,
            results=results,
            summary={
                "by_category": by_category,
                "high_confidence_findings": len([v for v in vulnerabilities if v.confidence >= 0.7]),
                "race_conditions_found": len([v for v in vulnerabilities if v.category == "race_condition"]),
                "average_confidence": sum(v.confidence for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0,
            }
        )

    def get_high_confidence_findings(self, threshold: float = 0.7) -> List[ExecutionResult]:
        """Get findings above confidence threshold."""
        return [r for r in self.results if r.vulnerability_detected and r.confidence >= threshold]

    def to_json_report(self) -> str:
        """Export results as JSON."""
        return json.dumps(
            {
                "target": self.target,
                "total_tests": len(self.results),
                "vulnerabilities": len([r for r in self.results if r.vulnerability_detected]),
                "results": [
                    {
                        "test_name": r.test_name,
                        "category": r.test_category,
                        "endpoint": r.endpoint,
                        "vulnerability_detected": r.vulnerability_detected,
                        "confidence": r.confidence,
                        "evidence": r.evidence,
                        "status_code": r.status_code,
                        "duration_ms": r.duration_ms,
                    }
                    for r in self.results
                ],
            },
            indent=2,
        )


async def execute_business_logic_tests(
    target: str,
    tests: List[GeneratedTest],
    auth_headers: Optional[Dict[str, str]] = None,
    parallel: bool = False,
) -> ExecutionReport:
    """
    Convenience function to execute business logic tests.

    Args:
        target: Target URL
        tests: Tests to execute
        auth_headers: Authentication headers
        parallel: Execute in parallel

    Returns:
        ExecutionReport
    """
    executor = TestExecutor(target, auth_headers=auth_headers)
    return await executor.execute_all(tests, parallel=parallel)
