"""
OpenAPI/Swagger Security Fuzzer

Comprehensive REST API security testing based on OpenAPI specifications:
- Automatic endpoint discovery from OpenAPI/Swagger specs
- Parameter fuzzing (path, query, header, body)
- Authentication bypass testing
- BOLA/IDOR detection
- Mass assignment vulnerabilities
- Rate limiting bypass

References:
- OWASP API Security Top 10
- https://swagger.io/specification/

Usage:
    from aipt_v2.tools.api_security import OpenAPIFuzzer

    fuzzer = OpenAPIFuzzer("https://api.target.com", spec_path="openapi.yaml")
    findings = await fuzzer.fuzz()
"""

import asyncio
import json
import re
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aipt_v2.core.event_loop_manager import current_time
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urljoin, urlencode

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class OpenAPIConfig:
    """OpenAPI fuzzer configuration."""
    base_url: str
    spec_path: Optional[str] = None
    spec_url: Optional[str] = None
    spec_data: Optional[Dict] = None

    # Authentication
    auth_token: str = ""
    auth_header: str = "Authorization"
    api_key: str = ""
    api_key_header: str = "X-API-Key"

    # Fuzzing options
    fuzz_parameters: bool = True
    fuzz_bodies: bool = True
    test_bola: bool = True  # Broken Object Level Authorization
    test_mass_assignment: bool = True
    test_rate_limit: bool = True
    test_auth_bypass: bool = True

    # Limits
    max_requests_per_endpoint: int = 10
    timeout: int = 30
    delay_ms: int = 100  # Delay between requests

    # Headers
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class OpenAPIFinding:
    """OpenAPI security finding."""
    vulnerability: str
    severity: str
    endpoint: str
    method: str
    description: str
    evidence: str
    remediation: str
    parameter: str = ""
    payload: str = ""
    response_code: int = 0
    timestamp: str = ""
    cwe: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class OpenAPIEndpoint:
    """Parsed OpenAPI endpoint."""
    path: str
    method: str
    operation_id: str
    summary: str
    parameters: List[Dict]
    request_body: Optional[Dict]
    responses: Dict
    security: List[Dict]
    tags: List[str]


@dataclass
class OpenAPIFuzzResult:
    """Result of OpenAPI fuzzing."""
    base_url: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    endpoints_tested: int
    requests_made: int
    findings: List[OpenAPIFinding]
    spec_info: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class OpenAPIFuzzer:
    """
    OpenAPI/Swagger Security Fuzzer.

    Parses OpenAPI specifications and performs comprehensive
    security testing on discovered endpoints.
    """

    # Fuzzing payloads by type
    SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1; DROP TABLE users--", "admin'--"]
    XSS_PAYLOADS = ["<script>alert(1)</script>", "javascript:alert(1)", "<img onerror=alert(1)>"]
    PATH_TRAVERSAL = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"]
    COMMAND_INJECTION = ["; ls -la", "| cat /etc/passwd", "`whoami`", "$(id)"]
    NOSQL_PAYLOADS = ['{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}']

    # BOLA test IDs
    BOLA_IDS = ["1", "0", "-1", "admin", "999999", "../1", "1 OR 1=1"]

    def __init__(self, base_url: str, config: Optional[OpenAPIConfig] = None, **kwargs):
        """
        Initialize OpenAPI fuzzer.

        Args:
            base_url: Base API URL
            config: Fuzzer configuration
            **kwargs: Additional config options
        """
        self.base_url = base_url.rstrip("/")
        self.config = config or OpenAPIConfig(
            base_url=base_url,
            spec_path=kwargs.get("spec_path"),
            spec_url=kwargs.get("spec_url")
        )
        self.spec: Dict = {}
        self.endpoints: List[OpenAPIEndpoint] = []
        self.findings: List[OpenAPIFinding] = []
        self.requests_made = 0

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AIPTX-OpenAPI-Fuzzer/1.0"
        }
        headers.update(self.config.headers)

        if self.config.auth_token:
            headers[self.config.auth_header] = f"Bearer {self.config.auth_token}"

        if self.config.api_key:
            headers[self.config.api_key_header] = self.config.api_key

        return headers

    async def load_spec(self) -> bool:
        """Load and parse OpenAPI specification."""
        spec_data = None

        # Try loading from data
        if self.config.spec_data:
            spec_data = self.config.spec_data

        # Try loading from file
        elif self.config.spec_path:
            path = Path(self.config.spec_path)
            if path.exists():
                content = path.read_text()
                if path.suffix in [".yaml", ".yml"]:
                    if yaml:
                        spec_data = yaml.safe_load(content)
                    else:
                        raise ImportError("PyYAML required for YAML specs. Install with: pip install pyyaml")
                else:
                    spec_data = json.loads(content)

        # Try loading from URL
        elif self.config.spec_url:
            if aiohttp:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            self.config.spec_url,
                            headers=self._get_headers(),
                            ssl=False
                        ) as response:
                            text = await response.text()
                            if "yaml" in self.config.spec_url or "yml" in self.config.spec_url:
                                if yaml:
                                    spec_data = yaml.safe_load(text)
                            else:
                                spec_data = json.loads(text)
                except Exception as e:
                    print(f"[!] Error loading spec from URL: {e}")

        # Try common spec locations
        if not spec_data:
            common_paths = [
                "/openapi.json", "/swagger.json", "/api-docs",
                "/openapi.yaml", "/swagger.yaml",
                "/v2/api-docs", "/v3/api-docs"
            ]

            if aiohttp:
                async with aiohttp.ClientSession() as session:
                    for path in common_paths:
                        try:
                            url = urljoin(self.base_url, path)
                            async with session.get(url, ssl=False, timeout=10) as response:
                                if response.status == 200:
                                    text = await response.text()
                                    try:
                                        spec_data = json.loads(text)
                                        print(f"[*] Found OpenAPI spec at {path}")
                                        break
                                    except json.JSONDecodeError:
                                        if yaml:
                                            spec_data = yaml.safe_load(text)
                                            print(f"[*] Found OpenAPI spec at {path}")
                                            break
                        except Exception:
                            continue

        if spec_data:
            self.spec = spec_data
            self._parse_endpoints()
            return True

        return False

    def _parse_endpoints(self):
        """Parse endpoints from OpenAPI spec."""
        self.endpoints = []

        # Get paths from spec
        paths = self.spec.get("paths", {})

        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
                    continue

                # Parse parameters
                parameters = []
                params = operation.get("parameters", []) + methods.get("parameters", [])
                for param in params:
                    # Handle $ref
                    if "$ref" in param:
                        ref_path = param["$ref"].split("/")[-1]
                        param = self.spec.get("components", {}).get("parameters", {}).get(ref_path, param)

                    parameters.append({
                        "name": param.get("name", ""),
                        "in": param.get("in", "query"),
                        "required": param.get("required", False),
                        "schema": param.get("schema", {}),
                        "type": param.get("schema", {}).get("type", "string")
                    })

                # Parse request body
                request_body = None
                if "requestBody" in operation:
                    rb = operation["requestBody"]
                    content = rb.get("content", {})
                    if "application/json" in content:
                        schema = content["application/json"].get("schema", {})
                        request_body = {
                            "required": rb.get("required", False),
                            "schema": schema
                        }

                endpoint = OpenAPIEndpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId", ""),
                    summary=operation.get("summary", ""),
                    parameters=parameters,
                    request_body=request_body,
                    responses=operation.get("responses", {}),
                    security=operation.get("security", []),
                    tags=operation.get("tags", [])
                )

                self.endpoints.append(endpoint)

    async def _send_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        body: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Send HTTP request and return response."""
        if aiohttp is None:
            raise ImportError("aiohttp required. Install with: pip install aiohttp")

        url = urljoin(self.base_url, path)
        if params:
            url = f"{url}?{urlencode(params)}"

        req_headers = self._get_headers()
        if headers:
            req_headers.update(headers)

        try:
            await asyncio.sleep(self.config.delay_ms / 1000)
            self.requests_made += 1

            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    json=body if body else None,
                    headers=req_headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    ssl=False
                ) as response:
                    text = await response.text()
                    try:
                        data = json.loads(text) if text else {}
                    except json.JSONDecodeError:
                        data = {"raw": text}

                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "data": data,
                        "url": str(response.url)
                    }
        except Exception as e:
            return {"error": str(e)}

    async def fuzz_endpoint(self, endpoint: OpenAPIEndpoint) -> List[OpenAPIFinding]:
        """Fuzz a single endpoint."""
        findings = []

        # Fuzz path parameters
        path = endpoint.path
        path_params = re.findall(r"\{(\w+)\}", path)

        for param in path_params:
            for payload in self.SQLI_PAYLOADS + self.PATH_TRAVERSAL:
                test_path = path.replace(f"{{{param}}}", payload)
                response = await self._send_request(endpoint.method, test_path)

                if self._check_sqli_response(response):
                    findings.append(OpenAPIFinding(
                        vulnerability="SQL Injection in Path Parameter",
                        severity="critical",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        parameter=param,
                        payload=payload,
                        description=f"Path parameter '{param}' appears vulnerable to SQL injection",
                        evidence=f"Response indicates SQL error or unexpected behavior",
                        response_code=response.get("status", 0),
                        remediation="Use parameterized queries and input validation",
                        cwe="CWE-89"
                    ))
                    break

        # Fuzz query parameters
        if self.config.fuzz_parameters:
            for param in endpoint.parameters:
                if param["in"] == "query":
                    for payload in self.SQLI_PAYLOADS + self.XSS_PAYLOADS:
                        path_with_id = self._replace_path_params(endpoint.path)
                        response = await self._send_request(
                            endpoint.method,
                            path_with_id,
                            params={param["name"]: payload}
                        )

                        if self._check_sqli_response(response):
                            findings.append(OpenAPIFinding(
                                vulnerability="SQL Injection in Query Parameter",
                                severity="critical",
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                parameter=param["name"],
                                payload=payload,
                                description=f"Query parameter '{param['name']}' vulnerable to injection",
                                evidence="Response indicates injection vulnerability",
                                response_code=response.get("status", 0),
                                remediation="Validate and sanitize all input",
                                cwe="CWE-89"
                            ))
                            break

                        if self._check_xss_response(response, payload):
                            findings.append(OpenAPIFinding(
                                vulnerability="Reflected XSS in Query Parameter",
                                severity="high",
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                parameter=param["name"],
                                payload=payload,
                                description=f"Query parameter '{param['name']}' reflects XSS payload",
                                evidence="XSS payload reflected in response",
                                response_code=response.get("status", 0),
                                remediation="Encode output and validate input",
                                cwe="CWE-79"
                            ))
                            break

        # Fuzz request body
        if self.config.fuzz_bodies and endpoint.request_body:
            findings.extend(await self._fuzz_body(endpoint))

        return findings

    def _replace_path_params(self, path: str) -> str:
        """Replace path parameters with test values."""
        return re.sub(r"\{(\w+)\}", "1", path)

    def _check_sqli_response(self, response: Dict) -> bool:
        """Check if response indicates SQL injection."""
        if "error" in response:
            return False

        data_str = json.dumps(response.get("data", {})).lower()
        sql_indicators = [
            "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
            "syntax error", "unclosed quotation", "unterminated",
            "ORA-", "PG::", "SQLSTATE", "SQL Server"
        ]
        return any(ind.lower() in data_str for ind in sql_indicators)

    def _check_xss_response(self, response: Dict, payload: str) -> bool:
        """Check if XSS payload is reflected."""
        if "error" in response:
            return False

        data_str = json.dumps(response.get("data", {}))
        return payload in data_str

    async def _fuzz_body(self, endpoint: OpenAPIEndpoint) -> List[OpenAPIFinding]:
        """Fuzz request body parameters."""
        findings = []

        if not endpoint.request_body:
            return findings

        schema = endpoint.request_body.get("schema", {})
        properties = schema.get("properties", {})

        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "string")

            # Test injection in string fields
            if prop_type == "string":
                for payload in self.SQLI_PAYLOADS[:3]:
                    body = {prop_name: payload}
                    path = self._replace_path_params(endpoint.path)
                    response = await self._send_request(endpoint.method, path, body=body)

                    if self._check_sqli_response(response):
                        findings.append(OpenAPIFinding(
                            vulnerability="SQL Injection in Request Body",
                            severity="critical",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=prop_name,
                            payload=payload,
                            description=f"Body parameter '{prop_name}' vulnerable to SQL injection",
                            evidence="SQL error detected in response",
                            response_code=response.get("status", 0),
                            remediation="Use parameterized queries",
                            cwe="CWE-89"
                        ))
                        break

        return findings

    async def test_bola(self) -> List[OpenAPIFinding]:
        """Test for Broken Object Level Authorization (BOLA/IDOR)."""
        findings = []

        for endpoint in self.endpoints:
            # Look for ID parameters in path
            if "{id}" in endpoint.path or any("{" in endpoint.path for _ in [1]):
                for test_id in self.BOLA_IDS:
                    path = re.sub(r"\{[^}]+\}", test_id, endpoint.path)
                    response = await self._send_request(endpoint.method, path)

                    if response.get("status") == 200 and "error" not in response:
                        data = response.get("data", {})
                        if data and data != {"raw": ""}:
                            findings.append(OpenAPIFinding(
                                vulnerability="Potential BOLA/IDOR",
                                severity="high",
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                payload=test_id,
                                description=f"Endpoint may be vulnerable to BOLA with ID: {test_id}",
                                evidence=f"Received 200 OK for ID: {test_id}",
                                response_code=200,
                                remediation="Implement proper authorization checks for all resources",
                                cwe="CWE-639"
                            ))
                            break

        return findings

    async def test_auth_bypass(self) -> List[OpenAPIFinding]:
        """Test for authentication bypass."""
        findings = []

        # Save current auth
        orig_token = self.config.auth_token
        orig_key = self.config.api_key

        # Test without auth
        self.config.auth_token = ""
        self.config.api_key = ""

        for endpoint in self.endpoints:
            if endpoint.security:  # Should require auth
                path = self._replace_path_params(endpoint.path)
                response = await self._send_request(endpoint.method, path)

                if response.get("status") == 200:
                    findings.append(OpenAPIFinding(
                        vulnerability="Authentication Bypass",
                        severity="critical",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        description="Endpoint accessible without authentication",
                        evidence=f"Received 200 OK without auth token",
                        response_code=200,
                        remediation="Enforce authentication on all protected endpoints",
                        cwe="CWE-306"
                    ))

        # Restore auth
        self.config.auth_token = orig_token
        self.config.api_key = orig_key

        return findings

    async def test_rate_limiting(self) -> List[OpenAPIFinding]:
        """Test for missing rate limiting."""
        findings = []

        # Pick a GET endpoint
        get_endpoints = [e for e in self.endpoints if e.method == "GET"]
        if not get_endpoints:
            return findings

        endpoint = get_endpoints[0]
        path = self._replace_path_params(endpoint.path)

        # Send rapid requests
        success_count = 0
        for _ in range(20):
            response = await self._send_request("GET", path)
            if response.get("status") == 200:
                success_count += 1
            elif response.get("status") == 429:
                return findings  # Rate limiting detected

        if success_count >= 18:
            findings.append(OpenAPIFinding(
                vulnerability="Missing Rate Limiting",
                severity="medium",
                endpoint=endpoint.path,
                method="GET",
                description="API lacks rate limiting protection",
                evidence=f"{success_count}/20 rapid requests succeeded",
                response_code=200,
                remediation="Implement rate limiting to prevent abuse",
                cwe="CWE-770"
            ))

        return findings

    async def test_mass_assignment(self) -> List[OpenAPIFinding]:
        """Test for mass assignment vulnerabilities."""
        findings = []

        # Look for POST/PUT/PATCH endpoints
        for endpoint in self.endpoints:
            if endpoint.method not in ["POST", "PUT", "PATCH"]:
                continue
            if not endpoint.request_body:
                continue

            # Try adding extra fields
            extra_fields = {
                "role": "admin",
                "isAdmin": True,
                "admin": True,
                "permissions": ["admin"],
                "is_superuser": True,
                "privilege": "admin"
            }

            path = self._replace_path_params(endpoint.path)

            for field_name, field_value in extra_fields.items():
                body = {field_name: field_value}
                response = await self._send_request(endpoint.method, path, body=body)

                if response.get("status") in [200, 201]:
                    data = response.get("data", {})
                    if isinstance(data, dict) and field_name in str(data):
                        findings.append(OpenAPIFinding(
                            vulnerability="Potential Mass Assignment",
                            severity="high",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=field_name,
                            description=f"API accepts undocumented field: {field_name}",
                            evidence=f"Field '{field_name}' was accepted in request",
                            response_code=response.get("status", 0),
                            remediation="Implement allowlist for acceptable fields",
                            cwe="CWE-915"
                        ))

        return findings

    async def fuzz(self) -> OpenAPIFuzzResult:
        """
        Run full OpenAPI fuzzing scan.

        Returns:
            OpenAPIFuzzResult with all findings
        """
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = current_time()

        # Load spec
        if not self.spec:
            spec_loaded = await self.load_spec()
            if not spec_loaded:
                return OpenAPIFuzzResult(
                    base_url=self.base_url,
                    status="failed",
                    started_at=started_at,
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    duration=0,
                    endpoints_tested=0,
                    requests_made=0,
                    findings=[],
                    spec_info={},
                    metadata={"error": "Could not load OpenAPI specification"}
                )

        findings = []

        # Fuzz each endpoint
        for endpoint in self.endpoints:
            endpoint_findings = await self.fuzz_endpoint(endpoint)
            findings.extend(endpoint_findings)

        # Run additional tests
        if self.config.test_bola:
            findings.extend(await self.test_bola())

        if self.config.test_auth_bypass:
            findings.extend(await self.test_auth_bypass())

        if self.config.test_rate_limit:
            findings.extend(await self.test_rate_limiting())

        if self.config.test_mass_assignment:
            findings.extend(await self.test_mass_assignment())

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = current_time() - start_time

        # Spec info
        spec_info = {
            "title": self.spec.get("info", {}).get("title", ""),
            "version": self.spec.get("info", {}).get("version", ""),
            "openapi_version": self.spec.get("openapi", self.spec.get("swagger", "")),
            "endpoints_count": len(self.endpoints),
            "servers": self.spec.get("servers", [])
        }

        return OpenAPIFuzzResult(
            base_url=self.base_url,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            endpoints_tested=len(self.endpoints),
            requests_made=self.requests_made,
            findings=findings,
            spec_info=spec_info,
            metadata={
                "config": {
                    "fuzz_parameters": self.config.fuzz_parameters,
                    "fuzz_bodies": self.config.fuzz_bodies,
                    "test_bola": self.config.test_bola,
                    "test_auth_bypass": self.config.test_auth_bypass
                }
            }
        )


# Convenience function
async def fuzz_openapi(
    base_url: str,
    spec_path: Optional[str] = None,
    spec_url: Optional[str] = None,
    auth_token: Optional[str] = None,
    full_scan: bool = True
) -> OpenAPIFuzzResult:
    """
    Quick OpenAPI fuzzing scan.

    Args:
        base_url: Base API URL
        spec_path: Path to OpenAPI spec file
        spec_url: URL to OpenAPI spec
        auth_token: Bearer token for authentication
        full_scan: Run all tests if True

    Returns:
        OpenAPIFuzzResult
    """
    config = OpenAPIConfig(
        base_url=base_url,
        spec_path=spec_path,
        spec_url=spec_url,
        auth_token=auth_token or "",
        test_bola=full_scan,
        test_mass_assignment=full_scan,
        test_rate_limit=full_scan,
        test_auth_bypass=full_scan
    )

    fuzzer = OpenAPIFuzzer(base_url, config)
    return await fuzzer.fuzz()
