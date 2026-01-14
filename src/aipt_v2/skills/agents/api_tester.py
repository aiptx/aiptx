"""
API Security Testing Agent - AI-powered REST API security assessment.

Tests APIs for:
- Injection vulnerabilities (SQLi, NoSQLi, Command Injection)
- Broken authentication and authorization (BOLA, BFLA)
- Data exposure
- Rate limiting bypass
- Mass assignment
- SSRF
"""

import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import structlog

from aipt_v2.skills.agents.base import (
    AgentConfig,
    AgentResult,
    BaseSecurityAgent,
    Finding,
    Severity,
    VulnCategory,
    register_tool,
)
from aipt_v2.skills.prompts import SkillPrompts

logger = structlog.get_logger()

# HTTP client for API testing
_http_client = None


def get_http_client():
    """Get or create HTTP client."""
    global _http_client
    if _http_client is None:
        import httpx
        _http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=False  # Allow self-signed certs for testing
        )
    return _http_client


# Register API testing tools
@register_tool(
    name="http_request",
    description="Send an HTTP request to test an API endpoint",
    parameters={
        "method": {"type": "string", "description": "HTTP method (GET, POST, PUT, DELETE, PATCH)"},
        "url": {"type": "string", "description": "Full URL to request"},
        "headers": {"type": "object", "description": "Optional headers dict"},
        "body": {"type": "string", "description": "Optional request body (JSON string)"},
        "params": {"type": "object", "description": "Optional query parameters"}
    },
    category="api_test"
)
async def http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    params: Optional[Dict[str, str]] = None
) -> str:
    """Send an HTTP request."""
    try:
        client = get_http_client()

        # Parse body if JSON string
        json_body = None
        if body:
            try:
                json_body = json.loads(body)
            except json.JSONDecodeError:
                pass

        response = await client.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=json_body if json_body else None,
            content=body if body and not json_body else None,
            params=params
        )

        # Build response summary
        result = f"""HTTP {method.upper()} {url}
Status: {response.status_code}
Headers: {dict(response.headers)}

Response Body:
{response.text[:5000]}"""

        return result

    except Exception as e:
        return f"Request failed: {str(e)}"


@register_tool(
    name="parse_openapi",
    description="Parse an OpenAPI/Swagger specification to discover endpoints",
    parameters={
        "spec_url_or_content": {"type": "string", "description": "URL to OpenAPI spec or the spec content itself"}
    },
    category="api_test"
)
async def parse_openapi(spec_url_or_content: str) -> str:
    """Parse OpenAPI specification."""
    try:
        import yaml

        # Try to fetch if URL
        if spec_url_or_content.startswith(('http://', 'https://')):
            client = get_http_client()
            response = await client.get(spec_url_or_content)
            content = response.text
        else:
            content = spec_url_or_content

        # Parse YAML or JSON
        try:
            spec = yaml.safe_load(content)
        except yaml.YAMLError:
            spec = json.loads(content)

        # Extract endpoints
        endpoints = []
        paths = spec.get('paths', {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ['get', 'post', 'put', 'delete', 'patch']:
                    params = []
                    for param in details.get('parameters', []):
                        params.append(f"{param.get('name')} ({param.get('in', 'query')})")

                    endpoint = {
                        'path': path,
                        'method': method.upper(),
                        'summary': details.get('summary', ''),
                        'parameters': params,
                        'security': details.get('security', [])
                    }
                    endpoints.append(endpoint)

        # Format output
        output = f"OpenAPI Spec: {spec.get('info', {}).get('title', 'Unknown')}\n"
        output += f"Version: {spec.get('info', {}).get('version', 'Unknown')}\n"
        output += f"Base URL: {spec.get('servers', [{}])[0].get('url', 'Not specified')}\n\n"
        output += f"Endpoints ({len(endpoints)}):\n"

        for ep in endpoints:
            output += f"\n{ep['method']} {ep['path']}"
            if ep['summary']:
                output += f" - {ep['summary']}"
            if ep['parameters']:
                output += f"\n  Parameters: {', '.join(ep['parameters'])}"
            if ep['security']:
                output += f"\n  Security: {ep['security']}"

        return output

    except Exception as e:
        return f"Failed to parse OpenAPI spec: {str(e)}"


@register_tool(
    name="fuzz_parameter",
    description="Fuzz a parameter with various payloads",
    parameters={
        "base_url": {"type": "string", "description": "Base URL of the endpoint"},
        "method": {"type": "string", "description": "HTTP method"},
        "param_name": {"type": "string", "description": "Parameter name to fuzz"},
        "param_location": {"type": "string", "description": "Location: query, body, header, path"},
        "payloads": {"type": "array", "description": "List of payloads to test"},
        "headers": {"type": "object", "description": "Optional headers"}
    },
    category="api_test"
)
async def fuzz_parameter(
    base_url: str,
    method: str,
    param_name: str,
    param_location: str,
    payloads: List[str],
    headers: Optional[Dict[str, str]] = None
) -> str:
    """Fuzz a parameter with various payloads."""
    try:
        client = get_http_client()
        results = []

        for payload in payloads[:20]:  # Limit to 20 payloads
            try:
                url = base_url
                req_headers = headers.copy() if headers else {}
                body = None
                params = None

                if param_location == "query":
                    params = {param_name: payload}
                elif param_location == "body":
                    body = json.dumps({param_name: payload})
                    req_headers["Content-Type"] = "application/json"
                elif param_location == "header":
                    req_headers[param_name] = payload
                elif param_location == "path":
                    url = base_url.replace(f"{{{param_name}}}", payload)

                response = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers,
                    content=body,
                    params=params
                )

                # Check for interesting responses
                interesting = False
                indicators = []

                # Error indicators
                if response.status_code >= 500:
                    interesting = True
                    indicators.append("Server Error")
                if "error" in response.text.lower():
                    interesting = True
                    indicators.append("Error in response")
                if "exception" in response.text.lower():
                    interesting = True
                    indicators.append("Exception disclosed")
                if "sql" in response.text.lower():
                    interesting = True
                    indicators.append("SQL-related")

                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "length": len(response.text),
                    "interesting": interesting,
                    "indicators": indicators,
                    "response_preview": response.text[:200] if interesting else ""
                })

                # Small delay between requests
                await asyncio.sleep(0.1)

            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e)
                })

        # Format results
        output = f"Fuzzing {param_name} ({param_location}) on {method} {base_url}\n\n"

        interesting_results = [r for r in results if r.get("interesting")]
        if interesting_results:
            output += "=== INTERESTING RESULTS ===\n"
            for r in interesting_results:
                output += f"\nPayload: {r['payload']}\n"
                output += f"Status: {r['status']}, Length: {r['length']}\n"
                output += f"Indicators: {', '.join(r['indicators'])}\n"
                if r.get('response_preview'):
                    output += f"Preview: {r['response_preview']}\n"

        output += f"\n=== ALL RESULTS ({len(results)} payloads) ===\n"
        for r in results:
            if 'error' in r:
                output += f"Payload: {r['payload']} - Error: {r['error']}\n"
            else:
                output += f"Payload: {r['payload']} - Status: {r['status']}, Length: {r['length']}\n"

        return output

    except Exception as e:
        return f"Fuzzing failed: {str(e)}"


import asyncio


@register_tool(
    name="test_authentication",
    description="Test API authentication mechanisms",
    parameters={
        "base_url": {"type": "string", "description": "API base URL"},
        "auth_endpoint": {"type": "string", "description": "Authentication endpoint (e.g., /auth/login)"},
        "test_credentials": {"type": "array", "description": "List of username:password pairs to test"}
    },
    category="api_test"
)
async def test_authentication(
    base_url: str,
    auth_endpoint: str,
    test_credentials: List[str]
) -> str:
    """Test authentication mechanisms."""
    try:
        client = get_http_client()
        url = urljoin(base_url, auth_endpoint)
        results = []

        for cred in test_credentials[:10]:  # Limit to 10 attempts
            try:
                username, password = cred.split(":", 1)

                # Try common auth payload formats
                payloads = [
                    {"username": username, "password": password},
                    {"email": username, "password": password},
                    {"user": username, "pass": password},
                    {"login": username, "password": password},
                ]

                for payload in payloads:
                    response = await client.post(url, json=payload)

                    # Check if authentication succeeded
                    success_indicators = ["token", "jwt", "session", "access_token", "auth"]
                    is_success = any(ind in response.text.lower() for ind in success_indicators)
                    is_success = is_success or response.status_code == 200

                    results.append({
                        "credential": cred,
                        "payload_format": list(payload.keys()),
                        "status": response.status_code,
                        "success": is_success,
                        "response_preview": response.text[:300]
                    })

                    if is_success:
                        break

                await asyncio.sleep(0.2)  # Rate limiting

            except Exception as e:
                results.append({"credential": cred, "error": str(e)})

        # Format output
        output = f"Authentication Testing: {url}\n\n"

        successful = [r for r in results if r.get("success")]
        if successful:
            output += "=== SUCCESSFUL AUTHENTICATIONS ===\n"
            for r in successful:
                output += f"Credential: {r['credential']}\n"
                output += f"Response: {r['response_preview']}\n\n"

        output += f"\n=== ALL RESULTS ({len(results)} attempts) ===\n"
        for r in results:
            if 'error' in r:
                output += f"{r['credential']}: Error - {r['error']}\n"
            else:
                status = "SUCCESS" if r['success'] else "FAILED"
                output += f"{r['credential']}: {status} (HTTP {r['status']})\n"

        return output

    except Exception as e:
        return f"Auth testing failed: {str(e)}"


@register_tool(
    name="test_authorization",
    description="Test for authorization bypass (IDOR/BOLA)",
    parameters={
        "url": {"type": "string", "description": "URL with object ID to test"},
        "auth_header": {"type": "string", "description": "Authorization header value"},
        "test_ids": {"type": "array", "description": "List of IDs to test access to"}
    },
    category="api_test"
)
async def test_authorization(
    url: str,
    auth_header: str,
    test_ids: List[str]
) -> str:
    """Test for authorization bypass."""
    try:
        client = get_http_client()
        results = []

        headers = {"Authorization": auth_header}

        for test_id in test_ids[:20]:  # Limit to 20 IDs
            try:
                # Replace ID placeholder in URL
                test_url = url.replace("{id}", test_id).replace(":id", test_id)

                response = await client.get(test_url, headers=headers)

                results.append({
                    "id": test_id,
                    "url": test_url,
                    "status": response.status_code,
                    "length": len(response.text),
                    "accessible": response.status_code == 200,
                    "response_preview": response.text[:200] if response.status_code == 200 else ""
                })

                await asyncio.sleep(0.1)

            except Exception as e:
                results.append({"id": test_id, "error": str(e)})

        # Analyze for IDOR
        accessible = [r for r in results if r.get("accessible")]

        output = f"Authorization Testing: {url}\n\n"

        if len(accessible) > 1:
            output += "⚠️ POTENTIAL IDOR DETECTED - Multiple resources accessible\n\n"

        output += f"=== ACCESSIBLE RESOURCES ({len(accessible)}) ===\n"
        for r in accessible:
            output += f"ID: {r['id']} - Length: {r['length']}\n"
            if r.get('response_preview'):
                output += f"Preview: {r['response_preview']}\n\n"

        output += f"\n=== ALL RESULTS ({len(results)} IDs tested) ===\n"
        for r in results:
            if 'error' in r:
                output += f"ID {r['id']}: Error - {r['error']}\n"
            else:
                status = "ACCESSIBLE" if r['accessible'] else "DENIED"
                output += f"ID {r['id']}: {status} (HTTP {r['status']})\n"

        return output

    except Exception as e:
        return f"Authorization testing failed: {str(e)}"


@register_tool(
    name="report_api_finding",
    description="Report an API security vulnerability",
    parameters={
        "title": {"type": "string", "description": "Title of the vulnerability"},
        "severity": {"type": "string", "description": "Severity level"},
        "endpoint": {"type": "string", "description": "Affected endpoint"},
        "method": {"type": "string", "description": "HTTP method"},
        "description": {"type": "string", "description": "Detailed description"},
        "request": {"type": "string", "description": "Example malicious request"},
        "response": {"type": "string", "description": "Response showing vulnerability"},
        "remediation": {"type": "string", "description": "How to fix"}
    },
    category="api_test"
)
async def report_api_finding(
    title: str,
    severity: str,
    endpoint: str,
    method: str,
    description: str,
    request: str,
    response: str,
    remediation: str
) -> str:
    """Report an API security finding."""
    return f"""API Security Finding Recorded:
Title: {title}
Severity: {severity}
Endpoint: {method} {endpoint}
Description: {description}
Request: {request[:500]}
Response: {response[:500]}
Remediation: {remediation}
"""


API_TEST_SYSTEM_PROMPT = """You are an expert API security tester specializing in REST API penetration testing.

## EXPERTISE AREAS
- OWASP API Security Top 10
- Authentication/Authorization attacks (BOLA, BFLA)
- Injection attacks (SQLi, NoSQLi, Command Injection)
- Mass assignment vulnerabilities
- Rate limiting bypass
- Information disclosure

## TESTING METHODOLOGY

### 1. Reconnaissance
- Parse OpenAPI/Swagger specs if available
- Enumerate endpoints and parameters
- Identify authentication mechanisms
- Map data models and relationships

### 2. Authentication Testing
- Test for weak credentials
- Check token handling (JWT vulnerabilities, session issues)
- Test password reset flows
- Check for authentication bypass

### 3. Authorization Testing (BOLA/BFLA)
- Test accessing other users' resources (horizontal escalation)
- Test accessing admin functions (vertical escalation)
- Check for IDOR vulnerabilities
- Test function-level access control

### 4. Injection Testing
- SQL injection in all parameters
- NoSQL injection (MongoDB operators)
- Command injection
- Template injection

### 5. Data Handling
- Test for mass assignment
- Check for sensitive data in responses
- Test file upload functionality
- Check for rate limiting

## PAYLOADS BY VULNERABILITY

### SQL Injection
- ' OR '1'='1
- 1; DROP TABLE--
- ' UNION SELECT NULL--

### NoSQL Injection
- {"$gt": ""}
- {"$ne": null}
- {"$where": "sleep(5000)"}

### Command Injection
- ; id
- | cat /etc/passwd
- `whoami`

### Mass Assignment
- Add admin: true to requests
- Add role: admin to user creation
- Include hidden fields

## OUTPUT FORMAT
Use report_api_finding for each vulnerability discovered with:
- Clear title and severity
- Affected endpoint and method
- Full request/response evidence
- Specific remediation steps

Be aggressive and thorough. Test every endpoint. Check every parameter."""


class APITestAgent(BaseSecurityAgent):
    """
    AI-powered API security testing agent.

    Performs comprehensive security testing of REST APIs including:
    - Authentication and authorization testing
    - Injection vulnerability testing
    - Business logic testing
    - Rate limiting and DoS testing

    Usage:
        agent = APITestAgent(base_url="https://api.example.com")
        result = await agent.run()
    """

    def __init__(
        self,
        base_url: str,
        config: Optional[AgentConfig] = None,
        openapi_spec: Optional[str] = None,
        auth_token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize the API testing agent.

        Args:
            base_url: Base URL of the API to test
            config: Agent configuration
            openapi_spec: Path or URL to OpenAPI/Swagger spec
            auth_token: Authentication token for API access
            headers: Additional headers to include in requests
        """
        super().__init__(config)
        self.base_url = base_url.rstrip('/')
        self.openapi_spec = openapi_spec
        self.auth_token = auth_token
        self.headers = headers or {}

        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

    def get_system_prompt(self) -> str:
        """Get the API testing system prompt."""
        return API_TEST_SYSTEM_PROMPT

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get tools available for API testing."""
        return [
            {
                "name": "http_request",
                "description": "Send an HTTP request to test an API endpoint",
                "parameters": {
                    "method": {"type": "string", "description": "HTTP method"},
                    "url": {"type": "string", "description": "Full URL"},
                    "headers": {"type": "object", "description": "Optional headers"},
                    "body": {"type": "string", "description": "Optional JSON body"},
                    "params": {"type": "object", "description": "Query parameters"}
                },
                "required": ["method", "url"]
            },
            {
                "name": "parse_openapi",
                "description": "Parse OpenAPI/Swagger specification",
                "parameters": {
                    "spec_url_or_content": {"type": "string", "description": "URL or content of spec"}
                },
                "required": ["spec_url_or_content"]
            },
            {
                "name": "fuzz_parameter",
                "description": "Fuzz a parameter with payloads",
                "parameters": {
                    "base_url": {"type": "string"},
                    "method": {"type": "string"},
                    "param_name": {"type": "string"},
                    "param_location": {"type": "string"},
                    "payloads": {"type": "array"},
                    "headers": {"type": "object"}
                },
                "required": ["base_url", "method", "param_name", "param_location", "payloads"]
            },
            {
                "name": "test_authentication",
                "description": "Test authentication mechanisms",
                "parameters": {
                    "base_url": {"type": "string"},
                    "auth_endpoint": {"type": "string"},
                    "test_credentials": {"type": "array"}
                },
                "required": ["base_url", "auth_endpoint", "test_credentials"]
            },
            {
                "name": "test_authorization",
                "description": "Test for IDOR/BOLA vulnerabilities",
                "parameters": {
                    "url": {"type": "string"},
                    "auth_header": {"type": "string"},
                    "test_ids": {"type": "array"}
                },
                "required": ["url", "auth_header", "test_ids"]
            },
            {
                "name": "report_api_finding",
                "description": "Report an API security finding",
                "parameters": {
                    "title": {"type": "string"},
                    "severity": {"type": "string"},
                    "endpoint": {"type": "string"},
                    "method": {"type": "string"},
                    "description": {"type": "string"},
                    "request": {"type": "string"},
                    "response": {"type": "string"},
                    "remediation": {"type": "string"}
                },
                "required": ["title", "severity", "endpoint", "method", "description", "request", "response", "remediation"]
            }
        ]

    async def run(self, initial_message: Optional[str] = None) -> AgentResult:
        """
        Run the API security test.

        Args:
            initial_message: Optional additional instructions

        Returns:
            AgentResult with all security findings
        """
        message = f"""Perform comprehensive API security testing on: {self.base_url}

"""
        if self.openapi_spec:
            message += f"OpenAPI Specification available at: {self.openapi_spec}\nStart by parsing the OpenAPI spec to discover all endpoints.\n\n"
        else:
            message += "No OpenAPI spec provided. Start by discovering endpoints through common paths and responses.\n\n"

        if self.headers:
            message += f"Use these headers for authenticated requests: {json.dumps(self.headers)}\n\n"

        message += """Testing priorities:
1. Map all endpoints and parameters
2. Test authentication mechanisms
3. Check for authorization bypass (BOLA/IDOR)
4. Test injection vulnerabilities
5. Check for information disclosure
6. Test rate limiting

"""
        if initial_message:
            message += initial_message

        message += "\n\nBegin testing now."

        return await super().run(message)
