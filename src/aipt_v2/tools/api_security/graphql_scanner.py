"""
GraphQL Security Scanner

Comprehensive GraphQL API security testing including:
- Introspection query detection
- Query depth attacks (DoS)
- Batch query attacks
- Field suggestion brute-force
- SQL/NoSQL injection via GraphQL
- Authorization bypass
- Information disclosure

References:
- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- https://graphql.security/

Usage:
    from aipt_v2.tools.api_security import GraphQLScanner

    scanner = GraphQLScanner("https://api.target.com/graphql")
    findings = await scanner.scan()
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:
    aiohttp = None


@dataclass
class GraphQLConfig:
    """GraphQL scanner configuration."""
    endpoint: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    # Test options
    test_introspection: bool = True
    test_depth_attack: bool = True
    test_batch_attack: bool = True
    test_field_suggestions: bool = True
    test_injection: bool = True
    test_dos: bool = False  # Disabled by default (potentially harmful)

    # Limits
    max_depth: int = 10
    batch_size: int = 10
    timeout: int = 30

    # Authentication
    auth_token: str = ""
    auth_header: str = "Authorization"


@dataclass
class GraphQLFinding:
    """GraphQL security finding."""
    vulnerability: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str
    remediation: str
    endpoint: str
    timestamp: str = ""
    cwe: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class GraphQLScanResult:
    """Result of GraphQL security scan."""
    endpoint: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    findings: List[GraphQLFinding]
    schema_info: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class GraphQLScanner:
    """
    GraphQL API Security Scanner.

    Tests GraphQL endpoints for common security vulnerabilities
    including introspection exposure, DoS vectors, and injection attacks.
    """

    # Standard introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    args {
                        name
                        description
                        type { kind name }
                        defaultValue
                    }
                    type { kind name ofType { kind name } }
                    isDeprecated
                    deprecationReason
                }
                inputFields {
                    name
                    description
                    type { kind name }
                    defaultValue
                }
                interfaces { kind name }
                enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                }
                possibleTypes { kind name }
            }
            directives {
                name
                description
                locations
                args {
                    name
                    description
                    type { kind name }
                    defaultValue
                }
            }
        }
    }
    """

    # Partial introspection queries (sometimes full is blocked)
    PARTIAL_INTROSPECTION = """
    query { __schema { types { name } } }
    """

    # Type introspection
    TYPE_INTROSPECTION = """
    query { __type(name: "Query") { name fields { name } } }
    """

    # Field suggestion payloads
    FIELD_SUGGESTIONS = [
        "user", "users", "admin", "admins", "login", "me", "profile",
        "account", "accounts", "password", "token", "secret", "key",
        "credential", "auth", "session", "config", "setting", "flag",
        "debug", "test", "internal", "private", "hidden", "system"
    ]

    # SQL injection payloads for GraphQL
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        '" OR "1"="1',
        "1 OR 1=1",
        "'; DROP TABLE users; --",
        "1' AND '1'='1",
        "admin'--",
        "1; SELECT * FROM users--"
    ]

    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}'
    ]

    def __init__(self, endpoint: str, config: Optional[GraphQLConfig] = None):
        """
        Initialize GraphQL scanner.

        Args:
            endpoint: GraphQL endpoint URL
            config: Scanner configuration
        """
        self.endpoint = endpoint
        self.config = config or GraphQLConfig(endpoint=endpoint)
        self.findings: List[GraphQLFinding] = []
        self.schema = None

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AIPTX-GraphQL-Scanner/1.0"
        }
        headers.update(self.config.headers)

        if self.config.auth_token:
            headers[self.config.auth_header] = f"Bearer {self.config.auth_token}"

        return headers

    async def _send_query(self, query: str, variables: Optional[Dict] = None) -> Dict[str, Any]:
        """Send GraphQL query and return response."""
        if aiohttp is None:
            raise ImportError("aiohttp is required for GraphQL scanning. Install with: pip install aiohttp")

        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.endpoint,
                    json=payload,
                    headers=self._get_headers(),
                    cookies=self.config.cookies,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    ssl=False  # Allow self-signed certs
                ) as response:
                    text = await response.text()
                    try:
                        return {"status": response.status, "data": json.loads(text)}
                    except json.JSONDecodeError:
                        return {"status": response.status, "data": text, "raw": True}
        except Exception as e:
            return {"error": str(e)}

    async def test_introspection(self) -> List[GraphQLFinding]:
        """Test if introspection is enabled."""
        findings = []

        # Test full introspection
        response = await self._send_query(self.INTROSPECTION_QUERY)

        if "error" not in response:
            data = response.get("data", {})
            if isinstance(data, dict) and "data" in data:
                schema_data = data.get("data", {}).get("__schema")
                if schema_data:
                    self.schema = schema_data

                    # Count exposed types
                    types = schema_data.get("types", [])
                    custom_types = [t for t in types if not t.get("name", "").startswith("__")]

                    findings.append(GraphQLFinding(
                        vulnerability="GraphQL Introspection Enabled",
                        severity="medium",
                        description=f"Full introspection query is enabled, exposing {len(custom_types)} custom types",
                        evidence=f"Exposed types: {', '.join([t.get('name') for t in custom_types[:10]])}...",
                        remediation="Disable introspection in production or implement authentication for introspection queries",
                        endpoint=self.endpoint,
                        cwe="CWE-200"
                    ))

                    # Check for sensitive types
                    sensitive_patterns = ["user", "admin", "auth", "password", "token", "secret", "key"]
                    sensitive_types = [t for t in custom_types
                                     if any(p in t.get("name", "").lower() for p in sensitive_patterns)]

                    if sensitive_types:
                        findings.append(GraphQLFinding(
                            vulnerability="Sensitive Types Exposed via Introspection",
                            severity="high",
                            description=f"Introspection reveals {len(sensitive_types)} potentially sensitive types",
                            evidence=f"Sensitive types: {', '.join([t.get('name') for t in sensitive_types])}",
                            remediation="Review exposed types and implement field-level authorization",
                            endpoint=self.endpoint,
                            cwe="CWE-200"
                        ))

                    return findings

        # Try partial introspection
        response = await self._send_query(self.PARTIAL_INTROSPECTION)
        if "error" not in response:
            data = response.get("data", {})
            if isinstance(data, dict) and "__schema" in str(data):
                findings.append(GraphQLFinding(
                    vulnerability="GraphQL Partial Introspection Enabled",
                    severity="low",
                    description="Partial introspection query is allowed",
                    evidence="__schema query returned type information",
                    remediation="Disable all introspection queries in production",
                    endpoint=self.endpoint,
                    cwe="CWE-200"
                ))

        return findings

    async def test_depth_attack(self) -> List[GraphQLFinding]:
        """Test for query depth attack vulnerability (DoS)."""
        findings = []

        # Build nested query
        def build_nested_query(depth: int) -> str:
            query = "query {"
            indent = "  "
            for i in range(depth):
                query += f"\n{indent * (i + 1)}__typename"
                if i < depth - 1:
                    query += "\n" + indent * (i + 1) + "... on Query {"
            for i in range(depth - 1, 0, -1):
                query += "\n" + indent * i + "}"
            query += "\n}"
            return query

        # Test increasing depths
        for depth in [5, 10, 15]:
            nested_query = build_nested_query(depth)
            response = await self._send_query(nested_query)

            if "error" not in response and response.get("status") == 200:
                data = response.get("data", {})
                if "errors" not in data:
                    if depth >= 10:
                        findings.append(GraphQLFinding(
                            vulnerability="GraphQL Query Depth Attack",
                            severity="medium",
                            description=f"Server accepts queries with depth {depth}, allowing DoS attacks",
                            evidence=f"Nested query with depth {depth} was accepted",
                            remediation="Implement query depth limiting (recommended max: 5-7)",
                            endpoint=self.endpoint,
                            cwe="CWE-400"
                        ))
                        break

        return findings

    async def test_batch_attack(self) -> List[GraphQLFinding]:
        """Test for batch query attack vulnerability."""
        findings = []

        # Build batch query
        batch_query = " ".join([f"q{i}: __typename" for i in range(self.config.batch_size)])
        query = f"query {{ {batch_query} }}"

        response = await self._send_query(query)

        if "error" not in response and response.get("status") == 200:
            data = response.get("data", {})
            if isinstance(data, dict) and "data" in data:
                result_data = data.get("data", {})
                if isinstance(result_data, dict) and len(result_data) >= self.config.batch_size:
                    findings.append(GraphQLFinding(
                        vulnerability="GraphQL Batch Query Attack",
                        severity="medium",
                        description=f"Server accepts batch queries with {self.config.batch_size}+ aliases",
                        evidence=f"Batch query with {self.config.batch_size} aliases was accepted",
                        remediation="Implement query complexity limiting and alias restrictions",
                        endpoint=self.endpoint,
                        cwe="CWE-400"
                    ))

        # Test array batching
        batch_payload = [
            {"query": "{ __typename }"}
            for _ in range(self.config.batch_size)
        ]

        if aiohttp:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.endpoint,
                        json=batch_payload,
                        headers=self._get_headers(),
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if isinstance(data, list) and len(data) >= self.config.batch_size:
                                findings.append(GraphQLFinding(
                                    vulnerability="GraphQL Array Batching Enabled",
                                    severity="medium",
                                    description="Server accepts array-based batch queries",
                                    evidence=f"Array batch with {self.config.batch_size} queries was accepted",
                                    remediation="Disable array batching or implement strict rate limiting",
                                    endpoint=self.endpoint,
                                    cwe="CWE-400"
                                ))
            except Exception:
                pass

        return findings

    async def test_field_suggestions(self) -> List[GraphQLFinding]:
        """Test for field suggestion information disclosure."""
        findings = []
        discovered_fields = []

        for field_name in self.FIELD_SUGGESTIONS:
            query = f"query {{ {field_name} }}"
            response = await self._send_query(query)

            if "error" not in response:
                data = response.get("data", {})
                if isinstance(data, dict):
                    errors = data.get("errors", [])
                    for error in errors:
                        message = error.get("message", "")
                        # Check for field suggestions in error
                        if "Did you mean" in message or "suggestions" in message.lower():
                            # Extract suggested fields
                            suggestions = re.findall(r'"([^"]+)"', message)
                            discovered_fields.extend(suggestions)

        if discovered_fields:
            unique_fields = list(set(discovered_fields))
            findings.append(GraphQLFinding(
                vulnerability="GraphQL Field Suggestion Disclosure",
                severity="low",
                description=f"Error messages reveal {len(unique_fields)} valid field names",
                evidence=f"Discovered fields: {', '.join(unique_fields[:10])}",
                remediation="Disable field suggestions in production or use generic error messages",
                endpoint=self.endpoint,
                cwe="CWE-200"
            ))

        return findings

    async def test_injection(self) -> List[GraphQLFinding]:
        """Test for SQL/NoSQL injection via GraphQL arguments."""
        findings = []

        # Test SQL injection
        for payload in self.SQLI_PAYLOADS:
            query = f'query {{ user(id: "{payload}") {{ id }} }}'
            response = await self._send_query(query)

            if "error" not in response:
                data = response.get("data", {})
                if isinstance(data, dict):
                    # Check for SQL error patterns
                    response_str = json.dumps(data).lower()
                    sql_errors = ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle"]
                    if any(err in response_str for err in sql_errors):
                        findings.append(GraphQLFinding(
                            vulnerability="Potential SQL Injection via GraphQL",
                            severity="critical",
                            description="GraphQL argument appears vulnerable to SQL injection",
                            evidence=f"Payload: {payload} triggered SQL-related error",
                            remediation="Use parameterized queries and input validation",
                            endpoint=self.endpoint,
                            cwe="CWE-89"
                        ))
                        break

        # Test NoSQL injection
        for payload in self.NOSQL_PAYLOADS:
            query = f'query {{ user(filter: {payload}) {{ id }} }}'
            response = await self._send_query(query)

            if "error" not in response:
                data = response.get("data", {})
                response_str = json.dumps(data).lower()
                nosql_errors = ["mongodb", "mongoose", "objectid", "bson"]
                if any(err in response_str for err in nosql_errors):
                    findings.append(GraphQLFinding(
                        vulnerability="Potential NoSQL Injection via GraphQL",
                        severity="critical",
                        description="GraphQL argument appears vulnerable to NoSQL injection",
                        evidence=f"Payload triggered NoSQL-related response",
                        remediation="Validate and sanitize all input before database queries",
                        endpoint=self.endpoint,
                        cwe="CWE-943"
                    ))
                    break

        return findings

    async def test_authorization_bypass(self) -> List[GraphQLFinding]:
        """Test for authorization bypass via alias abuse."""
        findings = []

        # Try to access potentially restricted fields via aliases
        sensitive_queries = [
            'query { admin: user(role: "admin") { id email } }',
            'query { allUsers: users(limit: 1000) { id email role } }',
            'query { config: systemConfig { debugMode apiKeys } }',
            'query { me: currentUser { id role permissions } }'
        ]

        for query in sensitive_queries:
            response = await self._send_query(query)

            if "error" not in response:
                data = response.get("data", {})
                if isinstance(data, dict):
                    result = data.get("data", {})
                    if result and "errors" not in data:
                        # Check if we got actual data
                        if any(result.values()):
                            findings.append(GraphQLFinding(
                                vulnerability="Potential Authorization Bypass",
                                severity="high",
                                description="Query returned data that may require authorization",
                                evidence=f"Query '{query[:50]}...' returned data without proper auth check",
                                remediation="Implement field-level authorization and access control",
                                endpoint=self.endpoint,
                                cwe="CWE-862"
                            ))

        return findings

    async def scan(self) -> GraphQLScanResult:
        """
        Run full GraphQL security scan.

        Returns:
            GraphQLScanResult with all findings
        """
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = asyncio.get_event_loop().time()

        findings = []

        # Run enabled tests
        if self.config.test_introspection:
            findings.extend(await self.test_introspection())

        if self.config.test_depth_attack:
            findings.extend(await self.test_depth_attack())

        if self.config.test_batch_attack:
            findings.extend(await self.test_batch_attack())

        if self.config.test_field_suggestions:
            findings.extend(await self.test_field_suggestions())

        if self.config.test_injection:
            findings.extend(await self.test_injection())

        # Authorization bypass test
        findings.extend(await self.test_authorization_bypass())

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = asyncio.get_event_loop().time() - start_time

        # Build schema info summary
        schema_info = {}
        if self.schema:
            types = self.schema.get("types", [])
            schema_info = {
                "total_types": len(types),
                "query_type": self.schema.get("queryType", {}).get("name"),
                "mutation_type": self.schema.get("mutationType", {}).get("name"),
                "subscription_type": self.schema.get("subscriptionType", {}).get("name"),
                "custom_types": len([t for t in types if not t.get("name", "").startswith("__")])
            }

        return GraphQLScanResult(
            endpoint=self.endpoint,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            findings=findings,
            schema_info=schema_info,
            metadata={
                "tests_run": sum([
                    self.config.test_introspection,
                    self.config.test_depth_attack,
                    self.config.test_batch_attack,
                    self.config.test_field_suggestions,
                    self.config.test_injection
                ])
            }
        )


# Convenience function
async def scan_graphql(
    endpoint: str,
    auth_token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    full_scan: bool = True
) -> GraphQLScanResult:
    """
    Quick GraphQL security scan.

    Args:
        endpoint: GraphQL endpoint URL
        auth_token: Bearer token for authentication
        headers: Additional headers
        full_scan: Run all tests if True

    Returns:
        GraphQLScanResult
    """
    config = GraphQLConfig(
        endpoint=endpoint,
        auth_token=auth_token or "",
        headers=headers or {},
        test_introspection=True,
        test_depth_attack=full_scan,
        test_batch_attack=full_scan,
        test_field_suggestions=full_scan,
        test_injection=full_scan
    )

    scanner = GraphQLScanner(endpoint, config)
    return await scanner.scan()
