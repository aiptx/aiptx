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

from aipt_v2.core.event_loop_manager import current_time

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
    test_mutations: bool = True  # Mutation security testing
    test_subscriptions: bool = True  # WebSocket subscription testing
    test_complexity: bool = True  # Query complexity analysis
    test_field_authorization: bool = True  # Field-level auth testing
    test_schema_security: bool = True  # Schema security analysis

    # Limits
    max_depth: int = 10
    batch_size: int = 10
    timeout: int = 30
    complexity_threshold: int = 1000  # Max query complexity score

    # Authentication (for comparing auth vs no-auth responses)
    auth_token: str = ""
    auth_header: str = "Authorization"
    secondary_auth_token: str = ""  # For testing user A vs user B


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

    async def test_mutation_security(self) -> List[GraphQLFinding]:
        """
        Test GraphQL mutations for security issues.

        Tests for:
        - Mass assignment vulnerabilities
        - Unauthorized mutation access
        - Destructive mutations without auth
        - Mutation rate limiting
        """
        findings = []

        if not self.schema:
            # Try to get schema first
            await self.test_introspection()

        # Extract mutations from schema
        mutations = []
        if self.schema:
            mutation_type = self.schema.get("mutationType", {})
            if mutation_type:
                mutation_name = mutation_type.get("name", "Mutation")
                for t in self.schema.get("types", []):
                    if t.get("name") == mutation_name:
                        mutations = t.get("fields", [])
                        break

        # Categorize mutations by risk
        dangerous_patterns = {
            "delete": "high",
            "remove": "high",
            "destroy": "high",
            "drop": "critical",
            "admin": "critical",
            "update": "medium",
            "modify": "medium",
            "create": "low",
            "add": "low"
        }

        sensitive_mutations = []
        for mutation in mutations:
            name = mutation.get("name", "").lower()
            for pattern, severity in dangerous_patterns.items():
                if pattern in name:
                    sensitive_mutations.append({
                        "name": mutation.get("name"),
                        "pattern": pattern,
                        "severity": severity,
                        "args": mutation.get("args", [])
                    })
                    break

        # Test dangerous mutations without authentication
        if sensitive_mutations:
            findings.append(GraphQLFinding(
                vulnerability="Sensitive Mutations Exposed",
                severity="medium",
                description=f"Schema exposes {len(sensitive_mutations)} potentially dangerous mutations",
                evidence=f"Mutations: {', '.join([m['name'] for m in sensitive_mutations[:5]])}...",
                remediation="Ensure all sensitive mutations require proper authorization",
                endpoint=self.endpoint,
                cwe="CWE-862"
            ))

        # Test for mass assignment in mutations
        mass_assignment_payloads = [
            ('mutation { updateUser(id: "1", role: "admin") { id role } }', "role escalation"),
            ('mutation { updateProfile(isAdmin: true) { id isAdmin } }', "admin flag"),
            ('mutation { createUser(role: "admin", verified: true) { id } }', "user creation with elevated privileges"),
        ]

        for payload, test_type in mass_assignment_payloads:
            response = await self._send_query(payload)
            if "error" not in response:
                data = response.get("data", {})
                if isinstance(data, dict):
                    # Check if mutation was accepted (even with errors, structure acceptance is a signal)
                    if "data" in data and data["data"]:
                        findings.append(GraphQLFinding(
                            vulnerability="Potential Mass Assignment via Mutation",
                            severity="high",
                            description=f"Mutation may allow {test_type}",
                            evidence=f"Payload: {payload[:80]}...",
                            remediation="Whitelist allowed fields in mutation resolvers, never blindly accept input",
                            endpoint=self.endpoint,
                            cwe="CWE-915"
                        ))
                        break

        # Test CSRF on mutations (check if mutations accept GET)
        if aiohttp:
            try:
                async with aiohttp.ClientSession() as session:
                    test_query = 'mutation { __typename }'
                    url_with_query = f"{self.endpoint}?query={test_query}"
                    async with session.get(
                        url_with_query,
                        headers=self._get_headers(),
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data and data.get("data", {}).get("__typename"):
                                findings.append(GraphQLFinding(
                                    vulnerability="GraphQL Mutations Accept GET Requests",
                                    severity="medium",
                                    description="Mutations can be executed via GET requests, enabling CSRF attacks",
                                    evidence="GET request with mutation query parameter was accepted",
                                    remediation="Reject mutations via GET method, only accept POST for mutations",
                                    endpoint=self.endpoint,
                                    cwe="CWE-352"
                                ))
            except Exception:
                pass

        return findings

    async def test_subscription_security(self) -> List[GraphQLFinding]:
        """
        Test GraphQL subscriptions for security issues.

        Tests for:
        - Subscription availability without auth
        - WebSocket origin validation
        - Subscription DoS potential
        """
        findings = []

        if not self.schema:
            await self.test_introspection()

        # Check if subscriptions exist
        subscriptions = []
        if self.schema:
            sub_type = self.schema.get("subscriptionType", {})
            if sub_type:
                sub_name = sub_type.get("name", "Subscription")
                for t in self.schema.get("types", []):
                    if t.get("name") == sub_name:
                        subscriptions = t.get("fields", [])
                        break

        if subscriptions:
            findings.append(GraphQLFinding(
                vulnerability="GraphQL Subscriptions Enabled",
                severity="info",
                description=f"Schema exposes {len(subscriptions)} subscription endpoints",
                evidence=f"Subscriptions: {', '.join([s.get('name') for s in subscriptions[:5]])}",
                remediation="Ensure subscriptions require authentication and implement rate limiting",
                endpoint=self.endpoint,
                cwe="CWE-284"
            ))

            # Check for sensitive subscriptions
            sensitive_patterns = ["user", "admin", "payment", "order", "message", "notification", "event"]
            sensitive_subs = [
                s for s in subscriptions
                if any(p in s.get("name", "").lower() for p in sensitive_patterns)
            ]

            if sensitive_subs:
                findings.append(GraphQLFinding(
                    vulnerability="Sensitive Subscriptions Exposed",
                    severity="medium",
                    description=f"{len(sensitive_subs)} subscriptions may expose sensitive real-time data",
                    evidence=f"Sensitive subscriptions: {', '.join([s.get('name') for s in sensitive_subs])}",
                    remediation="Implement subscription-level authorization and validate user access to subscribed resources",
                    endpoint=self.endpoint,
                    cwe="CWE-200"
                ))

        # Try to discover WebSocket endpoint
        ws_endpoints = [
            self.endpoint.replace("http://", "ws://").replace("https://", "wss://"),
            self.endpoint + "/websocket",
            self.endpoint.replace("/graphql", "/subscriptions"),
        ]

        # Note: Full WebSocket testing is handled by WebSocketScanner
        # Here we just identify the subscription attack surface

        return findings

    async def test_query_complexity(self) -> List[GraphQLFinding]:
        """
        Test for query complexity attacks (more sophisticated than depth).

        Analyzes:
        - Query complexity scoring
        - Width attacks (many fields)
        - Combined depth + width attacks
        - Fragment-based complexity
        """
        findings = []

        # Test 1: Width attack - many fields at same level
        wide_query = "query { " + " ".join([f"f{i}: __typename" for i in range(50)]) + " }"
        response = await self._send_query(wide_query)

        if "error" not in response and response.get("status") == 200:
            data = response.get("data", {})
            if "errors" not in data or not data.get("errors"):
                findings.append(GraphQLFinding(
                    vulnerability="GraphQL Query Width Attack",
                    severity="medium",
                    description="Server accepts queries with 50+ fields at the same level",
                    evidence="Wide query with 50 aliases was accepted",
                    remediation="Implement query complexity analysis and limit total field count",
                    endpoint=self.endpoint,
                    cwe="CWE-400"
                ))

        # Test 2: Fragment spread complexity
        fragment_query = """
        query FragmentBomb {
            ...F1
        }
        fragment F1 on Query { ...F2 ...F2 }
        fragment F2 on Query { ...F3 ...F3 }
        fragment F3 on Query { ...F4 ...F4 }
        fragment F4 on Query { __typename }
        """
        response = await self._send_query(fragment_query)

        if "error" not in response and response.get("status") == 200:
            data = response.get("data", {})
            if isinstance(data, dict) and "data" in data:
                findings.append(GraphQLFinding(
                    vulnerability="GraphQL Fragment Complexity Attack",
                    severity="medium",
                    description="Server accepts exponential fragment spreads (Fragment Bomb)",
                    evidence="Fragment query with exponential expansion was accepted",
                    remediation="Limit fragment spread depth and detect exponential patterns",
                    endpoint=self.endpoint,
                    cwe="CWE-400"
                ))

        # Test 3: Directive abuse
        directive_query = "query { __typename @skip(if: false) @include(if: true) " + " @skip(if: false)" * 20 + " }"
        response = await self._send_query(directive_query)

        if "error" not in response and response.get("status") == 200:
            findings.append(GraphQLFinding(
                vulnerability="GraphQL Directive Abuse",
                severity="low",
                description="Server accepts excessive directive usage",
                evidence="Query with 20+ directives was accepted",
                remediation="Limit directive count per field/query",
                endpoint=self.endpoint,
                cwe="CWE-400"
            ))

        return findings

    async def test_field_level_authorization(self) -> List[GraphQLFinding]:
        """
        Test for field-level authorization issues.

        Tests for:
        - IDOR via GraphQL queries
        - Accessing other users' data
        - Horizontal privilege escalation
        - Sensitive field exposure
        """
        findings = []

        # Test 1: IDOR - Access different user IDs
        idor_queries = [
            ('query { user(id: "1") { id email password passwordHash } }', "direct user access"),
            ('query { user(id: "2") { id email } }', "other user access"),
            ('query { order(id: "1") { id userId total items } }', "order access"),
            ('query { profile(userId: "1") { id privateData ssn } }', "profile with sensitive data"),
        ]

        for query, test_type in idor_queries:
            response = await self._send_query(query)
            if "error" not in response:
                data = response.get("data", {})
                if isinstance(data, dict) and "data" in data:
                    result = data.get("data", {})
                    if result and any(v for v in result.values() if v):
                        findings.append(GraphQLFinding(
                            vulnerability="Potential IDOR via GraphQL",
                            severity="high",
                            description=f"May allow {test_type} without proper authorization",
                            evidence=f"Query returned data: {query[:60]}...",
                            remediation="Implement field-level authorization, verify user owns requested resource",
                            endpoint=self.endpoint,
                            cwe="CWE-639"
                        ))
                        break

        # Test 2: Check for sensitive field exposure in schema
        if self.schema:
            sensitive_field_patterns = [
                "password", "passwordHash", "secret", "apiKey", "privateKey",
                "ssn", "socialSecurity", "creditCard", "token", "session",
                "salt", "hash", "internal", "debug"
            ]

            exposed_sensitive = []
            for type_def in self.schema.get("types", []):
                if type_def.get("name", "").startswith("__"):
                    continue
                for field_def in type_def.get("fields", []) or []:
                    field_name = field_def.get("name", "").lower()
                    if any(p in field_name for p in sensitive_field_patterns):
                        exposed_sensitive.append(f"{type_def.get('name')}.{field_def.get('name')}")

            if exposed_sensitive:
                findings.append(GraphQLFinding(
                    vulnerability="Sensitive Fields Exposed in Schema",
                    severity="high",
                    description=f"Schema exposes {len(exposed_sensitive)} potentially sensitive fields",
                    evidence=f"Fields: {', '.join(exposed_sensitive[:10])}",
                    remediation="Remove sensitive fields from schema or implement strict field-level authorization",
                    endpoint=self.endpoint,
                    cwe="CWE-200"
                ))

        # Test 3: Compare authenticated vs unauthenticated responses
        if self.config.auth_token:
            # Save auth token temporarily
            original_token = self.config.auth_token
            self.config.auth_token = ""

            test_query = "query { me { id email role } }"
            unauth_response = await self._send_query(test_query)

            self.config.auth_token = original_token
            auth_response = await self._send_query(test_query)

            # Check if unauthenticated got similar data
            if "error" not in unauth_response and "error" not in auth_response:
                unauth_data = unauth_response.get("data", {}).get("data", {})
                auth_data = auth_response.get("data", {}).get("data", {})

                if unauth_data and unauth_data == auth_data:
                    findings.append(GraphQLFinding(
                        vulnerability="Missing Authentication Check",
                        severity="critical",
                        description="Query returns same data authenticated and unauthenticated",
                        evidence="'me' query accessible without authentication",
                        remediation="Implement authentication middleware for sensitive queries",
                        endpoint=self.endpoint,
                        cwe="CWE-306"
                    ))

        return findings

    async def test_schema_security(self) -> List[GraphQLFinding]:
        """
        Analyze GraphQL schema for security issues.

        Checks for:
        - Deprecated but accessible fields
        - Dangerous type patterns
        - Missing input validation hints
        - Debug/internal types exposed
        """
        findings = []

        if not self.schema:
            await self.test_introspection()

        if not self.schema:
            return findings  # Can't analyze without schema

        types = self.schema.get("types", [])
        custom_types = [t for t in types if not t.get("name", "").startswith("__")]

        # Test 1: Check for deprecated fields still accessible
        deprecated_fields = []
        for type_def in custom_types:
            for field_def in type_def.get("fields", []) or []:
                if field_def.get("isDeprecated"):
                    deprecated_fields.append({
                        "type": type_def.get("name"),
                        "field": field_def.get("name"),
                        "reason": field_def.get("deprecationReason", "No reason provided")
                    })

        if deprecated_fields:
            deprecated_list = [f"{d['type']}.{d['field']}" for d in deprecated_fields[:5]]
            findings.append(GraphQLFinding(
                vulnerability="Deprecated Fields Still Accessible",
                severity="low",
                description=f"{len(deprecated_fields)} deprecated fields are still accessible",
                evidence=f"Deprecated: {', '.join(deprecated_list)}",
                remediation="Remove deprecated fields or ensure they're properly secured",
                endpoint=self.endpoint,
                cwe="CWE-1104"
            ))

        # Test 2: Check for debug/internal types
        debug_patterns = ["debug", "internal", "test", "dev", "staging", "admin", "system"]
        debug_types = [
            t for t in custom_types
            if any(p in t.get("name", "").lower() for p in debug_patterns)
        ]

        if debug_types:
            findings.append(GraphQLFinding(
                vulnerability="Debug/Internal Types Exposed",
                severity="medium",
                description=f"{len(debug_types)} potentially debug/internal types found",
                evidence=f"Types: {', '.join([t.get('name') for t in debug_types])}",
                remediation="Remove debug types from production schema",
                endpoint=self.endpoint,
                cwe="CWE-489"
            ))

        # Test 3: Check for overly permissive input types
        for type_def in custom_types:
            if type_def.get("kind") == "INPUT_OBJECT":
                input_fields = type_def.get("inputFields", []) or []
                # Check for JSON scalar (accepts anything)
                for field_def in input_fields:
                    field_type = field_def.get("type", {})
                    type_name = field_type.get("name", "") or ""
                    if type_name.lower() in ["json", "jsonobject", "any", "object", "map"]:
                        findings.append(GraphQLFinding(
                            vulnerability="Overly Permissive Input Type",
                            severity="medium",
                            description=f"Input type {type_def.get('name')} has untyped JSON/Any field",
                            evidence=f"Field {field_def.get('name')} accepts arbitrary JSON",
                            remediation="Use strongly-typed input objects instead of JSON/Any types",
                            endpoint=self.endpoint,
                            cwe="CWE-20"
                        ))
                        break

        # Test 4: Check for dangerous union/interface patterns
        for type_def in custom_types:
            if type_def.get("kind") in ["UNION", "INTERFACE"]:
                possible_types = type_def.get("possibleTypes", []) or []
                type_names = [pt.get("name", "").lower() for pt in possible_types]

                # Check if union mixes user types with admin types
                has_user = any("user" in n for n in type_names)
                has_admin = any("admin" in n for n in type_names)

                if has_user and has_admin:
                    findings.append(GraphQLFinding(
                        vulnerability="Mixed Privilege Types in Union",
                        severity="low",
                        description=f"Union {type_def.get('name')} mixes user and admin types",
                        evidence=f"Types: {', '.join([pt.get('name') for pt in possible_types])}",
                        remediation="Separate user and admin types into different unions",
                        endpoint=self.endpoint,
                        cwe="CWE-269"
                    ))

        # Test 5: Estimate schema complexity
        total_fields = sum(
            len(t.get("fields", []) or []) for t in custom_types
        )
        total_args = sum(
            sum(len(f.get("args", []) or []) for f in t.get("fields", []) or [])
            for t in custom_types
        )

        if total_fields > 500 or total_args > 1000:
            findings.append(GraphQLFinding(
                vulnerability="Large Attack Surface",
                severity="info",
                description=f"Schema has {total_fields} fields and {total_args} arguments",
                evidence="Large schemas increase attack surface and maintenance burden",
                remediation="Consider schema pruning and removing unused fields",
                endpoint=self.endpoint,
                cwe="CWE-1104"
            ))

        return findings

    async def scan(self) -> GraphQLScanResult:
        """
        Run full GraphQL security scan.

        Returns:
            GraphQLScanResult with all findings
        """
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = current_time()

        findings = []
        tests_run = 0

        # Run enabled tests - Basic tests
        if self.config.test_introspection:
            findings.extend(await self.test_introspection())
            tests_run += 1

        if self.config.test_depth_attack:
            findings.extend(await self.test_depth_attack())
            tests_run += 1

        if self.config.test_batch_attack:
            findings.extend(await self.test_batch_attack())
            tests_run += 1

        if self.config.test_field_suggestions:
            findings.extend(await self.test_field_suggestions())
            tests_run += 1

        if self.config.test_injection:
            findings.extend(await self.test_injection())
            tests_run += 1

        # Authorization bypass test
        findings.extend(await self.test_authorization_bypass())
        tests_run += 1

        # Enhanced tests (v4.0)
        if self.config.test_mutations:
            findings.extend(await self.test_mutation_security())
            tests_run += 1

        if self.config.test_subscriptions:
            findings.extend(await self.test_subscription_security())
            tests_run += 1

        if self.config.test_complexity:
            findings.extend(await self.test_query_complexity())
            tests_run += 1

        if self.config.test_field_authorization:
            findings.extend(await self.test_field_level_authorization())
            tests_run += 1

        if self.config.test_schema_security:
            findings.extend(await self.test_schema_security())
            tests_run += 1

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = current_time() - start_time

        # Build schema info summary
        schema_info = {}
        if self.schema:
            types = self.schema.get("types", [])
            custom_types = [t for t in types if not t.get("name", "").startswith("__")]

            # Count mutations and subscriptions
            mutation_count = 0
            subscription_count = 0

            mutation_type = self.schema.get("mutationType", {})
            if mutation_type:
                for t in types:
                    if t.get("name") == mutation_type.get("name"):
                        mutation_count = len(t.get("fields", []) or [])
                        break

            subscription_type = self.schema.get("subscriptionType", {})
            if subscription_type:
                for t in types:
                    if t.get("name") == subscription_type.get("name"):
                        subscription_count = len(t.get("fields", []) or [])
                        break

            schema_info = {
                "total_types": len(types),
                "query_type": self.schema.get("queryType", {}).get("name"),
                "mutation_type": self.schema.get("mutationType", {}).get("name"),
                "mutation_count": mutation_count,
                "subscription_type": self.schema.get("subscriptionType", {}).get("name"),
                "subscription_count": subscription_count,
                "custom_types": len(custom_types),
                "total_fields": sum(len(t.get("fields", []) or []) for t in custom_types),
                "deprecated_fields": sum(
                    1 for t in custom_types
                    for f in (t.get("fields", []) or [])
                    if f.get("isDeprecated")
                )
            }

        # Deduplicate findings by vulnerability name
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f.vulnerability, f.severity)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return GraphQLScanResult(
            endpoint=self.endpoint,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            findings=unique_findings,
            schema_info=schema_info,
            metadata={
                "tests_run": tests_run,
                "scanner_version": "4.0",
                "enhanced_tests": {
                    "mutations": self.config.test_mutations,
                    "subscriptions": self.config.test_subscriptions,
                    "complexity": self.config.test_complexity,
                    "field_authorization": self.config.test_field_authorization,
                    "schema_security": self.config.test_schema_security
                }
            }
        )


# Convenience function
async def scan_graphql(
    endpoint: str,
    auth_token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    full_scan: bool = True,
    enhanced_tests: bool = True
) -> GraphQLScanResult:
    """
    Quick GraphQL security scan.

    Args:
        endpoint: GraphQL endpoint URL
        auth_token: Bearer token for authentication
        headers: Additional headers
        full_scan: Run all tests if True
        enhanced_tests: Run v4.0 enhanced tests (mutations, subscriptions, complexity)

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
        test_injection=full_scan,
        # Enhanced v4.0 tests
        test_mutations=enhanced_tests,
        test_subscriptions=enhanced_tests,
        test_complexity=enhanced_tests,
        test_field_authorization=enhanced_tests,
        test_schema_security=enhanced_tests
    )

    scanner = GraphQLScanner(endpoint, config)
    return await scanner.scan()


# Schema security analysis helper
def analyze_graphql_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a GraphQL schema for security concerns.

    Args:
        schema: Parsed GraphQL schema (from introspection)

    Returns:
        Analysis results with security recommendations
    """
    analysis = {
        "summary": {},
        "concerns": [],
        "recommendations": []
    }

    types = schema.get("types", [])
    custom_types = [t for t in types if not t.get("name", "").startswith("__")]

    # Summary
    analysis["summary"] = {
        "total_types": len(custom_types),
        "queries": 0,
        "mutations": 0,
        "subscriptions": 0,
        "input_types": len([t for t in custom_types if t.get("kind") == "INPUT_OBJECT"]),
        "enums": len([t for t in custom_types if t.get("kind") == "ENUM"]),
    }

    # Count operations
    for type_name in ["Query", "Mutation", "Subscription"]:
        for t in custom_types:
            if t.get("name") == type_name:
                count = len(t.get("fields", []) or [])
                if type_name == "Query":
                    analysis["summary"]["queries"] = count
                elif type_name == "Mutation":
                    analysis["summary"]["mutations"] = count
                else:
                    analysis["summary"]["subscriptions"] = count

    # Check for concerns
    sensitive_patterns = ["password", "secret", "token", "key", "ssn", "credit"]
    for t in custom_types:
        for f in t.get("fields", []) or []:
            name = f.get("name", "").lower()
            if any(p in name for p in sensitive_patterns):
                analysis["concerns"].append({
                    "type": "sensitive_field",
                    "location": f"{t.get('name')}.{f.get('name')}",
                    "severity": "high"
                })

    # Recommendations
    if analysis["summary"]["mutations"] > 0:
        analysis["recommendations"].append(
            "Ensure all mutations require authentication"
        )
    if analysis["summary"]["subscriptions"] > 0:
        analysis["recommendations"].append(
            "Implement subscription-level authorization and rate limiting"
        )
    if len(analysis["concerns"]) > 0:
        analysis["recommendations"].append(
            "Review and restrict access to sensitive fields"
        )

    return analysis
