"""
API Security Testing Playbooks.

Specialized playbooks for testing REST APIs, GraphQL endpoints,
and microservices architectures.
"""

from .base_playbook import BasePlaybook, Phase, PlaybookMode


class APIPlaybook(BasePlaybook):
    """
    Comprehensive API security testing playbook.

    Covers OWASP API Security Top 10 and common API vulnerabilities.
    """

    name = "api"
    description = "API Security Testing (REST, GraphQL, gRPC)"
    mode = PlaybookMode.ADAPTIVE
    target_type = "api"
    estimated_duration = 5400  # 1.5 hours

    phases = [
        # Phase 1: API Reconnaissance
        Phase(
            name="API Reconnaissance",
            objective="Discover and document API structure and capabilities",
            techniques=[
                "Locate and parse OpenAPI/Swagger specifications",
                "Discover undocumented endpoints via fuzzing",
                "Identify API versioning (v1, v2, etc.)",
                "Map all HTTP methods accepted per endpoint",
                "Identify response formats and error patterns",
                "Discover rate limiting and throttling mechanisms",
                "Identify WebSocket and Server-Sent Events endpoints",
            ],
            required_tools=["httpx", "ffuf", "kiterunner"],
            mitre_techniques=["T1595.002", "T1592.002"],
            timeout=600,
            parallel_safe=True,
        ),
        # Phase 2: Authentication & Authorization
        Phase(
            name="API Authentication",
            objective="Test authentication mechanisms and token handling",
            techniques=[
                "Test for missing authentication on endpoints",
                "Analyze JWT implementation (algorithm confusion, weak secrets)",
                "Test OAuth 2.0 flows for misconfigurations",
                "Test API key handling and rotation",
                "Test for session token prediction",
                "Test token refresh mechanism abuse",
                "Test for authentication bypass via HTTP method override",
            ],
            required_tools=["jwt_tool", "burp", "postman"],
            mitre_techniques=["T1078", "T1550"],
            timeout=600,
            depends_on=["API Reconnaissance"],
        ),
        # Phase 3: Authorization (BOLA/BFLA)
        Phase(
            name="API Authorization",
            objective="Test for broken object and function level authorization",
            techniques=[
                "Test BOLA (Broken Object Level Authorization) - IDOR",
                "Test BFLA (Broken Function Level Authorization)",
                "Test for privilege escalation via role manipulation",
                "Test for horizontal access control bypass",
                "Test for vertical access control bypass",
                "Test admin endpoint exposure to regular users",
                "Test for mass assignment vulnerabilities",
            ],
            required_tools=["burp", "autorize"],
            mitre_techniques=["T1068", "T1548"],
            timeout=900,
            depends_on=["API Authentication"],
        ),
        # Phase 4: Injection Attacks
        Phase(
            name="API Injection",
            objective="Test for injection vulnerabilities in API inputs",
            techniques=[
                "Test SQL injection in query/path/body parameters",
                "Test NoSQL injection (MongoDB, CouchDB)",
                "Test for command injection via API parameters",
                "Test LDAP injection in user lookup endpoints",
                "Test for Server-Side Request Forgery (SSRF)",
                "Test XML injection and XXE if XML accepted",
                "Test for code injection in eval-like endpoints",
            ],
            required_tools=["sqlmap", "nuclei", "commix"],
            mitre_techniques=["T1190", "T1059"],
            timeout=900,
            depends_on=["API Reconnaissance"],
        ),
        # Phase 5: Data Exposure
        Phase(
            name="API Data Exposure",
            objective="Identify excessive data exposure and sensitive data handling",
            techniques=[
                "Test for excessive data exposure in responses",
                "Check for sensitive data in error messages",
                "Test for PII exposure without proper filtering",
                "Analyze response filtering effectiveness",
                "Test for debug information leakage",
                "Check for sensitive data in logs (via verbose mode)",
                "Test pagination for data enumeration",
            ],
            required_tools=["burp"],
            mitre_techniques=["T1552", "T1530"],
            timeout=600,
            depends_on=["API Authorization"],
        ),
        # Phase 6: Resource & Rate Limiting
        Phase(
            name="API Resources",
            objective="Test rate limiting and resource consumption controls",
            techniques=[
                "Test rate limiting implementation",
                "Test for resource exhaustion via large payloads",
                "Test GraphQL query complexity limits",
                "Test batch endpoint abuse",
                "Test file upload size limits",
                "Test pagination limits (large page sizes)",
                "Test for DoS via expensive operations",
            ],
            required_tools=["nuclei", "turbo-intruder"],
            mitre_techniques=["T1499"],
            timeout=600,
            depends_on=["API Reconnaissance"],
            parallel_safe=True,
        ),
        # Phase 7: Business Logic
        Phase(
            name="API Business Logic",
            objective="Test for business logic flaws specific to API operations",
            techniques=[
                "Test multi-step operations for bypass",
                "Test for race conditions in concurrent requests",
                "Test idempotency violations",
                "Test for replay attacks on sensitive operations",
                "Test state manipulation between requests",
                "Test webhook security and SSRF via callbacks",
                "Test for mass assignment in resource creation",
            ],
            required_tools=["burp", "turbo-intruder"],
            mitre_techniques=["T1068"],
            timeout=600,
            depends_on=["API Authorization"],
        ),
    ]


class GraphQLPlaybook(BasePlaybook):
    """
    Specialized playbook for GraphQL API testing.

    Covers GraphQL-specific vulnerabilities and attack vectors.
    """

    name = "graphql"
    description = "GraphQL API Security Testing"
    mode = PlaybookMode.SEQUENTIAL
    target_type = "graphql"
    estimated_duration = 2700  # 45 minutes

    phases = [
        Phase(
            name="GraphQL Discovery",
            objective="Discover and analyze GraphQL schema",
            techniques=[
                "Locate GraphQL endpoint (common paths: /graphql, /api/graphql)",
                "Test introspection query availability",
                "Extract full schema via introspection",
                "Identify queries, mutations, and subscriptions",
                "Map custom scalars and types",
                "Analyze field descriptions for sensitive info",
            ],
            required_tools=["graphql-cop", "inql", "graphqlmap"],
            mitre_techniques=["T1595.002"],
            timeout=300,
        ),
        Phase(
            name="GraphQL Authorization",
            objective="Test authorization in GraphQL operations",
            techniques=[
                "Test for unauthorized query/mutation access",
                "Test field-level authorization",
                "Test for IDOR via GraphQL ID parameters",
                "Test nested query authorization bypass",
                "Test subscription authorization",
                "Test for horizontal/vertical privilege escalation",
            ],
            required_tools=["inql", "burp"],
            mitre_techniques=["T1068"],
            timeout=600,
            depends_on=["GraphQL Discovery"],
        ),
        Phase(
            name="GraphQL Injection",
            objective="Test for injection vulnerabilities in GraphQL",
            techniques=[
                "Test SQL injection through GraphQL arguments",
                "Test for NoSQL injection in resolvers",
                "Test for SSRF via URL-type fields",
                "Test for command injection in custom scalars",
                "Test batch query injection",
            ],
            required_tools=["graphqlmap", "sqlmap"],
            mitre_techniques=["T1190"],
            timeout=600,
            depends_on=["GraphQL Discovery"],
        ),
        Phase(
            name="GraphQL DoS",
            objective="Test for denial of service vulnerabilities",
            techniques=[
                "Test deeply nested query attacks",
                "Test query complexity attacks",
                "Test alias-based attacks",
                "Test field duplication attacks",
                "Test circular fragment attacks",
                "Test batch query limits",
            ],
            required_tools=["graphql-cop"],
            mitre_techniques=["T1499"],
            timeout=300,
            depends_on=["GraphQL Discovery"],
        ),
    ]
