"""
AIPT API Security Module - Comprehensive API Vulnerability Scanning

Provides security testing for modern API architectures:
- REST APIs (OpenAPI/Swagger fuzzing)
- GraphQL APIs (Introspection, DoS, Injection)
- JWT Tokens (Algorithm confusion, signature bypass)
- API Discovery (Endpoint enumeration, documentation detection)

Usage:
    from aipt_v2.tools.api_security import (
        GraphQLScanner,
        OpenAPIFuzzer,
        JWTAnalyzer,
        APIDiscovery
    )

    # Scan GraphQL endpoint
    scanner = GraphQLScanner("https://api.target.com/graphql")
    findings = await scanner.scan()

    # Fuzz REST API from OpenAPI spec
    fuzzer = OpenAPIFuzzer("https://api.target.com", spec_path="openapi.yaml")
    findings = await fuzzer.fuzz()

    # Analyze JWT token
    analyzer = JWTAnalyzer()
    findings = analyzer.analyze(token)
"""

from aipt_v2.tools.api_security.graphql_scanner import (
    GraphQLScanner,
    GraphQLConfig,
    GraphQLFinding,
    scan_graphql,
)

from aipt_v2.tools.api_security.openapi_fuzzer import (
    OpenAPIFuzzer,
    OpenAPIConfig,
    OpenAPIFinding,
    fuzz_openapi,
)

from aipt_v2.tools.api_security.jwt_analyzer import (
    JWTAnalyzer,
    JWTFinding,
    analyze_jwt,
)

from aipt_v2.tools.api_security.api_discovery import (
    APIDiscovery,
    DiscoveredEndpoint,
    discover_api,
)

__all__ = [
    # GraphQL
    "GraphQLScanner",
    "GraphQLConfig",
    "GraphQLFinding",
    "scan_graphql",
    # OpenAPI
    "OpenAPIFuzzer",
    "OpenAPIConfig",
    "OpenAPIFinding",
    "fuzz_openapi",
    # JWT
    "JWTAnalyzer",
    "JWTFinding",
    "analyze_jwt",
    # Discovery
    "APIDiscovery",
    "DiscoveredEndpoint",
    "discover_api",
]
