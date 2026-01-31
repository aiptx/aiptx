"""
Access Control Test Patterns

Tests for horizontal/vertical privilege escalation, IDOR,
and authorization bypass vulnerabilities.
"""

from aipt_v2.business_logic.patterns.base import (
    TestPattern,
    TestCase,
    PatternCategory,
    TestSeverity,
)


ACCESS_CONTROL_PATTERNS = [
    TestPattern(
        id="IDOR-001",
        name="Horizontal Privilege Escalation (IDOR)",
        description="Access other users' resources by manipulating ID parameters",
        category=PatternCategory.ACCESS_CONTROL,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-639", "CWE-284"],
        owasp_category="A01:2021 - Broken Access Control",
        remediation="Implement proper authorization checks, verify resource ownership server-side",
        endpoint_patterns=[
            r"/user", r"/profile", r"/account", r"/document", r"/file",
            r"/order", r"/invoice", r"/message"
        ],
        applicable_to=["multi-tenant", "user-data"],
        test_cases=[
            TestCase(
                name="User ID Enumeration",
                description="Access other users' profiles by changing ID",
                method="GET",
                endpoint_pattern=r"/user/\d+|/profile/\d+",
                body_template={},
                manipulation={"id": ["1", "2", "3", "100", "admin"]},
                success_indicators=["email", "profile", "name"],
                failure_indicators=["forbidden", "unauthorized", "not found"]
            ),
            TestCase(
                name="Document Access",
                description="Access other users' documents",
                method="GET",
                endpoint_pattern=r"/document/|/file/|/attachment/",
                manipulation={"document_id": ["1", "2", "3", "1000"]},
                success_indicators=["content", "download"],
                failure_indicators=["forbidden", "unauthorized"]
            ),
            TestCase(
                name="Order Details Access",
                description="View other users' order details",
                method="GET",
                endpoint_pattern=r"/order/\d+",
                manipulation={"order_id": ["1", "2", "1000", "99999"]},
                success_indicators=["items", "total", "shipping"],
                failure_indicators=["forbidden", "not found"]
            )
        ]
    ),

    TestPattern(
        id="IDOR-002",
        name="IDOR in Modifications",
        description="Modify other users' resources through ID manipulation",
        category=PatternCategory.ACCESS_CONTROL,
        severity=TestSeverity.CRITICAL,
        cwe_ids=["CWE-639", "CWE-284"],
        owasp_category="A01:2021 - Broken Access Control",
        remediation="Check ownership before any modification operation",
        endpoint_patterns=[
            r"/user", r"/profile", r"/settings", r"/update"
        ],
        applicable_to=["multi-tenant"],
        test_cases=[
            TestCase(
                name="Update Other Profile",
                description="Update another user's profile",
                method="PUT",
                endpoint_pattern=r"/user/|/profile/",
                body_template={"user_id": "{{other_user_id}}", "email": "attacker@test.com"},
                success_indicators=["updated", "success"],
                failure_indicators=["forbidden", "unauthorized"]
            ),
            TestCase(
                name="Delete Other Resource",
                description="Delete another user's resource",
                method="DELETE",
                endpoint_pattern=r"/user/|/document/|/post/",
                manipulation={"id": ["1", "2", "100"]},
                success_indicators=["deleted", "success"],
                failure_indicators=["forbidden", "unauthorized"]
            )
        ]
    ),

    TestPattern(
        id="PRIV-001",
        name="Vertical Privilege Escalation",
        description="Escalate privileges by manipulating role/permission parameters",
        category=PatternCategory.ACCESS_CONTROL,
        severity=TestSeverity.CRITICAL,
        cwe_ids=["CWE-269", "CWE-266"],
        owasp_category="A01:2021 - Broken Access Control",
        remediation="Never trust client-provided role/permission data, validate server-side",
        endpoint_patterns=[
            r"/user", r"/admin", r"/role", r"/permission"
        ],
        applicable_to=["role-based"],
        test_cases=[
            TestCase(
                name="Role Parameter Injection",
                description="Set role to admin in request",
                method="POST",
                body_template={"username": "test", "role": "admin"},
                manipulation={"role": ["admin", "administrator", "superuser", "root"]},
                success_indicators=["admin", "elevated"],
                failure_indicators=["denied", "insufficient"]
            ),
            TestCase(
                name="Permission Flag Manipulation",
                description="Enable admin permissions through flags",
                method="PUT",
                body_template={"is_admin": True, "is_superuser": True},
                manipulation={"is_admin": [True, 1, "true"]},
                success_indicators=["updated"],
                failure_indicators=["denied", "cannot modify"]
            ),
            TestCase(
                name="Admin Endpoint Access",
                description="Access admin endpoints as regular user",
                method="GET",
                endpoint_pattern=r"/admin",
                success_indicators=["dashboard", "users", "settings"],
                failure_indicators=["forbidden", "unauthorized", "login"]
            )
        ]
    ),

    TestPattern(
        id="AUTH-001",
        name="Function-Level Access Control",
        description="Access administrative functions without proper authorization",
        category=PatternCategory.ACCESS_CONTROL,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-285"],
        owasp_category="A01:2021 - Broken Access Control",
        remediation="Implement consistent authorization checks for all sensitive functions",
        endpoint_patterns=[
            r"/admin", r"/manage", r"/config", r"/system"
        ],
        applicable_to=["admin-functions"],
        test_cases=[
            TestCase(
                name="Admin Function Access",
                description="Call administrative functions",
                method="POST",
                endpoint_pattern=r"/admin/|/manage/",
                body_template={"action": "{{admin_action}}"},
                manipulation={"action": ["create_user", "delete_user", "export_data", "change_config"]},
                success_indicators=["success", "completed"],
                failure_indicators=["forbidden", "admin required"]
            ),
            TestCase(
                name="Mass Data Export",
                description="Export all user data without authorization",
                method="GET",
                endpoint_pattern=r"/export|/download.*all|/backup",
                success_indicators=["csv", "json", "xml", "download"],
                failure_indicators=["forbidden", "unauthorized"]
            )
        ]
    ),

    TestPattern(
        id="AUTH-002",
        name="Insecure Direct Object References in APIs",
        description="IDOR vulnerabilities in REST API endpoints",
        category=PatternCategory.ACCESS_CONTROL,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-639"],
        owasp_category="A01:2021 - Broken Access Control",
        remediation="Use indirect references or verify authorization for each request",
        endpoint_patterns=[
            r"/api/", r"/v1/", r"/v2/"
        ],
        applicable_to=["api"],
        test_cases=[
            TestCase(
                name="API Resource Enumeration",
                description="Enumerate resources through API",
                method="GET",
                endpoint_pattern=r"/api/.*/\d+",
                manipulation={"id": ["1", "2", "10", "100", "1000"]},
                success_indicators=["data", "id"],
                failure_indicators=["forbidden", "not found"]
            ),
            TestCase(
                name="Batch API Access",
                description="Access multiple records through batch endpoint",
                method="POST",
                endpoint_pattern=r"/api/batch|/api/bulk",
                body_template={"ids": [1, 2, 3, 100, 1000]},
                success_indicators=["results"],
                failure_indicators=["partial", "forbidden"]
            )
        ]
    ),

    TestPattern(
        id="AUTH-003",
        name="JWT/Token Manipulation",
        description="Manipulate JWT claims to escalate privileges",
        category=PatternCategory.ACCESS_CONTROL,
        severity=TestSeverity.CRITICAL,
        cwe_ids=["CWE-287", "CWE-345"],
        owasp_category="A07:2021 - Identification and Authentication Failures",
        remediation="Validate JWT signatures properly, use strong algorithms, don't trust client claims",
        endpoint_patterns=[
            r"/api/", r"/protected/"
        ],
        applicable_to=["jwt-auth"],
        test_cases=[
            TestCase(
                name="Algorithm None Attack",
                description="Set JWT algorithm to 'none'",
                method="GET",
                headers={"Authorization": "Bearer {{tampered_jwt}}"},
                success_indicators=["data"],
                failure_indicators=["invalid token", "unauthorized"]
            ),
            TestCase(
                name="Role Claim Manipulation",
                description="Modify role claim in JWT",
                method="GET",
                headers={"Authorization": "Bearer {{modified_jwt}}"},
                success_indicators=["admin", "elevated"],
                failure_indicators=["invalid signature"]
            )
        ]
    ),
]
