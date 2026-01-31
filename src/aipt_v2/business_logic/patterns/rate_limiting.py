"""
Rate Limiting Test Patterns

Tests for rate limit bypasses, brute force vulnerabilities,
and DoS prevention mechanisms.
"""

from aipt_v2.business_logic.patterns.base import (
    TestPattern,
    TestCase,
    PatternCategory,
    TestSeverity,
)


RATE_LIMIT_PATTERNS = [
    TestPattern(
        id="RATE-001",
        name="Rate Limit Header Bypass",
        description="Bypass rate limiting by manipulating IP-related headers",
        category=PatternCategory.RATE_LIMITING,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-307", "CWE-770"],
        owasp_category="Security Misconfiguration",
        remediation="Validate X-Forwarded-For and similar headers, use multiple rate limit keys",
        endpoint_patterns=[
            r"/login", r"/api/", r"/search", r"/submit"
        ],
        applicable_to=["authentication", "api"],
        test_cases=[
            TestCase(
                name="X-Forwarded-For Bypass",
                description="Rotate X-Forwarded-For header to bypass IP-based rate limiting",
                method="POST",
                headers={"X-Forwarded-For": "{{random_ip}}"},
                body_template={"username": "test", "password": "test"},
                success_indicators=["attempt"],
                failure_indicators=["rate limit"]
            ),
            TestCase(
                name="X-Real-IP Bypass",
                description="Use X-Real-IP header to bypass rate limiting",
                method="POST",
                headers={"X-Real-IP": "{{random_ip}}"},
                success_indicators=["attempt"],
                failure_indicators=["too many requests"]
            ),
            TestCase(
                name="Client-IP Bypass",
                description="Use Client-IP header for bypass",
                method="POST",
                headers={
                    "X-Forwarded-For": "{{random_ip}}",
                    "X-Real-IP": "{{random_ip_2}}",
                    "X-Client-IP": "{{random_ip_3}}",
                    "CF-Connecting-IP": "{{random_ip_4}}"
                },
                success_indicators=["response"],
                failure_indicators=["rate limit", "429"]
            )
        ]
    ),

    TestPattern(
        id="RATE-002",
        name="Account Lockout Bypass",
        description="Bypass account lockout mechanisms",
        category=PatternCategory.RATE_LIMITING,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-307"],
        owasp_category="A07:2021 - Identification and Authentication Failures",
        remediation="Implement robust lockout with exponential backoff, don't reset on valid username",
        endpoint_patterns=[
            r"/login", r"/signin", r"/auth"
        ],
        applicable_to=["authentication"],
        test_cases=[
            TestCase(
                name="Username Variation",
                description="Bypass lockout with username variations",
                method="POST",
                body_template={"username": "{{username_variation}}", "password": "test"},
                manipulation={"username": ["user", "User", "USER", "user ", " user", "user@domain.com"]},
                success_indicators=["invalid password"],
                failure_indicators=["locked", "try again"]
            ),
            TestCase(
                name="Case Sensitivity Bypass",
                description="Test if lockout is case-sensitive",
                method="POST",
                body_template={"username": "ADMIN", "password": "{{password}}"},
                success_indicators=["invalid"],
                failure_indicators=["locked"]
            ),
            TestCase(
                name="Lockout Reset via Valid Login",
                description="Check if failed attempts reset after successful login",
                method="POST",
                body_template={"username": "test", "password": "correct"},
                setup_steps=["Make 4 failed attempts", "Make 1 successful attempt", "Make more failed attempts"],
                success_indicators=["attempt"],
                failure_indicators=["locked"]
            )
        ]
    ),

    TestPattern(
        id="RATE-003",
        name="Password Reset Rate Limiting",
        description="Test rate limiting on password reset functionality",
        category=PatternCategory.RATE_LIMITING,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-307", "CWE-640"],
        owasp_category="A07:2021 - Identification and Authentication Failures",
        remediation="Rate limit by IP and account, implement CAPTCHA after threshold",
        endpoint_patterns=[
            r"/reset", r"/forgot", r"/recover"
        ],
        applicable_to=["authentication"],
        test_cases=[
            TestCase(
                name="Email Enumeration via Reset",
                description="Enumerate valid emails through reset responses",
                method="POST",
                endpoint_pattern=r"/forgot.*password|password.*reset",
                body_template={"email": "{{email}}"},
                manipulation={"email": ["admin@test.com", "user@test.com", "test@test.com"]},
                success_indicators=["sent", "email"],
                failure_indicators=["not found", "invalid"]
            ),
            TestCase(
                name="Reset Flood",
                description="Send many reset requests to flood inbox",
                method="POST",
                body_template={"email": "target@test.com"},
                concurrent_requests=20,
                success_indicators=["sent"],
                failure_indicators=["rate limit", "try again"]
            )
        ]
    ),

    TestPattern(
        id="RATE-004",
        name="API Rate Limit Bypass",
        description="Bypass API rate limits through various techniques",
        category=PatternCategory.RATE_LIMITING,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-770"],
        owasp_category="Security Misconfiguration",
        remediation="Implement multi-factor rate limiting, use sliding windows",
        endpoint_patterns=[
            r"/api/"
        ],
        applicable_to=["api"],
        test_cases=[
            TestCase(
                name="Endpoint Variation",
                description="Access same resource through URL variations",
                method="GET",
                manipulation={"path": [
                    "/api/users/1",
                    "/api/users/1/",
                    "/api/users/1?",
                    "/api/users/1?_=1",
                    "/api/Users/1",
                    "/api/./users/1"
                ]},
                success_indicators=["data"],
                failure_indicators=["rate limit"]
            ),
            TestCase(
                name="HTTP Method Variation",
                description="Try different HTTP methods for same endpoint",
                method="GET",
                manipulation={"method": ["GET", "HEAD", "OPTIONS"]},
                success_indicators=["response"],
                failure_indicators=["rate limit"]
            ),
            TestCase(
                name="Parameter Pollution",
                description="Bypass rate limit with duplicate parameters",
                method="GET",
                body_template={"id": ["1", "1"]},
                success_indicators=["data"],
                failure_indicators=["rate limit"]
            )
        ]
    ),

    TestPattern(
        id="RATE-005",
        name="OTP/2FA Brute Force",
        description="Brute force OTP or 2FA codes",
        category=PatternCategory.RATE_LIMITING,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-307", "CWE-287"],
        owasp_category="A07:2021 - Identification and Authentication Failures",
        remediation="Limit OTP attempts, implement exponential backoff, invalidate after threshold",
        endpoint_patterns=[
            r"/verify", r"/otp", r"/2fa", r"/mfa", r"/code"
        ],
        applicable_to=["authentication", "2fa"],
        test_cases=[
            TestCase(
                name="OTP Brute Force",
                description="Attempt to brute force 6-digit OTP",
                method="POST",
                endpoint_pattern=r"/verify.*otp|otp.*verify",
                body_template={"otp": "{{otp_code}}"},
                manipulation={"otp": ["000000", "123456", "111111", "000001"]},
                success_indicators=["verified", "success"],
                failure_indicators=["invalid", "locked", "expired"]
            ),
            TestCase(
                name="OTP Reuse",
                description="Test if OTP can be reused",
                method="POST",
                body_template={"otp": "{{valid_otp}}"},
                setup_steps=["Use valid OTP once", "Try same OTP again"],
                success_indicators=["verified"],
                failure_indicators=["already used", "invalid"]
            )
        ]
    ),

    TestPattern(
        id="RATE-006",
        name="Search/Query Rate Limiting",
        description="Test rate limits on search and data query endpoints",
        category=PatternCategory.RATE_LIMITING,
        severity=TestSeverity.LOW,
        cwe_ids=["CWE-770", "CWE-400"],
        owasp_category="Security Misconfiguration",
        remediation="Implement search rate limits, add CAPTCHA for excessive searches",
        endpoint_patterns=[
            r"/search", r"/query", r"/find", r"/lookup"
        ],
        applicable_to=["search"],
        test_cases=[
            TestCase(
                name="Search Scraping",
                description="Rapid search requests to scrape data",
                method="GET",
                endpoint_pattern=r"/search",
                body_template={"q": "{{search_term}}"},
                concurrent_requests=50,
                success_indicators=["results"],
                failure_indicators=["rate limit", "captcha"]
            ),
            TestCase(
                name="Wildcard Search Abuse",
                description="Use wildcard searches to dump data",
                method="GET",
                body_template={"q": "*"},
                manipulation={"q": ["*", "a*", "b*", "%", "_"]},
                success_indicators=["results"],
                failure_indicators=["not allowed", "specific"]
            )
        ]
    ),
]
