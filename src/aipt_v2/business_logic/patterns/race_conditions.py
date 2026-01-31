"""
Race Condition Test Patterns

Tests for TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities,
double-spending, and concurrent operation issues.
"""

from aipt_v2.business_logic.patterns.base import (
    TestPattern,
    TestCase,
    PatternCategory,
    TestSeverity,
)


RACE_CONDITION_PATTERNS = [
    TestPattern(
        id="RACE-001",
        name="Double-Spend Attack",
        description="Test for double-spending by sending concurrent payment/withdrawal requests",
        category=PatternCategory.RACE_CONDITION,
        severity=TestSeverity.CRITICAL,
        cwe_ids=["CWE-362", "CWE-367"],
        owasp_category="Business Logic Errors",
        remediation="Implement proper transaction locking, use database transactions with appropriate isolation levels, implement idempotency keys",
        endpoint_patterns=[
            r"/payment", r"/transfer", r"/withdraw", r"/checkout",
            r"/purchase", r"/order", r"/transaction"
        ],
        applicable_to=["e-commerce", "banking", "payment"],
        test_cases=[
            TestCase(
                name="Concurrent Withdrawal",
                description="Send multiple withdrawal requests simultaneously",
                method="POST",
                endpoint_pattern=r"/(withdraw|transfer|payment)",
                body_template={"amount": 100, "account": "{{account_id}}"},
                concurrent_requests=10,
                success_indicators=["success", "completed", "approved"],
                failure_indicators=["insufficient", "balance", "failed"]
            ),
            TestCase(
                name="Concurrent Order Placement",
                description="Place multiple orders for limited stock item",
                method="POST",
                endpoint_pattern=r"/(order|checkout|purchase)",
                body_template={"item_id": "{{item_id}}", "quantity": 1},
                concurrent_requests=5,
                success_indicators=["order_id", "confirmed"],
                failure_indicators=["out_of_stock", "unavailable"]
            )
        ]
    ),

    TestPattern(
        id="RACE-002",
        name="Coupon Race Condition",
        description="Apply same single-use coupon multiple times via concurrent requests",
        category=PatternCategory.RACE_CONDITION,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-362"],
        owasp_category="Business Logic Errors",
        remediation="Implement coupon redemption with database locks, use atomic operations",
        endpoint_patterns=[
            r"/coupon", r"/promo", r"/discount", r"/voucher", r"/redeem"
        ],
        applicable_to=["e-commerce", "marketing"],
        test_cases=[
            TestCase(
                name="Concurrent Coupon Application",
                description="Apply single-use coupon to multiple carts simultaneously",
                method="POST",
                endpoint_pattern=r"/(apply.*coupon|redeem|promo)",
                body_template={"code": "{{coupon_code}}", "cart_id": "{{cart_id}}"},
                concurrent_requests=5,
                success_indicators=["applied", "discount", "success"],
                failure_indicators=["already_used", "invalid", "expired"]
            )
        ]
    ),

    TestPattern(
        id="RACE-003",
        name="Bonus/Reward Race",
        description="Claim signup bonus or reward multiple times",
        category=PatternCategory.RACE_CONDITION,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-362", "CWE-367"],
        owasp_category="Business Logic Errors",
        remediation="Use atomic claim operations, implement proper state management",
        endpoint_patterns=[
            r"/bonus", r"/reward", r"/claim", r"/redeem", r"/spin"
        ],
        applicable_to=["gaming", "loyalty", "marketing"],
        test_cases=[
            TestCase(
                name="Concurrent Bonus Claim",
                description="Claim one-time bonus through concurrent requests",
                method="POST",
                endpoint_pattern=r"/(claim|redeem|bonus)",
                body_template={"reward_id": "{{reward_id}}"},
                concurrent_requests=10,
                success_indicators=["claimed", "credited", "success"],
                failure_indicators=["already_claimed", "not_eligible"]
            )
        ]
    ),

    TestPattern(
        id="RACE-004",
        name="Vote/Like Race Condition",
        description="Submit multiple votes or likes bypassing single-vote restriction",
        category=PatternCategory.RACE_CONDITION,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-362"],
        owasp_category="Business Logic Errors",
        remediation="Use unique constraints and atomic operations for vote tracking",
        endpoint_patterns=[
            r"/vote", r"/like", r"/upvote", r"/rate"
        ],
        applicable_to=["social", "voting", "content"],
        test_cases=[
            TestCase(
                name="Concurrent Votes",
                description="Submit multiple votes simultaneously",
                method="POST",
                endpoint_pattern=r"/(vote|like|upvote)",
                body_template={"target_id": "{{target_id}}", "direction": "up"},
                concurrent_requests=5,
                success_indicators=["voted", "success"],
                failure_indicators=["already_voted", "duplicate"]
            )
        ]
    ),

    TestPattern(
        id="RACE-005",
        name="Password Reset Race",
        description="Exploit race condition in password reset token validation",
        category=PatternCategory.RACE_CONDITION,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-362", "CWE-640"],
        owasp_category="Authentication Flaws",
        remediation="Invalidate token immediately upon first use, use atomic operations",
        endpoint_patterns=[
            r"/reset", r"/password", r"/forgot"
        ],
        applicable_to=["authentication"],
        test_cases=[
            TestCase(
                name="Concurrent Reset Token Use",
                description="Use same reset token in concurrent password changes",
                method="POST",
                endpoint_pattern=r"/(reset.*password|password.*reset)",
                body_template={
                    "token": "{{reset_token}}",
                    "new_password": "NewPass123!"
                },
                concurrent_requests=3,
                success_indicators=["changed", "updated", "success"],
                failure_indicators=["invalid_token", "expired", "already_used"]
            )
        ]
    ),
]
