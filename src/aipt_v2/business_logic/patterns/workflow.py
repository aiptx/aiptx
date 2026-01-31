"""
Workflow Bypass Test Patterns

Tests for step-skipping, state tampering, and workflow manipulation
vulnerabilities.
"""

from aipt_v2.business_logic.patterns.base import (
    TestPattern,
    TestCase,
    PatternCategory,
    TestSeverity,
)


WORKFLOW_PATTERNS = [
    TestPattern(
        id="FLOW-001",
        name="Checkout Step Skipping",
        description="Skip required checkout steps like address or payment verification",
        category=PatternCategory.WORKFLOW,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-841", "CWE-639"],
        owasp_category="Business Logic Errors",
        remediation="Implement server-side workflow state machine, validate all required steps completed",
        endpoint_patterns=[
            r"/checkout", r"/complete", r"/confirm", r"/order"
        ],
        applicable_to=["e-commerce"],
        test_cases=[
            TestCase(
                name="Direct Completion",
                description="Skip directly to order completion",
                method="POST",
                endpoint_pattern=r"/complete.*order|order.*complete",
                body_template={"cart_id": "{{cart_id}}", "confirm": True},
                setup_steps=["Add item to cart", "Skip shipping", "Skip payment"],
                success_indicators=["order_id", "confirmed"],
                failure_indicators=["step", "required", "incomplete"]
            ),
            TestCase(
                name="Skip Payment Step",
                description="Complete checkout without payment",
                method="POST",
                body_template={"cart_id": "{{cart_id}}", "step": "complete"},
                setup_steps=["Add item", "Set shipping"],
                success_indicators=["order_id"],
                failure_indicators=["payment required"]
            )
        ]
    ),

    TestPattern(
        id="FLOW-002",
        name="Verification Bypass",
        description="Skip email, phone, or identity verification steps",
        category=PatternCategory.WORKFLOW,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-841", "CWE-287"],
        owasp_category="Authentication Flaws",
        remediation="Enforce verification status server-side before allowing protected actions",
        endpoint_patterns=[
            r"/verify", r"/confirm", r"/activate", r"/profile"
        ],
        applicable_to=["authentication", "onboarding"],
        test_cases=[
            TestCase(
                name="Skip Email Verification",
                description="Access features without email verification",
                method="POST",
                endpoint_pattern=r"/profile|/settings|/account",
                body_template={"action": "update", "verified": True},
                success_indicators=["success", "updated"],
                failure_indicators=["verify email", "not verified"]
            ),
            TestCase(
                name="Direct Activation",
                description="Activate account without completing verification flow",
                method="POST",
                endpoint_pattern=r"/activate",
                body_template={"user_id": "{{user_id}}", "status": "active"},
                success_indicators=["activated"],
                failure_indicators=["verification required"]
            )
        ]
    ),

    TestPattern(
        id="FLOW-003",
        name="State Tampering",
        description="Modify workflow state to bypass restrictions",
        category=PatternCategory.WORKFLOW,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-841", "CWE-20"],
        owasp_category="Business Logic Errors",
        remediation="Store workflow state server-side only, validate state transitions",
        endpoint_patterns=[
            r"/order", r"/status", r"/workflow", r"/state"
        ],
        applicable_to=["e-commerce", "workflow"],
        test_cases=[
            TestCase(
                name="Status Jump",
                description="Change order status directly",
                method="POST",
                body_template={"order_id": "{{order_id}}", "status": "shipped"},
                manipulation={"status": ["approved", "shipped", "delivered", "refunded"]},
                success_indicators=["updated", "success"],
                failure_indicators=["invalid transition", "not allowed"]
            ),
            TestCase(
                name="Approval Bypass",
                description="Skip approval step by setting approved status",
                method="POST",
                body_template={"request_id": "{{id}}", "approved": True},
                success_indicators=["approved"],
                failure_indicators=["pending", "requires approval"]
            )
        ]
    ),

    TestPattern(
        id="FLOW-004",
        name="Time-Based Restriction Bypass",
        description="Bypass time-based restrictions on actions",
        category=PatternCategory.WORKFLOW,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-841"],
        owasp_category="Business Logic Errors",
        remediation="Validate timestamps server-side, don't trust client time",
        endpoint_patterns=[
            r"/submit", r"/action", r"/deadline"
        ],
        applicable_to=["voting", "auctions", "forms"],
        test_cases=[
            TestCase(
                name="Past Deadline Submission",
                description="Submit after deadline by manipulating timestamp",
                method="POST",
                body_template={"submission_time": "{{past_time}}", "data": "test"},
                manipulation={"submission_time": ["2020-01-01T00:00:00Z"]},
                success_indicators=["submitted", "accepted"],
                failure_indicators=["deadline", "closed", "expired"]
            ),
            TestCase(
                name="Future Date Access",
                description="Access content before release date",
                method="GET",
                body_template={"date": "{{future_date}}"},
                success_indicators=["content"],
                failure_indicators=["not yet available"]
            )
        ]
    ),

    TestPattern(
        id="FLOW-005",
        name="Multi-Use Single-Use Token",
        description="Reuse single-use tokens, invites, or links",
        category=PatternCategory.WORKFLOW,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-613", "CWE-384"],
        owasp_category="Session Management",
        remediation="Invalidate tokens immediately upon first use, use atomic operations",
        endpoint_patterns=[
            r"/invite", r"/token", r"/link", r"/redeem"
        ],
        applicable_to=["invitations", "promotions"],
        test_cases=[
            TestCase(
                name="Invite Reuse",
                description="Use same invite link multiple times",
                method="POST",
                endpoint_pattern=r"/accept.*invite|invite.*accept",
                body_template={"token": "{{invite_token}}"},
                concurrent_requests=3,
                success_indicators=["accepted", "joined"],
                failure_indicators=["already_used", "invalid", "expired"]
            ),
            TestCase(
                name="Download Link Reuse",
                description="Use single-use download link multiple times",
                method="GET",
                endpoint_pattern=r"/download",
                body_template={"token": "{{download_token}}"},
                success_indicators=["content-disposition"],
                failure_indicators=["expired", "invalid"]
            )
        ]
    ),

    TestPattern(
        id="FLOW-006",
        name="Parameter Tampering for Flow Control",
        description="Modify parameters that control workflow progression",
        category=PatternCategory.WORKFLOW,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-472", "CWE-20"],
        owasp_category="Business Logic Errors",
        remediation="Don't expose workflow control in client-accessible parameters",
        endpoint_patterns=[
            r"/wizard", r"/step", r"/flow", r"/process"
        ],
        applicable_to=["onboarding", "forms"],
        test_cases=[
            TestCase(
                name="Step Parameter Manipulation",
                description="Change step parameter to skip steps",
                method="POST",
                body_template={"step": 10, "data": "final"},
                manipulation={"step": [5, 10, 99, -1]},
                success_indicators=["completed", "success"],
                failure_indicators=["invalid step", "out of order"]
            ),
            TestCase(
                name="Progress Override",
                description="Set progress to 100%",
                method="POST",
                body_template={"progress": 100, "complete": True},
                success_indicators=["completed"],
                failure_indicators=["incomplete steps"]
            )
        ]
    ),
]
