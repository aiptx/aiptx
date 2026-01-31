"""
Price Manipulation Test Patterns

Tests for price/amount tampering, currency manipulation,
overflow attacks, and calculation errors.
"""

from aipt_v2.business_logic.patterns.base import (
    TestPattern,
    TestCase,
    PatternCategory,
    TestSeverity,
)


PRICE_MANIPULATION_PATTERNS = [
    TestPattern(
        id="PRICE-001",
        name="Negative Amount Injection",
        description="Submit negative amounts to reverse transactions or gain credits",
        category=PatternCategory.PRICE_MANIPULATION,
        severity=TestSeverity.CRITICAL,
        cwe_ids=["CWE-20", "CWE-1284"],
        owasp_category="Input Validation Errors",
        remediation="Validate all amounts are positive on server-side, use unsigned types where appropriate",
        endpoint_patterns=[
            r"/payment", r"/cart", r"/order", r"/checkout", r"/transfer"
        ],
        applicable_to=["e-commerce", "payment", "banking"],
        test_cases=[
            TestCase(
                name="Negative Price",
                description="Submit negative price for item",
                method="POST",
                body_template={"item_id": "{{item_id}}", "price": -100},
                manipulation={"price": [-1, -100, -999999]},
                success_indicators=["total", "order_id"],
                failure_indicators=["invalid", "negative not allowed"]
            ),
            TestCase(
                name="Negative Quantity",
                description="Submit negative quantity to get refund credits",
                method="POST",
                body_template={"item_id": "{{item_id}}", "quantity": -5},
                manipulation={"quantity": [-1, -10, -100]},
                success_indicators=["added", "cart"],
                failure_indicators=["invalid", "positive"]
            ),
            TestCase(
                name="Negative Shipping",
                description="Submit negative shipping cost",
                method="POST",
                body_template={"shipping_cost": -50},
                manipulation={"shipping_cost": [-10, -100]},
                success_indicators=["total"],
                failure_indicators=["invalid"]
            )
        ]
    ),

    TestPattern(
        id="PRICE-002",
        name="Integer Overflow Attack",
        description="Cause integer overflow to manipulate calculated totals",
        category=PatternCategory.PRICE_MANIPULATION,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-190", "CWE-191"],
        owasp_category="Input Validation Errors",
        remediation="Use safe math libraries, validate input ranges, use appropriate data types",
        endpoint_patterns=[
            r"/cart", r"/order", r"/calculate", r"/quantity"
        ],
        applicable_to=["e-commerce", "payment"],
        test_cases=[
            TestCase(
                name="Quantity Overflow",
                description="Submit very large quantity to cause overflow",
                method="POST",
                body_template={"item_id": "{{item_id}}", "quantity": 2147483647},
                manipulation={"quantity": [2147483647, 2147483648, 9999999999]},
                success_indicators=["total"],
                failure_indicators=["overflow", "too large"]
            ),
            TestCase(
                name="Price Overflow",
                description="Manipulate price calculation via overflow",
                method="POST",
                body_template={"price": 2147483647, "quantity": 2},
                success_indicators=["total"],
                failure_indicators=["overflow"]
            )
        ]
    ),

    TestPattern(
        id="PRICE-003",
        name="Decimal/Float Manipulation",
        description="Exploit floating-point precision issues in price calculations",
        category=PatternCategory.PRICE_MANIPULATION,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-682"],
        owasp_category="Business Logic Errors",
        remediation="Use decimal types for currency, avoid floating-point for financial calculations",
        endpoint_patterns=[
            r"/price", r"/calculate", r"/total", r"/discount"
        ],
        applicable_to=["e-commerce", "payment"],
        test_cases=[
            TestCase(
                name="Precision Exploitation",
                description="Submit prices with many decimal places",
                method="POST",
                body_template={"price": 0.0000001},
                manipulation={"price": [0.001, 0.0001, 0.00001, 0.000001]},
                success_indicators=["total"],
                failure_indicators=["invalid"]
            ),
            TestCase(
                name="Rounding Abuse",
                description="Exploit rounding in repeated small transactions",
                method="POST",
                body_template={"amount": 0.004},
                success_indicators=["success"],
                failure_indicators=["minimum"]
            )
        ]
    ),

    TestPattern(
        id="PRICE-004",
        name="Currency Manipulation",
        description="Switch currency codes to get favorable exchange rates",
        category=PatternCategory.PRICE_MANIPULATION,
        severity=TestSeverity.HIGH,
        cwe_ids=["CWE-20", "CWE-807"],
        owasp_category="Business Logic Errors",
        remediation="Validate currency codes server-side, use locked exchange rates per session",
        endpoint_patterns=[
            r"/payment", r"/checkout", r"/currency", r"/exchange"
        ],
        applicable_to=["e-commerce", "payment", "forex"],
        test_cases=[
            TestCase(
                name="Currency Code Swap",
                description="Change currency code to lower-value currency",
                method="POST",
                body_template={"amount": 100, "currency": "{{currency}}"},
                manipulation={"currency": ["USD", "INR", "IDR", "VND", "IRR"]},
                success_indicators=["confirmed", "total"],
                failure_indicators=["invalid currency"]
            ),
            TestCase(
                name="Invalid Currency Code",
                description="Submit invalid currency code",
                method="POST",
                body_template={"amount": 100, "currency": "XXX"},
                manipulation={"currency": ["XXX", "AAA", "", "null"]},
                success_indicators=["total"],
                failure_indicators=["invalid", "not supported"]
            )
        ]
    ),

    TestPattern(
        id="PRICE-005",
        name="Tax/Fee Manipulation",
        description="Bypass or manipulate taxes and fees",
        category=PatternCategory.PRICE_MANIPULATION,
        severity=TestSeverity.MEDIUM,
        cwe_ids=["CWE-20"],
        owasp_category="Business Logic Errors",
        remediation="Calculate taxes server-side only, never trust client-provided tax values",
        endpoint_patterns=[
            r"/tax", r"/fee", r"/checkout", r"/calculate"
        ],
        applicable_to=["e-commerce", "payment"],
        test_cases=[
            TestCase(
                name="Zero Tax Injection",
                description="Submit zero tax amount",
                method="POST",
                body_template={"tax": 0, "subtotal": 100},
                manipulation={"tax": [0, -10]},
                success_indicators=["total"],
                failure_indicators=["invalid"]
            ),
            TestCase(
                name="Tax Region Spoofing",
                description="Claim tax-exempt region",
                method="POST",
                body_template={"region": "tax_exempt_region"},
                manipulation={"region": ["DE", "OR", "MT", "NH", "AK"]},
                success_indicators=["tax: 0"],
                failure_indicators=[]
            )
        ]
    ),

    TestPattern(
        id="PRICE-006",
        name="Cart Total Manipulation",
        description="Directly modify cart total or bypass price verification",
        category=PatternCategory.PRICE_MANIPULATION,
        severity=TestSeverity.CRITICAL,
        cwe_ids=["CWE-20", "CWE-807"],
        owasp_category="Business Logic Errors",
        remediation="Always recalculate totals server-side, never trust client-sent totals",
        endpoint_patterns=[
            r"/checkout", r"/payment", r"/cart"
        ],
        applicable_to=["e-commerce"],
        test_cases=[
            TestCase(
                name="Direct Total Override",
                description="Send modified total in checkout request",
                method="POST",
                body_template={"total": 0.01, "cart_id": "{{cart_id}}"},
                manipulation={"total": [0.01, 1, 0]},
                success_indicators=["order_id", "confirmed"],
                failure_indicators=["mismatch", "invalid total"]
            ),
            TestCase(
                name="Hidden Field Total",
                description="Modify hidden total field from form",
                method="POST",
                body_template={"_cart_total": 1, "checkout": True},
                success_indicators=["success"],
                failure_indicators=["mismatch"]
            )
        ]
    ),
]
