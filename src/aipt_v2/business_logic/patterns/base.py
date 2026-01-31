"""
Base classes for business logic test patterns.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime, timezone


class PatternCategory(Enum):
    """Categories of business logic vulnerabilities."""
    RACE_CONDITION = "race_condition"
    PRICE_MANIPULATION = "price_manipulation"
    WORKFLOW = "workflow"
    ACCESS_CONTROL = "access_control"
    RATE_LIMITING = "rate_limiting"
    PROMO_ABUSE = "promo_abuse"
    DATA_INTEGRITY = "data_integrity"


class TestSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TestCase:
    """
    A single test case for a business logic pattern.
    """
    name: str
    description: str

    # Request configuration
    method: str = "POST"
    endpoint_pattern: str = ""  # Regex to match endpoint
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: Dict[str, Any] = field(default_factory=dict)

    # Test-specific parameters
    manipulation: Dict[str, Any] = field(default_factory=dict)
    concurrent_requests: int = 1  # For race conditions
    delay_between_requests: float = 0  # Seconds

    # Validation
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    expected_status_codes: List[int] = field(default_factory=lambda: [200, 201])

    # Additional context
    requires_auth: bool = True
    requires_session: bool = False
    setup_steps: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Result of a business logic test execution."""
    test_case: str
    pattern_id: str
    success: bool
    vulnerability_found: bool

    # Evidence
    request_sent: Dict[str, Any] = field(default_factory=dict)
    response_received: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""

    # Timing
    started_at: str = ""
    finished_at: str = ""
    duration_ms: float = 0

    # For race conditions
    concurrent_results: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()


@dataclass
class TestPattern:
    """
    A business logic test pattern.

    Patterns define a class of vulnerability and how to test for it.
    """
    id: str
    name: str
    description: str
    category: PatternCategory
    severity: TestSeverity

    # Test cases
    test_cases: List[TestCase] = field(default_factory=list)

    # Detection
    cwe_ids: List[str] = field(default_factory=list)
    owasp_category: str = ""

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Applicability
    applicable_to: List[str] = field(default_factory=list)  # e.g., ["e-commerce", "banking"]
    endpoint_patterns: List[str] = field(default_factory=list)  # Regex patterns to match

    # Custom validator
    _validator: Optional[Callable] = None

    def matches_endpoint(self, endpoint: str) -> bool:
        """Check if pattern applies to given endpoint."""
        import re
        if not self.endpoint_patterns:
            return True  # Apply to all endpoints
        return any(re.search(p, endpoint, re.I) for p in self.endpoint_patterns)

    def to_dict(self) -> Dict[str, Any]:
        """Convert pattern to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "cwe_ids": self.cwe_ids,
            "owasp_category": self.owasp_category,
            "remediation": self.remediation,
            "test_case_count": len(self.test_cases)
        }
