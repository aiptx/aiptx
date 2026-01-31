"""
AIPTX Validation Module - PoC Validation for Zero False Positives

Every reported vulnerability includes a working proof-of-concept
that proves exploitability. This eliminates false positives and
provides actionable evidence.

Components:
- PoCValidator: Core validation engine
- ValidationStrategy: Per-vulnerability validation logic
- EvidenceCollector: Captures proof (screenshots, responses)
- ExploitExecutor: Safe exploitation in sandbox
"""

from aipt_v2.validation.poc_validator import (
    PoCValidator,
    ValidatorConfig,
    ValidatedFinding,
    ValidationResult,
    ValidationStatus,
    validate_finding,
    validate_findings,
)
from aipt_v2.validation.strategies import (
    ValidationStrategy,
    SQLiValidationStrategy,
    XSSValidationStrategy,
    SSRFValidationStrategy,
    RCEValidationStrategy,
    LFIValidationStrategy,
    AuthBypassValidationStrategy,
    IDORValidationStrategy,
    get_strategy_for_vuln_type,
)
from aipt_v2.validation.evidence import (
    Evidence,
    EvidenceType,
    EvidenceCollector,
    Screenshot,
    HTTPExchange,
)
from aipt_v2.validation.executor import (
    ExploitExecutor,
    ExecutionResult,
    ExecutionContext,
    SandboxConfig,
)

__all__ = [
    # Core validator
    "PoCValidator",
    "ValidatorConfig",
    "ValidatedFinding",
    "ValidationResult",
    "ValidationStatus",
    "validate_finding",
    "validate_findings",
    # Strategies
    "ValidationStrategy",
    "SQLiValidationStrategy",
    "XSSValidationStrategy",
    "SSRFValidationStrategy",
    "RCEValidationStrategy",
    "LFIValidationStrategy",
    "AuthBypassValidationStrategy",
    "IDORValidationStrategy",
    "get_strategy_for_vuln_type",
    # Evidence
    "Evidence",
    "EvidenceType",
    "EvidenceCollector",
    "Screenshot",
    "HTTPExchange",
    # Executor
    "ExploitExecutor",
    "ExecutionResult",
    "ExecutionContext",
    "SandboxConfig",
]
