"""
AIPTX Validation Module - PoC Validation for Zero False Positives.

Every reported vulnerability includes a working proof-of-concept
that proves exploitability. This eliminates false positives and
provides actionable evidence.

Components:
- PoCValidator: Core validation engine
- ValidationStrategy: Per-vulnerability validation logic
- EvidenceCollector: Captures proof (screenshots, responses)
- ExploitExecutor: Safe exploitation in sandbox
- CallbackManager: OOB callback server for blind vulnerabilities
- FalsePositiveEngine: Multi-factor FP detection with LLM consensus (v5.2)
- RiskScorer: CVSS + EPSS + business impact scoring (v5.2)
"""

from aipt_v2.validation.callback_server import (
    CallbackManager,
    CallbackResult,
    DNSCallbackServer,
    HTTPCallbackServer,
    InteractshClient,
    PendingCallback,
    create_callback_server,
    generate_oob_payloads,
)
from aipt_v2.validation.evidence import (
    Evidence,
    EvidenceCollector,
    EvidenceType,
    HTTPExchange,
    Screenshot,
)
from aipt_v2.validation.executor import (
    ExecutionContext,
    ExecutionResult,
    ExploitExecutor,
    SandboxConfig,
)

# v5.2 - False Positive Engine
from aipt_v2.validation.false_positive_engine import (
    BayesianFilter,
    ConfidenceLevel,
    CVSSData,
    EPSSData,
    FalsePositiveDatabase,
    FalsePositiveEngine,
    FindingStatus,
    FPValidationResult,
    LLMVotingEngine,
    RiskFactors,
)
from aipt_v2.validation.false_positive_engine import validate_finding as fp_validate_finding
from aipt_v2.validation.poc_validator import (
    PoCValidator,
    ValidatedFinding,
    ValidationResult,
    ValidationStatus,
    ValidatorConfig,
    validate_finding,
    validate_findings,
)

# v5.2 - Risk Scorer
from aipt_v2.validation.risk_scorer import (
    AssetCriticality,
    DataClassification,
    EPSSResult,
    RiskLevel,
    RiskScore,
    RiskScorer,
    calculate_risk,
    get_epss,
)
from aipt_v2.validation.strategies import (
    AuthBypassValidationStrategy,
    IDORValidationStrategy,
    LFIValidationStrategy,
    RCEValidationStrategy,
    SQLiValidationStrategy,
    SSRFValidationStrategy,
    ValidationStrategy,
    XSSValidationStrategy,
    get_strategy_for_vuln_type,
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
    # Callback Server (OOB Detection)
    "CallbackManager",
    "CallbackResult",
    "HTTPCallbackServer",
    "DNSCallbackServer",
    "InteractshClient",
    "PendingCallback",
    "create_callback_server",
    "generate_oob_payloads",
    # v5.2 - False Positive Engine
    "FalsePositiveEngine",
    "FPValidationResult",
    "ConfidenceLevel",
    "FindingStatus",
    "CVSSData",
    "EPSSData",
    "RiskFactors",
    "BayesianFilter",
    "FalsePositiveDatabase",
    "LLMVotingEngine",
    "fp_validate_finding",
    # v5.2 - Risk Scorer
    "RiskScorer",
    "RiskScore",
    "RiskLevel",
    "EPSSResult",
    "AssetCriticality",
    "DataClassification",
    "calculate_risk",
    "get_epss",
]
