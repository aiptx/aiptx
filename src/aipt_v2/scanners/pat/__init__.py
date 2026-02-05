"""
PAT Scanner - PayloadsAllTheThings Integration

Automated vulnerability testing using the PayloadsAllTheThings payload library.

Features:
- Parses 70+ vulnerability categories from PAT repository
- Generates HTTP requests with intelligent payload injection
- Executes requests in parallel with rate limiting and WAF detection
- Analyzes responses using error-based, time-based, and content-diff detection
- Produces evidence-based findings with confidence scoring

Usage:
    from aipt_v2.scanners.pat import PATScanner, PATScanConfig, VulnerabilityType

    config = PATScanConfig(
        target_url="https://example.com/api",
        parameters=["id", "user", "search"],
        vuln_types=[
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.XSS,
            VulnerabilityType.COMMAND_INJECTION,
        ],
        authorized=True,  # REQUIRED - confirms authorization
    )

    scanner = PATScanner(config)
    result = await scanner.scan()

    for finding in result.findings:
        print(f"[{finding.severity}] {finding.title}")

Quick scan:
    from aipt_v2.scanners.pat import scan_url, VulnerabilityType

    result = await scan_url(
        url="https://example.com/search?q=test",
        vuln_types=[VulnerabilityType.SQL_INJECTION],
        authorized=True,
    )
"""

# Configuration
from .config import (
    PATScanConfig,
    EnhancedPATScanConfig,
    VulnerabilityType,
    InjectionPoint,
    PayloadTechnique,
    DetectionMethod,
    ExecutorConfig,
    AnalyzerConfig,
    PayloadConfig,
    SecurityError,
    ScopeViolation,
    AuthorizationError,
)

# Payload management
from .payload_parser import ParsedPayload, PayloadParser
from .payload_database import (
    PayloadDatabase,
    PayloadStats,
    get_payload_database,
    get_payloads_for_vuln,
)

# Request generation
from .request_generator import (
    RequestGenerator,
    EnhancedRequestGenerator,
    InjectionRequest,
)

# Execution
from .executor import (
    ParallelExecutor,
    WAFAwareExecutor,
    ExecutionResult,
    WAFProbeResult,
    RateLimiter,
    WAFDetector,
    ScopeEnforcer,
    execute_requests,
)

# Analysis
from .analyzer import (
    ResponseAnalyzer,
    EnhancedResponseAnalyzer,
    AnalysisResult,
    BaselineData,
    analyze_results,
)

# Detection patterns
from .detection_patterns import (
    DetectionPattern,
    get_detection_patterns,
    get_compiled_patterns,
    match_any_pattern,
)

# Reporting pipeline
from .reporters import (
    PATReportPipeline,
    PATReportConfig,
    generate_pat_sarif,
    generate_pat_html,
    PAT_CWE_MAPPINGS,
    OWASP_TOP_10_MAPPINGS,
)

# Main scanner
from .pat_scanner import (
    PATScanner,
    EnhancedPATScanner,
    ValidatingPATScanner,
    ChainEscalatingPATScanner,
    OOBEnabledPATScanner,
    BrowserValidatingPATScanner,
    PATScanResult,
    ValidatedScanFinding,
    ChainEnrichedFinding,
    scan_url,
    update_payloads,
)

# Browser validation
from .browser_validator import (
    PATBrowserValidator,
    BrowserValidationResult,
    validate_xss_in_browser,
    validate_prototype_pollution_in_browser,
)

# Custom payload loading
from .custom_payloads import (
    CustomPayloadLoader,
    CustomPayloadFile,
    PayloadTemplate,
    PayloadTemplateEngine,
    load_custom_payloads,
    load_payloads_directory,
    create_payload_file,
)


__all__ = [
    # Main scanner
    "PATScanner",
    "EnhancedPATScanner",
    "ValidatingPATScanner",
    "ChainEscalatingPATScanner",
    "OOBEnabledPATScanner",
    "BrowserValidatingPATScanner",
    "PATScanConfig",
    "PATScanResult",
    "ValidatedScanFinding",
    "ChainEnrichedFinding",

    # Browser validation
    "PATBrowserValidator",
    "BrowserValidationResult",
    "validate_xss_in_browser",
    "validate_prototype_pollution_in_browser",

    # Enhanced scanner
    "EnhancedPATScanConfig",
    "EnhancedRequestGenerator",

    # Configuration
    "VulnerabilityType",
    "InjectionPoint",
    "PayloadTechnique",
    "DetectionMethod",
    "ExecutorConfig",
    "AnalyzerConfig",
    "PayloadConfig",

    # Exceptions
    "SecurityError",
    "ScopeViolation",
    "AuthorizationError",

    # Payloads
    "ParsedPayload",
    "PayloadParser",
    "PayloadDatabase",
    "PayloadStats",
    "get_payload_database",
    "get_payloads_for_vuln",

    # Request generation
    "RequestGenerator",
    "EnhancedRequestGenerator",
    "InjectionRequest",

    # Execution
    "ParallelExecutor",
    "WAFAwareExecutor",
    "ExecutionResult",
    "WAFProbeResult",
    "RateLimiter",
    "WAFDetector",
    "ScopeEnforcer",
    "execute_requests",

    # Analysis
    "ResponseAnalyzer",
    "EnhancedResponseAnalyzer",
    "AnalysisResult",
    "BaselineData",
    "analyze_results",

    # Detection
    "DetectionPattern",
    "get_detection_patterns",
    "get_compiled_patterns",
    "match_any_pattern",

    # Reporting
    "PATReportPipeline",
    "PATReportConfig",
    "generate_pat_sarif",
    "generate_pat_html",
    "PAT_CWE_MAPPINGS",
    "OWASP_TOP_10_MAPPINGS",

    # Convenience functions
    "scan_url",
    "update_payloads",

    # Custom payload loading
    "CustomPayloadLoader",
    "CustomPayloadFile",
    "PayloadTemplate",
    "PayloadTemplateEngine",
    "load_custom_payloads",
    "load_payloads_directory",
    "create_payload_file",
]
