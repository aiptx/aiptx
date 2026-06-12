"""
PAT Scanner Configuration

Configuration dataclasses for PayloadsAllTheThings scanner integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class VulnerabilityType(str, Enum):
    """
    Vulnerability categories supported by PAT scanner.

    Full coverage of PayloadsAllTheThings repository (67 categories).
    Organized by attack class for easier navigation.
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # EXISTING - Core Injection Types (19)
    # ═══════════════════════════════════════════════════════════════════════════
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    LFI = "lfi"
    RFI = "rfi"
    SSTI = "ssti"
    NOSQL_INJECTION = "nosql_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    CRLF_INJECTION = "crlf_injection"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    JWT_ATTACKS = "jwt_attacks"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    FILE_UPLOAD = "file_upload"

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Authentication & Access Control (5) - CWE-287, CWE-352, CWE-639
    # ═══════════════════════════════════════════════════════════════════════════
    CSRF = "csrf"  # Cross-Site Request Forgery (CWE-352)
    IDOR = "idor"  # Insecure Direct Object References (CWE-639)
    OAUTH_MISCONFIG = "oauth_misconfiguration"  # OAuth/OpenID misconfigurations (CWE-287)
    SAML_INJECTION = "saml_injection"  # SAML assertion manipulation (CWE-290)
    ACCOUNT_TAKEOVER = "account_takeover"  # Password reset, session fixation (CWE-287)

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Protocol/Request Attacks (6) - CWE-444, CWE-235, CWE-350
    # ═══════════════════════════════════════════════════════════════════════════
    HTTP_SMUGGLING = "http_request_smuggling"  # CL.TE, TE.CL desync (CWE-444)
    HPP = "http_parameter_pollution"  # Parameter precedence abuse (CWE-235)
    DNS_REBINDING = "dns_rebinding"  # DNS rebinding attacks (CWE-350)
    CORS_MISCONFIG = "cors_misconfiguration"  # Access-Control-* misconfigs (CWE-942)
    TABNABBING = "tabnabbing"  # Reverse tabnabbing (CWE-1022)
    CACHE_POISONING = "web_cache_poisoning"  # Web cache deception/poisoning (CWE-525)

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Client-Side Attacks (4) - CWE-79, CWE-1021, CWE-1321
    # ═══════════════════════════════════════════════════════════════════════════
    DOM_CLOBBERING = "dom_clobbering"  # DOM element overwriting (CWE-79)
    CLICKJACKING = "clickjacking"  # UI redressing (CWE-1021)
    PROTOTYPE_POLLUTION = "prototype_pollution"  # JS prototype chain manipulation (CWE-1321)
    CLIENT_PATH_TRAVERSAL = "client_side_path_traversal"  # Client-side path abuse (CWE-22)

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - File & Data Attacks (5) - CWE-22, CWE-1236, CWE-200
    # ═══════════════════════════════════════════════════════════════════════════
    CSV_INJECTION = "csv_injection"  # Formula injection in CSV/Excel (CWE-1236)
    ZIP_SLIP = "zip_slip"  # Archive path traversal (CWE-22)
    ORM_LEAK = "orm_leak"  # ORM/ActiveRecord data leak (CWE-200)
    SECRETS_EXPOSURE = "secrets_exposure"  # Secrets in files/responses (CWE-798)
    API_KEY_LEAK = "api_key_leak"  # API key/token exposure (CWE-798)

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Business Logic & Timing (5) - CWE-362, CWE-915, CWE-843
    # ═══════════════════════════════════════════════════════════════════════════
    RACE_CONDITION = "race_condition"  # TOCTOU, double-spend (CWE-362)
    MASS_ASSIGNMENT = "mass_assignment"  # Parameter binding abuse (CWE-915)
    TYPE_JUGGLING = "type_juggling"  # Loose comparison abuse (CWE-843)
    BUSINESS_LOGIC = "business_logic"  # Application logic flaws (CWE-840)
    INSECURE_RANDOM = "insecure_randomness"  # Predictable tokens (CWE-330)

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Injection Variants (6) - CWE-94, CWE-97, CWE-91
    # ═══════════════════════════════════════════════════════════════════════════
    LATEX_INJECTION = "latex_injection"  # LaTeX command injection (CWE-94)
    SSI_INJECTION = "ssi_injection"  # Server Side Include (CWE-97)
    XSLT_INJECTION = "xslt_injection"  # XSLT transform injection (CWE-91)
    PROMPT_INJECTION = "prompt_injection"  # LLM/AI prompt injection (CWE-77)
    REGEX_DOS = "regex_dos"  # ReDoS catastrophic backtracking (CWE-1333)
    JAVA_RMI = "java_rmi"  # Java RMI deserialization (CWE-502)

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Misconfiguration & Exposure (8) - CWE-538, CWE-472, CWE-749
    # ═══════════════════════════════════════════════════════════════════════════
    GIT_EXPOSURE = "git_exposure"  # .git/ directory exposed (CWE-538)
    HIDDEN_PARAMS = "hidden_parameters"  # Undocumented parameters (CWE-472)
    ADMIN_INTERFACE = "admin_interface"  # Exposed admin panels (CWE-749)
    VIRTUAL_HOST = "virtual_host"  # VHost enumeration (CWE-200)
    REVERSE_PROXY = "reverse_proxy_misconfig"  # Proxy hop abuse (CWE-441)
    GWT_VULN = "gwt_vulnerability"  # Google Web Toolkit (CWE-502)
    DEPENDENCY_CONFUSION = "dependency_confusion"  # Package manager abuse (CWE-427)
    CVE_EXPLOITS = "cve_exploits"  # Known CVE payloads (Various)

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Additional Edge Cases (6) - Extended coverage
    # ═══════════════════════════════════════════════════════════════════════════
    ENV_INJECTION = "env_injection"  # Environment variable manipulation (CWE-94)
    HEADLESS_BROWSER = "headless_browser"  # Puppeteer/Playwright exploits (CWE-94)
    ENCODING_BYPASS = "encoding_bypass"  # Charset/encoding filter bypass (CWE-838)
    HOST_HEADER = "host_header_injection"  # Host header poisoning (CWE-644)
    HTTP_VERB_TAMPERING = "http_verb_tampering"  # Method override attacks (CWE-650)
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"  # Dangling DNS records (CWE-284)


class InjectionPoint(str, Enum):
    """HTTP injection point types."""

    URL_PARAM = "url_param"  # ?id=PAYLOAD
    URL_PATH = "url_path"  # /api/PAYLOAD/endpoint
    POST_BODY = "post_body"  # Raw POST body
    POST_FORM = "post_form"  # application/x-www-form-urlencoded
    POST_JSON = "post_json"  # application/json
    HEADER = "header"  # X-Custom: PAYLOAD
    COOKIE = "cookie"  # session=PAYLOAD
    XML_BODY = "xml_body"  # XML injection points
    MULTIPART = "multipart"  # multipart/form-data


class PayloadTechnique(str, Enum):
    """Payload techniques/attack methods."""

    # SQL Injection techniques
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"

    # XSS techniques
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"

    # Generic
    DIRECT = "direct"
    FILTER_BYPASS = "filter_bypass"
    WAF_BYPASS = "waf_bypass"
    ENCODING_BYPASS = "encoding_bypass"


class DetectionMethod(str, Enum):
    """Methods for detecting successful exploitation."""

    ERROR_BASED = "error_based"  # Look for error messages
    TIME_BASED = "time_based"  # Measure response time
    CONTENT_DIFF = "content_diff"  # Compare content changes
    REFLECTION = "reflection"  # Payload appears in response
    CALLBACK = "callback"  # Out-of-band callback received
    STATUS_CODE = "status_code"  # HTTP status code change
    HEADER_BASED = "header_based"  # Response header analysis


@dataclass
class ExecutorConfig:
    """Configuration for parallel HTTP executor."""

    max_concurrent: int = 10  # Maximum parallel requests
    requests_per_second: float = 10.0  # Rate limit (RPS)
    timeout: float = 30.0  # Per-request timeout (seconds)
    retry_count: int = 2  # Number of retries on failure
    retry_backoff: float = 2.0  # Exponential backoff multiplier
    verify_ssl: bool = False  # SSL certificate verification
    follow_redirects: bool = True  # Follow HTTP redirects
    max_redirects: int = 5  # Maximum redirects to follow
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    proxy: Optional[str] = None  # HTTP proxy (e.g., http://127.0.0.1:8080)

    # WAF handling
    waf_detection: bool = True  # Enable WAF detection
    waf_backoff_multiplier: float = 3.0  # Slowdown when WAF detected


@dataclass
class AnalyzerConfig:
    """Configuration for response analyzer."""

    # Time-based detection
    time_based_threshold_ms: float = 5000.0  # Minimum delay to consider time-based
    time_based_variance_ms: float = 1000.0  # Allowed variance

    # Content-based detection
    content_diff_threshold: float = 0.3  # 30% content difference
    min_response_length: int = 100  # Minimum response length to analyze

    # Confidence thresholds
    confidence_threshold: float = 0.7  # Minimum confidence for positive
    false_positive_check: bool = True  # Enable false positive verification

    # Evidence collection
    max_evidence_size: int = 5000  # Max evidence bytes to store
    capture_full_response: bool = False  # Store full response bodies


@dataclass
class PayloadConfig:
    """Configuration for payload loading and filtering."""

    # Repository settings
    repo_path: Path = field(
        default_factory=lambda: Path.home() / ".aiptx" / "payloads" / "PayloadsAllTheThings"
    )
    repo_url: str = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    auto_update: bool = False  # Auto-update on scan

    # Payload filtering
    max_payloads_per_type: int = 100  # Limit payloads per vuln type
    max_payload_length: int = 2000  # Maximum payload length
    include_dangerous: bool = False  # Include destructive payloads

    # Database
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".aiptx" / "cache" / "pat")
    cache_ttl_hours: int = 24  # Cache time-to-live


@dataclass
class PATScanConfig:
    """Main configuration for PAT scanner."""

    # Target settings
    target_url: str = ""
    parameters: list[str] = field(default_factory=list)
    injection_points: list[InjectionPoint] = field(
        default_factory=lambda: [
            InjectionPoint.URL_PARAM,
            InjectionPoint.POST_FORM,
            InjectionPoint.POST_JSON,
        ]
    )

    # HTTP settings
    method: str = "GET"  # Default HTTP method
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str = ""  # Request body template

    # Scan scope
    vuln_types: list[VulnerabilityType] = field(
        default_factory=lambda: [
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.XSS,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.SSRF,
            VulnerabilityType.XXE,
            VulnerabilityType.LFI,
            VulnerabilityType.NOSQL_INJECTION,
        ]
    )

    # Component configs
    executor: ExecutorConfig = field(default_factory=ExecutorConfig)
    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    payload: PayloadConfig = field(default_factory=PayloadConfig)

    # Safety settings
    authorized: bool = False  # MUST be True to run
    scope_patterns: list[str] = field(default_factory=list)  # Allowed URL patterns

    # Output settings
    output_dir: str = "./pat_results"
    save_evidence: bool = True
    save_requests: bool = True  # Save all request/response pairs

    # Advanced settings
    baseline_requests: int = 3  # Baseline requests before testing
    stop_on_first: bool = False  # Stop on first finding per param
    smart_detection: bool = True  # Use AI-assisted detection


class SecurityError(Exception):
    """Raised when security controls are violated."""

    pass


class ScopeViolation(SecurityError):
    """Raised when target is out of scope."""

    pass


class AuthorizationError(SecurityError):
    """Raised when authorization is not granted."""

    pass


@dataclass
class EnhancedPATScanConfig(PATScanConfig):
    """
    Enhanced configuration for PAT scanner with mutation engine support.

    Adds offensive pentesting capabilities:
    - Mutation engines for payload variants (SQLi/XSS/CMD)
    - WAF-aware execution with proactive bypass
    - Smart payload prioritization based on technique speed
    - Learning system integration for success tracking
    - PoC validation and evidence collection
    - Exploit chain escalation
    """

    # Mutation settings
    enable_mutations: bool = True  # Use mutation engines
    max_mutations_per_payload: int = 10  # Limit variants per base payload
    mutation_dbms: str = "mysql"  # DBMS for SQLi mutations
    mutation_os: str = "linux"  # OS for CMD mutations
    mutation_xss_context: str = "html_body"  # Context for XSS mutations

    # WAF handling (proactive)
    waf_aware: bool = True  # Proactive WAF bypass
    waf_probe_first: bool = True  # Fingerprint WAF before scan
    waf_type: Optional[str] = None  # Known WAF type (auto-detect if None)

    # Learning integration
    use_learning_system: bool = True  # Query ExploitationLearner
    record_successes: bool = True  # Feed back to learner

    # Validation
    auto_validate: bool = True  # Run PoC validator
    collect_evidence: bool = True  # Full evidence capture

    # Escalation
    auto_escalate: bool = False  # Build exploit chains
    chain_templates: list[str] = field(default_factory=list)

    # Prioritization
    prioritize_by_speed: bool = True  # Error-based before time-based
    global_early_stop: bool = True  # Stop all on confirmed vuln

    # Deduplication
    deduplicate_payloads: bool = True  # Skip duplicate payloads
