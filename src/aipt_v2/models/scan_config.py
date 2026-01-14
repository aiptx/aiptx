"""
AIPT Scan Configuration

Defines scan modes and configuration options for the unified pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScanMode(Enum):
    """
    Scan intensity modes

    QUICK: Fast reconnaissance + AI-autonomous testing only (Aipt)
    STANDARD: Traditional scanners + AI testing (balanced)
    COMPREHENSIVE: All scanners + aggressive AI testing + exploitation
    STEALTH: Low-noise scanning with minimal active probing
    """
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"


class ScannerType(Enum):
    """Available scanners in the pipeline"""
    # Traditional DAST
    ACUNETIX = "acunetix"
    BURP_SUITE = "burp"
    ZAP = "zap"

    # Template-based
    NUCLEI = "nuclei"

    # AI-Autonomous
    STRIX = "aipt"

    # Reconnaissance
    NMAP = "nmap"
    SUBFINDER = "subfinder"
    HTTPX = "httpx"

    # Fuzzing
    FFUF = "ffuf"
    SQLMAP = "sqlmap"


@dataclass
class ScanConfig:
    """
    Unified scan configuration for AIPT

    This config controls all aspects of the scanning pipeline:
    - Target specification
    - Scanner selection and configuration
    - AI agent settings
    - Output and reporting options
    """

    # Target configuration
    target: str  # Primary target URL or domain
    scope: list[str] = field(default_factory=list)  # Additional in-scope URLs/patterns
    exclude_patterns: list[str] = field(default_factory=list)  # URLs to exclude

    # Scan mode
    mode: ScanMode = ScanMode.STANDARD

    # Phase configuration
    enable_recon: bool = True
    enable_traditional_scan: bool = True
    enable_ai_pentest: bool = True  # NEW: Aipt AI-autonomous testing
    enable_exploitation: bool = False  # Disabled by default for safety
    enable_reporting: bool = True

    # Scanner selection
    enabled_scanners: list[ScannerType] = field(default_factory=lambda: [
        ScannerType.NUCLEI,
        ScannerType.STRIX,
    ])

    # Traditional scanner configs
    acunetix_config: dict[str, Any] = field(default_factory=dict)
    burp_config: dict[str, Any] = field(default_factory=dict)
    zap_config: dict[str, Any] = field(default_factory=dict)
    nuclei_config: dict[str, Any] = field(default_factory=dict)

    # Aipt AI configuration
    aipt_config: "AiptConfig" = field(default_factory=lambda: AiptConfig())

    # Authentication
    auth_config: dict[str, Any] | None = None

    # Rate limiting
    max_requests_per_second: int = 10
    max_concurrent_scans: int = 3

    # Timeouts (in seconds)
    phase_timeout: int = 3600  # 1 hour per phase
    total_timeout: int = 14400  # 4 hours total

    # Output configuration
    output_dir: str = "./aipt_results"
    report_formats: list[str] = field(default_factory=lambda: ["html", "json", "pdf"])

    # Verbosity
    verbose: bool = False
    debug: bool = False

    @classmethod
    def quick(cls, target: str) -> "ScanConfig":
        """Create a quick scan config (AI + Nuclei only)"""
        return cls(
            target=target,
            mode=ScanMode.QUICK,
            enable_recon=True,
            enable_traditional_scan=False,
            enable_ai_pentest=True,
            enable_exploitation=False,
            enabled_scanners=[ScannerType.NUCLEI, ScannerType.STRIX],
            phase_timeout=1800,  # 30 min
            total_timeout=3600,  # 1 hour
        )

    @classmethod
    def standard(cls, target: str) -> "ScanConfig":
        """Create a standard scan config"""
        return cls(
            target=target,
            mode=ScanMode.STANDARD,
            enabled_scanners=[
                ScannerType.NUCLEI,
                ScannerType.ZAP,
                ScannerType.STRIX,
            ],
        )

    @classmethod
    def comprehensive(cls, target: str) -> "ScanConfig":
        """Create a comprehensive scan config (all scanners + exploitation)"""
        return cls(
            target=target,
            mode=ScanMode.COMPREHENSIVE,
            enable_exploitation=True,
            enabled_scanners=[
                ScannerType.ACUNETIX,
                ScannerType.BURP_SUITE,
                ScannerType.ZAP,
                ScannerType.NUCLEI,
                ScannerType.STRIX,
            ],
            aipt_config=AiptConfig(
                modules=["all"],
                autonomous_exploitation=True,
                max_agent_iterations=50,
            ),
            phase_timeout=7200,  # 2 hours
            total_timeout=28800,  # 8 hours
        )


@dataclass
class AiptConfig:
    """
    Aipt AI Agent Configuration

    Controls how the AI-autonomous pentesting phase operates.
    """

    # LLM configuration
    llm_provider: str = "openai"  # openai, anthropic, azure
    llm_model: str = "gpt-4o"  # gpt-4o, claude-3-5-sonnet, etc.
    llm_api_key: str | None = None  # If None, uses environment variable

    # Prompt modules to load (vulnerability knowledge)
    modules: list[str] = field(default_factory=lambda: [
        "sql_injection",
        "xss",
        "rce",
        "ssrf",
        "auth_bypass",
    ])

    # Agent behavior
    max_agent_iterations: int = 30  # Max tool calls per session
    autonomous_exploitation: bool = False  # If True, attempts full exploitation
    confirm_before_exploit: bool = True  # Require human confirmation

    # Scope constraints
    stay_in_scope: bool = True
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    disallowed_paths: list[str] = field(default_factory=lambda: [
        "/admin",
        "/logout",
        "/delete",
    ])

    # Sandbox settings
    use_docker_sandbox: bool = True
    sandbox_network_mode: str = "bridge"
    sandbox_timeout: int = 300  # 5 min per sandbox session

    # Output
    save_agent_traces: bool = True
    trace_output_dir: str = "./aipt_traces"
