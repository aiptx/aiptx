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

# Scanner integrations
from aipt_v2.tools.scanners import (
    AcunetixTool,
    AcunetixConfig,
    ScanProfile,
    BurpTool,
    BurpConfig,
    get_acunetix,
    get_burp,
    acunetix_scan,
    acunetix_vulns,
    test_all_connections,
)

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
    full_mode: bool = False  # Enable all tools including exploitation

    # Output control
    verbose: bool = True  # Show verbose output and command results in real-time
    show_command_output: bool = True  # Display command stdout/stderr as it runs

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
    use_nessus: bool = False  # NEW
    use_zap: bool = False  # NEW
    acunetix_profile: str = "full"
    wait_for_scanners: bool = False
    scanner_timeout: int = 3600

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

        # State
        self.findings: List[Finding] = []
        self.phase_results: Dict[Phase, PhaseResult] = {}
        self.subdomains: List[str] = []
        self.live_hosts: List[str] = []
        self.scan_ids: Dict[str, str] = {}  # Scanner -> scan_id mapping

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

        logger.info(f"Orchestrator initialized for {self.domain}")
        logger.info(f"Output directory: {self.output_dir}")
        if self.config.enable_intelligence:
            logger.info("Intelligence module enabled (chaining, triage, scope)")

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

    def _log_phase(self, phase: Phase, message: str):
        """Log a phase message."""
        print(f"\n{'='*60}", flush=True)
        print(f"  [{phase.value.upper()}] {message}", flush=True)
        print(f"{'='*60}\n", flush=True)

    def _log_tool(self, tool: str, status: str = "running", elapsed: float = None, error: str = None):
        """Log tool execution with status indicator and elapsed time."""
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
        elif status == "error" and error:
            print(f"      \033[31m→ Error: {error[:100]}\033[0m", flush=True)
        elif status == "done" and self.config.verbose:
            pass  # Output already shown during execution

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

    def _add_finding(self, finding: Finding):
        """Add a finding and trigger callback."""
        self.findings.append(finding)
        if self.on_finding:
            self.on_finding(finding)

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
            # Security: Use safe_domain to prevent command injection
            ret, output = await self._run_command(
                f"echo {self.safe_domain} | waybackurls | head -5000"
            )
            tool_elapsed = time.time() - tool_start
            if ret == 0:
                (self.output_dir / f"wayback_{self.domain}.txt").write_text(output)
                url_count = len([u for u in output.split("\n") if u.strip()])
                tools_run.append("waybackurls")
                self._log_tool(f"waybackurls - {url_count} URLs", "done", tool_elapsed)
            else:
                errors.append(f"waybackurls failed: {output[:100] if output else 'unknown error'}")
                self._log_tool("waybackurls", "error", tool_elapsed, output[:100] if output else "command failed")

        # 5. Amass - Advanced Subdomain Enumeration (NEW)
        if "amass" in self.config.recon_tools:
            self._log_tool("amass", "running")
            tool_start = time.time()
            ret, output = await self._run_command(
                f"amass enum -passive -d {self.safe_domain} -timeout 5",
                timeout=360
            )
            tool_elapsed = time.time() - tool_start
            if ret == 0:
                subs = [s.strip() for s in output.split("\n") if s.strip()]
                self.subdomains.extend(subs)
                (self.output_dir / f"amass_{self.domain}.txt").write_text(output)
                tools_run.append("amass")
                self._log_tool(f"amass - {len(subs)} subdomains", "done", tool_elapsed)
            else:
                errors.append(f"amass failed: {output[:100] if output else 'unknown error'}")
                self._log_tool("amass", "error", tool_elapsed, output[:100] if output else "command failed")

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

        # 1. Nuclei Scanning
        if "nuclei" in self.config.scan_tools:
            self._log_tool("nuclei", "running")
            ret, output = await self._run_command(
                f"nuclei -u {self.target} -severity low,medium,high,critical -silent 2>/dev/null",
                timeout=600
            )
            if ret == 0:
                (self.output_dir / f"nuclei_{self.domain}.txt").write_text(output)
                tools_run.append("nuclei")

                # Parse nuclei findings
                for line in output.split("\n"):
                    if line.strip():
                        # Format: [template-id] [severity] [matched-at]
                        parts = line.split()
                        if len(parts) >= 2:
                            findings.append(Finding(
                                type="vulnerability",
                                value=parts[0] if parts else line,
                                description=line,
                                severity=self._parse_nuclei_severity(line),
                                phase="scan",
                                tool="nuclei",
                                target=self.domain
                            ))

                self._log_tool(f"nuclei - {len([f for f in findings if f.tool == 'nuclei'])} findings", "done")

        # 2. SSL/TLS Scanning
        if "sslscan" in self.config.scan_tools:
            self._log_tool("sslscan", "running")
            # Security: Use safe_domain to prevent command injection
            ret, output = await self._run_command(
                f"sslscan {self.safe_domain} 2>/dev/null"
            )
            if ret == 0:
                (self.output_dir / "sslscan_results.txt").write_text(output)
                tools_run.append("sslscan")

                # Check for weak ciphers
                if "Accepted" in output and ("RC4" in output or "DES" in output or "NULL" in output):
                    findings.append(Finding(
                        type="weak_cipher",
                        value="Weak TLS ciphers detected",
                        description="Server accepts weak cryptographic ciphers",
                        severity="medium",
                        phase="scan",
                        tool="sslscan",
                        target=self.domain
                    ))

                self._log_tool("sslscan - completed", "done")

        # 3. Directory Fuzzing
        if "ffuf" in self.config.scan_tools:
            self._log_tool("ffuf", "running")
            ret, output = await self._run_command(
                f"ffuf -u {self.target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -s 2>/dev/null | head -50",
                timeout=300
            )
            if ret == 0:
                (self.output_dir / f"ffuf_{self.domain}.txt").write_text(output)
                tools_run.append("ffuf")
                self._log_tool("ffuf - completed", "done")

        # 4. Nikto - Web Server Vulnerability Scanner (NEW)
        if "nikto" in self.config.scan_tools:
            self._log_tool("nikto", "running")
            ret, output = await self._run_command(
                f"nikto -h {self.target} -Format txt -output {self.output_dir}/nikto_{self.domain}.txt -Tuning 123bde 2>/dev/null",
                timeout=600
            )
            if ret == 0:
                tools_run.append("nikto")
                # Parse nikto findings
                for line in output.split("\n"):
                    if "+ " in line and ("OSVDB" in line or "vulnerability" in line.lower() or "outdated" in line.lower()):
                        severity = "medium"
                        if "critical" in line.lower() or "remote" in line.lower():
                            severity = "high"
                        findings.append(Finding(
                            type="web_vulnerability",
                            value=line.strip(),
                            description=line.strip(),
                            severity=severity,
                            phase="scan",
                            tool="nikto",
                            target=self.target
                        ))
                nikto_findings = len([f for f in findings if f.tool == "nikto"])
                self._log_tool(f"nikto - {nikto_findings} findings", "done")

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
                self._log_tool(f"testssl - {len(ssl_issues)} issues", "done")

        # 7. Gobuster - Directory/Vhost Enumeration (NEW)
        if "gobuster" in self.config.scan_tools:
            self._log_tool("gobuster", "running")
            ret, output = await self._run_command(
                f"gobuster dir -u {self.target} -w /usr/share/wordlists/dirb/common.txt -q -t 20 --no-error 2>/dev/null | head -100",
                timeout=300
            )
            if ret == 0:
                (self.output_dir / f"gobuster_{self.domain}.txt").write_text(output)
                tools_run.append("gobuster")
                # Parse discovered paths
                for line in output.split("\n"):
                    if line.strip() and ("Status:" in line or "(Status:" in line):
                        # Check for interesting paths
                        if any(p in line.lower() for p in ["admin", "backup", "config", "api", "debug", ".git"]):
                            findings.append(Finding(
                                type="interesting_path",
                                value=line.strip(),
                                description=f"Potentially sensitive path discovered: {line.strip()}",
                                severity="low",
                                phase="scan",
                                tool="gobuster",
                                target=self.target
                            ))
                self._log_tool("gobuster - completed", "done")

        # 8. Dirsearch - Advanced Directory Discovery (NEW)
        if "dirsearch" in self.config.scan_tools:
            self._log_tool("dirsearch", "running")
            ret, output = await self._run_command(
                f"dirsearch -u {self.target} -e php,asp,aspx,jsp,html,js -t 20 --format plain -o {self.output_dir}/dirsearch_{self.domain}.txt 2>/dev/null",
                timeout=300
            )
            if ret == 0:
                tools_run.append("dirsearch")
                self._log_tool("dirsearch - completed", "done")

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
                    self._log_tool(f"Acunetix - Scan started: {scan_id[:8]}...", "done")

                    # Optionally wait for completion
                    if self.config.wait_for_scanners:
                        self._log_tool("Acunetix - Waiting for completion...", "running")
                        result = acunetix.wait_for_scan(
                            scan_id,
                            timeout=self.config.scanner_timeout,
                            poll_interval=30
                        )

                        # Get vulnerabilities
                        vulns = acunetix.get_scan_vulnerabilities(scan_id)
                        for vuln in vulns:
                            findings.append(Finding(
                                type="vulnerability",
                                value=vuln.name,
                                description=vuln.description or vuln.name,
                                severity=vuln.severity,
                                phase="scan",
                                tool="acunetix",
                                target=vuln.affected_url,
                                metadata={
                                    "vuln_id": vuln.vuln_id,
                                    "cvss": vuln.cvss_score,
                                    "cwe": vuln.cwe_id
                                }
                            ))

                        self._log_tool(f"Acunetix - {len(vulns)} vulnerabilities found", "done")
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
                        models_findings.append(ModelsFinding(
                            title=f.value,
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

        # 1. Check Sensitive Endpoints
        if self.config.check_sensitive_paths:
            self._log_tool("Sensitive Path Check", "running")

            sensitive_paths = [
                "/metrics", "/actuator", "/actuator/health", "/actuator/env",
                "/.env", "/.git/config", "/swagger-ui.html", "/api/swagger",
                "/graphql", "/debug", "/admin", "/phpinfo.php",
                "/server-status", "/.aws/credentials", "/backup"
            ]

            for path in sensitive_paths:
                try:
                    ret, output = await self._run_command(
                        f"curl -s -o /dev/null -w '%{{http_code}}' '{self.target}{path}' --connect-timeout 5",
                        timeout=10
                    )
                    if ret == 0 and output.strip() in ["200", "301", "302"]:
                        severity = "high" if path in ["/.env", "/.git/config", "/.aws/credentials"] else "medium"
                        findings.append(Finding(
                            type="exposed_endpoint",
                            value=f"{self.target}{path}",
                            description=f"Sensitive endpoint accessible: {path} (HTTP {output.strip()})",
                            severity=severity,
                            phase="exploit",
                            tool="path_check",
                            target=self.target
                        ))
                except Exception:
                    continue

            exposed_count = len([f for f in findings if f.type == "exposed_endpoint"])
            tools_run.append("sensitive_path_check")
            self._log_tool(f"Sensitive Path Check - {exposed_count} exposed", "done")

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

        # ==================== EXPLOITATION TOOLS (Enabled in full_mode) ====================
        if self.config.full_mode or self.config.enable_exploitation:

            # 3. SQLMap - SQL Injection Testing (NEW)
            if "sqlmap" in self.config.exploit_tools:
                self._log_tool("sqlmap", "running")
                sqlmap_output_dir = self.output_dir / "sqlmap"
                sqlmap_output_dir.mkdir(exist_ok=True)

                # Run SQLMap in batch mode with safe settings
                ret, output = await self._run_command(
                    f"sqlmap -u {shlex.quote(self.target)} --batch --forms --crawl=2 "
                    f"--level={self.config.sqlmap_level} --risk={self.config.sqlmap_risk} "
                    f"--output-dir={sqlmap_output_dir} --random-agent 2>/dev/null",
                    timeout=self.config.sqlmap_timeout
                )
                if ret == 0:
                    (self.output_dir / f"sqlmap_{self.domain}.txt").write_text(output)
                    tools_run.append("sqlmap")

                    # Parse SQLMap findings
                    if "is vulnerable" in output.lower() or "injection" in output.lower():
                        # Extract vulnerable parameters
                        vuln_params = []
                        for line in output.split("\n"):
                            if "Parameter:" in line or "is vulnerable" in line:
                                vuln_params.append(line.strip())

                        if vuln_params:
                            findings.append(Finding(
                                type="sql_injection",
                                value="SQL Injection Detected",
                                description=f"SQL injection vulnerability found. Parameters: {'; '.join(vuln_params[:5])}",
                                severity="critical",
                                phase="exploit",
                                tool="sqlmap",
                                target=self.target,
                                metadata={"vulnerable_params": vuln_params}
                            ))
                            # Mark shell access if OS shell was obtained
                            if "--os-shell" in output or "os-shell" in output:
                                self.config.shell_obtained = True
                                self.config.target_os = "linux" if "linux" in output.lower() else "windows"

                    self._log_tool(f"sqlmap - {'Vulnerable!' if vuln_params else 'No injection found'}", "done")
                else:
                    self._log_tool("sqlmap - completed", "done")

            # 4. Commix - Command Injection Testing (NEW)
            if "commix" in self.config.exploit_tools:
                self._log_tool("commix", "running")
                ret, output = await self._run_command(
                    f"commix -u {shlex.quote(self.target)} --batch --crawl=1 --level=2 2>/dev/null",
                    timeout=300
                )
                if ret == 0:
                    (self.output_dir / f"commix_{self.domain}.txt").write_text(output)
                    tools_run.append("commix")

                    if "is vulnerable" in output.lower() or "command injection" in output.lower():
                        findings.append(Finding(
                            type="command_injection",
                            value="Command Injection Detected",
                            description="OS command injection vulnerability found",
                            severity="critical",
                            phase="exploit",
                            tool="commix",
                            target=self.target
                        ))
                        self.config.shell_obtained = True

                    self._log_tool("commix - completed", "done")

            # 5. XSStrike - XSS Detection (NEW)
            if "xsstrike" in self.config.exploit_tools:
                self._log_tool("xsstrike", "running")
                ret, output = await self._run_command(
                    f"xsstrike -u {shlex.quote(self.target)} --crawl -l 2 --blind 2>/dev/null",
                    timeout=300
                )
                if ret == 0:
                    (self.output_dir / f"xsstrike_{self.domain}.txt").write_text(output)
                    tools_run.append("xsstrike")

                    # Parse XSS findings
                    xss_count = output.lower().count("xss") + output.lower().count("reflection")
                    if xss_count > 0 or "vulnerable" in output.lower():
                        findings.append(Finding(
                            type="xss_vulnerability",
                            value="XSS Vulnerability Detected",
                            description=f"Cross-site scripting vulnerability detected",
                            severity="high",
                            phase="exploit",
                            tool="xsstrike",
                            target=self.target
                        ))

                    self._log_tool(f"xsstrike - {xss_count} potential XSS", "done")

            # 6. Hydra - Credential Brute-forcing (NEW)
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

        # 8. Fetch Acunetix Results (if scan completed)
        if "acunetix" in self.scan_ids and not self.config.wait_for_scanners:
            self._log_tool("Fetching Acunetix Results", "running")
            try:
                acunetix = get_acunetix()
                status = acunetix.get_scan_status(self.scan_ids["acunetix"])

                if status.status == "completed":
                    vulns = acunetix.get_scan_vulnerabilities(self.scan_ids["acunetix"])
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
                    self._log_tool(f"Acunetix Results - {len(vulns)} vulnerabilities", "done")
                else:
                    self._log_tool(f"Acunetix - Scan still {status.status} ({status.progress}%)", "done")
            except Exception as e:
                errors.append(f"Error fetching Acunetix results: {e}")

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
            sev = f.severity.lower()
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

    def _generate_html_report(self) -> str:
        """Generate HTML report."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        findings_html = ""
        for f in self.findings:
            sev_class = f.severity.lower()
            findings_html += f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="severity-badge {sev_class}">{f.severity.upper()}</span>
                    <span class="finding-title">{f.value}</span>
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
        print(f"  Exploitation: {'Enabled' if (self.config.full_mode or self.config.enable_exploitation) else 'Disabled'}")
        print("="*60 + "\n")

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

            if Phase.REPORT in phases and not self.config.skip_report:
                await self.run_report()

        except Exception as e:
            logger.exception(f"Orchestration error: {e}")
            raise

        total_duration = time.time() - start_time

        # Final summary
        print("\n" + "="*60)
        print("  SCAN COMPLETE")
        print("="*60)
        print(f"  Duration: {total_duration:.1f}s")
        print(f"  Findings: {len(self.findings)}")
        if self.attack_chains:
            print(f"  Attack Chains: {len(self.attack_chains)}")
        print(f"  Output: {self.output_dir}")
        print("="*60 + "\n")

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

Tools included:
  RECON:   subfinder, assetfinder, amass, nmap, waybackurls, theHarvester, dnsrecon, wafw00f, whatweb
  SCAN:    nuclei, ffuf, sslscan, nikto, wpscan, testssl, gobuster, dirsearch
  EXPLOIT: sqlmap, commix, xsstrike, hydra, searchsploit (--full mode)
  POST:    linpeas, winpeas, pspy, lazagne (auto-triggers on shell access)
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

    args = parser.parse_args()

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
        wait_for_scanners=args.wait,
        acunetix_profile=args.acunetix_profile,
        enable_exploitation=args.exploit or args.full,
        sqlmap_level=args.sqlmap_level,
        sqlmap_risk=args.sqlmap_risk,
        enable_container_scan=args.container,
        enable_secret_detection=args.secrets
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
