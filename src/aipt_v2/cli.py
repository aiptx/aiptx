"""
AIPTX Command Line Interface
============================

Entry point for the AIPTX command-line tool.
Zero-click installation: pipx install aiptx

Usage:
    aiptx setup                     # Run setup wizard (first-time)
    aiptx scan example.com          # Run security scan
    aiptx scan example.com --full   # Comprehensive scan
    aiptx api                       # Start REST API
    aiptx status                    # Check configuration
"""

import argparse
import asyncio
import os

# =============================================================================
# Readline Configuration (MUST be before any input operations)
# Fixes backspace/delete key handling on macOS and Linux
# =============================================================================
import platform
import sys
import warnings
from pathlib import Path

_is_windows = platform.system() == "Windows"

try:
    if _is_windows:
        # Windows: use pyreadline3 but skip Unix keybindings
        try:
            import pyreadline3 as readline

            # pyreadline3 handles keys differently, no special config needed
        except ImportError:
            readline = None  # readline not available
    else:
        import readline

        # macOS uses libedit which needs different configuration
        if readline.__doc__ and "libedit" in readline.__doc__:
            # macOS libedit compatibility
            readline.parse_and_bind("bind ^[[3~ delete-char")  # Delete key
            readline.parse_and_bind("bind ^H backward-delete-char")  # Backspace
            readline.parse_and_bind("bind ^? backward-delete-char")  # Alt backspace
        else:
            # GNU readline (Linux)
            readline.parse_and_bind(r'"\e[3~": delete-char')
            readline.parse_and_bind(r'"\C-h": backward-delete-char')
except ImportError:
    readline = None  # readline not available, basic input will be used

# Suppress noisy warnings for cleaner user experience
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", message=".*urllib3.*OpenSSL.*")
warnings.filterwarnings("ignore", message=".*NotOpenSSLWarning.*")
warnings.filterwarnings("ignore", message=".*coroutine.*was never awaited.*")
warnings.filterwarnings("ignore", message=".*Enable tracemalloc.*")

# Suppress litellm verbose output

os.environ.setdefault("LITELLM_LOG", "ERROR")
os.environ.setdefault("LITELLM_TELEMETRY", "false")

# Set default log level to WARNING before any imports that might log
os.environ.setdefault("AIPT_LOG_LEVEL", "WARNING")

# Handle imports for both installed package and local development
try:
    from . import __version__
    from .config import get_config, reload_config, validate_config_for_features
    from .interface.icons import icon, supports_emoji
    from .setup_wizard import is_configured, prompt_first_run_setup, run_setup_wizard
    from .utils.logging import logger, setup_logging
    from .utils.security import mask_path, sanitize_error_message
except ImportError:
    # Local development fallback
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from __init__ import __version__
    from config import get_config, reload_config, validate_config_for_features
    from interface.icons import icon
    from setup_wizard import is_configured, prompt_first_run_setup, run_setup_wizard
    from utils.logging import logger, setup_logging
    from utils.security import mask_path


def _get_llm_model_config():
    """
    Get LLM model configuration from user's config file.
    Returns (model_string, api_base) tuple formatted for litellm.
    Also sets appropriate environment variables for the provider.

    This function forcefully reloads the .env file to ensure the latest
    configuration is used (fixes caching issues).
    """
    import os
    from pathlib import Path

    from dotenv import load_dotenv

    # Forcefully reload the .env file to ensure we have the latest config
    # This fixes issues where the config was cached at module import time
    global_env = Path.home() / ".aiptx" / ".env"
    if global_env.exists():
        load_dotenv(global_env, override=True)

    local_env = Path(".env")
    if local_env.exists():
        load_dotenv(local_env, override=True)

    # Now reload the config with fresh environment variables
    config = reload_config()

    # Also check environment directly as a fallback
    provider = config.llm.provider.lower()
    base_model = config.llm.model
    api_key = config.llm.api_key
    api_base = config.llm.api_base

    # Fallback: Check environment variables directly if config has defaults
    env_provider = os.getenv("AIPT_LLM__PROVIDER") or os.getenv("AIPT_LLM_PROVIDER")
    env_model = os.getenv("AIPT_LLM__MODEL") or os.getenv("AIPT_LLM_MODEL")

    if env_provider:
        provider = env_provider.lower()
    if env_model:
        base_model = env_model

    # Build the model string for litellm based on provider
    # IMPORTANT: api_base should only be set for providers that need custom base URLs
    # (like Ollama). For cloud providers (Anthropic, OpenAI, etc.), we must NOT pass
    # api_base or litellm will incorrectly route requests to the wrong endpoint.
    final_api_base = None  # Default: let litellm use the provider's default endpoint

    if provider == "ollama":
        model = f"ollama/{base_model}" if not base_model.startswith("ollama/") else base_model
        # Ollama needs a custom base URL (defaults to localhost)
        final_api_base = (
            api_base
            or os.getenv("AIPT_LLM__OLLAMA_BASE_URL")
            or os.getenv("OLLAMA_API_BASE")
            or "http://localhost:11434"
        )
        os.environ["OLLAMA_API_BASE"] = final_api_base
    elif provider == "anthropic":
        model = f"anthropic/{base_model}" if not base_model.startswith("anthropic/") else base_model
        # Anthropic uses their cloud API - do NOT set api_base
        if api_key:
            os.environ["ANTHROPIC_API_KEY"] = api_key
    elif provider == "openai":
        model = f"openai/{base_model}" if not base_model.startswith("openai/") else base_model
        # For OpenAI-compatible providers (like custom deployments), api_base might be needed
        if api_base and not api_base.startswith("http://localhost"):
            final_api_base = api_base  # Only use if explicitly set and not localhost
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
    elif provider == "deepseek":
        model = f"deepseek/{base_model}" if not base_model.startswith("deepseek/") else base_model
        if api_key:
            os.environ["DEEPSEEK_API_KEY"] = api_key
    else:
        model = base_model
        if api_key:
            os.environ["LLM_API_KEY"] = api_key

    return model, final_api_base


def main():
    """Main CLI entry point."""
    # Handle keyboard interrupts gracefully at the top level
    import signal

    def signal_handler(signum, frame):
        """Handle interrupt signals gracefully."""
        from rich.console import Console

        Console().print("\n[yellow]Operation cancelled.[/yellow]")
        sys.exit(130)  # Standard exit code for Ctrl+C

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(
        prog="aiptx",
        description="AIPTX - AI-Powered Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aiptx scan example.com                   Run basic scan
  aiptx scan example.com --full            Run comprehensive scan
  aiptx scan example.com --ai              AI-guided scanning
  aiptx api                                Start REST API server
  aiptx status                             Check configuration status
  aiptx version                            Show version information

First-time setup:
  aiptx setup                              Interactive configuration wizard

Installation:
  pipx install aiptx                       Zero-click install
  pip install aiptx[full]                  Install with all features
        """,
    )

    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"AIPTX v{__version__}",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity (use -vv for debug)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("target", help="Target URL or domain")
    scan_parser.add_argument("--client", "-c", help="Client name")
    scan_parser.add_argument("--output", "-o", help="Output directory")
    scan_parser.add_argument(
        "--mode",
        "-m",
        choices=["quick", "standard", "full", "ai"],
        default="standard",
        help="Scan mode (default: standard)",
    )
    scan_parser.add_argument(
        "--full",
        action="store_true",
        help="Run full comprehensive scan (60-90 min with enterprise scanners)",
    )
    scan_parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan - skip enterprise scanners (Acunetix/Nessus/Burp/ZAP)",
    )
    scan_parser.add_argument("--ai", action="store_true", help="Enable AI-guided scanning")
    scan_parser.add_argument("--use-vps", action="store_true", help="Use VPS for tool execution")
    scan_parser.add_argument("--use-acunetix", action="store_true", help="Include Acunetix scan")
    scan_parser.add_argument("--use-burp", action="store_true", help="Include Burp Suite scan")
    scan_parser.add_argument("--skip-recon", action="store_true", help="Skip reconnaissance phase")
    scan_parser.add_argument(
        "--quiet", "-q", action="store_true", help="Quiet mode - minimal output"
    )
    scan_parser.add_argument(
        "--no-stream", action="store_true", help="Don't stream command output (show progress only)"
    )
    scan_parser.add_argument(
        "--check",
        action="store_true",
        help="Run pre-flight checks to validate config/connections before scan",
    )

    # v4.0 Enhanced scanning options
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "sarif", "html"],
        default="text",
        help="Output format (default: text, use sarif for GitHub Security integration)",
    )
    scan_parser.add_argument(
        "--sast", action="store_true", help="Include SAST (source code) analysis"
    )
    scan_parser.add_argument("--dast", action="store_true", help="Include DAST (runtime) analysis")
    scan_parser.add_argument(
        "--business-logic", action="store_true", help="Enable business logic testing"
    )
    scan_parser.add_argument(
        "--websocket", action="store_true", help="Include WebSocket endpoint testing"
    )
    scan_parser.add_argument(
        "--spa", action="store_true", help="Enable SPA (browser-based) scanning"
    )
    scan_parser.add_argument(
        "--graphql", action="store_true", help="Enhanced GraphQL security testing"
    )
    scan_parser.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit with error if findings >= severity (for CI/CD)",
    )
    scan_parser.add_argument(
        "--validate-pocs", action="store_true", help="Validate findings with PoC execution"
    )
    scan_parser.add_argument(
        "--sarif-output", help="Path for SARIF output file (implies --format sarif)"
    )
    scan_parser.add_argument(
        "--playbook",
        choices=["web", "web_api", "api", "graphql", "ad", "ad_quick"],
        default=None,
        help="Use a structured attack playbook (v5.1)",
    )
    scan_parser.add_argument(
        "--parallel", action="store_true", help="Enable parallel worker execution"
    )

    # API command
    api_parser = subparsers.add_parser("api", help="Start REST API server")
    # Security: Default to localhost to prevent accidental network exposure
    api_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="API host (default: 127.0.0.1, use 0.0.0.0 for network access)",
    )
    api_parser.add_argument("--port", "-p", type=int, default=8000, help="API port (default: 8000)")
    api_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )

    # Status command
    subparsers.add_parser("status", help="Check configuration and dependencies")

    # Check command - Enterprise prerequisites validation
    check_parser = subparsers.add_parser(
        "check", help="Run enterprise prerequisites check before operations"
    )
    check_parser.add_argument(
        "--strict", "-s", action="store_true", help="Fail on warnings (for CI/CD pipelines)"
    )
    check_parser.add_argument(
        "--json", "-j", action="store_true", help="Output JSON format for automation"
    )
    check_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show all checks including passed ones"
    )
    check_parser.add_argument(
        "--minimal", "-m", action="store_true", help="Skip optional dependency checks"
    )

    # Test command - validate all configurations
    test_parser = subparsers.add_parser("test", help="Test and validate all configurations")
    test_parser.add_argument("--llm", action="store_true", help="Test LLM API key only")
    test_parser.add_argument("--vps", action="store_true", help="Test VPS connection only")
    test_parser.add_argument(
        "--scanners", action="store_true", help="Test scanner integrations only"
    )
    test_parser.add_argument("--tools", action="store_true", help="Test local tool availability")
    test_parser.add_argument("--all", "-a", action="store_true", help="Test everything (default)")

    # Version command
    subparsers.add_parser("version", help="Show detailed version information")

    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Run interactive setup wizard")
    setup_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force reconfiguration even if already configured",
    )

    # VPS command with subcommands
    vps_parser = subparsers.add_parser("vps", help="VPS remote execution management")
    vps_subparsers = vps_parser.add_subparsers(dest="vps_command", help="VPS commands")

    # vps setup - Install tools on VPS
    vps_setup = vps_subparsers.add_parser("setup", help="Install security tools on VPS")
    vps_setup.add_argument(
        "--categories",
        "-c",
        nargs="+",
        choices=["recon", "scan", "exploit", "post_exploit", "api", "network"],
        help="Tool categories to install (default: all)",
    )
    vps_setup.add_argument("--tools", "-t", nargs="+", help="Specific tools to install")

    # vps status - Check VPS connection and tools
    vps_subparsers.add_parser("status", help="Check VPS connection and installed tools")

    # vps scan - Run scan from VPS
    vps_scan = vps_subparsers.add_parser("scan", help="Run security scan from VPS")
    vps_scan.add_argument("target", help="Target URL or domain")
    vps_scan.add_argument(
        "--mode", "-m", choices=["quick", "standard", "full"], default="standard", help="Scan mode"
    )
    vps_scan.add_argument("--tools", "-t", nargs="+", help="Specific tools to run")

    # vps script - Generate setup script
    vps_script = vps_subparsers.add_parser("script", help="Generate VPS setup script")
    vps_script.add_argument("--output", "-o", help="Output file (default: stdout)")
    vps_script.add_argument("--categories", "-c", nargs="+", help="Tool categories to include")

    # Verify command - Installation verification
    verify_parser = subparsers.add_parser("verify", help="Verify installation and configuration")
    verify_parser.add_argument("--quick", "-q", action="store_true", help="Run quick checks only")
    verify_parser.add_argument("--fix", action="store_true", help="Attempt to auto-fix issues")
    verify_parser.add_argument("--report", "-r", help="Save markdown report to file")

    # Shell command - Interactive shell
    shell_parser = subparsers.add_parser("shell", help="Start interactive security shell")
    shell_parser.add_argument("--log", "-l", help="Log session to file")
    shell_parser.add_argument("--dir", "-d", help="Working directory")

    # Tools command with subcommands
    tools_parser = subparsers.add_parser("tools", help="Manage local security tools")
    tools_subparsers = tools_parser.add_subparsers(dest="tools_command", help="Tools commands")

    # tools install - Install security tools
    tools_install = tools_subparsers.add_parser(
        "install", help="Install security tools on local system"
    )
    tools_install.add_argument(
        "--categories",
        "-c",
        nargs="+",
        choices=[
            "recon",
            "scan",
            "exploit",
            "post_exploit",
            "api",
            "network",
            "prerequisite",
            "active_directory",
            "cloud",
            "container",
            "osint",
            "wireless",
            "web",
            "secrets",
            "mobile",
        ],
        help="Tool categories to install (default: core tools)",
    )
    tools_install.add_argument("--tools", "-t", nargs="+", help="Specific tools to install")
    tools_install.add_argument(
        "--all", "-a", action="store_true", help="Install all available tools"
    )
    tools_install.add_argument(
        "--core", action="store_true", help="Install only core essential tools (default)"
    )
    tools_install.add_argument(
        "--no-sudo", action="store_true", help="Don't use sudo for installation"
    )

    # tools list - List available/installed tools
    tools_list = tools_subparsers.add_parser("list", help="List available and installed tools")
    tools_list.add_argument(
        "--category",
        "-c",
        choices=[
            "recon",
            "scan",
            "exploit",
            "post_exploit",
            "api",
            "network",
            "prerequisite",
            "active_directory",
            "cloud",
            "container",
            "osint",
            "wireless",
            "web",
            "secrets",
            "mobile",
            "all",
        ],
        default="all",
        help="Filter by category",
    )
    tools_list.add_argument(
        "--installed-only", action="store_true", help="Show only installed tools"
    )

    # tools check - Check tool availability
    tools_subparsers.add_parser("check", help="Check which tools are installed")

    # AI Skills command with subcommands
    ai_parser = subparsers.add_parser(
        "ai", help="AI-powered security testing (code review, API testing, web pentesting)"
    )
    ai_subparsers = ai_parser.add_subparsers(dest="ai_command", help="AI testing commands")

    # ai code-review - AI source code security review
    ai_code = ai_subparsers.add_parser("code-review", help="AI-powered source code security review")
    ai_code.add_argument("target", help="Path to code directory to review")
    ai_code.add_argument(
        "--focus",
        "-f",
        nargs="+",
        choices=["sqli", "xss", "auth", "crypto", "secrets", "injection"],
        help="Focus areas for review",
    )
    ai_code.add_argument(
        "--model",
        "-m",
        default="claude-3-7-sonnet-20250219",
        help="LLM model to use (default: claude-3-7-sonnet-20250219)",
    )
    ai_code.add_argument(
        "--max-steps", type=int, default=100, help="Maximum agent steps (default: 100)"
    )
    ai_code.add_argument(
        "--quick", "-q", action="store_true", help="Quick scan focusing on high-priority patterns"
    )
    ai_code.add_argument("--output", "-o", help="Output file for results (JSON)")

    # ai api-test - AI API security testing
    ai_api = ai_subparsers.add_parser("api-test", help="AI-powered REST API security testing")
    ai_api.add_argument("target", help="Base URL of the API to test")
    ai_api.add_argument("--openapi", "-s", help="Path or URL to OpenAPI/Swagger spec")
    ai_api.add_argument("--auth-token", "-t", help="Bearer token for API authentication")
    ai_api.add_argument(
        "--model", "-m", default="claude-3-7-sonnet-20250219", help="LLM model to use"
    )
    ai_api.add_argument("--max-steps", type=int, default=100, help="Maximum agent steps")
    ai_api.add_argument("--output", "-o", help="Output file for results (JSON)")

    # ai web-pentest - AI web penetration testing
    ai_web = ai_subparsers.add_parser(
        "web-pentest", help="AI-powered web application penetration testing"
    )
    ai_web.add_argument("target", help="Target URL to test")
    ai_web.add_argument("--auth-token", "-t", help="Bearer token for authentication")
    ai_web.add_argument(
        "--cookie", "-c", action="append", help="Cookies for authenticated testing (key=value)"
    )
    ai_web.add_argument(
        "--model", "-m", default="claude-3-7-sonnet-20250219", help="LLM model to use"
    )
    ai_web.add_argument("--max-steps", type=int, default=100, help="Maximum agent steps")
    ai_web.add_argument(
        "--quick", "-q", action="store_true", help="Quick scan focusing on critical vulnerabilities"
    )
    ai_web.add_argument("--output", "-o", help="Output file for results (JSON)")

    # ai full - Full AI-driven security assessment
    ai_full = ai_subparsers.add_parser("full", help="Full AI-driven security assessment")
    ai_full.add_argument("target", help="Target URL or code path")
    ai_full.add_argument(
        "--types",
        "-t",
        nargs="+",
        choices=["web", "api", "code"],
        default=["web"],
        help="Types of testing to perform",
    )
    ai_full.add_argument(
        "--model", "-m", default="claude-3-7-sonnet-20250219", help="LLM model to use"
    )
    ai_full.add_argument("--output", "-o", help="Output file for results (JSON)")

    # ========== AD (Active Directory) Commands (v5.0) ==========
    ad_parser = subparsers.add_parser("ad", help="Active Directory penetration testing (v5.0)")
    ad_subparsers = ad_parser.add_subparsers(dest="ad_command", help="AD commands")

    # ad recon - Domain reconnaissance
    ad_recon = ad_subparsers.add_parser("recon", help="AD domain reconnaissance and enumeration")
    ad_recon.add_argument("domain", help="Target AD domain (e.g., corp.local)")
    ad_recon.add_argument("--dc", "-d", help="Domain Controller IP address")
    ad_recon.add_argument("--username", "-u", help="Username for authenticated enumeration")
    ad_recon.add_argument("--password", "-p", help="Password (will prompt if not provided)")
    ad_recon.add_argument("--hash", "-H", help="NTLM hash for Pass-the-Hash")
    ad_recon.add_argument(
        "--method",
        "-m",
        choices=["dns", "ldap", "smb", "kerberos", "all"],
        default="all",
        help="Reconnaissance method (default: all)",
    )
    ad_recon.add_argument("--output", "-o", help="Output file for results (JSON)")
    ad_recon.add_argument("--bloodhound", "-b", action="store_true", help="Collect BloodHound data")

    # ad scan - AD vulnerability scanning
    ad_scan = ad_subparsers.add_parser(
        "scan", help="Scan AD for vulnerabilities and misconfigurations"
    )
    ad_scan.add_argument("domain", help="Target AD domain")
    ad_scan.add_argument("--dc", "-d", required=True, help="Domain Controller IP address")
    ad_scan.add_argument("--username", "-u", required=True, help="Username for scanning")
    ad_scan.add_argument("--password", "-p", help="Password (will prompt if not provided)")
    ad_scan.add_argument("--hash", "-H", help="NTLM hash for Pass-the-Hash")
    ad_scan.add_argument(
        "--type",
        "-t",
        nargs="+",
        choices=["privesc", "adcs", "delegation", "acl", "winpwn", "all"],
        default=["all"],
        help="Scan types (default: all)",
    )
    ad_scan.add_argument("--output", "-o", help="Output file for results (JSON)")
    ad_scan.add_argument(
        "--winpwn-script", dest="winpwn_script", help="Path to WinPwn.ps1 for WinPwn scans"
    )
    ad_scan.add_argument(
        "--extract-creds",
        dest="extract_creds",
        action="store_true",
        help="Enable credential extraction in WinPwn scan",
    )

    # ad attack - Execute AD attack chains
    ad_attack = ad_subparsers.add_parser(
        "attack", help="Execute AD attack chains (authorized testing only)"
    )
    ad_attack.add_argument("domain", help="Target AD domain")
    ad_attack.add_argument("--dc", "-d", required=True, help="Domain Controller IP address")
    ad_attack.add_argument("--username", "-u", required=True, help="Username")
    ad_attack.add_argument("--password", "-p", help="Password (will prompt if not provided)")
    ad_attack.add_argument("--hash", "-H", help="NTLM hash for Pass-the-Hash")
    ad_attack.add_argument(
        "--chain",
        "-c",
        choices=[
            "kerberoast",
            "asreproast",
            "rbcd",
            "adcs-esc1",
            "adcs-esc8",
            "golden-ticket",
            "auto",
        ],
        default="auto",
        help="Attack chain to execute (default: auto - LLM selects)",
    )
    ad_attack.add_argument(
        "--stealth",
        "-s",
        choices=["fast", "balanced", "stealth", "paranoid"],
        default="balanced",
        help="Stealth profile (default: balanced)",
    )
    ad_attack.add_argument("--output", "-o", help="Output file for results (JSON)")
    ad_attack.add_argument(
        "--dry-run", action="store_true", help="Show attack plan without executing"
    )

    # ad tools - List available AD tools
    ad_tools = ad_subparsers.add_parser("tools", help="Check available AD security tools")

    # ========== MCP Commands (v5.1 - PentestAgent Integration) ==========
    mcp_parser = subparsers.add_parser("mcp", help="Manage MCP (Model Context Protocol) servers")
    mcp_subparsers = mcp_parser.add_subparsers(dest="mcp_command", help="MCP commands")

    # mcp list - List configured servers
    mcp_subparsers.add_parser("list", help="List configured MCP servers")

    # mcp add - Add a new server
    mcp_add = mcp_subparsers.add_parser("add", help="Add a new MCP server")
    mcp_add.add_argument("name", help="Server name (unique identifier)")
    mcp_add.add_argument("--command", "-c", required=True, help="Command to start the server")
    mcp_add.add_argument(
        "--args", "-a", nargs="*", default=[], help="Arguments for the server command"
    )
    mcp_add.add_argument(
        "--env", "-e", nargs="*", default=[], help="Environment variables (KEY=VALUE)"
    )

    # mcp remove - Remove a server
    mcp_remove = mcp_subparsers.add_parser("remove", help="Remove an MCP server")
    mcp_remove.add_argument("name", help="Server name to remove")

    # mcp connect - Connect and list available tools
    mcp_connect = mcp_subparsers.add_parser("connect", help="Connect to MCP servers and list tools")
    mcp_connect.add_argument("--server", "-s", help="Specific server to connect to (default: all)")

    # ========== Notes Commands (v5.1 - PentestAgent Integration) ==========
    notes_parser = subparsers.add_parser("notes", help="Quick findings and notes management")
    notes_subparsers = notes_parser.add_subparsers(dest="notes_command", help="Notes commands")

    # notes create
    notes_create = notes_subparsers.add_parser("create", help="Create a new note")
    notes_create.add_argument("key", help="Unique key for the note")
    notes_create.add_argument("value", help="Note content")
    notes_create.add_argument(
        "--category",
        "-c",
        choices=["finding", "credential", "vulnerability", "artifact", "task", "info"],
        default="info",
        help="Note category",
    )
    notes_create.add_argument(
        "--severity",
        "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Severity level",
    )
    notes_create.add_argument("--evidence", "-e", help="Supporting evidence")

    # notes list
    notes_list = notes_subparsers.add_parser("list", help="List all notes")
    notes_list.add_argument("--category", "-c", help="Filter by category")
    notes_list.add_argument("--severity", "-s", help="Filter by severity")

    # notes search
    notes_search = notes_subparsers.add_parser("search", help="Search notes by content")
    notes_search.add_argument("query", help="Search query")

    # notes export
    notes_export = notes_subparsers.add_parser("export", help="Export notes")
    notes_export.add_argument(
        "--format", "-f", choices=["json", "markdown"], default="json", help="Export format"
    )
    notes_export.add_argument("--output", "-o", help="Output file (default: stdout)")

    # notes delete
    notes_delete = notes_subparsers.add_parser("delete", help="Delete a note")
    notes_delete.add_argument("key", help="Note key to delete")

    # notes clear
    notes_subparsers.add_parser("clear", help="Clear all notes")

    # ========== Playbooks Command (v5.1) ==========
    playbook_parser = subparsers.add_parser("playbook", help="Attack playbook management")
    playbook_subparsers = playbook_parser.add_subparsers(
        dest="playbook_command", help="Playbook commands"
    )

    # playbook list
    playbook_subparsers.add_parser("list", help="List available playbooks")

    # playbook show
    playbook_show = playbook_subparsers.add_parser("show", help="Show playbook details")
    playbook_show.add_argument("name", help="Playbook name")

    args = parser.parse_args()

    # Setup logging based on verbosity
    log_level = "DEBUG" if args.verbose >= 2 else "INFO" if args.verbose == 1 else "WARNING"
    setup_logging(level=log_level, json_format=args.json)

    # Handle commands - wrap in try/except for graceful interrupt handling
    try:
        if args.command == "setup":
            return run_setup(args)
        elif args.command == "scan":
            return run_scan(args)
        elif args.command == "api":
            return run_api(args)
        elif args.command == "status":
            return show_status(args)
        elif args.command == "check":
            return run_check(args)
        elif args.command == "test":
            return run_config_test(args)
        elif args.command == "version":
            return show_version()
        elif args.command == "vps":
            return run_vps_command(args)
        elif args.command == "tools":
            return run_tools_command(args)
        elif args.command == "shell":
            return run_shell(args)
        elif args.command == "verify":
            return run_verify(args)
        elif args.command == "ai":
            return run_ai_command(args)
        elif args.command == "ad":
            return run_ad_command(args)
        elif args.command == "mcp":
            return run_mcp_command(args)
        elif args.command == "notes":
            return run_notes_command(args)
        elif args.command == "playbook":
            return run_playbook_command(args)
        else:
            # No command given - start interactive mode
            return run_interactive_mode()
    except KeyboardInterrupt:
        # Gracefully handle Ctrl+C
        from rich.console import Console

        Console().print("\n[yellow]Operation cancelled.[/yellow]")
        return 130


def show_first_run_help():
    """Show helpful guidance for first-time users."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    console.print()
    console.print(
        Panel(
            "[bold cyan]Welcome to AIPTX![/bold cyan]\n\n"
            "[bold yellow]First-time setup required[/bold yellow]\n\n"
            "AIPTX needs an LLM API key to power AI-guided security testing.\n\n"
            "[bold]Quick Start:[/bold]\n"
            "  1. Run [bold green]aiptx setup[/bold green] to configure interactively\n"
            "  2. Or set environment variable:\n"
            "     [dim]export ANTHROPIC_API_KEY=your-key-here[/dim]\n\n"
            "[bold]Then run:[/bold]\n"
            "  [bold green]aiptx scan example.com[/bold green]",
            title=f"{icon('rocket')} AIPTX - AI-Powered Penetration Testing",
            border_style="cyan",
            padding=(1, 2),
        )
    )
    console.print()

    return 0


def run_interactive_mode():
    """Run AIPTX in interactive shell mode with hacker aesthetic."""
    import os
    import platform
    import socket
    from datetime import datetime

    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text

    console = Console()
    term_width = console.size.width

    # Hacker-style color constants
    NEON_GREEN = "#00ff41"
    DARK_GREEN = "#008f11"
    MATRIX_GREEN = "#00ff00"
    CYBER_BLUE = "#00d4ff"
    BLOOD_RED = "#ff0040"
    GHOST_WHITE = "#c0c0c0"

    # Epic ASCII banner with cyber styling
    banner = f"""
[bold {NEON_GREEN}]    ╔═══════════════════════════════════════════════════════════════════════════════╗[/]
[bold {NEON_GREEN}]    ║[/] [bold {MATRIX_GREEN}]   █████╗ ██╗██████╗ ████████╗██╗  ██╗[/]                                      [bold {NEON_GREEN}]║[/]
[bold {NEON_GREEN}]    ║[/] [bold {MATRIX_GREEN}]  ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝[/]                                      [bold {NEON_GREEN}]║[/]
[bold {NEON_GREEN}]    ║[/] [bold {CYBER_BLUE}]  ███████║██║██████╔╝   ██║    ╚███╔╝ [/]   [bold white]AI-POWERED PENETRATION TESTING[/]   [bold {NEON_GREEN}]║[/]
[bold {NEON_GREEN}]    ║[/] [bold {CYBER_BLUE}]  ██╔══██║██║██╔═══╝    ██║    ██╔██╗ [/]   [dim {GHOST_WHITE}]Autonomous Security Framework[/]    [bold {NEON_GREEN}]║[/]
[bold {NEON_GREEN}]    ║[/] [{BLOOD_RED}]  ██║  ██║██║██║        ██║   ██╔╝ ██╗[/]   [dim]v{__version__} // aiptx.io[/]              [bold {NEON_GREEN}]║[/]
[bold {NEON_GREEN}]    ║[/] [{BLOOD_RED}]  ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝[/]                                      [bold {NEON_GREEN}]║[/]
[bold {NEON_GREEN}]    ╚═══════════════════════════════════════════════════════════════════════════════╝[/]"""

    # Clear screen and show banner
    console.clear()
    console.print(Align.center(banner))

    # System info bar (like neofetch)
    try:
        hostname = socket.gethostname()
        username = os.getenv("USER") or os.getenv("USERNAME") or "operator"
        os_info = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()
        current_time = datetime.now().strftime("%H:%M:%S")
    except Exception:
        hostname = "localhost"
        username = "operator"
        os_info = platform.system()
        py_version = platform.python_version()
        current_time = datetime.now().strftime("%H:%M:%S")

    # Status indicators
    config_status = (
        f"[bold {NEON_GREEN}]●[/] READY"
        if is_configured()
        else f"[bold {BLOOD_RED}]●[/] UNCONFIGURED"
    )

    sys_info = Text()
    sys_info.append("    ┌─", style=f"dim {DARK_GREEN}")
    sys_info.append(f" {username}@{hostname}", style=f"bold {NEON_GREEN}")
    sys_info.append(" │ ", style=f"dim {DARK_GREEN}")
    sys_info.append(f"󰌽 {os_info}", style=f"{GHOST_WHITE}")
    sys_info.append(" │ ", style=f"dim {DARK_GREEN}")
    sys_info.append(f" Python {py_version}", style=f"{GHOST_WHITE}")
    sys_info.append(" │ ", style=f"dim {DARK_GREEN}")
    sys_info.append(f" {current_time}", style=f"{GHOST_WHITE}")
    sys_info.append(" │ ", style=f"dim {DARK_GREEN}")
    sys_info.append(config_status)
    sys_info.append(" ─┐", style=f"dim {DARK_GREEN}")

    console.print()
    console.print(Align.center(sys_info))
    console.print()

    # Cyber separator
    separator = f"[{DARK_GREEN}]" + "═" * term_width + f"[/{DARK_GREEN}]"
    console.print(separator)
    console.print()

    # Command modules in a grid layout
    modules_left = Table(
        show_header=True,
        header_style=f"bold {CYBER_BLUE}",
        box=box.ROUNDED,
        border_style=DARK_GREEN,
        padding=(0, 1),
        expand=True,
    )
    modules_left.add_column("⚡ ATTACK MODULES", style=f"bold {NEON_GREEN}")
    modules_left.add_column("", style=f"dim {GHOST_WHITE}")

    modules_left.add_row("[bold]scan[/] <target>", "→ Execute security scan")
    modules_left.add_row("[bold]scan[/] <target> [cyan]--ai[/]", "→ AI-guided exploitation")
    modules_left.add_row("[bold]scan[/] <target> [cyan]--full[/]", "→ Deep penetration test")
    modules_left.add_row("[bold]ai[/] <command>", "→ AI security analysis")
    modules_left.add_row("[bold]vps[/] <command>", "→ Remote VPS execution")

    modules_right = Table(
        show_header=True,
        header_style=f"bold {CYBER_BLUE}",
        box=box.ROUNDED,
        border_style=DARK_GREEN,
        padding=(0, 1),
        expand=True,
    )
    modules_right.add_column("🔧 SYSTEM", style=f"bold {NEON_GREEN}")
    modules_right.add_column("", style=f"dim {GHOST_WHITE}")

    modules_right.add_row("[bold]setup[/]", "→ Configure framework")
    modules_right.add_row("[bold]status[/]", "→ System diagnostics")
    modules_right.add_row("[bold]test[/]", "→ Validate connections")
    modules_right.add_row("[bold]help[/]", "→ Command reference")
    modules_right.add_row("[bold]exit[/]", "→ Terminate session")

    # Display modules side by side
    console.print(Columns([modules_left, modules_right], expand=True, padding=2))
    console.print()

    # Bottom separator with tips
    console.print(separator)
    console.print()

    tip_text = Text()
    tip_text.append("    [", style=f"dim {DARK_GREEN}")
    tip_text.append("!", style=f"bold {BLOOD_RED}")
    tip_text.append("] ", style=f"dim {DARK_GREEN}")
    tip_text.append("Quick Start", style=f"bold {CYBER_BLUE}")
    tip_text.append(": ", style="dim")
    tip_text.append("scan target.com --ai", style=f"bold {NEON_GREEN}")
    tip_text.append("    ", style="dim")
    tip_text.append("[", style=f"dim {DARK_GREEN}")
    tip_text.append("?", style=f"bold {CYBER_BLUE}")
    tip_text.append("] ", style=f"dim {DARK_GREEN}")
    tip_text.append("Docs", style=f"bold {CYBER_BLUE}")
    tip_text.append(": ", style="dim")
    tip_text.append("https://aiptx.io/docs", style=f"underline {GHOST_WHITE}")

    console.print(Align.center(tip_text))
    console.print()

    # Warning panel if not configured
    if not is_configured():
        warning_panel = Panel(
            f"[bold {BLOOD_RED}]⚠ FRAMEWORK NOT INITIALIZED[/]\n\n"
            f"[{GHOST_WHITE}]Execute [bold {NEON_GREEN}]setup[/] to configure API keys and scanner integrations.\n"
            f"Alternative: [dim]export ANTHROPIC_API_KEY=<your-key>[/dim][/]",
            border_style=BLOOD_RED,
            title=f"[bold {BLOOD_RED}][ ALERT ][/]",
            title_align="center",
            width=term_width,
        )
        console.print(warning_panel)
        console.print()

    # Interactive loop
    while True:
        try:
            # Flush stdin to avoid stale input from previous commands
            import sys

            if sys.stdin.isatty():
                # Clear any buffered input (platform-specific)
                if platform.system() == "Windows":
                    import msvcrt

                    while msvcrt.kbhit():
                        msvcrt.getch()
                else:
                    import select

                    while select.select([sys.stdin], [], [], 0)[0]:
                        sys.stdin.read(1)

            # Hacker-style prompt
            prompt_time = datetime.now().strftime("%H:%M:%S")
            prompt_text = f"[dim {DARK_GREEN}]┌──([/][bold {NEON_GREEN}]aiptx[/][dim {DARK_GREEN}])─[[/][dim]{prompt_time}[/][dim {DARK_GREEN}]][/]\n[dim {DARK_GREEN}]└─[/][bold {BLOOD_RED}]$[/]"
            user_input = Prompt.ask(prompt_text, default="").strip()

            if not user_input:
                continue

            # Parse the input
            parts = user_input.split()
            cmd = parts[0].lower()
            args_list = parts[1:] if len(parts) > 1 else []

            # Handle commands
            if cmd in ("exit", "quit", "q"):
                console.print()
                exit_msg = Text()
                exit_msg.append("\n    [", style=f"dim {DARK_GREEN}")
                exit_msg.append("✓", style=f"bold {NEON_GREEN}")
                exit_msg.append("] ", style=f"dim {DARK_GREEN}")
                exit_msg.append("Session terminated. ", style=f"{GHOST_WHITE}")
                exit_msg.append("Stay stealthy.", style=f"italic {DARK_GREEN}")
                exit_msg.append("\n    [", style=f"dim {DARK_GREEN}")
                exit_msg.append("→", style=f"bold {CYBER_BLUE}")
                exit_msg.append("] ", style=f"dim {DARK_GREEN}")
                exit_msg.append("https://aiptx.io", style=f"underline dim {GHOST_WHITE}")
                exit_msg.append("\n")
                console.print(exit_msg)
                break

            elif cmd == "help":
                show_interactive_help(console)

            elif cmd == "clear":
                console.clear()

            elif cmd == "setup":
                run_setup_wrapper()

            elif cmd == "status":
                show_status_wrapper()

            elif cmd == "test":
                run_test_wrapper(parts[1:] if len(parts) > 1 else None)

            elif cmd == "version":
                console.print(f"[cyan]AIPTX v{__version__}[/cyan]")

            elif cmd == "scan":
                if not args_list:
                    console.print("[red]Usage:[/red] scan <target> [--mode quick|standard|full]")
                else:
                    run_scan_wrapper(args_list)

            elif cmd == "vps":
                run_vps_wrapper(args_list)

            elif cmd == "ai":
                run_ai_wrapper(args_list)

            else:
                console.print(f"[red]Unknown command:[/red] {cmd}")
                console.print("[dim]Type 'help' for available commands[/dim]")

        except KeyboardInterrupt:
            console.print("\n[dim]Press Ctrl+C again to exit, or type 'exit'[/dim]")
            try:
                # Give user a chance to continue
                continue
            except KeyboardInterrupt:
                console.print("\n[dim]Goodbye![/dim]")
                break
        except EOFError:
            # Handle Ctrl+D
            console.print("\n[dim]Goodbye![/dim]")
            break

    return 0


def show_interactive_help(console):
    """Show help for interactive mode with hacker aesthetic."""
    from rich import box
    from rich.align import Align
    from rich.table import Table
    from rich.text import Text

    # Hacker colors
    NEON_GREEN = "#00ff41"
    DARK_GREEN = "#008f11"
    CYBER_BLUE = "#00d4ff"
    BLOOD_RED = "#ff0040"
    GHOST_WHITE = "#c0c0c0"

    term_width = console.size.width

    # Header
    header = Text()
    header.append(
        "╔══════════════════════════════════════════════════════════════════╗\n",
        style=f"bold {DARK_GREEN}",
    )
    header.append("║", style=f"bold {DARK_GREEN}")
    header.append(
        "                    AIPTX COMMAND REFERENCE                       ",
        style=f"bold {CYBER_BLUE}",
    )
    header.append("║\n", style=f"bold {DARK_GREEN}")
    header.append(
        "╚══════════════════════════════════════════════════════════════════╝",
        style=f"bold {DARK_GREEN}",
    )

    console.print()
    console.print(Align.center(header))
    console.print()

    # Attack modules
    attack_table = Table(
        show_header=True,
        header_style=f"bold {BLOOD_RED}",
        box=box.HEAVY_EDGE,
        border_style=DARK_GREEN,
        expand=True,
        title=f"[bold {BLOOD_RED}]⚔ ATTACK VECTORS[/]",
        title_style=f"bold {BLOOD_RED}",
    )
    attack_table.add_column("MODULE", style=f"bold {NEON_GREEN}", ratio=1)
    attack_table.add_column("FUNCTION", style=f"{GHOST_WHITE}", ratio=2)
    attack_table.add_column("SYNTAX", style=f"dim {CYBER_BLUE}", ratio=2)

    attack_table.add_row("scan", "Execute automated security scan", "scan <target> [--ai|--full]")
    attack_table.add_row(
        "ai code-review", "AI-powered source code analysis", "ai code-review ./path"
    )
    attack_table.add_row(
        "ai api-test", "Intelligent API security testing", "ai api-test https://api.target.com"
    )
    attack_table.add_row(
        "ai web-pentest", "Full AI-guided web exploitation", "ai web-pentest https://target.com"
    )
    attack_table.add_row("vps scan", "Execute scan from remote VPS", "vps scan <target>")

    console.print(attack_table)
    console.print()

    # Infrastructure modules
    infra_table = Table(
        show_header=True,
        header_style=f"bold {CYBER_BLUE}",
        box=box.HEAVY_EDGE,
        border_style=DARK_GREEN,
        expand=True,
        title=f"[bold {CYBER_BLUE}]🖥 INFRASTRUCTURE[/]",
        title_style=f"bold {CYBER_BLUE}",
    )
    infra_table.add_column("MODULE", style=f"bold {NEON_GREEN}", ratio=1)
    infra_table.add_column("FUNCTION", style=f"{GHOST_WHITE}", ratio=2)
    infra_table.add_column("SYNTAX", style=f"dim {CYBER_BLUE}", ratio=2)

    infra_table.add_row("vps setup", "Deploy toolkit on remote VPS", "vps setup")
    infra_table.add_row("vps status", "Query VPS operational status", "vps status")
    infra_table.add_row("setup", "Initialize framework configuration", "setup")
    infra_table.add_row("status", "Display system diagnostics", "status")
    infra_table.add_row("test", "Validate all service connections", "test")

    console.print(infra_table)
    console.print()

    # System commands
    sys_table = Table(
        show_header=True,
        header_style=f"bold {NEON_GREEN}",
        box=box.HEAVY_EDGE,
        border_style=DARK_GREEN,
        expand=True,
        title=f"[bold {NEON_GREEN}]⚙ SYSTEM[/]",
        title_style=f"bold {NEON_GREEN}",
    )
    sys_table.add_column("CMD", style=f"bold {NEON_GREEN}", ratio=1)
    sys_table.add_column("ACTION", style=f"{GHOST_WHITE}", ratio=3)

    sys_table.add_row("clear", "Purge terminal buffer")
    sys_table.add_row("help", "Display this reference")
    sys_table.add_row("exit", "Terminate session")

    console.print(sys_table)
    console.print()


def run_setup_wrapper():
    """Wrapper to run setup from interactive mode."""
    from rich.console import Console

    console = Console()
    try:
        success = run_setup_wizard(force=True)
        # Reload configuration after successful setup
        if success:
            reload_config()
    except Exception as e:
        console.print(f"[red]Setup error:[/red] {e}")


def show_status_wrapper():
    """Wrapper to show status from interactive mode."""
    import argparse

    args = argparse.Namespace(verbose=0, json=False)
    show_status(args)


def run_test_wrapper(args_list=None):
    """Wrapper to run config test from interactive mode."""
    import argparse

    from rich.console import Console

    console = Console()

    # Parse test arguments
    test_llm = False
    test_vps = False
    test_scanners = False
    test_tools = False
    test_all = True

    if args_list:
        for arg in args_list:
            if arg == "--llm":
                test_llm = True
                test_all = False
            elif arg == "--vps":
                test_vps = True
                test_all = False
            elif arg == "--scanners":
                test_scanners = True
                test_all = False
            elif arg == "--tools":
                test_tools = True
                test_all = False

    args = argparse.Namespace(
        llm=test_llm,
        vps=test_vps,
        scanners=test_scanners,
        tools=test_tools,
        all=test_all,
    )

    try:
        run_config_test(args)
    except Exception as e:
        console.print(f"[red]Test error:[/red] {e}")


def run_scan_wrapper(args_list):
    """Wrapper to run scan from interactive mode."""
    import argparse

    from rich.console import Console

    console = Console()

    # Parse scan arguments
    target = args_list[0]
    mode = "standard"
    full = False
    ai = False
    check = False
    use_vps = False

    for i, arg in enumerate(args_list[1:]):
        if arg == "--full":
            full = True
        elif arg == "--ai":
            ai = True
        elif arg == "--check":
            check = True
        elif arg == "--use-vps":
            use_vps = True
        elif arg in ("--mode", "-m") and i + 2 < len(args_list):
            mode = args_list[i + 2]

    args = argparse.Namespace(
        target=target,
        client=None,
        output=None,
        mode=mode,
        full=full,
        ai=ai,
        use_vps=use_vps,
        use_acunetix=False,
        use_burp=False,
        skip_recon=False,
        verbose=0,
        check=check,
        quiet=False,
        no_stream=False,
    )

    try:
        run_scan(args)
    except Exception as e:
        console.print(f"[red]Scan error:[/red] {e}")


def run_vps_wrapper(args_list):
    """Wrapper to run VPS commands from interactive mode."""
    import argparse

    from rich.console import Console

    console = Console()

    if not args_list:
        console.print("[yellow]VPS Commands:[/yellow]")
        console.print("  vps setup   - Install security tools")
        console.print("  vps status  - Check VPS status")
        console.print("  vps scan    - Run scan from VPS")
        return

    vps_cmd = args_list[0]
    args = argparse.Namespace(
        vps_command=vps_cmd,
        categories=None,
        tools=None,
        target=args_list[1] if len(args_list) > 1 else None,
        mode="standard",
        output=None,
    )

    try:
        run_vps_command(args)
    except Exception as e:
        console.print(f"[red]VPS error:[/red] {e}")


def run_ai_wrapper(args_list):
    """Wrapper to run AI commands from interactive mode."""
    import argparse

    from rich.console import Console

    console = Console()

    if not args_list:
        console.print("[yellow]AI Commands:[/yellow]")
        console.print("  ai code-review <path>  - AI code security review")
        console.print("  ai api-test <url>      - AI API testing")
        console.print("  ai web-pentest <url>   - AI web pentesting")
        console.print("  ai full <target>       - Full AI assessment")
        return

    ai_cmd = args_list[0]
    target = args_list[1] if len(args_list) > 1 else None

    if not target and ai_cmd != "help":
        console.print(f"[red]Usage:[/red] ai {ai_cmd} <target>")
        return

    args = argparse.Namespace(
        ai_command=ai_cmd,
        target=target,
        focus=None,
        model="claude-3-7-sonnet-20250219",
        max_steps=100,
        quick="--quick" in args_list or "-q" in args_list,
        output=None,
        openapi=None,
        auth_token=None,
        cookie=None,
        types=["web"],
    )

    try:
        run_ai_command(args)
    except Exception as e:
        console.print(f"[red]AI error:[/red] {e}")


def run_setup(args):
    """Run the interactive setup wizard."""
    force = getattr(args, "force", False)
    success = run_setup_wizard(force=force)

    # Reload configuration after successful setup so it's immediately available
    if success:
        reload_config()

    return 0 if success else 1


def run_scan(args):
    """Run security scan."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    try:
        from .orchestrator import Orchestrator, OrchestratorConfig
    except ImportError as e:
        # Provide helpful error message for missing dependencies
        error_msg = str(e)
        console.print()
        console.print(
            Panel(
                "[bold red]Missing Dependencies[/bold red]\n\n"
                f"[dim]Import error: {error_msg}[/dim]\n\n"
                "The scan module requires additional dependencies.\n\n"
                "[bold]To fix, install the full package:[/bold]\n"
                "  [bold green]pip install aiptx[full][/bold green]\n\n"
                "[bold]Or install specific dependencies:[/bold]\n"
                "  [dim]pip install sentence-transformers torch langchain-core[/dim]",
                title=f"{icon('warning')} Scan Module Not Available",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()
        return 1

    # Check if configured - prompt for setup if not
    if not is_configured():
        # Interactive setup for first-time users
        if not prompt_first_run_setup():
            return 1  # User declined setup or setup failed

    # Validate configuration for requested features
    features = ["llm"]
    if args.use_acunetix:
        features.append("acunetix")
    if args.use_burp:
        features.append("burp")
    if args.use_vps:
        features.append("vps")

    errors = validate_config_for_features(features)
    if errors:
        console.print()
        console.print(
            Panel(
                "[bold red]Configuration Error[/bold red]\n\n"
                "The following issues need to be resolved:\n\n"
                + "\n".join(f"  [yellow]{icon('bullet')}[/yellow] {error}" for error in errors)
                + "\n\n[bold]To fix:[/bold]\n"
                "  Run [bold green]aiptx setup[/bold green] to configure interactively\n\n"
                "[bold]Or set environment variables:[/bold]\n"
                "  [dim]export ANTHROPIC_API_KEY=your-key-here[/dim]",
                title=f"{icon('warning')} Setup Required",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()
        return 1

    # Run quick prerequisites check (always runs, but non-blocking for core features)
    from .prerequisites import check_prerequisites_sync

    is_ready, prereq_errors = check_prerequisites_sync(
        require_llm=True,
        require_tools=False,  # Tools are optional for basic scan
    )

    if not is_ready:
        console.print()
        console.print(
            Panel(
                "[bold red]Prerequisites Check Failed[/bold red]\n\n"
                + "\n".join(f"  [red]•[/red] {e}" for e in prereq_errors)
                + "\n\n[bold]To diagnose:[/bold]\n"
                "  Run [bold green]aiptx check[/bold green] for detailed report\n\n"
                "[bold]To fix common issues:[/bold]\n"
                "  [dim]aiptx setup          # Configure API keys[/dim]\n"
                "  [dim]pip install aiptx[full]  # Install all dependencies[/dim]",
                title=f"{icon('warning')} System Not Ready",
                border_style="red",
                padding=(1, 2),
            )
        )
        console.print()
        return 1

    # Run pre-flight checks if requested (connection validation)
    if getattr(args, "check", False):
        ai_mode = args.ai or args.mode == "ai"
        checks_passed = run_preflight_check(
            console=console,
            use_vps=args.use_vps,
            use_acunetix=args.use_acunetix,
            use_burp=args.use_burp,
            ai_mode=ai_mode,
        )

        if not checks_passed:
            console.print("[yellow]Scan aborted due to failed pre-flight checks.[/yellow]")
            console.print(
                "[dim]Fix the issues above and try again, or run without --check to skip validation.[/dim]"
            )
            return 1

        console.print("[dim]Pre-flight checks passed. Starting scan...[/dim]")
        console.print()

    # Create config
    # Verbose mode is OFF by default, -v enables it (cleaner output)
    # Use args.verbose from global parser (count type)
    verbose_level = getattr(args, "verbose", 0)
    verbose = verbose_level > 0 or getattr(args, "quiet", False) is False and verbose_level > 0
    # Show command output only if verbose, or if not in quiet mode with --no-stream
    show_command_output = verbose_level > 0 and not getattr(args, "no_stream", False)

    config = OrchestratorConfig(
        target=args.target,
        output_dir=Path(args.output) if args.output else Path("./results"),
        skip_recon=args.skip_recon,
        use_acunetix=args.use_acunetix,
        use_burp=args.use_burp,
        verbose=verbose,
        show_command_output=show_command_output,
    )

    # v4.0 Enhanced scanning options
    output_format = getattr(args, "format", "text")
    sarif_output = getattr(args, "sarif_output", None)
    if sarif_output:
        output_format = "sarif"

    # Add v4.0 scanning flags to config if OrchestratorConfig supports them
    # These may need to be added to OrchestratorConfig in a future update
    scan_options = {
        "sast": getattr(args, "sast", False),
        "dast": getattr(args, "dast", False),
        "business_logic": getattr(args, "business_logic", False),
        "websocket": getattr(args, "websocket", False),
        "spa": getattr(args, "spa", False),
        "graphql": getattr(args, "graphql", False),
        "validate_pocs": getattr(args, "validate_pocs", False),
    }

    # Determine mode
    if args.ai or args.mode == "ai":
        mode = "ai"
    elif args.full or args.mode == "full":
        mode = "full"
        config.full_mode = True
    elif getattr(args, "quick", False) or args.mode == "quick":
        mode = "quick"
        # Quick mode: Disable enterprise scanners for faster scan
        config.use_acunetix = False
        config.use_burp = False
        config.use_nessus = False
        config.use_zap = False
        config.wait_for_scanners = False
        config.full_mode = False
    else:
        mode = "standard"

    # Show scan starting message
    console.print()
    console.print(f"[bold cyan]Starting {mode} scan on[/bold cyan] [bold]{args.target}[/bold]")
    console.print()

    # Run orchestrator
    orchestrator = Orchestrator(args.target, config)

    try:
        # Use custom event loop handling to avoid cleanup warnings
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(orchestrator.run())
        finally:
            # Clean up pending tasks before closing the loop
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                # Give tasks a chance to respond to cancellation
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass  # Ignore cleanup errors
            loop.close()

        console.print()
        console.print(f"[bold green]{icon('check')} Scan completed successfully[/bold green]")

        # v4.0: Generate SARIF output if requested
        if output_format == "sarif" or sarif_output:
            try:
                from .agents.shared.finding_repository import FindingRepository
                from .reports.sarif import SARIFConfig, SARIFGenerator

                # Get findings from the scan result
                findings = getattr(orchestrator, "findings", [])

                if findings:
                    sarif_config = SARIFConfig(
                        include_poc=getattr(args, "validate_pocs", False),
                        include_evidence=True,
                    )
                    generator = SARIFGenerator(sarif_config)
                    sarif_report = generator.generate(findings, target=args.target)

                    output_path = sarif_output or str(config.output_dir / "results.sarif")
                    generator.to_file(output_path, sarif_report)
                    console.print(f"[dim]SARIF report written to {output_path}[/dim]")

                    # v4.0: Check fail-on-severity threshold
                    fail_on = getattr(args, "fail_on_severity", None)
                    if fail_on:
                        from .agents.shared.finding_repository import FindingSeverity

                        severity_order = ["info", "low", "medium", "high", "critical"]
                        threshold_index = severity_order.index(fail_on)

                        max_severity = 0
                        for finding in findings:
                            finding_index = severity_order.index(finding.severity.value.lower())
                            max_severity = max(max_severity, finding_index)

                        if max_severity >= threshold_index:
                            severity_name = severity_order[max_severity]
                            console.print(
                                f"[bold red]CI/CD: Found {severity_name} severity findings (threshold: {fail_on})[/bold red]"
                            )
                            return 1

            except ImportError as e:
                console.print(f"[yellow]Warning: Could not generate SARIF report: {e}[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Warning: SARIF generation failed: {e}[/yellow]")

        return 0
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]Scan interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print()
        console.print(f"[bold red]{icon('cross')} Scan failed:[/bold red] {e}")
        if getattr(args, "verbose", 0) > 0:
            import traceback

            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return 1


def run_api(args):
    """Start REST API server."""
    import uvicorn

    logger.info(f"Starting API server on {args.host}:{args.port}")

    # Try package import first, then local
    try:
        uvicorn.run(
            "app:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="info",
        )
    except Exception:
        # Fallback for installed package
        uvicorn.run(
            "aiptx.app:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="info",
        )

    return 0


def show_status(args):
    """Show configuration status with actual connection validation."""
    import asyncio
    import os
    import time
    from pathlib import Path

    from dotenv import load_dotenv
    from rich.console import Console
    from rich.table import Table

    console = Console()

    # Force reload .env file with override=True to ensure fresh config
    env_path = Path.home() / ".aiptx" / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)

        # WINDOWS FIX: Also read .env directly to bypass any python-dotenv encoding issues
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip()
                        # Remove surrounding quotes if present
                        if (value.startswith('"') and value.endswith('"')) or (
                            value.startswith("'") and value.endswith("'")
                        ):
                            value = value[1:-1]
                        os.environ[key] = value
        except Exception:
            pass  # Fall back to dotenv

    # Clear config cache and get fresh config
    from .config import reload_config

    config = reload_config()

    console.print("\n[bold cyan]AIPT v2 Configuration Status[/bold cyan]\n")

    # Store validation results for summary
    validation_results = {}

    # ==================== LLM Configuration ====================
    llm_status = None
    llm_error = None

    # Check if API key is required - Ollama doesn't need one
    provider = config.llm.provider.lower()
    requires_api_key = provider not in ["ollama"]

    if config.llm.api_key or not requires_api_key:
        with console.status("[yellow]Validating LLM connection...[/yellow]"):
            try:
                import logging

                import litellm

                # Suppress litellm verbose output
                litellm.suppress_debug_info = True
                litellm.set_verbose = False
                logging.getLogger("LiteLLM").setLevel(logging.ERROR)
                logging.getLogger("httpx").setLevel(logging.ERROR)

                provider = config.llm.provider.lower()
                model = config.llm.model

                import os as _os

                # Build model string and set credentials based on provider
                api_base = config.llm.api_base
                completion_kwargs = {
                    "messages": [{"role": "user", "content": "Reply with only: OK"}],
                    "max_tokens": 10,
                    "timeout": 30,
                }

                # IMPORTANT: Clear OTHER provider keys to avoid litellm using wrong provider
                for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"]:
                    _os.environ.pop(key, None)

                if provider == "anthropic":
                    model_str = (
                        f"anthropic/{model}" if not model.startswith("anthropic/") else model
                    )
                    _os.environ["ANTHROPIC_API_KEY"] = config.llm.api_key
                elif provider == "openai":
                    model_str = f"openai/{model}" if not model.startswith("openai/") else model
                    _os.environ["OPENAI_API_KEY"] = config.llm.api_key
                elif provider == "deepseek":
                    model_str = f"deepseek/{model}" if not model.startswith("deepseek/") else model
                    _os.environ["DEEPSEEK_API_KEY"] = config.llm.api_key
                elif provider == "ollama":
                    model_str = f"ollama/{model}" if not model.startswith("ollama/") else model
                    # Ollama doesn't need an API key, but needs base URL
                    if not api_base:
                        api_base = config.llm.ollama_base_url or "http://localhost:11434"
                    _os.environ["OLLAMA_API_BASE"] = api_base
                    completion_kwargs["api_base"] = api_base
                else:
                    model_str = model
                    litellm.api_key = config.llm.api_key

                completion_kwargs["model"] = model_str

                start = time.time()
                # Retry logic for transient connection issues
                max_retries = 3
                last_error = None
                response = None
                for attempt in range(max_retries):
                    try:
                        response = litellm.completion(**completion_kwargs)
                        break
                    except Exception as retry_err:
                        last_error = retry_err
                        err_str = str(retry_err).lower()
                        is_connection_error = (
                            "connection" in err_str
                            or "refused" in err_str
                            or "timeout" in err_str
                            or "errno" in err_str
                        )
                        if is_connection_error and attempt < max_retries - 1:
                            time.sleep(2 * (attempt + 1))  # 2s, 4s backoff
                            continue
                        elif not is_connection_error:
                            raise

                if response is None and last_error:
                    raise last_error

                elapsed = time.time() - start
                llm_status = True
                validation_results["llm"] = (True, f"Connected ({elapsed:.1f}s)")

            except ImportError:
                llm_status = None
                llm_error = "litellm not installed"
                validation_results["llm"] = (None, "litellm not installed")
            except Exception as e:
                llm_status = False
                # Parse error for cleaner display
                error_str = str(e)
                error_type = type(e).__name__

                if "<!DOCTYPE" in error_str or "<html" in error_str.lower():
                    llm_error = "Wrong API endpoint (HTML response)"
                elif "Connection" in error_str or "connect" in error_str.lower():
                    llm_error = "Connection failed - check network/URL"
                elif "getaddrinfo" in error_str.lower():
                    llm_error = "DNS resolution failed - check URL"
                elif "401" in error_str or "Unauthorized" in error_str:
                    llm_error = "Invalid API key"
                elif "AuthenticationError" in error_type:
                    llm_error = "Authentication failed - check API key/provider"
                elif "timeout" in error_str.lower():
                    llm_error = "Request timed out"
                elif "refused" in error_str.lower():
                    llm_error = "Connection refused - is service running?"
                else:
                    # Sanitize potential API keys from error message
                    import re

                    sanitized = re.sub(r"sk-[a-zA-Z0-9-]{20,}", "[API_KEY]", error_str)
                    llm_error = sanitized[:60] if len(sanitized) > 60 else sanitized
                validation_results["llm"] = (False, f"{error_type}: {llm_error}")
    else:
        llm_status = False
        llm_error = "API key not configured"
        validation_results["llm"] = (False, "API key not configured")

    # LLM Status Table
    table = Table(title="LLM Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_column("Status")

    # Color-coded status
    if llm_status is True:
        provider_status = "[green][OK][/green]"
        model_status = "[green][OK][/green]"
        key_status = "[green][OK][/green]"
    elif llm_status is None:
        provider_status = "[yellow][?][/yellow]"
        model_status = "[yellow][?][/yellow]"
        key_status = "[yellow][?][/yellow]"
    else:
        provider_status = "[red][X][/red]" if not config.llm.provider else "[green][OK][/green]"
        model_status = "[red][X][/red]" if not config.llm.model else "[green][OK][/green]"
        key_status = "[red][X][/red]"

    table.add_row("Provider", config.llm.provider or "Not set", provider_status)
    table.add_row("Model", config.llm.model or "Not set", model_status)
    table.add_row("API Key", "****" if config.llm.api_key else "Not set", key_status)

    console.print(table)

    # ==================== Scanner Configuration ====================
    console.print()

    # Test each scanner connection
    scanner_results = {}

    def normalize_scanner_url(url):
        """Normalize scanner URL to ensure proper format."""
        if not url:
            return url
        url = url.strip()
        # Add http:// if no protocol specified
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        # Remove trailing slashes
        url = url.rstrip("/")
        return url

    async def test_scanner_connection(name, url, test_endpoint, headers, check_header=None):
        """Test scanner connectivity.

        Args:
            name: Scanner name for logging
            url: Base URL of the scanner
            test_endpoint: Endpoint to test
            headers: Request headers
            check_header: Optional header name to verify (e.g., 'X-Burp-Version')
        """
        if not url:
            return None, "Not configured"
        try:
            import httpx

            # Normalize URL before testing
            url = normalize_scanner_url(url)
            # Ensure endpoint starts with /
            if not test_endpoint.startswith("/"):
                test_endpoint = "/" + test_endpoint
            full_url = f"{url}{test_endpoint}"
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                response = await client.get(full_url, headers=headers)
                # For Burp Suite, check for version header (more reliable than status code)
                if check_header and check_header in response.headers:
                    return True, f"v{response.headers[check_header]}"
                if response.status_code == 200:
                    return True, "Connected"
                else:
                    return False, f"HTTP {response.status_code}"
        except Exception as e:
            error_str = str(e)
            # Provide more helpful error messages
            if "getaddrinfo" in error_str.lower() or "11001" in error_str:
                return False, "DNS/network unreachable - check VPN/firewall"
            elif "connection refused" in error_str.lower() or "10061" in error_str:
                return False, "Connection refused - service not running?"
            elif "timed out" in error_str.lower() or "timeout" in error_str.lower():
                return False, "Connection timed out - check firewall"
            elif "certificate" in error_str.lower() or "ssl" in error_str.lower():
                return False, "SSL/certificate error"
            else:
                return False, error_str[:40]

    async def test_all_scanners():
        results = {}

        # Acunetix
        if config.scanners.acunetix_url:
            with console.status("[yellow]Testing Acunetix...[/yellow]"):
                results["acunetix"] = await test_scanner_connection(
                    "Acunetix",
                    config.scanners.acunetix_url,
                    "/api/v1/me",
                    {"X-Auth": config.scanners.acunetix_api_key or ""},
                )
        else:
            results["acunetix"] = (None, "Not configured")

        # Burp Suite
        if config.scanners.burp_url:
            with console.status("[yellow]Testing Burp Suite...[/yellow]"):
                # Use root endpoint and check for X-Burp-Version header
                # GET /scan requires a task ID and returns 400 without one
                results["burp"] = await test_scanner_connection(
                    "Burp Suite",
                    config.scanners.burp_url,
                    "/",
                    {"Authorization": config.scanners.burp_api_key or ""},
                    check_header="X-Burp-Version",
                )
        else:
            results["burp"] = (None, "Not configured")

        # Nessus
        if config.scanners.nessus_url:
            with console.status("[yellow]Testing Nessus...[/yellow]"):
                results["nessus"] = await test_scanner_connection(
                    "Nessus",
                    config.scanners.nessus_url,
                    "/server/status",
                    {
                        "X-ApiKeys": f"accessKey={config.scanners.nessus_access_key or ''};secretKey={config.scanners.nessus_secret_key or ''}"
                    },
                )
        else:
            results["nessus"] = (None, "Not configured")

        # OWASP ZAP
        if config.scanners.zap_url:
            with console.status("[yellow]Testing OWASP ZAP...[/yellow]"):
                zap_endpoint = "/JSON/core/view/version/"
                if config.scanners.zap_api_key:
                    zap_endpoint += f"?apikey={config.scanners.zap_api_key}"
                results["zap"] = await test_scanner_connection(
                    "OWASP ZAP", config.scanners.zap_url, zap_endpoint, {}
                )
        else:
            results["zap"] = (None, "Not configured")

        return results

    scanner_results = asyncio.run(test_all_scanners())
    validation_results.update({f"scanner_{k}": v for k, v in scanner_results.items()})

    # Scanner Status Table
    table = Table(title="Scanner Configuration")
    table.add_column("Scanner", style="cyan")
    table.add_column("URL")
    table.add_column("Status")

    def get_scanner_status_display(result):
        """Get colored status display for scanner."""
        status, msg = result
        if status is True:
            return "[green][OK][/green]"
        elif status is None:
            return "[dim][--][/dim]"
        else:
            return "[red][X][/red]"

    table.add_row(
        "Acunetix",
        config.scanners.acunetix_url or "Not configured",
        get_scanner_status_display(scanner_results["acunetix"]),
    )
    table.add_row(
        "Burp Suite",
        config.scanners.burp_url or "Not configured",
        get_scanner_status_display(scanner_results["burp"]),
    )
    table.add_row(
        "Nessus",
        config.scanners.nessus_url or "Not configured",
        get_scanner_status_display(scanner_results["nessus"]),
    )
    table.add_row(
        "OWASP ZAP",
        config.scanners.zap_url or "Not configured",
        get_scanner_status_display(scanner_results["zap"]),
    )

    console.print(table)

    # ==================== VPS Configuration ====================
    console.print()

    vps_status = None
    vps_error = None

    if config.vps.host and config.vps.key_path:
        with console.status("[yellow]Testing VPS connection...[/yellow]"):
            try:
                from pathlib import Path

                key_path = Path(config.vps.key_path).expanduser()

                if not key_path.exists():
                    vps_status = False
                    vps_error = "SSH key not found"
                else:

                    async def test_vps():
                        import os
                        import tempfile

                        import asyncssh

                        conn = await asyncssh.connect(
                            config.vps.host,
                            port=config.vps.port,
                            username=config.vps.user,
                            client_keys=[str(key_path)],
                            known_hosts=None,
                        )

                        # Test 1: Basic SSH connection
                        result = await conn.run("echo 'OK'", check=True)
                        if "OK" not in result.stdout:
                            conn.close()
                            await conn.wait_closed()
                            return False, "SSH command execution failed"

                        # Test 2: Create results directory and test file
                        results_dir = config.vps.results_dir or "/var/tmp/aiptx_results"
                        test_file = f"{results_dir}/.aiptx_test_{os.getpid()}"
                        test_content = "AIPTX_REPORT_TEST_OK"

                        result = await conn.run(
                            f"mkdir -p {results_dir} && echo '{test_content}' > {test_file}",
                            check=False,
                        )
                        if result.exit_status != 0:
                            conn.close()
                            await conn.wait_closed()
                            return False, f"Cannot write to results dir: {results_dir}"

                        # Test 3: SFTP retrieval - the critical report download test
                        try:
                            async with conn.start_sftp_client() as sftp:
                                # Create a temp local file to receive the test file
                                with tempfile.NamedTemporaryFile(
                                    delete=False, suffix=".txt"
                                ) as tmp:
                                    local_test_path = tmp.name

                                # Download the test file
                                await sftp.get(test_file, local_test_path)

                                # Verify content
                                with open(local_test_path, "r") as f:
                                    downloaded_content = f.read().strip()

                                # Clean up local temp file
                                os.unlink(local_test_path)

                                if test_content not in downloaded_content:
                                    # Clean up remote test file
                                    await conn.run(f"rm -f {test_file}", check=False)
                                    conn.close()
                                    await conn.wait_closed()
                                    return False, "SFTP content verification failed"

                        except Exception as sftp_err:
                            # Clean up remote test file
                            await conn.run(f"rm -f {test_file}", check=False)
                            conn.close()
                            await conn.wait_closed()
                            return False, f"SFTP retrieval failed: {str(sftp_err)[:30]}"

                        # Test 4: Clean up remote test file
                        await conn.run(f"rm -f {test_file}", check=False)

                        # All tests passed
                        conn.close()
                        await conn.wait_closed()
                        return True, "Connected (SSH + SFTP verified)"

                    # Use a new event loop to avoid conflicts with existing loops
                    loop = asyncio.new_event_loop()
                    try:
                        asyncio.set_event_loop(loop)
                        vps_status, vps_message = loop.run_until_complete(test_vps())
                        if not vps_status:
                            vps_error = vps_message
                        else:
                            vps_error = None  # Success message stored in vps_message
                    finally:
                        loop.close()

            except ImportError:
                vps_status = None
                vps_error = "asyncssh not installed"
            except Exception as e:
                vps_status = False
                vps_error = str(e)[:50]

        # Use the detailed message for successful connections
        if vps_status and not vps_error:
            validation_results["vps"] = (vps_status, vps_message)
        else:
            validation_results["vps"] = (vps_status, vps_error if vps_error else "Connected")
    elif config.vps.host:
        vps_status = False
        vps_error = "SSH key not configured"
        validation_results["vps"] = (False, vps_error)
    else:
        vps_status = None
        validation_results["vps"] = (None, "Not configured")

    # VPS Status Table
    table = Table(title="VPS Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    if vps_status is True:
        host_display = f"[green]{config.vps.host}[/green]"
    elif vps_status is False:
        host_display = f"[red]{config.vps.host or 'Not configured'}[/red]"
    else:
        host_display = config.vps.host or "Not configured"

    table.add_row("Host", host_display)
    table.add_row("User", config.vps.user)
    # Mask SSH key path to avoid exposing full filesystem structure
    table.add_row(
        "SSH Key", mask_path(config.vps.key_path) if config.vps.key_path else "Not configured"
    )

    console.print(table)

    # ==================== Configuration Validation Summary ====================
    console.print("\n[bold]Configuration Validation:[/bold]")

    # LLM
    llm_result = validation_results.get("llm", (False, "Unknown"))
    if llm_result[0] is True:
        console.print(f"  [green]{icon('check')}[/green] llm: {llm_result[1]}")
    elif llm_result[0] is None:
        console.print(f"  [yellow]{icon('warning')}[/yellow] llm: {llm_result[1]}")
    else:
        console.print(f"  [red]{icon('cross')}[/red] llm: {llm_result[1]}")

    # Scanners - only show configured ones
    for scanner_name in ["acunetix", "burp", "nessus", "zap"]:
        result = scanner_results.get(scanner_name, (None, "Unknown"))
        if result[0] is True:
            console.print(f"  [green]{icon('check')}[/green] {scanner_name}: {result[1]}")
        elif result[0] is None:
            # Don't show unconfigured scanners as errors
            pass
        else:
            console.print(f"  [red]{icon('cross')}[/red] {scanner_name}: {result[1]}")

    # VPS
    vps_result = validation_results.get("vps", (None, "Unknown"))
    if vps_result[0] is True:
        console.print(f"  [green]{icon('check')}[/green] vps: {vps_result[1]}")
    elif vps_result[0] is None:
        console.print(f"  [dim]{icon('circle_empty')}[/dim] vps: {vps_result[1]} (optional)")
    else:
        console.print(f"  [red]{icon('cross')}[/red] vps: {vps_result[1]}")

    return 0


def run_check(args):
    """
    Run enterprise-level prerequisites check.

    Validates all system requirements, dependencies, and configurations
    before allowing security operations to proceed. This is the recommended
    way to validate system readiness for enterprise deployments.
    """
    import asyncio

    from .prerequisites import run_prerequisites_check

    verbose = getattr(args, "verbose", False)
    strict = getattr(args, "strict", False)
    json_output = getattr(args, "json", False)
    minimal = getattr(args, "minimal", False)

    return asyncio.run(
        run_prerequisites_check(
            verbose=verbose,
            strict=strict,
            json_output=json_output,
            include_optional=not minimal,
        )
    )


def run_config_test(args):
    """
    Test and validate all configurations by making real connections.

    Unlike 'status' which just shows config values, 'test' actually
    validates that services are reachable and credentials work.
    """
    import asyncio
    import os
    import shutil
    import time
    from pathlib import Path

    from dotenv import load_dotenv
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table

    console = Console()

    # CRITICAL: Force reload .env file with override=True to ensure fresh API keys are loaded
    # This fixes the issue where config was cached before setup wizard wrote the keys
    env_path = Path.home() / ".aiptx" / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)

        # WINDOWS FIX: Also read .env directly to bypass any python-dotenv encoding issues
        # Parse manually and set env vars
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip()
                        # Remove surrounding quotes if present
                        if (value.startswith('"') and value.endswith('"')) or (
                            value.startswith("'") and value.endswith("'")
                        ):
                            value = value[1:-1]
                        os.environ[key] = value
        except Exception:
            pass  # Fall back to dotenv

    # Clear config cache and get fresh config
    from .config import reload_config

    config = reload_config()

    # Get terminal width for full-width display
    term_width = console.size.width

    console.print()
    console.print(
        Panel(
            Align.center(
                "[bold]AIPTX Configuration Validator[/bold]\n\n"
                "Testing all configured services and credentials..."
            ),
            title=f"{icon('search')} Self-Test",
            border_style="cyan",
            width=term_width,
        )
    )
    console.print()

    results = {}
    test_all = getattr(args, "all", False) or not any(
        [
            getattr(args, "llm", False),
            getattr(args, "vps", False),
            getattr(args, "scanners", False),
            getattr(args, "tools", False),
        ]
    )

    # ======================== LLM Test ========================
    if test_all or getattr(args, "llm", False):
        console.print(Rule("LLM API Test", style="bold cyan"))

        # Ollama doesn't require an API key, so check provider first
        provider = config.llm.provider.lower()
        requires_api_key = provider not in ["ollama"]

        if requires_api_key and not config.llm.api_key:
            console.print(f"  [red]{icon('cross')}[/red] No API key configured")
            console.print("    [dim]Run 'aiptx setup' to configure[/dim]")
            results["llm"] = False
        else:
            with console.status("[yellow]Testing LLM API connection...[/yellow]"):
                try:
                    import logging
                    import os

                    import litellm

                    # Suppress litellm verbose output
                    litellm.suppress_debug_info = True
                    litellm.set_verbose = False
                    logging.getLogger("LiteLLM").setLevel(logging.ERROR)
                    logging.getLogger("httpx").setLevel(logging.ERROR)

                    # Determine model string based on provider
                    provider = config.llm.provider.lower()
                    model = config.llm.model
                    api_key = config.llm.api_key
                    api_base = config.llm.api_base  # May be None for cloud providers

                    # Debug: show what we loaded when API key is missing
                    if not api_key:
                        console.print("    [yellow]Debug: No API key found in config[/yellow]")
                        console.print(
                            f"    [yellow]Debug: Provider={provider}, Model={model}[/yellow]"
                        )
                        # Check environment variables directly
                        env_keys = {
                            "ANTHROPIC_API_KEY": bool(os.environ.get("ANTHROPIC_API_KEY")),
                            "OPENAI_API_KEY": bool(os.environ.get("OPENAI_API_KEY")),
                            "DEEPSEEK_API_KEY": bool(os.environ.get("DEEPSEEK_API_KEY")),
                        }
                        console.print(f"    [yellow]Debug: Env vars: {env_keys}[/yellow]")
                        # Check .env file
                        from pathlib import Path

                        env_path = Path.home() / ".aiptx" / ".env"
                        console.print(
                            f"    [yellow]Debug: Config file exists: {env_path.exists()}[/yellow]"
                        )
                        if env_path.exists():
                            with open(env_path) as f:
                                content = f.read()
                                has_key = any(
                                    k in content
                                    for k in [
                                        "OPENAI_API_KEY",
                                        "ANTHROPIC_API_KEY",
                                        "DEEPSEEK_API_KEY",
                                    ]
                                )
                                console.print(
                                    f"    [yellow]Debug: API key in .env file: {has_key}[/yellow]"
                                )

                    # Set the appropriate environment variable for litellm
                    # litellm reads API keys from environment variables
                    # IMPORTANT: Clear OTHER provider keys to avoid litellm using wrong provider
                    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"]:
                        os.environ.pop(key, None)

                    # IMPORTANT: api_base should ONLY be passed for providers that need it
                    # (like Ollama). For cloud providers (Anthropic, OpenAI, DeepSeek), passing
                    # api_base will override the default endpoint and cause connection failures.
                    effective_api_base = None  # Default: let litellm use provider's endpoint

                    if provider == "anthropic":
                        model_str = (
                            f"anthropic/{model}" if not model.startswith("anthropic/") else model
                        )
                        os.environ["ANTHROPIC_API_KEY"] = api_key
                        # Do NOT set api_base - use Anthropic's cloud API
                    elif provider == "openai":
                        model_str = f"openai/{model}" if not model.startswith("openai/") else model
                        os.environ["OPENAI_API_KEY"] = api_key
                        # Only use api_base if explicitly set and NOT localhost (for custom deployments)
                        if api_base and not api_base.startswith("http://localhost"):
                            effective_api_base = api_base
                    elif provider == "deepseek":
                        model_str = (
                            f"deepseek/{model}" if not model.startswith("deepseek/") else model
                        )
                        os.environ["DEEPSEEK_API_KEY"] = api_key
                        # Do NOT set api_base - use DeepSeek's cloud API
                    elif provider == "ollama":
                        model_str = f"ollama/{model}" if not model.startswith("ollama/") else model
                        # Ollama doesn't need an API key, but needs base URL
                        effective_api_base = (
                            api_base
                            or os.getenv("AIPT_LLM__OLLAMA_BASE_URL")
                            or "http://localhost:11434"
                        )
                        os.environ["OLLAMA_API_BASE"] = effective_api_base
                    else:
                        model_str = model
                        os.environ["LLM_API_KEY"] = api_key

                    # Debug: show what we're about to use
                    key_len = len(api_key) if api_key else 0
                    key_preview = (
                        f"{api_key[:10]}...{api_key[-4:]}"
                        if api_key and len(api_key) > 14
                        else "[EMPTY]"
                    )
                    console.print(
                        f"    [dim]Testing: {model_str} (key length: {key_len}, preview: {key_preview})[/dim]"
                    )

                    start = time.time()
                    # Build completion kwargs
                    # Pass api_key directly to avoid env var issues
                    completion_kwargs = {
                        "model": model_str,
                        "messages": [{"role": "user", "content": "Reply with only: OK"}],
                        "max_tokens": 10,
                        "timeout": 30,
                        "api_key": api_key,  # Pass directly instead of relying on env var
                    }
                    # Only pass api_base for providers that need it (like Ollama)
                    if effective_api_base:
                        completion_kwargs["api_base"] = effective_api_base

                    # Retry logic for transient connection issues
                    max_retries = 3
                    last_error = None
                    response = None
                    for attempt in range(max_retries):
                        try:
                            response = litellm.completion(**completion_kwargs)
                            break
                        except Exception as retry_err:
                            last_error = retry_err
                            err_str = str(retry_err).lower()
                            # Only retry on connection errors, not auth errors
                            is_connection_error = (
                                "connection" in err_str
                                or "refused" in err_str
                                or "timeout" in err_str
                                or "errno" in err_str
                            )
                            if is_connection_error and attempt < max_retries - 1:
                                wait_time = 2 * (attempt + 1)  # 2s, 4s backoff
                                console.print(
                                    f"    [yellow]Connection failed, retrying ({attempt + 2}/{max_retries}) in {wait_time}s...[/yellow]"
                                )
                                import time as time_module

                                time_module.sleep(wait_time)
                                continue
                            elif not is_connection_error:
                                raise  # Don't retry auth errors etc.
                            # Last retry failed - will fall through to for-else

                    # Check if all retries exhausted
                    if response is None and last_error:
                        raise last_error

                    elapsed = time.time() - start

                    console.print(f"  [green]{icon('check')}[/green] LLM API connection successful")
                    console.print(f"    [dim]Provider: {provider}[/dim]")
                    console.print(f"    [dim]Model: {model}[/dim]")
                    console.print(f"    [dim]Response time: {elapsed:.2f}s[/dim]")
                    results["llm"] = True

                except ImportError:
                    console.print(f"  [red]{icon('cross')}[/red] litellm not installed")
                    console.print("    [dim]Install with: pip install litellm[/dim]")
                    results["llm"] = None
                except Exception as e:
                    # Parse and clean the error message
                    error_str = str(e)
                    error_type = type(e).__name__

                    # Sanitize API keys from error messages (sk-*, sk-ant-*, sk-proj-*)
                    import re

                    error_str = re.sub(r"sk-[a-zA-Z0-9_-]{10,}", "[REDACTED_KEY]", error_str)

                    # Detect common error patterns and provide helpful messages
                    if "<!DOCTYPE" in error_str or "<html" in error_str.lower():
                        error_msg = "API endpoint returned HTML (likely wrong URL or proxy error)"
                        suggestion = "Check LLM_API_BASE or provider configuration"
                    elif "Connection" in error_str or "connect" in error_str.lower():
                        error_msg = "Connection failed - API endpoint unreachable"
                        suggestion = "Check network connection and API base URL"
                    elif (
                        "AuthenticationError" in error_type
                        or "401" in error_str
                        or "Unauthorized" in error_str
                    ):
                        error_msg = "Authentication failed - invalid API key"
                        suggestion = "Verify your API key is correct and matches the provider"
                    elif "403" in error_str or "Forbidden" in error_str:
                        error_msg = "Access denied - API key lacks permissions"
                        suggestion = "Check API key permissions or quota"
                    elif "429" in error_str or "rate" in error_str.lower():
                        error_msg = "Rate limited - too many requests"
                        suggestion = "Wait and retry, or upgrade API plan"
                    elif "timeout" in error_str.lower():
                        error_msg = "Request timed out"
                        suggestion = "Check network connection or try again"
                    elif "getaddrinfo" in error_str.lower():
                        error_msg = "DNS resolution failed - check network/URL"
                        suggestion = "Check network connection or API base URL"
                    else:
                        # Extract just the core error message (already sanitized)
                        if ": " in error_str:
                            error_msg = error_str.split(": ")[-1][:80]
                        else:
                            error_msg = error_str[:80]
                        suggestion = "Run 'aiptx setup' to reconfigure"

                    console.print(f"  [red]{icon('cross')}[/red] LLM API test failed")
                    console.print(f"    [bold red]Error:[/bold red] {error_msg}")
                    console.print(f"    [dim cyan]Fix:[/dim cyan] {suggestion}")
                    # Show raw error for debugging (already sanitized)
                    if len(error_str) < 200:
                        console.print(f"    [dim yellow]Raw: {error_str}[/dim yellow]")
                    else:
                        console.print(f"    [dim yellow]Raw: {error_str[:200]}...[/dim yellow]")
                    results["llm"] = False

        console.print()

    # ======================== VPS Test ========================
    if test_all or getattr(args, "vps", False):
        console.print(Rule("VPS Connection Test", style="bold cyan"))

        if not config.vps.host:
            console.print(
                f"  [yellow]{icon('circle_empty')}[/yellow] VPS not configured (optional)"
            )
            results["vps"] = None
        elif not config.vps.key_path:
            console.print(f"  [red]{icon('cross')}[/red] SSH key path not configured")
            results["vps"] = False
        else:
            with console.status("[yellow]Testing SSH connection to VPS...[/yellow]"):
                try:
                    from pathlib import Path

                    key_path = Path(config.vps.key_path).expanduser()
                    if not key_path.exists():
                        # Mask the path to avoid exposing full filesystem structure
                        console.print(
                            f"  [red]{icon('cross')}[/red] SSH key not found: {mask_path(key_path)}"
                        )
                        results["vps"] = False
                    else:
                        # Test SSH connection and SFTP report retrieval using asyncssh
                        async def test_ssh_and_sftp():
                            import os as _os
                            import tempfile

                            import asyncssh

                            start = time.time()
                            conn = await asyncssh.connect(
                                config.vps.host,
                                port=config.vps.port,
                                username=config.vps.user,
                                client_keys=[str(key_path)],
                                known_hosts=None,
                            )

                            # Test 1: Basic SSH command
                            result = await conn.run("echo 'AIPTX_TEST_OK' && uname -a", check=True)
                            uname_output = result.stdout.strip()

                            if "AIPTX_TEST_OK" not in uname_output:
                                conn.close()
                                await conn.wait_closed()
                                return False, "SSH command failed", None, time.time() - start

                            # Test 2: Results directory write access
                            results_dir = config.vps.results_dir or "/var/tmp/aiptx_results"
                            test_file = f"{results_dir}/.aiptx_report_test_{_os.getpid()}"
                            test_content = "AIPTX_SFTP_TEST_OK"

                            result = await conn.run(
                                f"mkdir -p {results_dir} && echo '{test_content}' > {test_file}",
                                check=False,
                            )
                            if result.exit_status != 0:
                                conn.close()
                                await conn.wait_closed()
                                return (
                                    False,
                                    f"Cannot write to {results_dir}",
                                    None,
                                    time.time() - start,
                                )

                            # Test 3: SFTP retrieval (report download simulation)
                            sftp_ok = False
                            try:
                                async with conn.start_sftp_client() as sftp:
                                    with tempfile.NamedTemporaryFile(
                                        delete=False, suffix=".txt"
                                    ) as tmp:
                                        local_test_path = tmp.name

                                    await sftp.get(test_file, local_test_path)

                                    with open(local_test_path, "r") as f:
                                        downloaded = f.read().strip()

                                    _os.unlink(local_test_path)
                                    sftp_ok = test_content in downloaded

                            except Exception as sftp_err:
                                await conn.run(f"rm -f {test_file}", check=False)
                                conn.close()
                                await conn.wait_closed()
                                return (
                                    False,
                                    f"SFTP failed: {str(sftp_err)[:40]}",
                                    None,
                                    time.time() - start,
                                )

                            # Cleanup remote test file
                            await conn.run(f"rm -f {test_file}", check=False)

                            if not sftp_ok:
                                conn.close()
                                await conn.wait_closed()
                                return (
                                    False,
                                    "SFTP content verification failed",
                                    None,
                                    time.time() - start,
                                )

                            elapsed = time.time() - start
                            uname = uname_output.replace("AIPTX_TEST_OK", "").strip()
                            conn.close()
                            await conn.wait_closed()
                            return True, "SSH + SFTP OK", uname, elapsed

                        # Use explicit event loop to avoid conflicts
                        loop = asyncio.new_event_loop()
                        try:
                            asyncio.set_event_loop(loop)
                            success, message, uname, elapsed = loop.run_until_complete(
                                test_ssh_and_sftp()
                            )
                        finally:
                            loop.close()

                        if success:
                            console.print(
                                f"  [green]{icon('check')}[/green] VPS connection successful"
                            )
                            console.print(
                                f"    [dim]Host: {config.vps.user}@{config.vps.host}:{config.vps.port}[/dim]"
                            )
                            console.print(
                                f"    [dim]System: {uname[:60]}...[/dim]"
                                if uname and len(uname) > 60
                                else f"    [dim]System: {uname}[/dim]"
                            )
                            console.print(f"    [dim]Response time: {elapsed:.2f}s[/dim]")
                            console.print(
                                f"    [green]{icon('check')}[/green] [dim]Report retrieval (SFTP): Verified[/dim]"
                            )
                            results["vps"] = True
                        else:
                            console.print(
                                f"  [red]{icon('cross')}[/red] VPS connection failed - {message}"
                            )
                            results["vps"] = False

                except ImportError:
                    console.print(f"  [yellow]{icon('warning')}[/yellow] asyncssh not installed")
                    console.print("    [dim]Install with: pip install asyncssh[/dim]")
                    results["vps"] = None
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] VPS connection failed")
                    console.print(f"    [dim]Error: {str(e)[:100]}[/dim]")
                    results["vps"] = False

        console.print()

    # ======================== Scanner Tests ========================
    if test_all or getattr(args, "scanners", False):
        console.print(Rule("Scanner Integration Tests", style="bold cyan"))

        scanners_tested = 0

        # Acunetix
        if config.scanners.acunetix_url:
            scanners_tested += 1
            with console.status("[yellow]Testing Acunetix connection...[/yellow]"):
                try:
                    import httpx

                    response = httpx.get(
                        f"{config.scanners.acunetix_url}/api/v1/me",
                        headers={"X-Auth": config.scanners.acunetix_api_key},
                        verify=config.scanners.verify_tls,
                        timeout=10,
                    )
                    if response.status_code == 200:
                        console.print(f"  [green]{icon('check')}[/green] Acunetix connected")
                        console.print(f"    [dim]URL: {config.scanners.acunetix_url}[/dim]")
                        results["acunetix"] = True
                    else:
                        console.print(
                            f"  [red]{icon('cross')}[/red] Acunetix auth failed (HTTP {response.status_code})"
                        )
                        results["acunetix"] = False
                except Exception as e:
                    console.print(
                        f"  [red]{icon('cross')}[/red] Acunetix connection failed: {str(e)[:50]}"
                    )
                    results["acunetix"] = False

        # Burp Suite
        if config.scanners.burp_url:
            scanners_tested += 1
            with console.status("[yellow]Testing Burp Suite connection...[/yellow]"):
                try:
                    import httpx

                    response = httpx.get(
                        f"{config.scanners.burp_url}/api-internal/versions",
                        headers={"Authorization": f"Bearer {config.scanners.burp_api_key}"},
                        verify=config.scanners.verify_tls,
                        timeout=10,
                    )
                    if response.status_code == 200:
                        console.print(f"  [green]{icon('check')}[/green] Burp Suite connected")
                        console.print(f"    [dim]URL: {config.scanners.burp_url}[/dim]")
                        results["burp"] = True
                    else:
                        console.print(
                            f"  [red]{icon('cross')}[/red] Burp Suite auth failed (HTTP {response.status_code})"
                        )
                        results["burp"] = False
                except Exception as e:
                    console.print(
                        f"  [red]{icon('cross')}[/red] Burp Suite connection failed: {str(e)[:50]}"
                    )
                    results["burp"] = False

        # Nessus
        if config.scanners.nessus_url:
            scanners_tested += 1
            with console.status("[yellow]Testing Nessus connection...[/yellow]"):
                try:
                    import httpx

                    response = httpx.get(
                        f"{config.scanners.nessus_url}/server/status",
                        headers={
                            "X-ApiKeys": f"accessKey={config.scanners.nessus_access_key};secretKey={config.scanners.nessus_secret_key}"
                        },
                        verify=config.scanners.verify_tls,
                        timeout=10,
                    )
                    if response.status_code == 200:
                        console.print(f"  [green]{icon('check')}[/green] Nessus connected")
                        console.print(f"    [dim]URL: {config.scanners.nessus_url}[/dim]")
                        results["nessus"] = True
                    else:
                        console.print(
                            f"  [red]{icon('cross')}[/red] Nessus auth failed (HTTP {response.status_code})"
                        )
                        results["nessus"] = False
                except Exception as e:
                    console.print(
                        f"  [red]{icon('cross')}[/red] Nessus connection failed: {str(e)[:50]}"
                    )
                    results["nessus"] = False

        # ZAP
        if config.scanners.zap_url:
            scanners_tested += 1
            with console.status("[yellow]Testing OWASP ZAP connection...[/yellow]"):
                try:
                    import httpx

                    url = f"{config.scanners.zap_url}/JSON/core/view/version/"
                    if config.scanners.zap_api_key:
                        url += f"?apikey={config.scanners.zap_api_key}"
                    response = httpx.get(url, timeout=10)
                    if response.status_code == 200:
                        version = response.json().get("version", "unknown")
                        console.print(
                            f"  [green]{icon('check')}[/green] OWASP ZAP connected (v{version})"
                        )
                        console.print(f"    [dim]URL: {config.scanners.zap_url}[/dim]")
                        results["zap"] = True
                    else:
                        console.print(
                            f"  [red]{icon('cross')}[/red] ZAP connection failed (HTTP {response.status_code})"
                        )
                        results["zap"] = False
                except Exception as e:
                    console.print(
                        f"  [red]{icon('cross')}[/red] ZAP connection failed: {str(e)[:50]}"
                    )
                    results["zap"] = False

        if scanners_tested == 0:
            console.print(
                f"  [yellow]{icon('circle_empty')}[/yellow] No scanners configured (optional)"
            )

        console.print()

    # ======================== Local Tools Test ========================
    if test_all or getattr(args, "tools", False):
        console.print(Rule("Local Security Tools", style="bold cyan"))

        tools = {
            "nmap": "nmap --version",
            "subfinder": "subfinder -version",
            "httpx": "httpx -version",
            "nuclei": "nuclei -version",
            "ffuf": "ffuf -V",
            "gobuster": "gobuster version",
            "nikto": "nikto -Version",
            "sqlmap": "sqlmap --version",
            "wpscan": "wpscan --version",
            "amass": "amass -version",
        }

        found_tools = []
        missing_tools = []

        for tool, check_cmd in tools.items():
            if shutil.which(tool):
                found_tools.append(tool)
            else:
                missing_tools.append(tool)

        if found_tools:
            console.print(f"  [green]{icon('check')}[/green] Available: {', '.join(found_tools)}")

        if missing_tools:
            console.print(
                f"  [yellow]{icon('circle_empty')}[/yellow] Not found: {', '.join(missing_tools)}"
            )
            console.print("    [dim]Install missing tools or use --use-vps to run on VPS[/dim]")

        results["tools"] = len(found_tools)
        console.print()

    # ======================== Summary ========================
    console.print(Rule("Test Summary", style="bold cyan"))

    table = Table(box=box.ROUNDED)
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Details")

    for component, status in results.items():
        if status is True:
            status_str = f"[green]{icon('check')} PASS[/green]"
            details = "Working correctly"
        elif status is False:
            status_str = f"[red]{icon('cross')} FAIL[/red]"
            details = "Check configuration"
        elif status is None:
            status_str = f"[yellow]{icon('circle_empty')} SKIP[/yellow]"
            details = "Not configured"
        elif isinstance(status, int):
            status_str = f"[green]{icon('check')} {status}[/green]"
            details = f"{status} tools available"
        else:
            status_str = "[dim]?[/dim]"
            details = "Unknown"

        table.add_row(component.upper(), status_str, details)

    console.print(table)

    # Overall result
    failures = sum(1 for v in results.values() if v is False)
    if failures == 0:
        console.print(f"\n[bold green]{icon('check')} All tests passed![/bold green]")
        return 0
    else:
        console.print(
            f"\n[bold yellow]{icon('warning')} {failures} test(s) failed. Run 'aiptx setup' to fix.[/bold yellow]"
        )
        return 1


def run_preflight_check(console, use_vps=False, use_acunetix=False, use_burp=False, ai_mode=False):
    """
    Run pre-flight checks before starting a scan.

    Validates that all required components are configured and reachable.
    Returns True if all checks pass, False otherwise.

    Args:
        console: Rich console for output
        use_vps: Whether VPS will be used for the scan
        use_acunetix: Whether Acunetix scanner will be used
        use_burp: Whether Burp Suite will be used
        ai_mode: Whether AI-guided scanning is enabled

    Returns:
        bool: True if all checks pass, False if any fail
    """
    import asyncio
    import shutil
    import time

    from rich import box
    from rich.align import Align
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table

    config = get_config()
    results = {}
    all_passed = True

    # Get terminal width for full-width display
    term_width = console.size.width

    console.print()
    console.print(
        Panel(
            Align.center(
                "[bold]Pre-flight Configuration Check[/bold]\n\n"
                "Validating all required services before scan..."
            ),
            title=f"{icon('airplane')} Pre-flight Check",
            border_style="cyan",
            width=term_width,
        )
    )
    console.print()

    # ======================== LLM Check (always required) ========================
    console.print(Rule("LLM API", style="bold cyan"))

    # Ollama doesn't require an API key
    provider = config.llm.provider.lower()
    requires_api_key = provider not in ["ollama"]

    if requires_api_key and not config.llm.api_key:
        console.print(f"  [red]{icon('cross')}[/red] No API key configured")
        console.print("    [dim]Run 'aiptx setup' to configure[/dim]")
        results["llm"] = False
        all_passed = False
    else:
        with console.status("[yellow]Testing LLM API...[/yellow]"):
            try:
                import os

                import litellm

                model = config.llm.model
                api_key = config.llm.api_key
                api_base = config.llm.api_base

                # Set the appropriate environment variable for litellm
                if provider == "anthropic":
                    model_str = (
                        f"anthropic/{model}" if not model.startswith("anthropic/") else model
                    )
                    if api_key:
                        os.environ["ANTHROPIC_API_KEY"] = api_key
                elif provider == "openai":
                    model_str = f"openai/{model}" if not model.startswith("openai/") else model
                    if api_key:
                        os.environ["OPENAI_API_KEY"] = api_key
                elif provider == "deepseek":
                    model_str = f"deepseek/{model}" if not model.startswith("deepseek/") else model
                    if api_key:
                        os.environ["DEEPSEEK_API_KEY"] = api_key
                elif provider == "ollama":
                    model_str = f"ollama/{model}" if not model.startswith("ollama/") else model
                    # Ollama doesn't need API key but needs base URL
                    if not api_base:
                        api_base = os.environ.get("OLLAMA_API_BASE") or "http://localhost:11434"
                    os.environ["OLLAMA_API_BASE"] = api_base
                else:
                    model_str = model
                    if api_key:
                        os.environ["LLM_API_KEY"] = api_key

                start = time.time()
                completion_kwargs = {
                    "model": model_str,
                    "messages": [{"role": "user", "content": "Reply with only: OK"}],
                    "max_tokens": 10,
                    "timeout": 30,
                }
                if api_base:
                    completion_kwargs["api_base"] = api_base

                # Retry logic for transient connection issues
                max_retries = 3
                last_error = None
                response = None
                for attempt in range(max_retries):
                    try:
                        response = litellm.completion(**completion_kwargs)
                        break
                    except Exception as retry_err:
                        last_error = retry_err
                        err_str = str(retry_err).lower()
                        is_connection_error = (
                            "connection" in err_str
                            or "refused" in err_str
                            or "timeout" in err_str
                            or "errno" in err_str
                        )
                        if is_connection_error and attempt < max_retries - 1:
                            time.sleep(2 * (attempt + 1))
                            continue
                        elif not is_connection_error:
                            raise

                if response is None and last_error:
                    raise last_error

                elapsed = time.time() - start

                console.print(
                    f"  [green]{icon('check')}[/green] LLM ready ({provider}/{model}) - {elapsed:.1f}s"
                )
                results["llm"] = True

            except ImportError:
                console.print(f"  [yellow]{icon('warning')}[/yellow] litellm not installed")
                results["llm"] = None
            except Exception as e:
                console.print(f"  [red]{icon('cross')}[/red] LLM connection failed: {str(e)[:60]}")
                results["llm"] = False
                all_passed = False

    console.print()

    # ======================== VPS Check (if requested) ========================
    if use_vps:
        console.print(Rule("VPS Connection", style="bold cyan"))

        if not config.vps.host:
            console.print(f"  [red]{icon('cross')}[/red] VPS not configured")
            console.print("    [dim]Run 'aiptx setup' to configure VPS[/dim]")
            results["vps"] = False
            all_passed = False
        elif not config.vps.key_path:
            console.print(f"  [red]{icon('cross')}[/red] SSH key path not configured")
            results["vps"] = False
            all_passed = False
        else:
            with console.status("[yellow]Testing SSH connection...[/yellow]"):
                try:
                    from pathlib import Path

                    import asyncssh

                    key_path = Path(config.vps.key_path).expanduser()
                    if not key_path.exists():
                        # Mask the path to avoid exposing full filesystem structure
                        console.print(
                            f"  [red]{icon('cross')}[/red] SSH key not found: {mask_path(key_path)}"
                        )
                        results["vps"] = False
                        all_passed = False
                    else:

                        async def test_ssh():
                            start = time.time()
                            conn = await asyncssh.connect(
                                config.vps.host,
                                port=config.vps.port,
                                username=config.vps.user,
                                client_keys=[str(key_path)],
                                known_hosts=None,
                            )
                            # conn.close() is not awaitable in all asyncssh versions
                            conn.close()
                            await conn.wait_closed()
                            return time.time() - start

                        # Use explicit event loop to avoid conflicts
                        loop = asyncio.new_event_loop()
                        try:
                            asyncio.set_event_loop(loop)
                            elapsed = loop.run_until_complete(test_ssh())
                        finally:
                            loop.close()
                        console.print(
                            f"  [green]{icon('check')}[/green] VPS connected ({config.vps.user}@{config.vps.host}) - {elapsed:.1f}s"
                        )
                        results["vps"] = True

                except ImportError:
                    console.print(f"  [yellow]{icon('warning')}[/yellow] asyncssh not installed")
                    console.print("    [dim]Install with: pip install asyncssh[/dim]")
                    results["vps"] = None
                except Exception as e:
                    console.print(
                        f"  [red]{icon('cross')}[/red] VPS connection failed: {str(e)[:60]}"
                    )
                    results["vps"] = False
                    all_passed = False

        console.print()

    # ======================== Scanner Checks (if requested) ========================
    if use_acunetix or use_burp:
        console.print(Rule("Scanner Integrations", style="bold cyan"))

        # Acunetix
        if use_acunetix:
            if not config.scanners.acunetix_url:
                console.print(f"  [red]{icon('cross')}[/red] Acunetix URL not configured")
                results["acunetix"] = False
                all_passed = False
            else:
                with console.status("[yellow]Testing Acunetix...[/yellow]"):
                    try:
                        import httpx

                        response = httpx.get(
                            f"{config.scanners.acunetix_url}/api/v1/me",
                            headers={"X-Auth": config.scanners.acunetix_api_key or ""},
                            verify=config.scanners.verify_tls,
                            timeout=10,
                        )
                        if response.status_code == 200:
                            console.print(f"  [green]{icon('check')}[/green] Acunetix connected")
                            results["acunetix"] = True
                        else:
                            console.print(
                                f"  [red]{icon('cross')}[/red] Acunetix auth failed (HTTP {response.status_code})"
                            )
                            results["acunetix"] = False
                            all_passed = False
                    except Exception as e:
                        console.print(
                            f"  [red]{icon('cross')}[/red] Acunetix failed: {str(e)[:50]}"
                        )
                        results["acunetix"] = False
                        all_passed = False

        # Burp Suite
        if use_burp:
            if not config.scanners.burp_url:
                console.print(f"  [red]{icon('cross')}[/red] Burp Suite URL not configured")
                results["burp"] = False
                all_passed = False
            else:
                with console.status("[yellow]Testing Burp Suite...[/yellow]"):
                    try:
                        import httpx

                        response = httpx.get(
                            f"{config.scanners.burp_url}/api-internal/versions",
                            headers={
                                "Authorization": f"Bearer {config.scanners.burp_api_key or ''}"
                            },
                            verify=config.scanners.verify_tls,
                            timeout=10,
                        )
                        if response.status_code == 200:
                            console.print(f"  [green]{icon('check')}[/green] Burp Suite connected")
                            results["burp"] = True
                        else:
                            console.print(
                                f"  [red]{icon('cross')}[/red] Burp Suite auth failed (HTTP {response.status_code})"
                            )
                            results["burp"] = False
                            all_passed = False
                    except Exception as e:
                        console.print(
                            f"  [red]{icon('cross')}[/red] Burp Suite failed: {str(e)[:50]}"
                        )
                        results["burp"] = False
                        all_passed = False

        console.print()

    # ======================== Local Tools Check ========================
    console.print(Rule("Local Security Tools", style="bold cyan"))

    essential_tools = ["nmap", "httpx", "nuclei"]
    optional_tools = ["subfinder", "ffuf", "nikto"]

    found_essential = []
    missing_essential = []

    for tool in essential_tools:
        if shutil.which(tool):
            found_essential.append(tool)
        else:
            missing_essential.append(tool)

    found_optional = [t for t in optional_tools if shutil.which(t)]

    if found_essential:
        console.print(f"  [green]{icon('check')}[/green] Essential: {', '.join(found_essential)}")
    if missing_essential:
        console.print(
            f"  [yellow]{icon('warning')}[/yellow] Missing essential: {', '.join(missing_essential)}"
        )
        if not use_vps:
            console.print("    [dim]Consider using --use-vps or install locally[/dim]")
    if found_optional:
        console.print(
            f"  [dim]{icon('circle_empty')}[/dim] Optional available: {', '.join(found_optional)}"
        )

    results["tools"] = len(missing_essential) == 0 or use_vps

    console.print()

    # ======================== Summary ========================
    console.print(Rule("Pre-flight Summary", style="bold cyan"))

    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="center")

    for component, status in results.items():
        if status is True:
            status_str = f"[green]{icon('check')} READY[/green]"
        elif status is False:
            status_str = f"[red]{icon('cross')} FAILED[/red]"
        elif status is None:
            status_str = f"[yellow]{icon('circle_empty')} SKIPPED[/yellow]"
        else:
            status_str = "[dim]?[/dim]"
        table.add_row(component.upper(), status_str)

    console.print(table)
    console.print()

    if all_passed:
        console.print(
            f"[bold green]{icon('check')} All pre-flight checks passed! Ready to scan.[/bold green]"
        )
    else:
        console.print(
            f"[bold red]{icon('cross')} Some checks failed. Fix issues above before scanning.[/bold red]"
        )
        console.print("[dim]Run 'aiptx setup' to configure missing components.[/dim]")

    console.print()

    return all_passed


def show_version():
    """Show detailed version information."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    info = f"""
[bold cyan]AIPT v2 - AI-Powered Penetration Testing Framework[/bold cyan]
Version: {__version__}

[bold]Components:[/bold]
  • LLM Integration (litellm)
  • Scanner Integration (Acunetix, Burp, Nessus, ZAP)
  • VPS Execution Support
  • AI-Guided Scanning
  • Professional Report Generation

[bold]Documentation:[/bold]
  https://github.com/aipt/aipt-v2

[bold]Author:[/bold]
  Satyam Rastogi
    """

    console.print(Panel(info, title="Version Information", border_style="cyan"))

    return 0


def run_verify(args):
    """Verify AIPTX installation."""
    import asyncio

    from aipt_v2.verify_install import verify_installation

    quick = getattr(args, "quick", False)
    auto_fix = getattr(args, "fix", False)
    report_file = getattr(args, "report", None)

    return asyncio.run(
        verify_installation(
            quick=quick,
            auto_fix=auto_fix,
            report_file=report_file,
        )
    )


def run_shell(args):
    """Start the interactive security shell."""
    import asyncio

    from aipt_v2.interactive_shell import start_interactive_shell

    log_file = getattr(args, "log", None)
    working_dir = getattr(args, "dir", None)

    return asyncio.run(
        start_interactive_shell(
            log_file=log_file,
            working_dir=working_dir,
        )
    )


def run_tools_command(args):
    """Handle tools subcommands for local tool management."""

    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    tools_cmd = getattr(args, "tools_command", None)

    if tools_cmd == "install":
        return run_tools_install(args, console)
    elif tools_cmd == "list":
        return run_tools_list(args, console)
    elif tools_cmd == "check":
        return run_tools_check(args, console)
    else:
        console.print(
            Panel(
                "[bold cyan]AIPTX Local Tools Management[/bold cyan]\n\n"
                "[bold]aiptx tools install[/bold]  - Install security tools locally\n"
                "[bold]aiptx tools list[/bold]     - List available/installed tools\n"
                "[bold]aiptx tools check[/bold]    - Check installed tool status\n\n"
                "[dim]Examples:[/dim]\n"
                "  aiptx tools install --core          # Install core tools\n"
                "  aiptx tools install -c recon scan   # Install by category\n"
                "  aiptx tools install -t nmap nuclei  # Install specific tools",
                title=f"{icon('wrench')} Local Security Tools",
                border_style="cyan",
            )
        )
        return 0


def run_tools_install(args, console):
    """Install security tools on local system."""
    import asyncio

    from rich.panel import Panel

    console.print()
    console.print(
        Panel(
            "[bold cyan]Local Tool Installation[/bold cyan]\n\n"
            "Installing security tools on your local system.\n"
            "Some tools may require sudo/admin privileges.",
            title=f"{icon('wrench')} Installation",
            border_style="cyan",
        )
    )
    console.print()

    async def _install():
        try:
            from aipt_v2.local_tool_installer import TOOLS, LocalToolInstaller
            from aipt_v2.system_detector import SystemDetector

            # Detect system first
            detector = SystemDetector()
            with console.status("[bold cyan]Detecting system...[/bold cyan]"):
                system_info = await detector.detect()

            console.print(
                f"[dim]Detected: {system_info.os_name} with {system_info.package_manager.value}[/dim]"
            )

            installer = LocalToolInstaller(system_info)
            use_sudo = not getattr(args, "no_sudo", False)

            # Determine what to install
            if getattr(args, "all", False):
                console.print("[cyan]Installing all available tools...[/cyan]")
                results = await installer.install_all()
            elif getattr(args, "tools", None):
                console.print(f"[cyan]Installing specific tools: {', '.join(args.tools)}[/cyan]")
                results = await installer.install_tools(tools=args.tools, use_sudo=use_sudo)
            elif getattr(args, "categories", None):
                console.print(f"[cyan]Installing categories: {', '.join(args.categories)}[/cyan]")
                results = await installer.install_tools(
                    categories=args.categories, use_sudo=use_sudo
                )
            else:
                # Default: core tools
                console.print("[cyan]Installing core security tools...[/cyan]")
                results = await installer.install_core_tools()

            # Show summary
            installer.print_tool_status(results)
            return 0

        except ImportError as e:
            console.print(f"[red]Error: Missing dependency - {e}[/red]")
            return 1
        except Exception as e:
            console.print(f"[red]Error during installation: {e}[/red]")
            return 1

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_install())
    finally:
        loop.close()


def run_tools_list(args, console):
    """List available and installed tools."""
    import asyncio

    from rich import box
    from rich.table import Table

    async def _list():
        try:
            from aipt_v2.local_tool_installer import TOOLS, LocalToolInstaller

            installer = LocalToolInstaller()
            installed = await installer.get_installed_tools()

            category = getattr(args, "category", "all")
            installed_only = getattr(args, "installed_only", False)

            table = Table(title="Security Tools", box=box.ROUNDED)
            table.add_column("Tool", style="cyan")
            table.add_column("Category", style="dim")
            table.add_column("Status", justify="center")
            table.add_column("Description")

            for tool_name, tool_def in sorted(TOOLS.items()):
                if category != "all" and tool_def.category.value != category:
                    continue

                is_installed = installed.get(tool_name, False)

                if installed_only and not is_installed:
                    continue

                status = (
                    f"[green]{icon('check')} Installed[/green]"
                    if is_installed
                    else f"[dim]{icon('circle_empty')} Not installed[/dim]"
                )
                core_badge = f" [yellow]{icon('sparkles')}[/yellow]" if tool_def.is_core else ""

                table.add_row(
                    f"{tool_name}{core_badge}",
                    tool_def.category.value,
                    status,
                    (
                        tool_def.description[:50] + "..."
                        if len(tool_def.description) > 50
                        else tool_def.description
                    ),
                )

            console.print()
            console.print(table)
            console.print()
            console.print(
                f"[dim]Legend: [yellow]{icon('sparkles')}[/yellow] = Core tool (recommended)[/dim]"
            )

            return 0

        except ImportError as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_list())
    finally:
        loop.close()


def run_tools_check(args, console):
    """Check installed tool status."""
    import asyncio

    from rich import box
    from rich.panel import Panel
    from rich.table import Table

    async def _check():
        try:
            from aipt_v2.local_tool_installer import TOOLS, LocalToolInstaller

            console.print()
            with console.status("[bold cyan]Checking installed tools...[/bold cyan]"):
                installer = LocalToolInstaller()
                installed = await installer.get_installed_tools()

            # Count by category
            categories = {}
            for tool_name, tool_def in TOOLS.items():
                cat = tool_def.category.value
                if cat not in categories:
                    categories[cat] = {"total": 0, "installed": 0}
                categories[cat]["total"] += 1
                if installed.get(tool_name, False):
                    categories[cat]["installed"] += 1

            # Summary table
            table = Table(box=box.ROUNDED)
            table.add_column("Category", style="cyan")
            table.add_column("Installed", justify="right", style="green")
            table.add_column("Total", justify="right")
            table.add_column("Coverage", justify="right")

            total_installed = 0
            total_tools = 0

            for cat, counts in sorted(categories.items()):
                coverage = (
                    (counts["installed"] / counts["total"] * 100) if counts["total"] > 0 else 0
                )
                coverage_color = (
                    "green" if coverage >= 75 else "yellow" if coverage >= 50 else "red"
                )

                table.add_row(
                    cat,
                    str(counts["installed"]),
                    str(counts["total"]),
                    f"[{coverage_color}]{coverage:.0f}%[/{coverage_color}]",
                )

                total_installed += counts["installed"]
                total_tools += counts["total"]

            table.add_row("─" * 15, "─" * 5, "─" * 5, "─" * 7)
            total_coverage = (total_installed / total_tools * 100) if total_tools > 0 else 0
            table.add_row(
                "[bold]Total[/bold]",
                f"[bold]{total_installed}[/bold]",
                f"[bold]{total_tools}[/bold]",
                f"[bold]{total_coverage:.0f}%[/bold]",
            )

            console.print()
            console.print(table)
            console.print()

            if total_coverage < 50:
                console.print(
                    Panel(
                        "[yellow]Many security tools are not installed.[/yellow]\n\n"
                        "Run [bold]aiptx tools install --core[/bold] to install essential tools.",
                        title=f"{icon('lightbulb')} Recommendation",
                        border_style="yellow",
                    )
                )

            return 0

        except ImportError as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_check())
    finally:
        loop.close()


def run_vps_command(args):
    """Handle VPS subcommands."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    # Check VPS configuration
    config = get_config()
    if not config.vps.host:
        console.print(
            Panel(
                "[bold red]VPS not configured![/bold red]\n\n"
                "Run [bold green]aiptx setup[/bold green] to configure VPS settings.\n\n"
                "[bold]Required settings:[/bold]\n"
                "  • VPS_HOST - VPS IP or hostname\n"
                "  • VPS_USER - SSH username (default: ubuntu)\n"
                "  • VPS_KEY  - Path to SSH private key",
                title=f"{icon('warning')} VPS Configuration Required",
                border_style="yellow",
            )
        )
        return 1

    vps_cmd = getattr(args, "vps_command", None)

    if vps_cmd == "setup":
        return run_vps_setup(args, console)
    elif vps_cmd == "status":
        return run_vps_status(args, console)
    elif vps_cmd == "scan":
        return run_vps_scan(args, console)
    elif vps_cmd == "script":
        return run_vps_script(args, console)
    else:
        console.print(
            Panel(
                "[bold cyan]AIPTX VPS Commands[/bold cyan]\n\n"
                "[bold]aiptx vps setup[/bold]   - Install security tools on VPS\n"
                "[bold]aiptx vps status[/bold]  - Check VPS connection and tools\n"
                "[bold]aiptx vps scan[/bold]    - Run security scan from VPS\n"
                "[bold]aiptx vps script[/bold]  - Generate setup script",
                title=f"{icon('desktop')} VPS Remote Execution",
                border_style="cyan",
            )
        )
        return 0


def run_vps_setup(args, console):
    """Install security tools on VPS with real-time progress."""
    from rich import box
    from rich.console import Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    # Check for asyncssh FIRST before any VPS operations
    try:
        import asyncssh
    except ImportError:
        console.print()
        console.print(
            Panel(
                "[bold red]Missing Dependency: asyncssh[/bold red]\n\n"
                "The VPS module requires asyncssh for SSH connectivity.\n\n"
                "[bold]Install with:[/bold]\n"
                "  [green]pip install asyncssh[/green]\n"
                "  [dim]or[/dim]\n"
                "  [green]pip install aiptx[vps][/green]\n"
                "  [dim]or[/dim]\n"
                "  [green]pip install aiptx[full][/green]",
                title=f"{icon('warning')} Dependency Required",
                border_style="yellow",
            )
        )
        console.print()
        return 1

    from aipt_v2.runtime.vps import VPS_TOOLS, VPSRuntime

    console.print()
    console.print(
        Panel(
            "[bold cyan]VPS Tool Installation[/bold cyan]\n\n"
            "Installing security tools on your VPS.\n"
            "This may take 10-30 minutes depending on your VPS speed.",
            title=f"{icon('wrench')} Setup",
            border_style="cyan",
        )
    )
    console.print()

    # Get categories and tools to install
    categories = getattr(args, "categories", None)
    specific_tools = getattr(args, "tools", None)

    # Build list of tools to install
    tools_to_install = []
    if specific_tools:
        tools_to_install = specific_tools
    elif categories:
        for cat in categories:
            if cat in VPS_TOOLS:
                tools_to_install.extend(VPS_TOOLS[cat].keys())
    else:
        for cat_tools in VPS_TOOLS.values():
            tools_to_install.extend(cat_tools.keys())

    # State for live display
    state = {
        "status": "Connecting...",
        "current_tool": "",
        "output": [],
        "results": {},
        "total": len(tools_to_install),
        "completed": 0,
    }

    def make_display():
        """Generate the live display."""
        lines = []

        # Status line
        status_text = Text()
        status_text.append(f"{icon('bolt')} ", style="yellow")
        status_text.append(state["status"], style="bold cyan")
        lines.append(status_text)

        # Progress
        if state["total"] > 0:
            pct = (state["completed"] / state["total"]) * 100
            bar_width = 40
            filled = int(bar_width * state["completed"] / state["total"])
            bar = "█" * filled + "░" * (bar_width - filled)
            progress_text = Text()
            progress_text.append(f"   [{bar}] ", style="cyan")
            progress_text.append(f"{state['completed']}/{state['total']} ", style="bold")
            progress_text.append(f"({pct:.0f}%)", style="dim")
            lines.append(progress_text)

        # Current tool
        if state["current_tool"]:
            tool_text = Text()
            tool_text.append(f"   {icon('arrow')} Installing: ", style="dim")
            tool_text.append(state["current_tool"], style="bold green")
            lines.append(tool_text)

        # Recent output (last 5 lines)
        if state["output"]:
            lines.append(Text())
            lines.append(Text("   Recent output:", style="dim"))
            for line in state["output"][-5:]:
                output_text = Text()
                output_text.append("   │ ", style="dim cyan")
                # Truncate long lines
                display_line = line[:70] + "..." if len(line) > 70 else line
                output_text.append(display_line, style="dim")
                lines.append(output_text)

        return Group(*lines)

    async def setup_vps_live(live):
        runtime = VPSRuntime()

        # Connect
        state["status"] = "Connecting to VPS..."
        live.update(make_display())
        await runtime.connect()
        state["status"] = f"Connected to {runtime.host}"
        state["output"].append(f"{icon('check')} Connected to {runtime.host}")
        live.update(make_display())

        # Setup base dependencies first
        state["status"] = "Installing base dependencies..."
        state["current_tool"] = "apt packages, Go, Python, Ruby"
        live.update(make_display())

        setup_script = """
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq git curl wget python3-pip golang-go ruby-full build-essential libssl-dev libffi-dev 2>/dev/null
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
        mkdir -p $GOPATH/bin
        echo 'Base dependencies installed'
        """
        stdout, stderr, code = await runtime._run_command(
            f"sudo bash -c '{setup_script}'", timeout=300
        )
        state["output"].append(f"{icon('check')} Base dependencies installed")
        live.update(make_display())

        # Install each tool
        state["status"] = "Installing security tools..."

        for tool_name in tools_to_install:
            state["current_tool"] = tool_name
            state["output"].append(f"Installing {tool_name}...")
            live.update(make_display())

            success = await runtime.install_tool(tool_name)
            state["results"][tool_name] = success
            state["completed"] += 1

            if success:
                state["output"].append(f"{icon('check')} {tool_name} installed")
            else:
                state["output"].append(f"{icon('cross')} {tool_name} failed")

            live.update(make_display())

        state["status"] = "Installation complete!"
        state["current_tool"] = ""
        live.update(make_display())

        await runtime.disconnect()
        return state["results"]

    # Run with live display
    try:
        with Live(make_display(), console=console, refresh_per_second=4) as live:
            results = asyncio.run(setup_vps_live(live))
    except KeyboardInterrupt:
        console.print("\n[yellow]Installation interrupted by user[/yellow]")
        return 130

    # Show final results
    console.print()
    table = Table(title="Installation Results", box=box.ROUNDED)
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="green")

    installed = 0
    failed = 0
    for tool, success in sorted(results.items()):
        if success:
            table.add_row(tool, f"[green]{icon('check')} Installed[/green]")
            installed += 1
        else:
            table.add_row(tool, f"[red]{icon('cross')} Failed[/red]")
            failed += 1

    console.print(table)
    console.print()

    if failed == 0:
        console.print(
            Panel(
                f"[bold green]{icon('check')} All {installed} tools installed successfully![/bold green]\n\n"
                "You can now run:\n"
                "  [bold]aiptx vps scan target.com[/bold]",
                title=f"{icon('sparkles')} Setup Complete",
                border_style="green",
            )
        )
    else:
        console.print(f"[bold]Summary:[/bold] {installed} installed, [red]{failed} failed[/red]")
        console.print("[dim]Failed tools may require manual installation on VPS[/dim]")

    return 0 if failed == 0 else 1


def run_vps_status(args, console):
    """Check VPS connection and installed tools."""
    from rich import box
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    # Check for asyncssh FIRST
    try:
        import asyncssh
    except ImportError:
        console.print()
        console.print(
            Panel(
                "[bold red]Missing Dependency: asyncssh[/bold red]\n\n"
                "The VPS module requires asyncssh for SSH connectivity.\n\n"
                "[bold]Install with:[/bold]\n"
                "  [green]pip install asyncssh[/green]\n"
                "  [dim]or[/dim]\n"
                "  [green]pip install aiptx[vps][/green]",
                title=f"{icon('warning')} Dependency Required",
                border_style="yellow",
            )
        )
        console.print()
        return 1

    from aipt_v2.runtime.vps import VPS_TOOLS, VPSRuntime

    config = get_config()

    # State for live display
    state = {"status": "Connecting...", "tool": "", "checked": 0, "total": 0}

    def make_status():
        text = Text()
        text.append(f"{icon('bolt')} ", style="yellow")
        text.append(state["status"], style="bold cyan")
        if state["tool"]:
            text.append(f" - checking {state['tool']}", style="dim")
        if state["total"] > 0:
            text.append(f" ({state['checked']}/{state['total']})", style="dim")
        return text

    async def check_status_live(live):
        runtime = VPSRuntime()

        # Try to connect
        state["status"] = "Connecting to VPS..."
        live.update(make_status())

        try:
            await runtime.connect()
        except Exception as e:
            return False, str(e), {}

        state["status"] = f"Connected to {runtime.host}"
        live.update(make_status())

        # Count total tools
        total_tools = sum(len(tools) for tools in VPS_TOOLS.values())
        state["total"] = total_tools
        state["status"] = "Checking installed tools..."
        live.update(make_status())

        # Check each tool
        tools_status = {}
        for category, tools in VPS_TOOLS.items():
            for tool_name, tool_info in tools.items():
                state["tool"] = tool_name
                state["checked"] += 1
                live.update(make_status())

                check_cmd = tool_info.get("check", f"which {tool_name}")
                stdout, stderr, code = await runtime._run_command(check_cmd, timeout=10)
                tools_status[tool_name] = code == 0

        state["status"] = "Done!"
        state["tool"] = ""
        live.update(make_status())

        await runtime.disconnect()
        return True, "Connected", tools_status

    console.print()

    try:
        with Live(make_status(), console=console, refresh_per_second=4) as live:
            connected, message, tools_status = asyncio.run(check_status_live(live))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        return 130

    # Connection status
    console.print()
    if connected:
        console.print(f"[green]{icon('check')}[/green] Connected to [bold]{config.vps.host}[/bold]")
    else:
        console.print(f"[red]{icon('cross')}[/red] Failed to connect: {message}")
        return 1

    # Tool status table
    console.print()
    table = Table(title="Security Tools Status", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Tool", style="white")
    table.add_column("Status", style="green")

    for category, tools in VPS_TOOLS.items():
        for tool_name in tools:
            status = tools_status.get(tool_name, False)
            status_str = (
                f"[green]{icon('check')} Installed[/green]"
                if status
                else f"[dim]{icon('circle_empty')} Not installed[/dim]"
            )
            table.add_row(category, tool_name, status_str)

    console.print(table)

    # Summary
    installed = sum(1 for v in tools_status.values() if v)
    total = len(tools_status)
    console.print()

    if installed == total:
        console.print(
            Panel(
                f"[bold green]{icon('check')} All {total} tools installed![/bold green]\n\n"
                "Your VPS is ready for scanning.\n"
                "Run: [bold]aiptx vps scan target.com[/bold]",
                title=f"{icon('sparkles')} VPS Ready",
                border_style="green",
            )
        )
    else:
        console.print(f"[bold]Tools:[/bold] {installed}/{total} installed")
        console.print()
        console.print("[dim]Run 'aiptx vps setup' to install missing tools[/dim]")

    return 0


def run_vps_scan(args, console):
    """Run security scan from VPS."""
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn

    # Check for asyncssh FIRST
    try:
        import asyncssh
    except ImportError:
        console.print()
        console.print(
            Panel(
                "[bold red]Missing Dependency: asyncssh[/bold red]\n\n"
                "The VPS module requires asyncssh for SSH connectivity.\n\n"
                "[bold]Install with:[/bold]\n"
                "  [green]pip install asyncssh[/green]\n"
                "  [dim]or[/dim]\n"
                "  [green]pip install aiptx[vps][/green]",
                title=f"{icon('warning')} Dependency Required",
                border_style="yellow",
            )
        )
        console.print()
        return 1

    target = args.target
    mode = getattr(args, "mode", "standard")
    tools = getattr(args, "tools", None)

    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Mode:[/bold] {mode}\n"
            f"[bold]Tools:[/bold] {', '.join(tools) if tools else 'Auto-selected'}",
            title=f"{icon('target')} VPS Scan Configuration",
            border_style="cyan",
        )
    )
    console.print()

    from aipt_v2.runtime.vps import VPSRuntime

    async def run_scan():
        runtime = VPSRuntime()
        await runtime.connect()

        results = await runtime.run_scan(
            target=target,
            scan_type=mode,
            tools=tools,
        )

        await runtime.disconnect()
        return results

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]Scanning {target} from VPS...", total=None)
        results = asyncio.run(run_scan())

    # Display results
    console.print()
    console.print(f"[bold green]{icon('check')} Scan complete![/bold green]")
    console.print()
    console.print(f"[bold]Results saved to:[/bold] {results.get('local_results_path', 'N/A')}")
    console.print()

    # Show tool outputs summary
    tool_outputs = results.get("tool_outputs", {})
    if tool_outputs:
        from rich.table import Table

        table = Table(title="Tool Execution Summary")
        table.add_column("Tool", style="cyan")
        table.add_column("Exit Code", style="green")
        table.add_column("Output Size", style="yellow")

        for tool, output in tool_outputs.items():
            exit_code = output.get("exit_code", -1)
            status = (
                "[green]{icon('check')}[/green]" if exit_code == 0 else f"[red]{exit_code}[/red]"
            )
            stdout_len = len(output.get("stdout", ""))
            table.add_row(tool, status, f"{stdout_len} bytes")

        console.print(table)

    return 0


def run_vps_script(args, console):
    """Generate VPS setup script."""
    from aipt_v2.runtime.vps import generate_vps_setup_script

    categories = getattr(args, "categories", None)
    output_file = getattr(args, "output", None)

    script = generate_vps_setup_script(categories=categories)

    if output_file:
        with open(output_file, "w") as f:
            f.write(script)
        console.print(f"[green]{icon('check')}[/green] Script saved to: {output_file}")
        console.print("[dim]Run on VPS: curl -sL <url> | sudo bash[/dim]")
    else:
        console.print(script)

    return 0


def run_ai_command(args):
    """Handle AI security testing commands."""

    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    ai_cmd = getattr(args, "ai_command", None)

    # Run prerequisites check for AI commands (requires LLM key)
    if ai_cmd in ("code-review", "api-test", "web-pentest", "full"):
        from .prerequisites import check_prerequisites_sync

        is_ready, prereq_errors = check_prerequisites_sync(
            require_llm=True,
            require_tools=False,
        )

        if not is_ready:
            console.print()
            console.print(
                Panel(
                    "[bold red]Prerequisites Check Failed[/bold red]\n\n"
                    "AI security testing requires an LLM API key.\n\n"
                    + "\n".join(f"  [red]•[/red] {e}" for e in prereq_errors)
                    + "\n\n[bold]To fix:[/bold]\n"
                    "  Run [bold green]aiptx setup[/bold green] to configure\n"
                    "  Or set: [dim]export ANTHROPIC_API_KEY=your-key[/dim]\n\n"
                    "[bold]For detailed diagnostics:[/bold]\n"
                    "  Run [bold green]aiptx check[/bold green]",
                    title=f"{icon('warning')} Configuration Required",
                    border_style="red",
                    padding=(1, 2),
                )
            )
            console.print()
            return 1

    if ai_cmd == "code-review":
        return run_ai_code_review(args, console)
    elif ai_cmd == "api-test":
        return run_ai_api_test(args, console)
    elif ai_cmd == "web-pentest":
        return run_ai_web_pentest(args, console)
    elif ai_cmd == "full":
        return run_ai_full_assessment(args, console)
    else:
        console.print()
        console.print(
            Panel(
                "[bold cyan]AIPTX AI Security Testing[/bold cyan]\n\n"
                "AI-powered security testing using LLMs (Claude, GPT, etc.)\n\n"
                "[bold]Commands:[/bold]\n"
                "  [bold green]aiptx ai code-review[/bold green] <path>  - AI source code security review\n"
                "  [bold green]aiptx ai api-test[/bold green] <url>     - AI REST API security testing\n"
                "  [bold green]aiptx ai web-pentest[/bold green] <url>  - AI web penetration testing\n"
                "  [bold green]aiptx ai full[/bold green] <target>      - Full AI-driven assessment\n\n"
                "[bold]Examples:[/bold]\n"
                "  aiptx ai code-review ./src --focus sqli xss\n"
                "  aiptx ai api-test https://api.example.com --openapi swagger.json\n"
                "  aiptx ai web-pentest https://example.com --quick",
                title=f"{icon('robot')} AI Security Testing",
                border_style="cyan",
            )
        )
        console.print()
        return 0


def run_ai_code_review(args, console):
    """Run AI-powered source code security review."""
    import json

    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn

    target = args.target
    focus = getattr(args, "focus", None)
    max_steps = getattr(args, "max_steps", 100)
    quick = getattr(args, "quick", False)
    output_file = getattr(args, "output", None)

    # Get model from user's config (supports Ollama, OpenAI, Anthropic, etc.)
    model, api_base = _get_llm_model_config()

    # Override with CLI argument if provided
    if hasattr(args, "model") and args.model:
        model = args.model

    # Verify target exists
    if not Path(target).exists():
        console.print(f"[red]Error:[/red] Target path does not exist: {target}")
        return 1

    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Model:[/bold] {model}\n"
            f"[bold]Mode:[/bold] {'Quick scan' if quick else 'Full review'}\n"
            f"[bold]Focus:[/bold] {', '.join(focus) if focus else 'All vulnerabilities'}",
            title=f"{icon('search')} AI Code Review",
            border_style="cyan",
        )
    )
    console.print()

    # Import agent
    from aipt_v2.skills.agents.base import AgentConfig
    from aipt_v2.skills.agents.code_review import CodeReviewAgent

    config = AgentConfig(
        model=model,
        max_steps=max_steps,
        verbose=True,
    )

    agent = CodeReviewAgent(
        target_path=target,
        config=config,
        focus_areas=focus,
    )

    # Run the review
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]AI reviewing code...", total=None)

        try:
            if quick:
                result = asyncio.run(agent.quick_scan())
            else:
                result = asyncio.run(agent.run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Review interrupted by user[/yellow]")
            return 130
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {e}")
            return 1

    # Display results
    console.print()
    display_ai_results(console, result, "Code Review")

    # Save to file if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if result.success else 1


def run_ai_api_test(args, console):
    """Run AI-powered API security testing."""
    import json

    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn

    target = args.target
    openapi_spec = getattr(args, "openapi", None)
    auth_token = getattr(args, "auth_token", None)
    max_steps = getattr(args, "max_steps", 100)
    output_file = getattr(args, "output", None)

    # Get model from user's config (supports Ollama, OpenAI, Anthropic, etc.)
    model, api_base = _get_llm_model_config()

    # Override with CLI argument if provided
    if hasattr(args, "model") and args.model:
        model = args.model

    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Model:[/bold] {model}\n"
            f"[bold]OpenAPI Spec:[/bold] {openapi_spec or 'Not provided'}\n"
            f"[bold]Authentication:[/bold] {'Bearer token' if auth_token else 'None'}",
            title="🔌 AI API Security Test",
            border_style="cyan",
        )
    )
    console.print()

    # Import agent
    from aipt_v2.skills.agents.api_tester import APITestAgent
    from aipt_v2.skills.agents.base import AgentConfig

    config = AgentConfig(
        model=model,
        max_steps=max_steps,
        verbose=True,
    )

    agent = APITestAgent(
        base_url=target,
        config=config,
        openapi_spec=openapi_spec,
        auth_token=auth_token,
    )

    # Run the test
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]AI testing API...", total=None)

        try:
            result = asyncio.run(agent.run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Test interrupted by user[/yellow]")
            return 130
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {e}")
            return 1

    # Display results
    console.print()
    display_ai_results(console, result, "API Test")

    # Save to file if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if result.success else 1


def run_ai_web_pentest(args, console):
    """Run AI-powered web penetration testing."""
    import json

    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn

    target = args.target
    auth_token = getattr(args, "auth_token", None)
    cookies_list = getattr(args, "cookie", None) or []
    max_steps = getattr(args, "max_steps", 100)
    quick = getattr(args, "quick", False)
    output_file = getattr(args, "output", None)

    # Get model from user's config (supports Ollama, OpenAI, Anthropic, etc.)
    model, api_base = _get_llm_model_config()

    # Override with CLI argument if provided
    if hasattr(args, "model") and args.model:
        model = args.model

    # Parse cookies
    cookies = {}
    for cookie in cookies_list:
        if "=" in cookie:
            key, value = cookie.split("=", 1)
            cookies[key] = value

    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Model:[/bold] {model}\n"
            f"[bold]Mode:[/bold] {'Quick scan' if quick else 'Full pentest'}\n"
            f"[bold]Authentication:[/bold] {'Token + Cookies' if auth_token and cookies else 'Token' if auth_token else 'Cookies' if cookies else 'None'}",
            title=f"{icon('globe')} AI Web Penetration Test",
            border_style="cyan",
        )
    )
    console.print()

    # Import agent
    from aipt_v2.skills.agents.base import AgentConfig
    from aipt_v2.skills.agents.web_pentest import WebPentestAgent

    config = AgentConfig(
        model=model,
        max_steps=max_steps,
        verbose=True,
    )

    agent = WebPentestAgent(
        target=target,
        config=config,
        cookies=cookies if cookies else None,
        auth_token=auth_token,
    )

    # Run the test
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]AI pentesting web app...", total=None)

        try:
            if quick:
                result = asyncio.run(agent.quick_scan())
            else:
                result = asyncio.run(agent.run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Pentest interrupted by user[/yellow]")
            return 130
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {e}")
            return 1

    # Display results
    console.print()
    display_ai_results(console, result, "Web Pentest")

    # Save to file if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if result.success else 1


def run_ai_full_assessment(args, console):
    """Run full AI-driven security assessment."""
    import json

    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn

    target = args.target
    test_types = getattr(args, "types", ["web"])
    output_file = getattr(args, "output", None)

    # Get model from user's config (supports Ollama, OpenAI, Anthropic, etc.)
    model, api_base = _get_llm_model_config()

    # Override with CLI argument if provided
    if hasattr(args, "model") and args.model:
        model = args.model

    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Model:[/bold] {model}\n"
            f"[bold]Test Types:[/bold] {', '.join(test_types)}",
            title=f"{icon('target')} Full AI Security Assessment",
            border_style="cyan",
        )
    )
    console.print()

    # Import agent
    from aipt_v2.skills.agents.base import AgentConfig
    from aipt_v2.skills.agents.security_agent import SecurityAgent

    config = AgentConfig(
        model=model,
        max_steps=150,  # More steps for full assessment
        verbose=True,
    )

    agent = SecurityAgent(
        target=target,
        config=config,
        test_types=test_types,
    )

    # Run the assessment
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running full AI assessment...", total=None)

        try:
            results = asyncio.run(agent.run_full_assessment())
            combined = agent.combine_results(results)
        except KeyboardInterrupt:
            console.print("\n[yellow]Assessment interrupted by user[/yellow]")
            return 130
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {e}")
            return 1

    # Display results
    console.print()
    display_ai_results(console, combined, "Full Assessment")

    # Show per-type results
    for test_type, result in results.items():
        if result.findings:
            console.print(f"\n[bold]{test_type.upper()} Findings:[/bold] {len(result.findings)}")

    # Save to file if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(combined.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if combined.success else 1


def display_ai_results(console, result, test_name):
    """Display AI testing results in a formatted way."""
    from rich import box
    from rich.panel import Panel
    from rich.table import Table

    # Summary panel
    severity_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    # Count by severity
    severity_counts = {}
    for finding in result.findings:
        sev = finding.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = severity_colors.get(sev, "white")
            summary_parts.append(f"[{color}]{sev.upper()}: {count}[/{color}]")

    summary = (
        " | ".join(summary_parts) if summary_parts else "[green]No vulnerabilities found[/green]"
    )

    console.print(
        Panel(
            f"[bold]Findings:[/bold] {len(result.findings)}\n"
            f"[bold]Severity:[/bold] {summary}\n"
            f"[bold]Steps:[/bold] {result.total_steps}\n"
            f"[bold]Time:[/bold] {result.execution_time:.1f}s\n"
            f"[bold]Model:[/bold] {result.model_used}",
            title=f"{icon('chart')} {test_name} Results",
            border_style="green" if result.success else "red",
        )
    )

    # Findings table
    if result.findings:
        console.print()
        table = Table(title="Security Findings", box=box.ROUNDED)
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=10)
        table.add_column("Title", style="white")
        table.add_column("Location", style="dim")

        for i, finding in enumerate(result.findings, 1):
            sev_color = severity_colors.get(finding.severity.value, "white")
            severity_text = f"[{sev_color}]{finding.severity.value.upper()}[/{sev_color}]"
            table.add_row(
                str(i),
                severity_text,
                finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                finding.location[:40] + "..." if len(finding.location) > 40 else finding.location,
            )

        console.print(table)

        # Show details for critical/high findings
        critical_high = [f for f in result.findings if f.severity.value in ["critical", "high"]]
        if critical_high:
            console.print()
            console.print("[bold red]Critical/High Severity Details:[/bold red]")
            for finding in critical_high[:5]:  # Limit to 5 detailed findings
                console.print(f"\n[bold]{finding.title}[/bold]")
                console.print(f"  [dim]Location:[/dim] {finding.location}")
                console.print(f"  [dim]Description:[/dim] {finding.description[:200]}...")
                if finding.remediation:
                    console.print(f"  [dim]Fix:[/dim] {finding.remediation[:150]}...")

    # Errors
    if result.errors:
        console.print()
        console.print("[bold red]Errors:[/bold red]")
        for error in result.errors:
            console.print(f"  [red]{icon('bullet')}[/red] {error}")


# =============================================================================
# Active Directory Commands (v5.0)
# =============================================================================


def run_ad_command(args):
    """Handle Active Directory penetration testing commands."""

    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    ad_cmd = getattr(args, "ad_command", None)

    if ad_cmd == "recon":
        return run_ad_recon(args, console)
    elif ad_cmd == "scan":
        return run_ad_scan(args, console)
    elif ad_cmd == "attack":
        return run_ad_attack(args, console)
    elif ad_cmd == "tools":
        return run_ad_tools(args, console)
    else:
        # Show AD help
        console.print()
        console.print(
            Panel(
                "[bold cyan]AIPTX Active Directory Testing (v5.0)[/bold cyan]\n\n"
                "[bold]Available Commands:[/bold]\n\n"
                f"  {icon('search')} [green]aiptx ad recon[/green] <domain>      Domain reconnaissance\n"
                f"  {icon('scan')} [green]aiptx ad scan[/green] <domain>       Vulnerability scanning\n"
                f"  {icon('exploit')} [green]aiptx ad attack[/green] <domain>     Execute attack chains\n"
                f"  {icon('tool')} [green]aiptx ad tools[/green]              Check available tools\n\n"
                "[bold]Examples:[/bold]\n"
                "  [dim]# Enumerate domain without credentials[/dim]\n"
                "  aiptx ad recon corp.local --dc 10.0.0.1 --method dns\n\n"
                "  [dim]# Authenticated enumeration with BloodHound[/dim]\n"
                "  aiptx ad recon corp.local --dc 10.0.0.1 -u jdoe -p pass123 --bloodhound\n\n"
                "  [dim]# Scan for ADCS vulnerabilities[/dim]\n"
                "  aiptx ad scan corp.local --dc 10.0.0.1 -u jdoe -p pass123 --type adcs\n\n"
                "  [dim]# Run Kerberoasting attack[/dim]\n"
                "  aiptx ad attack corp.local --dc 10.0.0.1 -u jdoe -p pass123 --chain kerberoast\n\n"
                "[bold yellow]WARNING:[/bold yellow] Use only for authorized penetration testing!",
                title=f"{icon('shield')} AD Security Testing",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        console.print()
        return 0


def run_ad_recon(args, console):
    """Run AD reconnaissance."""
    import asyncio
    import getpass
    import json

    from rich import box
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table

    console.print()
    console.print(
        Panel(
            f"[bold cyan]AD Reconnaissance[/bold cyan]\n"
            f"Target: [yellow]{args.domain}[/yellow]\n"
            f"DC: [yellow]{args.dc or 'Auto-detect'}[/yellow]\n"
            f"Method: [yellow]{args.method}[/yellow]",
            title=f"{icon('search')} Domain Enumeration",
            border_style="cyan",
        )
    )

    # Prompt for password if username provided but no password/hash
    password = args.password
    if args.username and not args.password and not args.hash:
        password = getpass.getpass(f"Password for {args.username}: ")

    try:
        from aipt_v2.recon.ad_discovery import ADDiscovery, ADDiscoveryConfig
        from aipt_v2.recon.ad_users import ADUserEnumConfig, ADUserEnumerator

        async def do_recon():
            results = {"domain": args.domain, "dcs": [], "users": [], "trusts": []}

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                # Domain discovery
                task = progress.add_task("Discovering domain controllers...", total=None)

                discovery_config = ADDiscoveryConfig()
                discovery = ADDiscovery(args.domain, args.dc, config=discovery_config)
                disc_result = await discovery.discover()

                results["dcs"] = [dc.hostname for dc in disc_result.domain_controllers]
                results["trusts"] = [
                    {"source": t.source_domain, "target": t.target_domain}
                    for t in disc_result.trusts
                ]
                progress.update(task, completed=True)

                # User enumeration if we have credentials or anonymous methods
                if args.username or args.method in ("kerberos", "all"):
                    progress.update(task, description="Enumerating users...")

                    dc_ip = args.dc or (
                        disc_result.domain_controllers[0].ip
                        if disc_result.domain_controllers
                        else None
                    )

                    if dc_ip:
                        enum_config = ADUserEnumConfig(
                            use_kerberos=(args.method in ("kerberos", "all")),
                            use_ldap=(args.method in ("ldap", "all") and args.username),
                        )
                        enumerator = ADUserEnumerator(
                            args.domain,
                            dc_ip,
                            username=args.username,
                            password=password,
                            ntlm_hash=args.hash,
                            config=enum_config,
                        )
                        enum_result = await enumerator.enumerate()
                        results["users"] = [
                            u.username for u in enum_result.users[:50]
                        ]  # Limit output
                        results["user_count"] = enum_result.total_found
                        results["kerberoastable"] = enum_result.kerberoastable_count
                        results["asrep_roastable"] = enum_result.asrep_roastable_count

            return results

        results = asyncio.run(do_recon())

        # Display results
        console.print()

        # DCs table
        if results["dcs"]:
            table = Table(title="Domain Controllers", box=box.ROUNDED)
            table.add_column("Hostname", style="cyan")
            for dc in results["dcs"]:
                table.add_row(dc)
            console.print(table)

        # Users summary
        if results.get("user_count"):
            console.print()
            console.print(
                Panel(
                    f"[bold]Total Users:[/bold] {results['user_count']}\n"
                    f"[bold]Kerberoastable:[/bold] [yellow]{results.get('kerberoastable', 0)}[/yellow]\n"
                    f"[bold]AS-REP Roastable:[/bold] [yellow]{results.get('asrep_roastable', 0)}[/yellow]",
                    title=f"{icon('user')} User Enumeration",
                    border_style="green",
                )
            )

        # Save output
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            console.print(f"\n[green]{icon('check')} Results saved to {args.output}[/green]")

        return 0

    except ImportError as e:
        console.print(f"\n[red]{icon('error')} Missing AD module: {e}[/red]")
        console.print("[dim]Install AD dependencies: pip install aiptx[ad][/dim]")
        return 1
    except Exception as e:
        console.print(f"\n[red]{icon('error')} Reconnaissance failed: {e}[/red]")
        return 1


def run_ad_scan(args, console):
    """Run AD vulnerability scanning."""
    import asyncio
    import getpass
    import json

    from rich import box
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table

    console.print()
    console.print(
        Panel(
            f"[bold cyan]AD Vulnerability Scan[/bold cyan]\n"
            f"Target: [yellow]{args.domain}[/yellow]\n"
            f"DC: [yellow]{args.dc}[/yellow]\n"
            f"Scan Types: [yellow]{', '.join(args.type)}[/yellow]",
            title=f"{icon('scan')} AD Security Scan",
            border_style="cyan",
        )
    )

    # Prompt for password if not provided
    password = args.password
    if not args.password and not args.hash:
        password = getpass.getpass(f"Password for {args.username}: ")

    try:
        findings = []

        async def do_scan():
            nonlocal findings

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:

                scan_types = (
                    args.type
                    if "all" not in args.type
                    else ["privesc", "adcs", "delegation", "winpwn"]
                )

                for scan_type in scan_types:
                    task = progress.add_task(f"Scanning for {scan_type} issues...", total=None)

                    if scan_type == "privesc":
                        from aipt_v2.scanners.ad_privesc_scanner import (
                            ADPrivescConfig,
                            ADPrivescScanner,
                        )

                        config = ADPrivescConfig(
                            domain=args.domain,
                            dc_ip=args.dc,
                            username=args.username,
                            password=password,
                            ntlm_hash=args.hash,
                        )
                        scanner = ADPrivescScanner(config)
                        result = await scanner.scan()
                        for account in result.privileged_accounts[:20]:
                            findings.append(
                                {
                                    "type": "Privileged Account",
                                    "severity": (
                                        "high"
                                        if "admin" in account.sam_account_name.lower()
                                        else "medium"
                                    ),
                                    "name": account.sam_account_name,
                                    "details": f"Groups: {', '.join(account.group_memberships[:3])}",
                                }
                            )

                    elif scan_type == "adcs":
                        from aipt_v2.scanners.ad_adcs_scanner import ADCSConfig, ADCSScanner

                        config = ADCSConfig(
                            domain=args.domain,
                            dc_ip=args.dc,
                            username=args.username,
                            password=password,
                            ntlm_hash=args.hash,
                        )
                        scanner = ADCSScanner(config)
                        result = await scanner.scan()
                        for vuln in result.vulnerabilities:
                            findings.append(
                                {
                                    "type": f"ADCS {vuln.esc_type.value}",
                                    "severity": "critical",
                                    "name": vuln.template_name,
                                    "details": vuln.description,
                                }
                            )

                    elif scan_type == "delegation":
                        from aipt_v2.exploitation.ad_delegation import (
                            ADDelegationAttacks,
                            ADDelegationConfig,
                        )

                        config = ADDelegationConfig(
                            domain=args.domain,
                            dc_ip=args.dc,
                            username=args.username,
                            password=password,
                            ntlm_hash=args.hash,
                        )
                        attacks = ADDelegationAttacks(config)
                        result = await attacks.enumerate_delegation()
                        for target in result.delegation_targets:
                            findings.append(
                                {
                                    "type": f"Delegation ({target.delegation_type.value})",
                                    "severity": "high",
                                    "name": target.sam_account_name,
                                    "details": f"Target: {target.target_spn or 'Any'}",
                                }
                            )

                    elif scan_type == "winpwn":
                        # WinPwn comprehensive Windows/AD assessment
                        from aipt_v2.scanners.winpwn_scanner import WinPwnScanConfig, WinPwnScanner

                        config = WinPwnScanConfig(
                            domain=args.domain,
                            dc_ip=args.dc,
                            username=args.username,
                            password=password,
                            ntlm_hash=args.hash,
                            script_path=getattr(args, "winpwn_script", ""),
                            modules=["localrecon", "domainrecon", "privesc", "kerberoasting"],
                            run_domain_recon=True,
                            run_kerberoasting=True,
                            run_credential_extraction=getattr(args, "extract_creds", False),
                        )
                        scanner = WinPwnScanner(config)
                        result = await scanner.scan()
                        for finding in result.findings:
                            findings.append(
                                {
                                    "type": f"WinPwn ({finding.template})",
                                    "severity": finding.severity.value,
                                    "name": finding.title[:40],
                                    "details": (
                                        finding.description[:60] if finding.description else ""
                                    ),
                                }
                            )
                        if result.credentials_found > 0:
                            findings.append(
                                {
                                    "type": "Credentials",
                                    "severity": "critical",
                                    "name": f"{result.credentials_found} credentials extracted",
                                    "details": "See detailed output for credential data",
                                }
                            )

                    progress.update(task, completed=True)

        asyncio.run(do_scan())

        # Display findings
        console.print()
        if findings:
            table = Table(title="Security Findings", box=box.ROUNDED)
            table.add_column("Type", style="cyan")
            table.add_column("Severity", width=10)
            table.add_column("Name", style="white")
            table.add_column("Details", style="dim")

            severity_colors = {
                "critical": "red",
                "high": "yellow",
                "medium": "blue",
                "low": "green",
            }
            for f in findings:
                color = severity_colors.get(f["severity"], "white")
                table.add_row(
                    f["type"],
                    f"[{color}]{f['severity'].upper()}[/{color}]",
                    f["name"][:30],
                    f["details"][:40] + "..." if len(f["details"]) > 40 else f["details"],
                )

            console.print(table)
            console.print(f"\n[bold]Total findings:[/bold] {len(findings)}")
        else:
            console.print("[green]{icon('check')} No vulnerabilities found[/green]")

        # Save output
        if args.output:
            with open(args.output, "w") as f:
                json.dump({"domain": args.domain, "findings": findings}, f, indent=2)
            console.print(f"\n[green]{icon('check')} Results saved to {args.output}[/green]")

        return 0

    except ImportError as e:
        console.print(f"\n[red]{icon('error')} Missing AD module: {e}[/red]")
        console.print("[dim]Install AD dependencies: pip install aiptx[ad][/dim]")
        return 1
    except Exception as e:
        console.print(f"\n[red]{icon('error')} Scan failed: {e}[/red]")
        return 1


def run_ad_attack(args, console):
    """Execute AD attack chains."""
    import getpass

    from rich import box
    from rich.panel import Panel
    from rich.table import Table

    # Warning banner
    console.print()
    console.print(
        Panel(
            "[bold red]WARNING: ACTIVE EXPLOITATION[/bold red]\n\n"
            "You are about to execute Active Directory attacks.\n"
            "Ensure you have [bold]explicit written authorization[/bold] for:\n\n"
            f"  • Domain: [yellow]{args.domain}[/yellow]\n"
            f"  • DC: [yellow]{args.dc}[/yellow]\n"
            f"  • Attack: [yellow]{args.chain}[/yellow]\n\n"
            "[dim]Unauthorized access is illegal and unethical.[/dim]",
            title=f"{icon('warning')} Authorization Required",
            border_style="red",
        )
    )

    if not args.dry_run:
        confirm = input("\nType 'AUTHORIZED' to continue: ")
        if confirm != "AUTHORIZED":
            console.print("[yellow]Attack cancelled.[/yellow]")
            return 0

    # Prompt for password
    password = args.password
    if not args.password and not args.hash:
        password = getpass.getpass(f"Password for {args.username}: ")

    try:
        from aipt_v2.evasion.ad_evasion import create_stealth_wrapper
        from aipt_v2.exploitation.ad_chain_templates import AD_ATTACK_CHAINS, get_ad_chain

        console.print()
        console.print(
            Panel(
                f"[bold cyan]AD Attack Execution[/bold cyan]\n"
                f"Target: [yellow]{args.domain}[/yellow]\n"
                f"Chain: [yellow]{args.chain}[/yellow]\n"
                f"Stealth: [yellow]{args.stealth}[/yellow]\n"
                f"Dry Run: [yellow]{args.dry_run}[/yellow]",
                title=f"{icon('exploit')} Attack Chain",
                border_style="red" if not args.dry_run else "yellow",
            )
        )

        # Get attack chain
        if args.chain == "auto":
            # Show available chains for auto mode
            console.print("\n[bold]Available Attack Chains:[/bold]")
            for name, chain in AD_ATTACK_CHAINS.items():
                console.print(f"  • [cyan]{name}[/cyan]: {chain.description[:60]}...")
            console.print("\n[dim]Use --chain <name> to select a specific chain[/dim]")
            return 0

        chain = get_ad_chain(args.chain)
        if not chain:
            console.print(f"[red]{icon('error')} Unknown attack chain: {args.chain}[/red]")
            return 1

        # Display attack plan
        console.print(f"\n[bold]Attack Chain: {chain.name}[/bold]")
        console.print(f"[dim]{chain.description}[/dim]\n")

        table = Table(title="Attack Steps", box=box.ROUNDED)
        table.add_column("#", style="dim", width=3)
        table.add_column("Step", style="cyan")
        table.add_column("Tool", style="yellow")
        table.add_column("Description", style="dim")

        for i, step in enumerate(chain.steps, 1):
            table.add_row(
                str(i),
                step.name,
                step.tool,
                step.description[:50] + "..." if len(step.description) > 50 else step.description,
            )

        console.print(table)

        if args.dry_run:
            console.print("\n[yellow]{icon('info')} Dry run - no attacks executed[/yellow]")
            return 0

        # Execute chain (placeholder - actual execution would need more implementation)
        console.print("\n[bold red]Executing attack chain...[/bold red]")
        console.print("[dim]Full attack chain execution requires additional implementation[/dim]")

        return 0

    except ImportError as e:
        console.print(f"\n[red]{icon('error')} Missing AD module: {e}[/red]")
        console.print("[dim]Install AD dependencies: pip install aiptx[ad][/dim]")
        return 1
    except Exception as e:
        console.print(f"\n[red]{icon('error')} Attack failed: {e}[/red]")
        return 1


def run_ad_tools(args, console):
    """Check available AD security tools."""
    import asyncio

    from rich import box
    from rich.panel import Panel
    from rich.table import Table

    console.print()
    console.print(
        Panel(
            "[bold cyan]AD Security Tools Status[/bold cyan]\n"
            "Checking availability of Active Directory testing tools...",
            title=f"{icon('tool')} Tool Check",
            border_style="cyan",
        )
    )

    try:
        from aipt_v2.execution.tool_registry import ToolCapability, get_registry

        async def check_tools():
            registry = get_registry()
            await registry.discover_tools()
            return registry

        registry = asyncio.run(check_tools())

        # Get AD tools
        ad_capabilities = [c for c in ToolCapability if c.value.startswith("ad_")]

        table = Table(title="AD Tools", box=box.ROUNDED)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", width=12)
        table.add_column("Capabilities", style="dim")
        table.add_column("Install", style="dim")

        ad_tool_count = 0
        available_count = 0

        for name, config in registry.tools.items():
            # Check if tool has any AD capability
            ad_caps = [c for c in config.capabilities if c.value.startswith("ad_")]
            if not ad_caps:
                continue

            ad_tool_count += 1
            status = registry.get_status(name)
            is_available = status and status.available

            if is_available:
                available_count += 1
                status_text = "[green]✓ Available[/green]"
            else:
                status_text = "[red]✗ Missing[/red]"

            caps_text = ", ".join(c.value.replace("ad_", "") for c in ad_caps)
            install_text = (
                config.install_cmd[:40] + "..."
                if config.install_cmd and len(config.install_cmd) > 40
                else (config.install_cmd or "")
            )

            table.add_row(name, status_text, caps_text, install_text)

        console.print()
        console.print(table)
        console.print(
            f"\n[bold]Summary:[/bold] {available_count}/{ad_tool_count} AD tools available"
        )

        if available_count < ad_tool_count:
            console.print("\n[dim]Install missing tools with: aiptx tools install --ad[/dim]")

        return 0

    except Exception as e:
        console.print(f"\n[red]{icon('error')} Tool check failed: {e}[/red]")
        return 1


# ============================================================================
# MCP Commands (v5.1 - PentestAgent Integration)
# ============================================================================


def run_mcp_command(args):
    """Handle MCP (Model Context Protocol) server management."""
    import asyncio

    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    mcp_cmd = getattr(args, "mcp_command", None)

    if mcp_cmd == "list":
        try:
            from aipt_v2.mcp import MCPManager

            async def do_list():
                manager = MCPManager()
                servers = manager.list_configured_servers()
                return servers

            servers = asyncio.run(do_list())

            console.print()
            if not servers:
                console.print(
                    Panel(
                        "No MCP servers configured.\n\n"
                        "Add a server with:\n"
                        "  [green]aiptx mcp add <name> --command <cmd>[/green]",
                        title=f"{icon('info')} MCP Servers",
                        border_style="yellow",
                    )
                )
            else:
                table = Table(title="Configured MCP Servers", box=box.ROUNDED)
                table.add_column("Name", style="cyan")
                table.add_column("Command", style="dim")
                table.add_column("Enabled", width=10)

                for name, config in servers.items():
                    enabled = (
                        "[green]Yes[/green]" if config.get("enabled", True) else "[red]No[/red]"
                    )
                    table.add_row(name, config.get("command", ""), enabled)

                console.print(table)
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif mcp_cmd == "add":
        try:
            from aipt_v2.mcp import MCPManager, MCPServerConfig

            # Parse environment variables
            env = {}
            for e in args.env or []:
                if "=" in e:
                    k, v = e.split("=", 1)
                    env[k] = v

            config = MCPServerConfig(
                command=args.command,
                args=args.args or [],
                env=env if env else None,
                enabled=True,
            )

            manager = MCPManager()
            manager.add_server(args.name, config)

            console.print(f"[green]Added MCP server '{args.name}'[/green]")
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif mcp_cmd == "remove":
        try:
            from aipt_v2.mcp import MCPManager

            manager = MCPManager()
            if manager.remove_server(args.name):
                console.print(f"[green]Removed MCP server '{args.name}'[/green]")
            else:
                console.print(f"[yellow]Server '{args.name}' not found[/yellow]")
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif mcp_cmd == "connect":
        try:
            from aipt_v2.mcp import MCPManager

            async def do_connect():
                manager = MCPManager()
                tools = await manager.connect_all()
                return tools

            console.print("[dim]Connecting to MCP servers...[/dim]")
            tools = asyncio.run(do_connect())

            if not tools:
                console.print("[yellow]No tools available from MCP servers[/yellow]")
            else:
                table = Table(title="MCP Tools", box=box.ROUNDED)
                table.add_column("Tool", style="cyan")
                table.add_column("Description", style="dim")

                for tool in tools:
                    table.add_row(tool.get("name", ""), tool.get("description", "")[:60] + "...")

                console.print(table)
                console.print(f"\n[green]Connected! {len(tools)} tools available[/green]")
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    else:
        # Show MCP help
        console.print()
        console.print(
            Panel(
                "[bold cyan]MCP Server Management (v5.1)[/bold cyan]\n\n"
                "[bold]Available Commands:[/bold]\n\n"
                "  [green]aiptx mcp list[/green]                  List configured servers\n"
                "  [green]aiptx mcp add[/green] <name> -c <cmd>   Add a new server\n"
                "  [green]aiptx mcp remove[/green] <name>         Remove a server\n"
                "  [green]aiptx mcp connect[/green]               Connect and list tools\n\n"
                "[bold]Example:[/bold]\n"
                "  [dim]# Add a local tool server[/dim]\n"
                "  aiptx mcp add my-tools -c python -a server.py\n\n"
                "[dim]MCP allows extending AIPTX with external tools via JSON-RPC[/dim]",
                title="MCP Servers",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        return 0


# ============================================================================
# Notes Commands (v5.1 - PentestAgent Integration)
# ============================================================================


def run_notes_command(args):
    """Handle quick notes management."""
    import asyncio

    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    notes_cmd = getattr(args, "notes_command", None)

    if notes_cmd == "create":
        try:
            from aipt_v2.tools.notes import notes_create

            result = asyncio.run(
                notes_create(
                    key=args.key,
                    value=args.value,
                    category=args.category,
                    severity=args.severity,
                    evidence=args.evidence or "",
                )
            )

            console.print(f"[green]{result}[/green]")
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif notes_cmd == "list":
        try:
            from aipt_v2.tools.notes import notes_list

            result = asyncio.run(
                notes_list(
                    category=args.category,
                    severity=args.severity,
                )
            )

            console.print(result)
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif notes_cmd == "search":
        try:
            from aipt_v2.tools.notes import notes_search

            result = asyncio.run(notes_search(query=args.query))
            console.print(result)
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif notes_cmd == "export":
        try:
            from aipt_v2.tools.notes import notes_export

            result = asyncio.run(notes_export(format=args.format))

            if args.output:
                with open(args.output, "w") as f:
                    f.write(result)
                console.print(f"[green]Exported to {args.output}[/green]")
            else:
                console.print(result)
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif notes_cmd == "delete":
        try:
            from aipt_v2.tools.notes import notes_delete

            result = asyncio.run(notes_delete(key=args.key))
            console.print(result)
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif notes_cmd == "clear":
        try:
            from aipt_v2.tools.notes import notes_clear

            # Confirm
            confirm = input("Clear all notes? (yes/no): ")
            if confirm.lower() != "yes":
                console.print("[yellow]Cancelled[/yellow]")
                return 0

            result = asyncio.run(notes_clear())
            console.print(f"[green]{result}[/green]")
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    else:
        # Show notes help
        console.print()
        console.print(
            Panel(
                "[bold cyan]Quick Notes Management (v5.1)[/bold cyan]\n\n"
                "[bold]Available Commands:[/bold]\n\n"
                "  [green]aiptx notes create[/green] <key> <value>  Create a note\n"
                "  [green]aiptx notes list[/green]                  List all notes\n"
                "  [green]aiptx notes search[/green] <query>        Search notes\n"
                "  [green]aiptx notes export[/green]                Export notes\n"
                "  [green]aiptx notes delete[/green] <key>          Delete a note\n"
                "  [green]aiptx notes clear[/green]                 Clear all notes\n\n"
                "[bold]Examples:[/bold]\n"
                "  [dim]# Record a credential finding[/dim]\n"
                "  aiptx notes create admin_creds 'admin:Password123' -c credential -s high\n\n"
                "  [dim]# List all vulnerabilities[/dim]\n"
                "  aiptx notes list -c vulnerability\n\n"
                "  [dim]# Export findings as markdown[/dim]\n"
                "  aiptx notes export -f markdown -o findings.md",
                title="Quick Notes",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        return 0


# ============================================================================
# Playbook Commands (v5.1)
# ============================================================================


def run_playbook_command(args):
    """Handle playbook management."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    playbook_cmd = getattr(args, "playbook_command", None)

    if playbook_cmd == "list":
        try:
            from aipt_v2.playbooks import list_playbooks

            playbooks = list_playbooks()

            console.print()
            table = Table(title="Attack Playbooks", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="dim")

            for name, desc in playbooks:
                table.add_row(name, desc)

            console.print(table)
            console.print("\n[dim]Use: aiptx scan <target> --playbook <name>[/dim]")
            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    elif playbook_cmd == "show":
        try:
            from aipt_v2.playbooks import get_playbook

            playbook = get_playbook(args.name)
            if not playbook:
                console.print(f"[red]Playbook '{args.name}' not found[/red]")
                return 1

            console.print()
            console.print(
                Panel(
                    f"[bold cyan]{playbook.description}[/bold cyan]\n"
                    f"Mode: [yellow]{playbook.mode.value}[/yellow]\n"
                    f"Target Type: [yellow]{playbook.target_type}[/yellow]\n"
                    f"Estimated Duration: [yellow]{playbook.estimated_duration // 60} minutes[/yellow]",
                    title=f"Playbook: {playbook.name}",
                    border_style="cyan",
                )
            )

            # Show phases
            console.print("\n[bold]Phases:[/bold]")
            for i, phase in enumerate(playbook.phases, 1):
                deps = f" (depends on: {', '.join(phase.depends_on)})" if phase.depends_on else ""
                parallel = " [green][parallel][/green]" if phase.parallel_safe else ""
                console.print(f"\n  [cyan]{i}. {phase.name}[/cyan]{deps}{parallel}")
                console.print(f"     [dim]{phase.objective}[/dim]")
                console.print(f"     Techniques: {len(phase.techniques)}")
                if phase.mitre_techniques:
                    console.print(f"     MITRE: {', '.join(phase.mitre_techniques[:3])}")

            return 0

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    else:
        # Show playbook help
        console.print()
        console.print(
            Panel(
                "[bold cyan]Attack Playbook Management (v5.1)[/bold cyan]\n\n"
                "[bold]Available Commands:[/bold]\n\n"
                "  [green]aiptx playbook list[/green]          List available playbooks\n"
                "  [green]aiptx playbook show[/green] <name>   Show playbook details\n\n"
                "[bold]Using Playbooks:[/bold]\n"
                "  [dim]# Run a scan with web playbook[/dim]\n"
                "  aiptx scan http://target.com --playbook web\n\n"
                "  [dim]# Run AD assessment with quick playbook[/dim]\n"
                "  aiptx scan dc.corp.local --playbook ad_quick\n\n"
                "[bold]Available Playbooks:[/bold]\n"
                "  web      - Web Application Black-Box Testing\n"
                "  api      - REST/GraphQL API Security Testing\n"
                "  graphql  - GraphQL-Specific Testing\n"
                "  ad       - Active Directory Penetration Testing\n"
                "  ad_quick - Quick AD Assessment",
                title="Attack Playbooks",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully without traceback
        from rich.console import Console

        Console().print("\n[yellow]Operation cancelled.[/yellow]")
        sys.exit(130)
