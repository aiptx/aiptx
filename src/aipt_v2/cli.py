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
import sys
import os
import warnings
from pathlib import Path

# Suppress noisy warnings for cleaner user experience
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*urllib3.*OpenSSL.*")
warnings.filterwarnings("ignore", message=".*NotOpenSSLWarning.*")

# Set default log level to WARNING before any imports that might log
os.environ.setdefault("AIPT_LOG_LEVEL", "WARNING")

# Handle imports for both installed package and local development
try:
    from . import __version__
    from .config import get_config, validate_config_for_features, reload_config
    from .utils.logging import setup_logging, logger
    from .setup_wizard import is_configured, prompt_first_run_setup, run_setup_wizard
    from .interface.icons import icon, supports_emoji
except ImportError:
    # Local development fallback
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from __init__ import __version__
    from config import get_config, validate_config_for_features, reload_config
    from utils.logging import setup_logging, logger
    from setup_wizard import is_configured, prompt_first_run_setup, run_setup_wizard
    from interface.icons import icon, supports_emoji


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
        "--version", "-V",
        action="version",
        version=f"AIPTX v{__version__}",
    )

    parser.add_argument(
        "--verbose", "-v",
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
        "--mode", "-m",
        choices=["quick", "standard", "full", "ai"],
        default="standard",
        help="Scan mode (default: standard)",
    )
    scan_parser.add_argument("--full", action="store_true", help="Run full comprehensive scan")
    scan_parser.add_argument("--ai", action="store_true", help="Enable AI-guided scanning")
    scan_parser.add_argument("--use-vps", action="store_true", help="Use VPS for tool execution")
    scan_parser.add_argument("--use-acunetix", action="store_true", help="Include Acunetix scan")
    scan_parser.add_argument("--use-burp", action="store_true", help="Include Burp Suite scan")
    scan_parser.add_argument("--skip-recon", action="store_true", help="Skip reconnaissance phase")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode - minimal output")
    scan_parser.add_argument("--no-stream", action="store_true", help="Don't stream command output (show progress only)")
    scan_parser.add_argument("--check", action="store_true", help="Run pre-flight checks to validate config/connections before scan")

    # API command
    api_parser = subparsers.add_parser("api", help="Start REST API server")
    # Security: Default to localhost to prevent accidental network exposure
    api_parser.add_argument("--host", default="127.0.0.1", help="API host (default: 127.0.0.1, use 0.0.0.0 for network access)")
    api_parser.add_argument("--port", "-p", type=int, default=8000, help="API port (default: 8000)")
    api_parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    # Status command
    subparsers.add_parser("status", help="Check configuration and dependencies")

    # Check command - Enterprise prerequisites validation
    check_parser = subparsers.add_parser("check", help="Run enterprise prerequisites check before operations")
    check_parser.add_argument(
        "--strict", "-s",
        action="store_true",
        help="Fail on warnings (for CI/CD pipelines)"
    )
    check_parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output JSON format for automation"
    )
    check_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show all checks including passed ones"
    )
    check_parser.add_argument(
        "--minimal", "-m",
        action="store_true",
        help="Skip optional dependency checks"
    )

    # Test command - validate all configurations
    test_parser = subparsers.add_parser("test", help="Test and validate all configurations")
    test_parser.add_argument("--llm", action="store_true", help="Test LLM API key only")
    test_parser.add_argument("--vps", action="store_true", help="Test VPS connection only")
    test_parser.add_argument("--scanners", action="store_true", help="Test scanner integrations only")
    test_parser.add_argument("--tools", action="store_true", help="Test local tool availability")
    test_parser.add_argument("--all", "-a", action="store_true", help="Test everything (default)")

    # Version command
    subparsers.add_parser("version", help="Show detailed version information")

    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Run interactive setup wizard")
    setup_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force reconfiguration even if already configured"
    )

    # VPS command with subcommands
    vps_parser = subparsers.add_parser("vps", help="VPS remote execution management")
    vps_subparsers = vps_parser.add_subparsers(dest="vps_command", help="VPS commands")

    # vps setup - Install tools on VPS
    vps_setup = vps_subparsers.add_parser("setup", help="Install security tools on VPS")
    vps_setup.add_argument(
        "--categories", "-c",
        nargs="+",
        choices=["recon", "scan", "exploit", "post_exploit", "api", "network"],
        help="Tool categories to install (default: all)"
    )
    vps_setup.add_argument(
        "--tools", "-t",
        nargs="+",
        help="Specific tools to install"
    )

    # vps status - Check VPS connection and tools
    vps_subparsers.add_parser("status", help="Check VPS connection and installed tools")

    # vps scan - Run scan from VPS
    vps_scan = vps_subparsers.add_parser("scan", help="Run security scan from VPS")
    vps_scan.add_argument("target", help="Target URL or domain")
    vps_scan.add_argument(
        "--mode", "-m",
        choices=["quick", "standard", "full"],
        default="standard",
        help="Scan mode"
    )
    vps_scan.add_argument(
        "--tools", "-t",
        nargs="+",
        help="Specific tools to run"
    )

    # vps script - Generate setup script
    vps_script = vps_subparsers.add_parser("script", help="Generate VPS setup script")
    vps_script.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)"
    )
    vps_script.add_argument(
        "--categories", "-c",
        nargs="+",
        help="Tool categories to include"
    )

    # Verify command - Installation verification
    verify_parser = subparsers.add_parser("verify", help="Verify installation and configuration")
    verify_parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Run quick checks only"
    )
    verify_parser.add_argument(
        "--fix",
        action="store_true",
        help="Attempt to auto-fix issues"
    )
    verify_parser.add_argument(
        "--report", "-r",
        help="Save markdown report to file"
    )

    # Shell command - Interactive shell
    shell_parser = subparsers.add_parser("shell", help="Start interactive security shell")
    shell_parser.add_argument(
        "--log", "-l",
        help="Log session to file"
    )
    shell_parser.add_argument(
        "--dir", "-d",
        help="Working directory"
    )

    # Tools command with subcommands
    tools_parser = subparsers.add_parser("tools", help="Manage local security tools")
    tools_subparsers = tools_parser.add_subparsers(dest="tools_command", help="Tools commands")

    # tools install - Install security tools
    tools_install = tools_subparsers.add_parser("install", help="Install security tools on local system")
    tools_install.add_argument(
        "--categories", "-c",
        nargs="+",
        choices=[
            "recon", "scan", "exploit", "post_exploit", "api", "network",
            "prerequisite", "active_directory", "cloud", "container",
            "osint", "wireless", "web", "secrets", "mobile"
        ],
        help="Tool categories to install (default: core tools)"
    )
    tools_install.add_argument(
        "--tools", "-t",
        nargs="+",
        help="Specific tools to install"
    )
    tools_install.add_argument(
        "--all", "-a",
        action="store_true",
        help="Install all available tools"
    )
    tools_install.add_argument(
        "--core",
        action="store_true",
        help="Install only core essential tools (default)"
    )
    tools_install.add_argument(
        "--no-sudo",
        action="store_true",
        help="Don't use sudo for installation"
    )

    # tools list - List available/installed tools
    tools_list = tools_subparsers.add_parser("list", help="List available and installed tools")
    tools_list.add_argument(
        "--category", "-c",
        choices=[
            "recon", "scan", "exploit", "post_exploit", "api", "network",
            "prerequisite", "active_directory", "cloud", "container",
            "osint", "wireless", "web", "secrets", "mobile", "all"
        ],
        default="all",
        help="Filter by category"
    )
    tools_list.add_argument(
        "--installed-only",
        action="store_true",
        help="Show only installed tools"
    )

    # tools check - Check tool availability
    tools_subparsers.add_parser("check", help="Check which tools are installed")

    # AI Skills command with subcommands
    ai_parser = subparsers.add_parser("ai", help="AI-powered security testing (code review, API testing, web pentesting)")
    ai_subparsers = ai_parser.add_subparsers(dest="ai_command", help="AI testing commands")

    # ai code-review - AI source code security review
    ai_code = ai_subparsers.add_parser("code-review", help="AI-powered source code security review")
    ai_code.add_argument("target", help="Path to code directory to review")
    ai_code.add_argument(
        "--focus", "-f",
        nargs="+",
        choices=["sqli", "xss", "auth", "crypto", "secrets", "injection"],
        help="Focus areas for review"
    )
    ai_code.add_argument(
        "--model", "-m",
        default="claude-sonnet-4-20250514",
        help="LLM model to use (default: claude-sonnet-4-20250514)"
    )
    ai_code.add_argument(
        "--max-steps",
        type=int,
        default=100,
        help="Maximum agent steps (default: 100)"
    )
    ai_code.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick scan focusing on high-priority patterns"
    )
    ai_code.add_argument(
        "--output", "-o",
        help="Output file for results (JSON)"
    )

    # ai api-test - AI API security testing
    ai_api = ai_subparsers.add_parser("api-test", help="AI-powered REST API security testing")
    ai_api.add_argument("target", help="Base URL of the API to test")
    ai_api.add_argument(
        "--openapi", "-s",
        help="Path or URL to OpenAPI/Swagger spec"
    )
    ai_api.add_argument(
        "--auth-token", "-t",
        help="Bearer token for API authentication"
    )
    ai_api.add_argument(
        "--model", "-m",
        default="claude-sonnet-4-20250514",
        help="LLM model to use"
    )
    ai_api.add_argument(
        "--max-steps",
        type=int,
        default=100,
        help="Maximum agent steps"
    )
    ai_api.add_argument(
        "--output", "-o",
        help="Output file for results (JSON)"
    )

    # ai web-pentest - AI web penetration testing
    ai_web = ai_subparsers.add_parser("web-pentest", help="AI-powered web application penetration testing")
    ai_web.add_argument("target", help="Target URL to test")
    ai_web.add_argument(
        "--auth-token", "-t",
        help="Bearer token for authentication"
    )
    ai_web.add_argument(
        "--cookie", "-c",
        action="append",
        help="Cookies for authenticated testing (key=value)"
    )
    ai_web.add_argument(
        "--model", "-m",
        default="claude-sonnet-4-20250514",
        help="LLM model to use"
    )
    ai_web.add_argument(
        "--max-steps",
        type=int,
        default=100,
        help="Maximum agent steps"
    )
    ai_web.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick scan focusing on critical vulnerabilities"
    )
    ai_web.add_argument(
        "--output", "-o",
        help="Output file for results (JSON)"
    )

    # ai full - Full AI-driven security assessment
    ai_full = ai_subparsers.add_parser("full", help="Full AI-driven security assessment")
    ai_full.add_argument("target", help="Target URL or code path")
    ai_full.add_argument(
        "--types", "-t",
        nargs="+",
        choices=["web", "api", "code"],
        default=["web"],
        help="Types of testing to perform"
    )
    ai_full.add_argument(
        "--model", "-m",
        default="claude-sonnet-4-20250514",
        help="LLM model to use"
    )
    ai_full.add_argument(
        "--output", "-o",
        help="Output file for results (JSON)"
    )

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
    console.print(Panel(
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
    ))
    console.print()

    return 0


def run_interactive_mode():
    """Run AIPTX in interactive shell mode."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich import box

    console = Console()

    # ASCII Art Logo
    logo = """
[bold cyan]     █████╗ ██╗██████╗ ████████╗██╗  ██╗[/bold cyan]
[bold cyan]    ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝[/bold cyan]
[bold blue]    ███████║██║██████╔╝   ██║    ╚███╔╝ [/bold blue]
[bold blue]    ██╔══██║██║██╔═══╝    ██║    ██╔██╗ [/bold blue]
[bold magenta]    ██║  ██║██║██║        ██║   ██╔╝ ██╗[/bold magenta]
[bold magenta]    ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝[/bold magenta]
"""

    # Show welcome banner
    console.print()
    console.print(logo)
    console.print("[bold white]         AI-Powered Penetration Testing Framework[/bold white]")
    console.print(f"[dim]                      v{__version__} • [link=https://aiptx.io]aiptx.io[/link][/dim]")
    console.print()

    # Stylish separator
    console.print("[dim cyan]" + "━" * 60 + "[/dim cyan]")
    console.print()

    # Quick commands in a nice table format
    commands_table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2),
        collapse_padding=True,
    )
    commands_table.add_column("Command", style="bold green", width=18)
    commands_table.add_column("Description", style="white")

    commands_table.add_row("scan <target>", f"{icon('search')} Run security scan")
    commands_table.add_row("scan <target> --ai", f"{icon('robot')} AI-guided intelligent scanning")
    commands_table.add_row("scan <target> --full", f"{icon('target')} Comprehensive assessment")
    commands_table.add_row("ai <command>", f"{icon('brain')} AI security testing")
    commands_table.add_row("vps <command>", f"{icon('cloud')} Remote VPS execution")
    commands_table.add_row("setup", f"{icon('gear')} Configure AIPTX")
    commands_table.add_row("status", f"{icon('chart')} Show configuration")
    commands_table.add_row("help", f"{icon('info')} Show all commands")
    commands_table.add_row("exit", f"{icon('arrow')} Exit AIPTX")

    console.print(commands_table)
    console.print()
    console.print("[dim cyan]" + "━" * 60 + "[/dim cyan]")
    console.print()
    console.print(f"[dim]{icon('lightbulb')} Tip: Type [bold green]scan example.com --ai[/bold green] to start AI-guided scanning[/dim]")
    console.print(f"[dim]{icon('globe')} Docs: [link=https://aiptx.io/docs]https://aiptx.io/docs[/link][/dim]")
    console.print()

    # Check configuration status
    if not is_configured():
        console.print(Panel(
            f"[yellow]{icon('warning')} AIPTX is not configured yet![/yellow]\n\n"
            "Run [bold green]setup[/bold green] to configure your API keys and scanners.\n"
            "Or set environment variable: [dim]export ANTHROPIC_API_KEY=your-key[/dim]",
            border_style="yellow",
            title="[bold yellow]Setup Required[/bold yellow]",
            title_align="left",
        ))
        console.print()

    # Interactive loop
    while True:
        try:
            # Flush stdin to avoid stale input from previous commands
            import sys
            import platform
            if sys.stdin.isatty():
                # Clear any buffered input (platform-specific)
                if platform.system() == "Windows":
                    # Windows: use msvcrt for non-blocking input check
                    import msvcrt
                    while msvcrt.kbhit():
                        msvcrt.getch()
                else:
                    # Unix/Linux/macOS: use select
                    import select
                    while select.select([sys.stdin], [], [], 0)[0]:
                        sys.stdin.read(1)

            # Get user input with stylish prompt
            user_input = Prompt.ask(f"[bold cyan]aiptx[/bold cyan] [dim]{icon('arrow')}[/dim]", default="").strip()

            if not user_input:
                continue

            # Parse the input
            parts = user_input.split()
            cmd = parts[0].lower()
            args_list = parts[1:] if len(parts) > 1 else []

            # Handle commands
            if cmd in ("exit", "quit", "q"):
                console.print()
                console.print(f"[bold cyan]Thanks for using AIPTX![/bold cyan] {icon('rocket')}")
                console.print("[dim]Visit [link=https://aiptx.io]aiptx.io[/link] for docs & updates[/dim]")
                console.print()
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
    """Show help for interactive mode."""
    from rich.table import Table
    from rich import box

    table = Table(title="AIPTX Commands", box=box.ROUNDED)
    table.add_column("Command", style="green")
    table.add_column("Description")
    table.add_column("Example", style="dim")

    table.add_row("scan <target>", "Run security scan", "scan example.com --check --full")
    table.add_row("ai code-review <path>", "AI code security review", "ai code-review ./src")
    table.add_row("ai api-test <url>", "AI API security testing", "ai api-test https://api.example.com")
    table.add_row("ai web-pentest <url>", "AI web penetration test", "ai web-pentest https://example.com")
    table.add_row("vps setup", "Install tools on VPS", "vps setup")
    table.add_row("vps status", "Check VPS status", "vps status")
    table.add_row("vps scan <target>", "Run scan from VPS", "vps scan example.com")
    table.add_row("setup", "Configure AIPTX", "setup")
    table.add_row("status", "Show configuration", "status")
    table.add_row("test", "Validate all configs", "test")
    table.add_row("clear", "Clear screen", "clear")
    table.add_row("exit", "Exit AIPTX", "exit")

    console.print(table)


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
        model="claude-sonnet-4-20250514",
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
    force = getattr(args, 'force', False)
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
        console.print(Panel(
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
        ))
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
        console.print(Panel(
            "[bold red]Configuration Error[/bold red]\n\n"
            "The following issues need to be resolved:\n\n" +
            "\n".join(f"  [yellow]{icon('bullet')}[/yellow] {error}" for error in errors) +
            "\n\n[bold]To fix:[/bold]\n"
            "  Run [bold green]aiptx setup[/bold green] to configure interactively\n\n"
            "[bold]Or set environment variables:[/bold]\n"
            "  [dim]export ANTHROPIC_API_KEY=your-key-here[/dim]",
            title=f"{icon('warning')} Setup Required",
            border_style="yellow",
            padding=(1, 2),
        ))
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
        console.print(Panel(
            "[bold red]Prerequisites Check Failed[/bold red]\n\n" +
            "\n".join(f"  [red]•[/red] {e}" for e in prereq_errors) +
            "\n\n[bold]To diagnose:[/bold]\n"
            "  Run [bold green]aiptx check[/bold green] for detailed report\n\n"
            "[bold]To fix common issues:[/bold]\n"
            "  [dim]aiptx setup          # Configure API keys[/dim]\n"
            "  [dim]pip install aiptx[full]  # Install all dependencies[/dim]",
            title=f"{icon('warning')} System Not Ready",
            border_style="red",
            padding=(1, 2),
        ))
        console.print()
        return 1

    # Run pre-flight checks if requested (connection validation)
    if getattr(args, 'check', False):
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
            console.print("[dim]Fix the issues above and try again, or run without --check to skip validation.[/dim]")
            return 1

        console.print("[dim]Pre-flight checks passed. Starting scan...[/dim]")
        console.print()

    # Create config
    # Verbose mode is default (True), quiet mode disables it
    verbose = not getattr(args, 'quiet', False)
    # Show command output is default (True), --no-stream disables it
    show_command_output = not getattr(args, 'no_stream', False)

    config = OrchestratorConfig(
        target=args.target,
        output_dir=Path(args.output) if args.output else Path("./results"),
        skip_recon=args.skip_recon,
        use_acunetix=args.use_acunetix,
        use_burp=args.use_burp,
        verbose=verbose,
        show_command_output=show_command_output,
    )

    # Determine mode
    if args.ai or args.mode == "ai":
        mode = "ai"
    elif args.full or args.mode == "full":
        mode = "full"
    elif args.mode == "quick":
        mode = "quick"
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
        return 0
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]Scan interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print()
        console.print(f"[bold red]{icon('cross')} Scan failed:[/bold red] {e}")
        if args.verbose:
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
    import time
    from rich.console import Console
    from rich.table import Table

    console = Console()
    config = get_config()

    console.print("\n[bold cyan]AIPT v2 Configuration Status[/bold cyan]\n")

    # Store validation results for summary
    validation_results = {}

    # ==================== LLM Configuration ====================
    llm_status = None
    llm_error = None

    if config.llm.api_key:
        with console.status("[yellow]Validating LLM connection...[/yellow]"):
            try:
                import litellm

                provider = config.llm.provider.lower()
                model = config.llm.model

                if provider == "anthropic":
                    model_str = f"anthropic/{model}" if not model.startswith("anthropic/") else model
                    litellm.api_key = config.llm.api_key
                elif provider == "openai":
                    model_str = f"openai/{model}" if not model.startswith("openai/") else model
                    litellm.api_key = config.llm.api_key
                elif provider == "deepseek":
                    model_str = f"deepseek/{model}" if not model.startswith("deepseek/") else model
                    litellm.api_key = config.llm.api_key
                else:
                    model_str = model

                start = time.time()
                response = litellm.completion(
                    model=model_str,
                    messages=[{"role": "user", "content": "Reply with only: OK"}],
                    max_tokens=10,
                    timeout=30,
                )
                elapsed = time.time() - start
                llm_status = True
                validation_results['llm'] = (True, f"Connected ({elapsed:.1f}s)")

            except ImportError:
                llm_status = None
                llm_error = "litellm not installed"
                validation_results['llm'] = (None, "litellm not installed")
            except Exception as e:
                llm_status = False
                llm_error = str(e)[:50]
                validation_results['llm'] = (False, str(e)[:50])
    else:
        llm_status = False
        llm_error = "API key not configured"
        validation_results['llm'] = (False, "API key not configured")

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

    async def test_scanner_connection(name, url, test_endpoint, headers):
        """Test scanner connectivity."""
        if not url:
            return None, "Not configured"
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                response = await client.get(f"{url}{test_endpoint}", headers=headers)
                if response.status_code == 200:
                    return True, "Connected"
                else:
                    return False, f"HTTP {response.status_code}"
        except Exception as e:
            return False, str(e)[:30]

    async def test_all_scanners():
        results = {}

        # Acunetix
        if config.scanners.acunetix_url:
            with console.status("[yellow]Testing Acunetix...[/yellow]"):
                results['acunetix'] = await test_scanner_connection(
                    "Acunetix",
                    config.scanners.acunetix_url,
                    "/api/v1/me",
                    {"X-Auth": config.scanners.acunetix_api_key or ""}
                )
        else:
            results['acunetix'] = (None, "Not configured")

        # Burp Suite
        if config.scanners.burp_url:
            with console.status("[yellow]Testing Burp Suite...[/yellow]"):
                results['burp'] = await test_scanner_connection(
                    "Burp Suite",
                    config.scanners.burp_url,
                    "/api-internal/versions",
                    {"Authorization": f"Bearer {config.scanners.burp_api_key or ''}"}
                )
        else:
            results['burp'] = (None, "Not configured")

        # Nessus
        if config.scanners.nessus_url:
            with console.status("[yellow]Testing Nessus...[/yellow]"):
                results['nessus'] = await test_scanner_connection(
                    "Nessus",
                    config.scanners.nessus_url,
                    "/server/status",
                    {"X-ApiKeys": f"accessKey={config.scanners.nessus_access_key or ''};secretKey={config.scanners.nessus_secret_key or ''}"}
                )
        else:
            results['nessus'] = (None, "Not configured")

        # OWASP ZAP
        if config.scanners.zap_url:
            with console.status("[yellow]Testing OWASP ZAP...[/yellow]"):
                zap_endpoint = "/JSON/core/view/version/"
                if config.scanners.zap_api_key:
                    zap_endpoint += f"?apikey={config.scanners.zap_api_key}"
                results['zap'] = await test_scanner_connection(
                    "OWASP ZAP",
                    config.scanners.zap_url,
                    zap_endpoint,
                    {}
                )
        else:
            results['zap'] = (None, "Not configured")

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
        get_scanner_status_display(scanner_results['acunetix']),
    )
    table.add_row(
        "Burp Suite",
        config.scanners.burp_url or "Not configured",
        get_scanner_status_display(scanner_results['burp']),
    )
    table.add_row(
        "Nessus",
        config.scanners.nessus_url or "Not configured",
        get_scanner_status_display(scanner_results['nessus']),
    )
    table.add_row(
        "OWASP ZAP",
        config.scanners.zap_url or "Not configured",
        get_scanner_status_display(scanner_results['zap']),
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
                        import asyncssh
                        conn = await asyncssh.connect(
                            config.vps.host,
                            port=config.vps.port,
                            username=config.vps.user,
                            client_keys=[str(key_path)],
                            known_hosts=None,
                        )
                        result = await conn.run("echo 'OK'", check=True)
                        await conn.close()
                        return "OK" in result.stdout

                    if asyncio.run(test_vps()):
                        vps_status = True
                    else:
                        vps_status = False
                        vps_error = "Connection test failed"

            except ImportError:
                vps_status = None
                vps_error = "asyncssh not installed"
            except Exception as e:
                vps_status = False
                vps_error = str(e)[:30]

        validation_results['vps'] = (vps_status, vps_error if vps_error else "Connected")
    elif config.vps.host:
        vps_status = False
        vps_error = "SSH key not configured"
        validation_results['vps'] = (False, vps_error)
    else:
        vps_status = None
        validation_results['vps'] = (None, "Not configured")

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
    table.add_row("SSH Key", config.vps.key_path or "Not configured")

    console.print(table)

    # ==================== Configuration Validation Summary ====================
    console.print("\n[bold]Configuration Validation:[/bold]")

    # LLM
    llm_result = validation_results.get('llm', (False, "Unknown"))
    if llm_result[0] is True:
        console.print(f"  [green]{icon('check')}[/green] llm: {llm_result[1]}")
    elif llm_result[0] is None:
        console.print(f"  [yellow]{icon('warning')}[/yellow] llm: {llm_result[1]}")
    else:
        console.print(f"  [red]{icon('cross')}[/red] llm: {llm_result[1]}")

    # Scanners - only show configured ones
    for scanner_name in ['acunetix', 'burp', 'nessus', 'zap']:
        result = scanner_results.get(scanner_name, (None, "Unknown"))
        if result[0] is True:
            console.print(f"  [green]{icon('check')}[/green] {scanner_name}: {result[1]}")
        elif result[0] is None:
            # Don't show unconfigured scanners as errors
            pass
        else:
            console.print(f"  [red]{icon('cross')}[/red] {scanner_name}: {result[1]}")

    # VPS
    vps_result = validation_results.get('vps', (None, "Unknown"))
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

    verbose = getattr(args, 'verbose', False)
    strict = getattr(args, 'strict', False)
    json_output = getattr(args, 'json', False)
    minimal = getattr(args, 'minimal', False)

    return asyncio.run(run_prerequisites_check(
        verbose=verbose,
        strict=strict,
        json_output=json_output,
        include_optional=not minimal,
    ))


def run_config_test(args):
    """
    Test and validate all configurations by making real connections.

    Unlike 'status' which just shows config values, 'test' actually
    validates that services are reachable and credentials work.
    """
    import asyncio
    import shutil
    import time
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box

    console = Console()
    config = get_config()

    console.print()
    console.print(Panel(
        "[bold]AIPTX Configuration Validator[/bold]\n\n"
        "Testing all configured services and credentials...",
        title=f"{icon('search')} Self-Test",
        border_style="cyan"
    ))
    console.print()

    results = {}
    test_all = getattr(args, 'all', False) or not any([
        getattr(args, 'llm', False),
        getattr(args, 'vps', False),
        getattr(args, 'scanners', False),
        getattr(args, 'tools', False),
    ])

    # ======================== LLM Test ========================
    if test_all or getattr(args, 'llm', False):
        console.print("[bold cyan]━━━ LLM API Test ━━━[/bold cyan]")

        if not config.llm.api_key:
            console.print(f"  [red]{icon('cross')}[/red] No API key configured")
            console.print("    [dim]Run 'aiptx setup' to configure[/dim]")
            results['llm'] = False
        else:
            with console.status("[yellow]Testing LLM API connection...[/yellow]"):
                try:
                    import litellm

                    # Determine model string based on provider
                    provider = config.llm.provider.lower()
                    model = config.llm.model

                    if provider == "anthropic":
                        model_str = f"anthropic/{model}" if not model.startswith("anthropic/") else model
                        litellm.api_key = config.llm.api_key
                    elif provider == "openai":
                        model_str = f"openai/{model}" if not model.startswith("openai/") else model
                        litellm.api_key = config.llm.api_key
                    elif provider == "deepseek":
                        model_str = f"deepseek/{model}" if not model.startswith("deepseek/") else model
                        litellm.api_key = config.llm.api_key
                    else:
                        model_str = model

                    start = time.time()
                    response = litellm.completion(
                        model=model_str,
                        messages=[{"role": "user", "content": "Reply with only: OK"}],
                        max_tokens=10,
                        timeout=30,
                    )
                    elapsed = time.time() - start

                    console.print(f"  [green]{icon('check')}[/green] LLM API connection successful")
                    console.print(f"    [dim]Provider: {provider}[/dim]")
                    console.print(f"    [dim]Model: {model}[/dim]")
                    console.print(f"    [dim]Response time: {elapsed:.2f}s[/dim]")
                    results['llm'] = True

                except ImportError:
                    console.print(f"  [yellow]{icon('warning')}[/yellow] litellm not installed")
                    console.print("    [dim]Install with: pip install litellm[/dim]")
                    results['llm'] = None
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] LLM API test failed")
                    console.print(f"    [dim]Error: {str(e)[:100]}[/dim]")
                    results['llm'] = False

        console.print()

    # ======================== VPS Test ========================
    if test_all or getattr(args, 'vps', False):
        console.print("[bold cyan]━━━ VPS Connection Test ━━━[/bold cyan]")

        if not config.vps.host:
            console.print(f"  [yellow]{icon('circle_empty')}[/yellow] VPS not configured (optional)")
            results['vps'] = None
        elif not config.vps.key_path:
            console.print(f"  [red]{icon('cross')}[/red] SSH key path not configured")
            results['vps'] = False
        else:
            with console.status("[yellow]Testing SSH connection to VPS...[/yellow]"):
                try:
                    from pathlib import Path

                    key_path = Path(config.vps.key_path).expanduser()
                    if not key_path.exists():
                        console.print(f"  [red]{icon('cross')}[/red] SSH key not found: {key_path}")
                        results['vps'] = False
                    else:
                        # Test SSH connection using asyncssh
                        async def test_ssh():
                            import asyncssh
                            start = time.time()
                            conn = await asyncssh.connect(
                                config.vps.host,
                                port=config.vps.port,
                                username=config.vps.user,
                                client_keys=[str(key_path)],
                                known_hosts=None,
                            )
                            # Run a simple command to verify
                            result = await conn.run("echo 'AIPTX_TEST_OK' && uname -a", check=True)
                            await conn.close()
                            elapsed = time.time() - start
                            return result.stdout.strip(), elapsed

                        output, elapsed = asyncio.run(test_ssh())

                        if "AIPTX_TEST_OK" in output:
                            uname = output.replace("AIPTX_TEST_OK", "").strip()
                            console.print(f"  [green]{icon('check')}[/green] VPS connection successful")
                            console.print(f"    [dim]Host: {config.vps.user}@{config.vps.host}:{config.vps.port}[/dim]")
                            console.print(f"    [dim]System: {uname[:60]}...[/dim]" if len(uname) > 60 else f"    [dim]System: {uname}[/dim]")
                            console.print(f"    [dim]Response time: {elapsed:.2f}s[/dim]")
                            results['vps'] = True
                        else:
                            console.print(f"  [red]{icon('cross')}[/red] VPS connection failed - unexpected response")
                            results['vps'] = False

                except ImportError:
                    console.print(f"  [yellow]{icon('warning')}[/yellow] asyncssh not installed")
                    console.print("    [dim]Install with: pip install asyncssh[/dim]")
                    results['vps'] = None
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] VPS connection failed")
                    console.print(f"    [dim]Error: {str(e)[:100]}[/dim]")
                    results['vps'] = False

        console.print()

    # ======================== Scanner Tests ========================
    if test_all or getattr(args, 'scanners', False):
        console.print("[bold cyan]━━━ Scanner Integration Tests ━━━[/bold cyan]")

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
                        verify=False,
                        timeout=10,
                    )
                    if response.status_code == 200:
                        console.print(f"  [green]{icon('check')}[/green] Acunetix connected")
                        console.print(f"    [dim]URL: {config.scanners.acunetix_url}[/dim]")
                        results['acunetix'] = True
                    else:
                        console.print(f"  [red]{icon('cross')}[/red] Acunetix auth failed (HTTP {response.status_code})")
                        results['acunetix'] = False
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] Acunetix connection failed: {str(e)[:50]}")
                    results['acunetix'] = False

        # Burp Suite
        if config.scanners.burp_url:
            scanners_tested += 1
            with console.status("[yellow]Testing Burp Suite connection...[/yellow]"):
                try:
                    import httpx
                    response = httpx.get(
                        f"{config.scanners.burp_url}/api-internal/versions",
                        headers={"Authorization": f"Bearer {config.scanners.burp_api_key}"},
                        verify=False,
                        timeout=10,
                    )
                    if response.status_code == 200:
                        console.print(f"  [green]{icon('check')}[/green] Burp Suite connected")
                        console.print(f"    [dim]URL: {config.scanners.burp_url}[/dim]")
                        results['burp'] = True
                    else:
                        console.print(f"  [red]{icon('cross')}[/red] Burp Suite auth failed (HTTP {response.status_code})")
                        results['burp'] = False
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] Burp Suite connection failed: {str(e)[:50]}")
                    results['burp'] = False

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
                        verify=False,
                        timeout=10,
                    )
                    if response.status_code == 200:
                        console.print(f"  [green]{icon('check')}[/green] Nessus connected")
                        console.print(f"    [dim]URL: {config.scanners.nessus_url}[/dim]")
                        results['nessus'] = True
                    else:
                        console.print(f"  [red]{icon('cross')}[/red] Nessus auth failed (HTTP {response.status_code})")
                        results['nessus'] = False
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] Nessus connection failed: {str(e)[:50]}")
                    results['nessus'] = False

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
                        console.print(f"  [green]{icon('check')}[/green] OWASP ZAP connected (v{version})")
                        console.print(f"    [dim]URL: {config.scanners.zap_url}[/dim]")
                        results['zap'] = True
                    else:
                        console.print(f"  [red]{icon('cross')}[/red] ZAP connection failed (HTTP {response.status_code})")
                        results['zap'] = False
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] ZAP connection failed: {str(e)[:50]}")
                    results['zap'] = False

        if scanners_tested == 0:
            console.print(f"  [yellow]{icon('circle_empty')}[/yellow] No scanners configured (optional)")

        console.print()

    # ======================== Local Tools Test ========================
    if test_all or getattr(args, 'tools', False):
        console.print("[bold cyan]━━━ Local Security Tools ━━━[/bold cyan]")

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
            console.print(f"  [yellow]{icon('circle_empty')}[/yellow] Not found: {', '.join(missing_tools)}")
            console.print("    [dim]Install missing tools or use --use-vps to run on VPS[/dim]")

        results['tools'] = len(found_tools)
        console.print()

    # ======================== Summary ========================
    console.print("[bold cyan]━━━ Test Summary ━━━[/bold cyan]")

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
        console.print(f"\n[bold yellow]{icon('warning')} {failures} test(s) failed. Run 'aiptx setup' to fix.[/bold yellow]")
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
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    config = get_config()
    results = {}
    all_passed = True

    console.print()
    console.print(Panel(
        "[bold]Pre-flight Configuration Check[/bold]\n\n"
        "Validating all required services before scan...",
        title=f"{icon('airplane')} Pre-flight Check",
        border_style="cyan"
    ))
    console.print()

    # ======================== LLM Check (always required) ========================
    console.print("[bold cyan]━━━ LLM API ━━━[/bold cyan]")

    if not config.llm.api_key:
        console.print(f"  [red]{icon('cross')}[/red] No API key configured")
        console.print("    [dim]Run 'aiptx setup' to configure[/dim]")
        results['llm'] = False
        all_passed = False
    else:
        with console.status("[yellow]Testing LLM API...[/yellow]"):
            try:
                import litellm

                provider = config.llm.provider.lower()
                model = config.llm.model

                if provider == "anthropic":
                    model_str = f"anthropic/{model}" if not model.startswith("anthropic/") else model
                elif provider == "openai":
                    model_str = f"openai/{model}" if not model.startswith("openai/") else model
                elif provider == "deepseek":
                    model_str = f"deepseek/{model}" if not model.startswith("deepseek/") else model
                else:
                    model_str = model

                start = time.time()
                response = litellm.completion(
                    model=model_str,
                    messages=[{"role": "user", "content": "Reply with only: OK"}],
                    max_tokens=10,
                    timeout=30,
                )
                elapsed = time.time() - start

                console.print(f"  [green]{icon('check')}[/green] LLM ready ({provider}/{model}) - {elapsed:.1f}s")
                results['llm'] = True

            except ImportError:
                console.print(f"  [yellow]{icon('warning')}[/yellow] litellm not installed")
                results['llm'] = None
            except Exception as e:
                console.print(f"  [red]{icon('cross')}[/red] LLM connection failed: {str(e)[:60]}")
                results['llm'] = False
                all_passed = False

    console.print()

    # ======================== VPS Check (if requested) ========================
    if use_vps:
        console.print("[bold cyan]━━━ VPS Connection ━━━[/bold cyan]")

        if not config.vps.host:
            console.print(f"  [red]{icon('cross')}[/red] VPS not configured")
            console.print("    [dim]Run 'aiptx setup' to configure VPS[/dim]")
            results['vps'] = False
            all_passed = False
        elif not config.vps.key_path:
            console.print(f"  [red]{icon('cross')}[/red] SSH key path not configured")
            results['vps'] = False
            all_passed = False
        else:
            with console.status("[yellow]Testing SSH connection...[/yellow]"):
                try:
                    from pathlib import Path
                    import asyncssh

                    key_path = Path(config.vps.key_path).expanduser()
                    if not key_path.exists():
                        console.print(f"  [red]{icon('cross')}[/red] SSH key not found: {key_path}")
                        results['vps'] = False
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
                            await conn.close()
                            return time.time() - start

                        elapsed = asyncio.run(test_ssh())
                        console.print(f"  [green]{icon('check')}[/green] VPS connected ({config.vps.user}@{config.vps.host}) - {elapsed:.1f}s")
                        results['vps'] = True

                except ImportError:
                    console.print(f"  [yellow]{icon('warning')}[/yellow] asyncssh not installed")
                    console.print("    [dim]Install with: pip install asyncssh[/dim]")
                    results['vps'] = None
                except Exception as e:
                    console.print(f"  [red]{icon('cross')}[/red] VPS connection failed: {str(e)[:60]}")
                    results['vps'] = False
                    all_passed = False

        console.print()

    # ======================== Scanner Checks (if requested) ========================
    if use_acunetix or use_burp:
        console.print("[bold cyan]━━━ Scanner Integrations ━━━[/bold cyan]")

        # Acunetix
        if use_acunetix:
            if not config.scanners.acunetix_url:
                console.print(f"  [red]{icon('cross')}[/red] Acunetix URL not configured")
                results['acunetix'] = False
                all_passed = False
            else:
                with console.status("[yellow]Testing Acunetix...[/yellow]"):
                    try:
                        import httpx
                        response = httpx.get(
                            f"{config.scanners.acunetix_url}/api/v1/me",
                            headers={"X-Auth": config.scanners.acunetix_api_key or ""},
                            verify=False,
                            timeout=10,
                        )
                        if response.status_code == 200:
                            console.print(f"  [green]{icon('check')}[/green] Acunetix connected")
                            results['acunetix'] = True
                        else:
                            console.print(f"  [red]{icon('cross')}[/red] Acunetix auth failed (HTTP {response.status_code})")
                            results['acunetix'] = False
                            all_passed = False
                    except Exception as e:
                        console.print(f"  [red]{icon('cross')}[/red] Acunetix failed: {str(e)[:50]}")
                        results['acunetix'] = False
                        all_passed = False

        # Burp Suite
        if use_burp:
            if not config.scanners.burp_url:
                console.print(f"  [red]{icon('cross')}[/red] Burp Suite URL not configured")
                results['burp'] = False
                all_passed = False
            else:
                with console.status("[yellow]Testing Burp Suite...[/yellow]"):
                    try:
                        import httpx
                        response = httpx.get(
                            f"{config.scanners.burp_url}/api-internal/versions",
                            headers={"Authorization": f"Bearer {config.scanners.burp_api_key or ''}"},
                            verify=False,
                            timeout=10,
                        )
                        if response.status_code == 200:
                            console.print(f"  [green]{icon('check')}[/green] Burp Suite connected")
                            results['burp'] = True
                        else:
                            console.print(f"  [red]{icon('cross')}[/red] Burp Suite auth failed (HTTP {response.status_code})")
                            results['burp'] = False
                            all_passed = False
                    except Exception as e:
                        console.print(f"  [red]{icon('cross')}[/red] Burp Suite failed: {str(e)[:50]}")
                        results['burp'] = False
                        all_passed = False

        console.print()

    # ======================== Local Tools Check ========================
    console.print("[bold cyan]━━━ Local Security Tools ━━━[/bold cyan]")

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
        console.print(f"  [yellow]{icon('warning')}[/yellow] Missing essential: {', '.join(missing_essential)}")
        if not use_vps:
            console.print("    [dim]Consider using --use-vps or install locally[/dim]")
    if found_optional:
        console.print(f"  [dim]{icon('circle_empty')}[/dim] Optional available: {', '.join(found_optional)}")

    results['tools'] = len(missing_essential) == 0 or use_vps

    console.print()

    # ======================== Summary ========================
    console.print("[bold cyan]━━━ Pre-flight Summary ━━━[/bold cyan]")

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
        console.print(f"[bold green]{icon('check')} All pre-flight checks passed! Ready to scan.[/bold green]")
    else:
        console.print(f"[bold red]{icon('cross')} Some checks failed. Fix issues above before scanning.[/bold red]")
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

    quick = getattr(args, 'quick', False)
    auto_fix = getattr(args, 'fix', False)
    report_file = getattr(args, 'report', None)

    return asyncio.run(verify_installation(
        quick=quick,
        auto_fix=auto_fix,
        report_file=report_file,
    ))


def run_shell(args):
    """Start the interactive security shell."""
    import asyncio

    from aipt_v2.interactive_shell import start_interactive_shell

    log_file = getattr(args, 'log', None)
    working_dir = getattr(args, 'dir', None)

    return asyncio.run(start_interactive_shell(
        log_file=log_file,
        working_dir=working_dir,
    ))


def run_tools_command(args):
    """Handle tools subcommands for local tool management."""
    import asyncio
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console = Console()

    tools_cmd = getattr(args, 'tools_command', None)

    if tools_cmd == "install":
        return run_tools_install(args, console)
    elif tools_cmd == "list":
        return run_tools_list(args, console)
    elif tools_cmd == "check":
        return run_tools_check(args, console)
    else:
        console.print(Panel(
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
        ))
        return 0


def run_tools_install(args, console):
    """Install security tools on local system."""
    import asyncio
    from rich.panel import Panel

    console.print()
    console.print(Panel(
        "[bold cyan]Local Tool Installation[/bold cyan]\n\n"
        "Installing security tools on your local system.\n"
        "Some tools may require sudo/admin privileges.",
        title=f"{icon('wrench')} Installation",
        border_style="cyan",
    ))
    console.print()

    async def _install():
        try:
            from aipt_v2.system_detector import SystemDetector
            from aipt_v2.local_tool_installer import LocalToolInstaller, TOOLS

            # Detect system first
            detector = SystemDetector()
            with console.status("[bold cyan]Detecting system...[/bold cyan]"):
                system_info = await detector.detect()

            console.print(f"[dim]Detected: {system_info.os_name} with {system_info.package_manager.value}[/dim]")

            installer = LocalToolInstaller(system_info)
            use_sudo = not getattr(args, 'no_sudo', False)

            # Determine what to install
            if getattr(args, 'all', False):
                console.print("[cyan]Installing all available tools...[/cyan]")
                results = await installer.install_all()
            elif getattr(args, 'tools', None):
                console.print(f"[cyan]Installing specific tools: {', '.join(args.tools)}[/cyan]")
                results = await installer.install_tools(tools=args.tools, use_sudo=use_sudo)
            elif getattr(args, 'categories', None):
                console.print(f"[cyan]Installing categories: {', '.join(args.categories)}[/cyan]")
                results = await installer.install_tools(categories=args.categories, use_sudo=use_sudo)
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
    from rich.table import Table
    from rich import box

    async def _list():
        try:
            from aipt_v2.local_tool_installer import LocalToolInstaller, TOOLS

            installer = LocalToolInstaller()
            installed = await installer.get_installed_tools()

            category = getattr(args, 'category', 'all')
            installed_only = getattr(args, 'installed_only', False)

            table = Table(title="Security Tools", box=box.ROUNDED)
            table.add_column("Tool", style="cyan")
            table.add_column("Category", style="dim")
            table.add_column("Status", justify="center")
            table.add_column("Description")

            for tool_name, tool_def in sorted(TOOLS.items()):
                if category != 'all' and tool_def.category.value != category:
                    continue

                is_installed = installed.get(tool_name, False)

                if installed_only and not is_installed:
                    continue

                status = f"[green]{icon('check')} Installed[/green]" if is_installed else f"[dim]{icon('circle_empty')} Not installed[/dim]"
                core_badge = f" [yellow]{icon('sparkles')}[/yellow]" if tool_def.is_core else ""

                table.add_row(
                    f"{tool_name}{core_badge}",
                    tool_def.category.value,
                    status,
                    tool_def.description[:50] + "..." if len(tool_def.description) > 50 else tool_def.description
                )

            console.print()
            console.print(table)
            console.print()
            console.print(f"[dim]Legend: [yellow]{icon('sparkles')}[/yellow] = Core tool (recommended)[/dim]")

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
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    async def _check():
        try:
            from aipt_v2.local_tool_installer import LocalToolInstaller, TOOLS

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
                coverage = (counts["installed"] / counts["total"] * 100) if counts["total"] > 0 else 0
                coverage_color = "green" if coverage >= 75 else "yellow" if coverage >= 50 else "red"

                table.add_row(
                    cat,
                    str(counts["installed"]),
                    str(counts["total"]),
                    f"[{coverage_color}]{coverage:.0f}%[/{coverage_color}]"
                )

                total_installed += counts["installed"]
                total_tools += counts["total"]

            table.add_row("─" * 15, "─" * 5, "─" * 5, "─" * 7)
            total_coverage = (total_installed / total_tools * 100) if total_tools > 0 else 0
            table.add_row(
                "[bold]Total[/bold]",
                f"[bold]{total_installed}[/bold]",
                f"[bold]{total_tools}[/bold]",
                f"[bold]{total_coverage:.0f}%[/bold]"
            )

            console.print()
            console.print(table)
            console.print()

            if total_coverage < 50:
                console.print(Panel(
                    "[yellow]Many security tools are not installed.[/yellow]\n\n"
                    "Run [bold]aiptx tools install --core[/bold] to install essential tools.",
                    title=f"{icon('lightbulb')} Recommendation",
                    border_style="yellow"
                ))

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
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn

    console = Console()

    # Check VPS configuration
    config = get_config()
    if not config.vps.host:
        console.print(Panel(
            "[bold red]VPS not configured![/bold red]\n\n"
            "Run [bold green]aiptx setup[/bold green] to configure VPS settings.\n\n"
            "[bold]Required settings:[/bold]\n"
            "  • VPS_HOST - VPS IP or hostname\n"
            "  • VPS_USER - SSH username (default: ubuntu)\n"
            "  • VPS_KEY  - Path to SSH private key",
            title=f"{icon('warning')} VPS Configuration Required",
            border_style="yellow",
        ))
        return 1

    vps_cmd = getattr(args, 'vps_command', None)

    if vps_cmd == "setup":
        return run_vps_setup(args, console)
    elif vps_cmd == "status":
        return run_vps_status(args, console)
    elif vps_cmd == "scan":
        return run_vps_scan(args, console)
    elif vps_cmd == "script":
        return run_vps_script(args, console)
    else:
        console.print(Panel(
            "[bold cyan]AIPTX VPS Commands[/bold cyan]\n\n"
            "[bold]aiptx vps setup[/bold]   - Install security tools on VPS\n"
            "[bold]aiptx vps status[/bold]  - Check VPS connection and tools\n"
            "[bold]aiptx vps scan[/bold]    - Run security scan from VPS\n"
            "[bold]aiptx vps script[/bold]  - Generate setup script",
            title=f"{icon('desktop')} VPS Remote Execution",
            border_style="cyan",
        ))
        return 0


def run_vps_setup(args, console):
    """Install security tools on VPS with real-time progress."""
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.console import Group
    from rich.spinner import Spinner
    from rich import box

    # Check for asyncssh FIRST before any VPS operations
    try:
        import asyncssh
    except ImportError:
        console.print()
        console.print(Panel(
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
        ))
        console.print()
        return 1

    from aipt_v2.runtime.vps import VPSRuntime, VPS_TOOLS

    console.print()
    console.print(Panel(
        "[bold cyan]VPS Tool Installation[/bold cyan]\n\n"
        "Installing security tools on your VPS.\n"
        "This may take 10-30 minutes depending on your VPS speed.",
        title=f"{icon('wrench')} Setup",
        border_style="cyan",
    ))
    console.print()

    # Get categories and tools to install
    categories = getattr(args, 'categories', None)
    specific_tools = getattr(args, 'tools', None)

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
        stdout, stderr, code = await runtime._run_command(f"sudo bash -c '{setup_script}'", timeout=300)
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
        console.print(Panel(
            f"[bold green]{icon('check')} All {installed} tools installed successfully![/bold green]\n\n"
            "You can now run:\n"
            "  [bold]aiptx vps scan target.com[/bold]",
            title=f"{icon('sparkles')} Setup Complete",
            border_style="green",
        ))
    else:
        console.print(f"[bold]Summary:[/bold] {installed} installed, [red]{failed} failed[/red]")
        console.print("[dim]Failed tools may require manual installation on VPS[/dim]")

    return 0 if failed == 0 else 1


def run_vps_status(args, console):
    """Check VPS connection and installed tools."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.text import Text
    from rich.console import Group
    from rich import box

    # Check for asyncssh FIRST
    try:
        import asyncssh
    except ImportError:
        console.print()
        console.print(Panel(
            "[bold red]Missing Dependency: asyncssh[/bold red]\n\n"
            "The VPS module requires asyncssh for SSH connectivity.\n\n"
            "[bold]Install with:[/bold]\n"
            "  [green]pip install asyncssh[/green]\n"
            "  [dim]or[/dim]\n"
            "  [green]pip install aiptx[vps][/green]",
            title=f"{icon('warning')} Dependency Required",
            border_style="yellow",
        ))
        console.print()
        return 1

    from aipt_v2.runtime.vps import VPSRuntime, VPS_TOOLS

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
            status_str = f"[green]{icon('check')} Installed[/green]" if status else f"[dim]{icon('circle_empty')} Not installed[/dim]"
            table.add_row(category, tool_name, status_str)

    console.print(table)

    # Summary
    installed = sum(1 for v in tools_status.values() if v)
    total = len(tools_status)
    console.print()

    if installed == total:
        console.print(Panel(
            f"[bold green]{icon('check')} All {total} tools installed![/bold green]\n\n"
            "Your VPS is ready for scanning.\n"
            "Run: [bold]aiptx vps scan target.com[/bold]",
            title=f"{icon('sparkles')} VPS Ready",
            border_style="green",
        ))
    else:
        console.print(f"[bold]Tools:[/bold] {installed}/{total} installed")
        console.print()
        console.print("[dim]Run 'aiptx vps setup' to install missing tools[/dim]")

    return 0


def run_vps_scan(args, console):
    """Run security scan from VPS."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel

    # Check for asyncssh FIRST
    try:
        import asyncssh
    except ImportError:
        console.print()
        console.print(Panel(
            "[bold red]Missing Dependency: asyncssh[/bold red]\n\n"
            "The VPS module requires asyncssh for SSH connectivity.\n\n"
            "[bold]Install with:[/bold]\n"
            "  [green]pip install asyncssh[/green]\n"
            "  [dim]or[/dim]\n"
            "  [green]pip install aiptx[vps][/green]",
            title=f"{icon('warning')} Dependency Required",
            border_style="yellow",
        ))
        console.print()
        return 1

    target = args.target
    mode = getattr(args, 'mode', 'standard')
    tools = getattr(args, 'tools', None)

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {mode}\n"
        f"[bold]Tools:[/bold] {', '.join(tools) if tools else 'Auto-selected'}",
        title=f"{icon('target')} VPS Scan Configuration",
        border_style="cyan",
    ))
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
    tool_outputs = results.get('tool_outputs', {})
    if tool_outputs:
        from rich.table import Table
        table = Table(title="Tool Execution Summary")
        table.add_column("Tool", style="cyan")
        table.add_column("Exit Code", style="green")
        table.add_column("Output Size", style="yellow")

        for tool, output in tool_outputs.items():
            exit_code = output.get('exit_code', -1)
            status = "[green]{icon('check')}[/green]" if exit_code == 0 else f"[red]{exit_code}[/red]"
            stdout_len = len(output.get('stdout', ''))
            table.add_row(tool, status, f"{stdout_len} bytes")

        console.print(table)

    return 0


def run_vps_script(args, console):
    """Generate VPS setup script."""
    from aipt_v2.runtime.vps import generate_vps_setup_script

    categories = getattr(args, 'categories', None)
    output_file = getattr(args, 'output', None)

    script = generate_vps_setup_script(categories=categories)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(script)
        console.print(f"[green]{icon('check')}[/green] Script saved to: {output_file}")
        console.print(f"[dim]Run on VPS: curl -sL <url> | sudo bash[/dim]")
    else:
        console.print(script)

    return 0


def run_ai_command(args):
    """Handle AI security testing commands."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    import json

    console = Console()

    ai_cmd = getattr(args, 'ai_command', None)

    # Run prerequisites check for AI commands (requires LLM key)
    if ai_cmd in ("code-review", "api-test", "web-pentest", "full"):
        from .prerequisites import check_prerequisites_sync
        is_ready, prereq_errors = check_prerequisites_sync(
            require_llm=True,
            require_tools=False,
        )

        if not is_ready:
            console.print()
            console.print(Panel(
                "[bold red]Prerequisites Check Failed[/bold red]\n\n"
                "AI security testing requires an LLM API key.\n\n" +
                "\n".join(f"  [red]•[/red] {e}" for e in prereq_errors) +
                "\n\n[bold]To fix:[/bold]\n"
                "  Run [bold green]aiptx setup[/bold green] to configure\n"
                "  Or set: [dim]export ANTHROPIC_API_KEY=your-key[/dim]\n\n"
                "[bold]For detailed diagnostics:[/bold]\n"
                "  Run [bold green]aiptx check[/bold green]",
                title=f"{icon('warning')} Configuration Required",
                border_style="red",
                padding=(1, 2),
            ))
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
        console.print(Panel(
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
        ))
        console.print()
        return 0


def run_ai_code_review(args, console):
    """Run AI-powered source code security review."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.live import Live
    from rich.text import Text
    from rich import box
    import json

    target = args.target
    focus = getattr(args, 'focus', None)
    model = getattr(args, 'model', 'claude-sonnet-4-20250514')
    max_steps = getattr(args, 'max_steps', 100)
    quick = getattr(args, 'quick', False)
    output_file = getattr(args, 'output', None)

    # Verify target exists
    if not Path(target).exists():
        console.print(f"[red]Error:[/red] Target path does not exist: {target}")
        return 1

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Model:[/bold] {model}\n"
        f"[bold]Mode:[/bold] {'Quick scan' if quick else 'Full review'}\n"
        f"[bold]Focus:[/bold] {', '.join(focus) if focus else 'All vulnerabilities'}",
        title=f"{icon('search')} AI Code Review",
        border_style="cyan",
    ))
    console.print()

    # Import agent
    from aipt_v2.skills.agents.code_review import CodeReviewAgent
    from aipt_v2.skills.agents.base import AgentConfig

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
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if result.success else 1


def run_ai_api_test(args, console):
    """Run AI-powered API security testing."""
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import json

    target = args.target
    openapi_spec = getattr(args, 'openapi', None)
    auth_token = getattr(args, 'auth_token', None)
    model = getattr(args, 'model', 'claude-sonnet-4-20250514')
    max_steps = getattr(args, 'max_steps', 100)
    output_file = getattr(args, 'output', None)

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Model:[/bold] {model}\n"
        f"[bold]OpenAPI Spec:[/bold] {openapi_spec or 'Not provided'}\n"
        f"[bold]Authentication:[/bold] {'Bearer token' if auth_token else 'None'}",
        title="🔌 AI API Security Test",
        border_style="cyan",
    ))
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
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if result.success else 1


def run_ai_web_pentest(args, console):
    """Run AI-powered web penetration testing."""
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import json

    target = args.target
    auth_token = getattr(args, 'auth_token', None)
    cookies_list = getattr(args, 'cookie', None) or []
    model = getattr(args, 'model', 'claude-sonnet-4-20250514')
    max_steps = getattr(args, 'max_steps', 100)
    quick = getattr(args, 'quick', False)
    output_file = getattr(args, 'output', None)

    # Parse cookies
    cookies = {}
    for cookie in cookies_list:
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            cookies[key] = value

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Model:[/bold] {model}\n"
        f"[bold]Mode:[/bold] {'Quick scan' if quick else 'Full pentest'}\n"
        f"[bold]Authentication:[/bold] {'Token + Cookies' if auth_token and cookies else 'Token' if auth_token else 'Cookies' if cookies else 'None'}",
        title=f"{icon('globe')} AI Web Penetration Test",
        border_style="cyan",
    ))
    console.print()

    # Import agent
    from aipt_v2.skills.agents.web_pentest import WebPentestAgent
    from aipt_v2.skills.agents.base import AgentConfig

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
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if result.success else 1


def run_ai_full_assessment(args, console):
    """Run full AI-driven security assessment."""
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import json

    target = args.target
    test_types = getattr(args, 'types', ['web'])
    model = getattr(args, 'model', 'claude-sonnet-4-20250514')
    output_file = getattr(args, 'output', None)

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Model:[/bold] {model}\n"
        f"[bold]Test Types:[/bold] {', '.join(test_types)}",
        title=f"{icon('target')} Full AI Security Assessment",
        border_style="cyan",
    ))
    console.print()

    # Import agent
    from aipt_v2.skills.agents.security_agent import SecurityAgent
    from aipt_v2.skills.agents.base import AgentConfig

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
        with open(output_file, 'w') as f:
            json.dump(combined.to_dict(), f, indent=2)
        console.print(f"\n[green]{icon('check')}[/green] Results saved to: {output_file}")

    return 0 if combined.success else 1


def display_ai_results(console, result, test_name):
    """Display AI testing results in a formatted way."""
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

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

    summary = " | ".join(summary_parts) if summary_parts else "[green]No vulnerabilities found[/green]"

    console.print(Panel(
        f"[bold]Findings:[/bold] {len(result.findings)}\n"
        f"[bold]Severity:[/bold] {summary}\n"
        f"[bold]Steps:[/bold] {result.total_steps}\n"
        f"[bold]Time:[/bold] {result.execution_time:.1f}s\n"
        f"[bold]Model:[/bold] {result.model_used}",
        title=f"{icon('chart')} {test_name} Results",
        border_style="green" if result.success else "red",
    ))

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


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully without traceback
        from rich.console import Console
        Console().print("\n[yellow]Operation cancelled.[/yellow]")
        sys.exit(130)
