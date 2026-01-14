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
except ImportError:
    # Local development fallback
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from __init__ import __version__
    from config import get_config, validate_config_for_features, reload_config
    from utils.logging import setup_logging, logger
    from setup_wizard import is_configured, prompt_first_run_setup, run_setup_wizard


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
        elif args.command == "test":
            return run_config_test(args)
        elif args.command == "version":
            return show_version()
        elif args.command == "vps":
            return run_vps_command(args)
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
        title="🚀 AIPTX - AI-Powered Penetration Testing",
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

    # Show welcome banner
    console.print()
    console.print(Panel(
        "[bold cyan]AIPTX Interactive Shell[/bold cyan]\n\n"
        "AI-Powered Penetration Testing Framework\n\n"
        "[bold]Commands:[/bold]\n"
        "  [green]scan[/green] <target>      - Run security scan\n"
        "  [green]ai[/green] <command>       - AI security testing\n"
        "  [green]vps[/green] <command>      - VPS management\n"
        "  [green]setup[/green]              - Configure AIPTX\n"
        "  [green]status[/green]             - Show configuration\n"
        "  [green]help[/green]               - Show all commands\n"
        "  [green]exit[/green] / [green]quit[/green]        - Exit AIPTX\n\n"
        "[dim]Type a command or 'help' for more options[/dim]",
        title="🚀 AIPTX v" + __version__,
        border_style="cyan",
    ))

    # Check configuration status
    if not is_configured():
        console.print()
        console.print("[yellow]⚠ Not configured.[/yellow] Run [bold green]setup[/bold green] to configure AIPTX.")
    console.print()

    # Interactive loop
    while True:
        try:
            # Get user input
            user_input = Prompt.ask("[bold cyan]aiptx[/bold cyan]", default="").strip()

            if not user_input:
                continue

            # Parse the input
            parts = user_input.split()
            cmd = parts[0].lower()
            args_list = parts[1:] if len(parts) > 1 else []

            # Handle commands
            if cmd in ("exit", "quit", "q"):
                console.print("[dim]Goodbye![/dim]")
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
    except ImportError:
        from orchestrator import Orchestrator, OrchestratorConfig

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
            "\n".join(f"  [yellow]•[/yellow] {error}" for error in errors) +
            "\n\n[bold]To fix:[/bold]\n"
            "  Run [bold green]aiptx setup[/bold green] to configure interactively\n\n"
            "[bold]Or set environment variables:[/bold]\n"
            "  [dim]export ANTHROPIC_API_KEY=your-key-here[/dim]",
            title="⚠️  Setup Required",
            border_style="yellow",
            padding=(1, 2),
        ))
        console.print()
        return 1

    # Run pre-flight checks if requested
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
        asyncio.run(orchestrator.run())
        console.print()
        console.print("[bold green]✓ Scan completed successfully[/bold green]")
        return 0
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]Scan interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print()
        console.print(f"[bold red]✗ Scan failed:[/bold red] {e}")
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
    """Show configuration status."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    config = get_config()

    console.print("\n[bold cyan]AIPT v2 Configuration Status[/bold cyan]\n")

    # LLM Status
    table = Table(title="LLM Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Status", style="yellow")

    table.add_row("Provider", config.llm.provider, "✓" if config.llm.provider else "✗")
    table.add_row("Model", config.llm.model, "✓" if config.llm.model else "✗")
    table.add_row("API Key", "****" if config.llm.api_key else "Not set", "✓" if config.llm.api_key else "✗")

    console.print(table)

    # Scanner Status
    table = Table(title="Scanner Configuration")
    table.add_column("Scanner", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("API Key", style="yellow")

    table.add_row(
        "Acunetix",
        config.scanners.acunetix_url or "Not configured",
        "✓" if config.scanners.acunetix_api_key else "✗",
    )
    table.add_row(
        "Burp Suite",
        config.scanners.burp_url or "Not configured",
        "✓" if config.scanners.burp_api_key else "✗",
    )
    table.add_row(
        "Nessus",
        config.scanners.nessus_url or "Not configured",
        "✓" if config.scanners.nessus_access_key else "✗",
    )
    table.add_row(
        "OWASP ZAP",
        config.scanners.zap_url or "Not configured",
        "✓" if config.scanners.zap_api_key else "✗",
    )

    console.print(table)

    # VPS Status
    table = Table(title="VPS Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Host", config.vps.host or "Not configured")
    table.add_row("User", config.vps.user)
    table.add_row("SSH Key", config.vps.key_path or "Not configured")

    console.print(table)

    # Check for issues
    console.print("\n[bold]Configuration Validation:[/bold]")

    all_features = ["llm", "acunetix", "burp", "nessus", "vps"]
    for feature in all_features:
        errors = validate_config_for_features([feature])
        if errors:
            console.print(f"  [yellow]⚠[/yellow] {feature}: {errors[0]}")
        else:
            console.print(f"  [green]✓[/green] {feature}: Ready")

    return 0


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
        title="🔍 Self-Test",
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
            console.print("  [red]✗[/red] No API key configured")
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

                    console.print(f"  [green]✓[/green] LLM API connection successful")
                    console.print(f"    [dim]Provider: {provider}[/dim]")
                    console.print(f"    [dim]Model: {model}[/dim]")
                    console.print(f"    [dim]Response time: {elapsed:.2f}s[/dim]")
                    results['llm'] = True

                except ImportError:
                    console.print("  [yellow]⚠[/yellow] litellm not installed")
                    console.print("    [dim]Install with: pip install litellm[/dim]")
                    results['llm'] = None
                except Exception as e:
                    console.print(f"  [red]✗[/red] LLM API test failed")
                    console.print(f"    [dim]Error: {str(e)[:100]}[/dim]")
                    results['llm'] = False

        console.print()

    # ======================== VPS Test ========================
    if test_all or getattr(args, 'vps', False):
        console.print("[bold cyan]━━━ VPS Connection Test ━━━[/bold cyan]")

        if not config.vps.host:
            console.print("  [yellow]○[/yellow] VPS not configured (optional)")
            results['vps'] = None
        elif not config.vps.key_path:
            console.print("  [red]✗[/red] SSH key path not configured")
            results['vps'] = False
        else:
            with console.status("[yellow]Testing SSH connection to VPS...[/yellow]"):
                try:
                    from pathlib import Path

                    key_path = Path(config.vps.key_path).expanduser()
                    if not key_path.exists():
                        console.print(f"  [red]✗[/red] SSH key not found: {key_path}")
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
                            console.print(f"  [green]✓[/green] VPS connection successful")
                            console.print(f"    [dim]Host: {config.vps.user}@{config.vps.host}:{config.vps.port}[/dim]")
                            console.print(f"    [dim]System: {uname[:60]}...[/dim]" if len(uname) > 60 else f"    [dim]System: {uname}[/dim]")
                            console.print(f"    [dim]Response time: {elapsed:.2f}s[/dim]")
                            results['vps'] = True
                        else:
                            console.print(f"  [red]✗[/red] VPS connection failed - unexpected response")
                            results['vps'] = False

                except ImportError:
                    console.print("  [yellow]⚠[/yellow] asyncssh not installed")
                    console.print("    [dim]Install with: pip install asyncssh[/dim]")
                    results['vps'] = None
                except Exception as e:
                    console.print(f"  [red]✗[/red] VPS connection failed")
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
                        console.print(f"  [green]✓[/green] Acunetix connected")
                        console.print(f"    [dim]URL: {config.scanners.acunetix_url}[/dim]")
                        results['acunetix'] = True
                    else:
                        console.print(f"  [red]✗[/red] Acunetix auth failed (HTTP {response.status_code})")
                        results['acunetix'] = False
                except Exception as e:
                    console.print(f"  [red]✗[/red] Acunetix connection failed: {str(e)[:50]}")
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
                        console.print(f"  [green]✓[/green] Burp Suite connected")
                        console.print(f"    [dim]URL: {config.scanners.burp_url}[/dim]")
                        results['burp'] = True
                    else:
                        console.print(f"  [red]✗[/red] Burp Suite auth failed (HTTP {response.status_code})")
                        results['burp'] = False
                except Exception as e:
                    console.print(f"  [red]✗[/red] Burp Suite connection failed: {str(e)[:50]}")
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
                        console.print(f"  [green]✓[/green] Nessus connected")
                        console.print(f"    [dim]URL: {config.scanners.nessus_url}[/dim]")
                        results['nessus'] = True
                    else:
                        console.print(f"  [red]✗[/red] Nessus auth failed (HTTP {response.status_code})")
                        results['nessus'] = False
                except Exception as e:
                    console.print(f"  [red]✗[/red] Nessus connection failed: {str(e)[:50]}")
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
                        console.print(f"  [green]✓[/green] OWASP ZAP connected (v{version})")
                        console.print(f"    [dim]URL: {config.scanners.zap_url}[/dim]")
                        results['zap'] = True
                    else:
                        console.print(f"  [red]✗[/red] ZAP connection failed (HTTP {response.status_code})")
                        results['zap'] = False
                except Exception as e:
                    console.print(f"  [red]✗[/red] ZAP connection failed: {str(e)[:50]}")
                    results['zap'] = False

        if scanners_tested == 0:
            console.print("  [yellow]○[/yellow] No scanners configured (optional)")

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
            console.print(f"  [green]✓[/green] Available: {', '.join(found_tools)}")

        if missing_tools:
            console.print(f"  [yellow]○[/yellow] Not found: {', '.join(missing_tools)}")
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
            status_str = "[green]✓ PASS[/green]"
            details = "Working correctly"
        elif status is False:
            status_str = "[red]✗ FAIL[/red]"
            details = "Check configuration"
        elif status is None:
            status_str = "[yellow]○ SKIP[/yellow]"
            details = "Not configured"
        elif isinstance(status, int):
            status_str = f"[green]✓ {status}[/green]"
            details = f"{status} tools available"
        else:
            status_str = "[dim]?[/dim]"
            details = "Unknown"

        table.add_row(component.upper(), status_str, details)

    console.print(table)

    # Overall result
    failures = sum(1 for v in results.values() if v is False)
    if failures == 0:
        console.print("\n[bold green]✓ All tests passed![/bold green]")
        return 0
    else:
        console.print(f"\n[bold yellow]⚠ {failures} test(s) failed. Run 'aiptx setup' to fix.[/bold yellow]")
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
        title="✈️  Pre-flight Check",
        border_style="cyan"
    ))
    console.print()

    # ======================== LLM Check (always required) ========================
    console.print("[bold cyan]━━━ LLM API ━━━[/bold cyan]")

    if not config.llm.api_key:
        console.print("  [red]✗[/red] No API key configured")
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

                console.print(f"  [green]✓[/green] LLM ready ({provider}/{model}) - {elapsed:.1f}s")
                results['llm'] = True

            except ImportError:
                console.print("  [yellow]⚠[/yellow] litellm not installed")
                results['llm'] = None
            except Exception as e:
                console.print(f"  [red]✗[/red] LLM connection failed: {str(e)[:60]}")
                results['llm'] = False
                all_passed = False

    console.print()

    # ======================== VPS Check (if requested) ========================
    if use_vps:
        console.print("[bold cyan]━━━ VPS Connection ━━━[/bold cyan]")

        if not config.vps.host:
            console.print("  [red]✗[/red] VPS not configured")
            console.print("    [dim]Run 'aiptx setup' to configure VPS[/dim]")
            results['vps'] = False
            all_passed = False
        elif not config.vps.key_path:
            console.print("  [red]✗[/red] SSH key path not configured")
            results['vps'] = False
            all_passed = False
        else:
            with console.status("[yellow]Testing SSH connection...[/yellow]"):
                try:
                    from pathlib import Path
                    import asyncssh

                    key_path = Path(config.vps.key_path).expanduser()
                    if not key_path.exists():
                        console.print(f"  [red]✗[/red] SSH key not found: {key_path}")
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
                        console.print(f"  [green]✓[/green] VPS connected ({config.vps.user}@{config.vps.host}) - {elapsed:.1f}s")
                        results['vps'] = True

                except ImportError:
                    console.print("  [yellow]⚠[/yellow] asyncssh not installed")
                    console.print("    [dim]Install with: pip install asyncssh[/dim]")
                    results['vps'] = None
                except Exception as e:
                    console.print(f"  [red]✗[/red] VPS connection failed: {str(e)[:60]}")
                    results['vps'] = False
                    all_passed = False

        console.print()

    # ======================== Scanner Checks (if requested) ========================
    if use_acunetix or use_burp:
        console.print("[bold cyan]━━━ Scanner Integrations ━━━[/bold cyan]")

        # Acunetix
        if use_acunetix:
            if not config.scanners.acunetix_url:
                console.print("  [red]✗[/red] Acunetix URL not configured")
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
                            console.print(f"  [green]✓[/green] Acunetix connected")
                            results['acunetix'] = True
                        else:
                            console.print(f"  [red]✗[/red] Acunetix auth failed (HTTP {response.status_code})")
                            results['acunetix'] = False
                            all_passed = False
                    except Exception as e:
                        console.print(f"  [red]✗[/red] Acunetix failed: {str(e)[:50]}")
                        results['acunetix'] = False
                        all_passed = False

        # Burp Suite
        if use_burp:
            if not config.scanners.burp_url:
                console.print("  [red]✗[/red] Burp Suite URL not configured")
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
                            console.print(f"  [green]✓[/green] Burp Suite connected")
                            results['burp'] = True
                        else:
                            console.print(f"  [red]✗[/red] Burp Suite auth failed (HTTP {response.status_code})")
                            results['burp'] = False
                            all_passed = False
                    except Exception as e:
                        console.print(f"  [red]✗[/red] Burp Suite failed: {str(e)[:50]}")
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
        console.print(f"  [green]✓[/green] Essential: {', '.join(found_essential)}")
    if missing_essential:
        console.print(f"  [yellow]⚠[/yellow] Missing essential: {', '.join(missing_essential)}")
        if not use_vps:
            console.print("    [dim]Consider using --use-vps or install locally[/dim]")
    if found_optional:
        console.print(f"  [dim]○[/dim] Optional available: {', '.join(found_optional)}")

    results['tools'] = len(missing_essential) == 0 or use_vps

    console.print()

    # ======================== Summary ========================
    console.print("[bold cyan]━━━ Pre-flight Summary ━━━[/bold cyan]")

    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="center")

    for component, status in results.items():
        if status is True:
            status_str = "[green]✓ READY[/green]"
        elif status is False:
            status_str = "[red]✗ FAILED[/red]"
        elif status is None:
            status_str = "[yellow]○ SKIPPED[/yellow]"
        else:
            status_str = "[dim]?[/dim]"
        table.add_row(component.upper(), status_str)

    console.print(table)
    console.print()

    if all_passed:
        console.print("[bold green]✓ All pre-flight checks passed! Ready to scan.[/bold green]")
    else:
        console.print("[bold red]✗ Some checks failed. Fix issues above before scanning.[/bold red]")
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
            title="⚠️  VPS Configuration Required",
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
            title="🖥️  VPS Remote Execution",
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
            title="⚠️  Dependency Required",
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
        title="🔧 Setup",
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
        status_text.append("⚡ ", style="yellow")
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
            tool_text.append("   → Installing: ", style="dim")
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
        state["output"].append(f"✓ Connected to {runtime.host}")
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
        state["output"].append("✓ Base dependencies installed")
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
                state["output"].append(f"✓ {tool_name} installed")
            else:
                state["output"].append(f"✗ {tool_name} failed")

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
            table.add_row(tool, "[green]✓ Installed[/green]")
            installed += 1
        else:
            table.add_row(tool, "[red]✗ Failed[/red]")
            failed += 1

    console.print(table)
    console.print()

    if failed == 0:
        console.print(Panel(
            f"[bold green]✓ All {installed} tools installed successfully![/bold green]\n\n"
            "You can now run:\n"
            "  [bold]aiptx vps scan target.com[/bold]",
            title="🎉 Setup Complete",
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
            title="⚠️  Dependency Required",
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
        text.append("⚡ ", style="yellow")
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
        console.print(f"[green]✓[/green] Connected to [bold]{config.vps.host}[/bold]")
    else:
        console.print(f"[red]✗[/red] Failed to connect: {message}")
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
            status_str = "[green]✓ Installed[/green]" if status else "[dim]○ Not installed[/dim]"
            table.add_row(category, tool_name, status_str)

    console.print(table)

    # Summary
    installed = sum(1 for v in tools_status.values() if v)
    total = len(tools_status)
    console.print()

    if installed == total:
        console.print(Panel(
            f"[bold green]✓ All {total} tools installed![/bold green]\n\n"
            "Your VPS is ready for scanning.\n"
            "Run: [bold]aiptx vps scan target.com[/bold]",
            title="🎉 VPS Ready",
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
            title="⚠️  Dependency Required",
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
        title="🎯 VPS Scan Configuration",
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
    console.print("[bold green]✓ Scan complete![/bold green]")
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
            status = "[green]✓[/green]" if exit_code == 0 else f"[red]{exit_code}[/red]"
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
        console.print(f"[green]✓[/green] Script saved to: {output_file}")
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
            title="🤖 AI Security Testing",
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
        title="🔍 AI Code Review",
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
        console.print(f"\n[green]✓[/green] Results saved to: {output_file}")

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
        console.print(f"\n[green]✓[/green] Results saved to: {output_file}")

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
        title="🌐 AI Web Penetration Test",
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
        console.print(f"\n[green]✓[/green] Results saved to: {output_file}")

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
        title="🎯 Full AI Security Assessment",
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
        console.print(f"\n[green]✓[/green] Results saved to: {output_file}")

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
        title=f"📊 {test_name} Results",
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
            console.print(f"  [red]•[/red] {error}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully without traceback
        from rich.console import Console
        Console().print("\n[yellow]Operation cancelled.[/yellow]")
        sys.exit(130)
