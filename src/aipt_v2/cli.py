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
    from .config import get_config, validate_config_for_features
    from .utils.logging import setup_logging, logger
    from .setup_wizard import is_configured, prompt_first_run_setup, run_setup_wizard
except ImportError:
    # Local development fallback
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from __init__ import __version__
    from config import get_config, validate_config_for_features
    from utils.logging import setup_logging, logger
    from setup_wizard import is_configured, prompt_first_run_setup, run_setup_wizard


def main():
    """Main CLI entry point."""
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

    # API command
    api_parser = subparsers.add_parser("api", help="Start REST API server")
    # Security: Default to localhost to prevent accidental network exposure
    api_parser.add_argument("--host", default="127.0.0.1", help="API host (default: 127.0.0.1, use 0.0.0.0 for network access)")
    api_parser.add_argument("--port", "-p", type=int, default=8000, help="API port (default: 8000)")
    api_parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    # Status command
    subparsers.add_parser("status", help="Check configuration and dependencies")

    # Version command
    subparsers.add_parser("version", help="Show detailed version information")

    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Run interactive setup wizard")
    setup_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force reconfiguration even if already configured"
    )

    args = parser.parse_args()

    # Setup logging based on verbosity
    log_level = "DEBUG" if args.verbose >= 2 else "INFO" if args.verbose == 1 else "WARNING"
    setup_logging(level=log_level, json_format=args.json)

    # Handle commands
    if args.command == "setup":
        return run_setup(args)
    elif args.command == "scan":
        return run_scan(args)
    elif args.command == "api":
        return run_api(args)
    elif args.command == "status":
        return show_status(args)
    elif args.command == "version":
        return show_version()
    else:
        # No command given - check if first run and guide user
        if not is_configured():
            return show_first_run_help()
        parser.print_help()
        return 0


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


def run_setup(args):
    """Run the interactive setup wizard."""
    force = getattr(args, 'force', False)
    success = run_setup_wizard(force=force)
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

    # Create config
    config = OrchestratorConfig(
        target=args.target,
        output_dir=Path(args.output) if args.output else Path("./results"),
        skip_recon=args.skip_recon,
        use_acunetix=args.use_acunetix,
        use_burp=args.use_burp,
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


if __name__ == "__main__":
    sys.exit(main())
