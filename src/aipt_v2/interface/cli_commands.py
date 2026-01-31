"""
AIPTX CLI Commands
==================

Subcommand-based CLI interface for AIPTX operations:
- scan: Run penetration testing scans
- verify: Verify offline mode and tool availability
- tools: List and check security tools
- setup: Configure offline data and wordlists

Usage:
    aiptx scan example.com
    aiptx scan example.com --phases recon,scan --ai-checkpoints
    aiptx verify --offline
    aiptx tools --check
    aiptx setup --offline
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)
console = Console()


# ============================================================================
# Scan Command
# ============================================================================

def add_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'scan' subcommand parser."""
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run penetration testing scan",
        description="Execute security scans with optional AI-driven checkpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick reconnaissance scan
  aiptx scan example.com --phases recon

  # Full scan with AI checkpoints (requires Ollama)
  aiptx scan example.com --ai-checkpoints --model mistral:7b

  # Targeted vulnerability scan
  aiptx scan https://app.example.com --phases scan --tools nuclei,nikto

  # Complete pipeline: RECON -> SCAN -> EXPLOIT
  aiptx scan example.com --full --ai-checkpoints

  # Offline mode (no internet, local tools only)
  aiptx scan example.com --offline --phases recon,scan

  # Save results to specific directory
  aiptx scan example.com --output ./results/$(date +%Y%m%d)
        """,
    )

    # Target
    scan_parser.add_argument(
        "target",
        type=str,
        help="Target to scan (domain, URL, IP address)",
    )

    # Phase selection
    scan_parser.add_argument(
        "--phases",
        type=str,
        default="recon,scan",
        help="Comma-separated phases to run: recon,scan,exploit,post_exploit (default: recon,scan)",
    )

    scan_parser.add_argument(
        "--full",
        action="store_true",
        help="Run full pipeline: recon,scan,exploit,post_exploit",
    )

    scan_parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan: recon only with fast tools",
    )

    # Tool selection
    scan_parser.add_argument(
        "--tools",
        type=str,
        help="Comma-separated list of specific tools to use (e.g., 'nmap,nuclei,sqlmap')",
    )

    scan_parser.add_argument(
        "--exclude-tools",
        type=str,
        help="Comma-separated list of tools to exclude",
    )

    # AI Checkpoints
    scan_parser.add_argument(
        "--ai-checkpoints",
        action="store_true",
        help="Enable AI-driven checkpoints between phases (requires Ollama)",
    )

    scan_parser.add_argument(
        "--model",
        type=str,
        default="mistral:7b",
        help="Ollama model for AI checkpoints (default: mistral:7b)",
    )

    scan_parser.add_argument(
        "--ollama-url",
        type=str,
        default="http://localhost:11434",
        help="Ollama API URL (default: http://localhost:11434)",
    )

    # Offline mode
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (no internet, local tools only)",
    )

    # Output
    scan_parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output directory for results (default: ./aiptx_results/<timestamp>)",
    )

    scan_parser.add_argument(
        "--format",
        type=str,
        choices=["json", "markdown", "html", "all"],
        default="all",
        help="Output format (default: all)",
    )

    # Concurrency
    scan_parser.add_argument(
        "--concurrent",
        type=int,
        default=3,
        help="Maximum concurrent tool executions (default: 3)",
    )

    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Default timeout per tool in seconds (default: 600)",
    )

    # Verbosity
    scan_parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)",
    )

    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-essential output",
    )

    scan_parser.set_defaults(func=run_scan_command)


async def run_scan_command(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    from aipt_v2.execution.phase_runner import (
        PhaseRunner,
        PhaseConfig,
        PipelineConfig,
        run_quick_scan,
        run_full_scan,
    )
    from aipt_v2.execution.tool_registry import ToolPhase, ToolRegistry, get_registry
    from aipt_v2.execution.result_collector import ResultCollector

    # Setup output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("aiptx_results") / f"{args.target.replace('/', '_')}_{timestamp}"

    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine phases
    if args.full:
        phases_str = "recon,scan,exploit,post_exploit"
    elif args.quick:
        phases_str = "recon"
    else:
        phases_str = args.phases

    phase_names = [p.strip().lower() for p in phases_str.split(",")]

    # Map to ToolPhase enum
    phase_map = {
        "recon": ToolPhase.RECON,
        "scan": ToolPhase.SCAN,
        "exploit": ToolPhase.EXPLOIT,
        "post_exploit": ToolPhase.POST_EXPLOIT,
    }

    phases = []
    for name in phase_names:
        if name in phase_map:
            phases.append(phase_map[name])
        else:
            console.print(f"[red]Unknown phase: {name}[/]")
            return 1

    # Display scan banner
    if not args.quiet:
        _display_scan_banner(args, phases, output_dir)

    # Discover available tools
    registry = get_registry()
    with console.status("[cyan]Discovering available tools...[/]"):
        tool_status = await registry.discover_tools()

    available_count = sum(1 for s in tool_status.values() if s.available)

    if not args.quiet:
        console.print(f"[green]✓[/] Found {available_count}/{len(tool_status)} tools available")

    # Build phase configurations
    phase_configs = []
    for phase in phases:
        tools = _get_tools_for_phase(registry, phase, args)
        if not tools:
            console.print(f"[yellow]Warning: No tools available for {phase.value} phase[/]")
            continue

        phase_configs.append(PhaseConfig(
            name=phase.value,
            phase=phase,
            tools=tools,
            timeout=args.timeout,
        ))

    if not phase_configs:
        console.print("[red]Error: No phases could be configured (no tools available)[/]")
        return 1

    # Build pipeline config
    pipeline_config = PipelineConfig(
        target=args.target,
        output_dir=output_dir,
        phases=phase_configs,
        enable_ai_checkpoints=args.ai_checkpoints,
        ollama_url=args.ollama_url,
        ollama_model=args.model,
        max_concurrent_tools=args.concurrent,
        offline_mode=args.offline,
    )

    # Execute pipeline
    runner = PhaseRunner(pipeline_config)
    collector = ResultCollector()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            disable=args.quiet,
        ) as progress:
            main_task = progress.add_task(
                f"[cyan]Scanning {args.target}...",
                total=len(phase_configs),
            )

            # Run each phase
            for phase_config in phase_configs:
                progress.update(main_task, description=f"[cyan]Running {phase_config.name}...")

                phase_report = await runner.run_phase(phase_config.name)

                # Collect findings
                for finding in phase_report.findings:
                    collector.add_finding(finding, phase=phase_config.name)

                progress.advance(main_task)

                # AI Checkpoint
                if args.ai_checkpoints and phase_config.name != phase_configs[-1].name:
                    progress.update(main_task, description="[magenta]AI Checkpoint analysis...")
                    await runner._ai_checkpoint(phase_config.name, phase_report.findings)

        # Generate reports
        if not args.quiet:
            console.print("\n[cyan]Generating reports...[/]")

        _generate_reports(collector, output_dir, args.format)

        # Display summary
        _display_scan_summary(collector, output_dir, args)

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/]")
        await runner.cancel()
        return 130

    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        return 1


def _get_tools_for_phase(
    registry,
    phase,
    args: argparse.Namespace,
) -> List[str]:
    """Get list of tools to use for a phase."""
    # Get available tools for phase
    available_tools = registry.get_tools_by_phase(phase)
    tool_names = [t.name for t in available_tools]

    # Filter by --tools if specified
    if args.tools:
        requested = [t.strip() for t in args.tools.split(",")]
        tool_names = [t for t in tool_names if t in requested]

    # Exclude tools if specified
    if args.exclude_tools:
        excluded = [t.strip() for t in args.exclude_tools.split(",")]
        tool_names = [t for t in tool_names if t not in excluded]

    return tool_names


def _display_scan_banner(
    args: argparse.Namespace,
    phases: List,
    output_dir: Path,
) -> None:
    """Display scan start banner."""
    banner_text = Text()
    banner_text.append("🎯 Target: ", style="cyan")
    banner_text.append(args.target, style="bold white")
    banner_text.append("\n")

    banner_text.append("📋 Phases: ", style="cyan")
    banner_text.append(", ".join(p.value for p in phases), style="white")
    banner_text.append("\n")

    if args.ai_checkpoints:
        banner_text.append("🤖 AI Checkpoints: ", style="cyan")
        banner_text.append(f"Enabled ({args.model})", style="green")
        banner_text.append("\n")

    if args.offline:
        banner_text.append("📴 Mode: ", style="cyan")
        banner_text.append("Offline", style="yellow")
        banner_text.append("\n")

    banner_text.append("📁 Output: ", style="cyan")
    banner_text.append(str(output_dir), style="dim white")

    panel = Panel(
        banner_text,
        title="[bold cyan]🛡️  AIPTX Scan",
        border_style="cyan",
    )
    console.print(panel)
    console.print()


def _display_scan_summary(
    collector,
    output_dir: Path,
    args: argparse.Namespace,
) -> None:
    """Display scan completion summary."""
    stats = collector.get_statistics()
    paths = collector.detect_attack_paths()

    summary_text = Text()
    summary_text.append("✅ Scan Complete\n\n", style="bold green")

    # Finding counts by severity
    summary_text.append("📊 Findings:\n", style="cyan")
    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for severity, count in stats.get("by_severity", {}).items():
        if count > 0:
            color = severity_colors.get(severity.lower(), "white")
            summary_text.append(f"   {severity.upper()}: ", style=color)
            summary_text.append(f"{count}\n", style="bold " + color)

    # Attack paths
    if paths:
        summary_text.append(f"\n⚡ Attack Chains Detected: ", style="magenta")
        summary_text.append(f"{len(paths)}\n", style="bold magenta")

    # Output location
    summary_text.append(f"\n📁 Results saved to: ", style="cyan")
    summary_text.append(str(output_dir), style="bold white")

    panel = Panel(
        summary_text,
        title="[bold green]🛡️  Scan Summary",
        border_style="green",
    )
    console.print()
    console.print(panel)


def _generate_reports(
    collector,
    output_dir: Path,
    format: str,
) -> None:
    """Generate output reports."""
    if format in ["json", "all"]:
        collector.export_json(str(output_dir / "findings.json"))

    if format in ["markdown", "all"]:
        collector.export_markdown(str(output_dir / "findings.md"))

    # Save compact format for LLM
    compact = collector.export_compact()
    (output_dir / "findings_compact.txt").write_text(compact)


# ============================================================================
# Verify Command
# ============================================================================

def add_verify_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'verify' subcommand parser."""
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify system readiness and tool availability",
        description="Check AIPTX installation, tools, and offline data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify all components
  aiptx verify

  # Verify offline mode readiness
  aiptx verify --offline

  # Check specific tools
  aiptx verify --tools nmap,nuclei,sqlmap

  # JSON output for scripting
  aiptx verify --json
        """,
    )

    verify_parser.add_argument(
        "--offline",
        action="store_true",
        help="Verify offline mode readiness (wordlists, databases, Ollama)",
    )

    verify_parser.add_argument(
        "--tools",
        type=str,
        help="Verify specific tools (comma-separated)",
    )

    verify_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output in JSON format",
    )

    verify_parser.add_argument(
        "--fix",
        action="store_true",
        help="Attempt to fix missing components (download data, etc.)",
    )

    verify_parser.set_defaults(func=run_verify_command)


async def run_verify_command(args: argparse.Namespace) -> int:
    """Execute the verify command."""
    from aipt_v2.execution.tool_registry import get_registry, ToolPhase
    from aipt_v2.offline.readiness import OfflineReadinessChecker

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "tools": {},
        "offline": {},
        "ollama": {},
        "overall_ready": True,
    }

    # Check tools
    if not args.json_output:
        console.print("[cyan]Checking security tools...[/]\n")

    registry = get_registry()
    tool_status = await registry.discover_tools()

    # Filter if specific tools requested
    if args.tools:
        requested = [t.strip() for t in args.tools.split(",")]
        tool_status = {k: v for k, v in tool_status.items() if k in requested}

    # Build tool results
    for name, status in tool_status.items():
        results["tools"][name] = {
            "available": status.available,
            "version": status.version,
            "path": status.path,
            "error": status.error,
        }

    if not args.json_output:
        _display_tool_status(tool_status)

    # Check offline mode if requested
    if args.offline:
        if not args.json_output:
            console.print("\n[cyan]Checking offline mode readiness...[/]\n")

        checker = OfflineReadinessChecker()
        offline_status = await checker.check_all()

        results["offline"] = offline_status

        if not args.json_output:
            _display_offline_status(offline_status)

        # Check Ollama
        ollama_status = await _check_ollama()
        results["ollama"] = ollama_status

        if not args.json_output:
            _display_ollama_status(ollama_status)

        # Check if any critical components are missing
        missing_critical = checker.get_missing_critical()
        if missing_critical:
            results["overall_ready"] = False

            if args.fix:
                if not args.json_output:
                    console.print("\n[yellow]Attempting to fix missing components...[/]\n")
                await _fix_offline_components(missing_critical)

    # Overall status
    available_tools = sum(1 for s in tool_status.values() if s.available)
    total_tools = len(tool_status)

    if available_tools == 0:
        results["overall_ready"] = False

    # Output
    if args.json_output:
        print(json.dumps(results, indent=2, default=str))
    else:
        _display_verify_summary(results, available_tools, total_tools)

    return 0 if results["overall_ready"] else 1


def _display_tool_status(tool_status: Dict) -> None:
    """Display tool availability table."""
    table = Table(title="Security Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Version", style="dim")
    table.add_column("Path", style="dim")

    for name, status in sorted(tool_status.items()):
        if status.available:
            status_str = "[green]✓ Available[/]"
        else:
            status_str = "[red]✗ Missing[/]"

        version = status.version[:40] + "..." if status.version and len(status.version) > 40 else (status.version or "-")
        path = status.path or "-"

        table.add_row(name, status_str, version, path)

    console.print(table)


def _display_offline_status(offline_status: Dict) -> None:
    """Display offline data status."""
    table = Table(title="Offline Data")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Size", style="dim")
    table.add_column("Last Updated", style="dim")

    for name, info in offline_status.items():
        if info.get("available"):
            status_str = "[green]✓ Ready[/]"
        elif info.get("critical"):
            status_str = "[red]✗ Missing (Critical)[/]"
        else:
            status_str = "[yellow]○ Missing[/]"

        size = info.get("size", "-")
        updated = info.get("last_updated", "-")

        table.add_row(name, status_str, str(size), str(updated))

    console.print(table)


async def _check_ollama() -> Dict[str, Any]:
    """Check Ollama availability and models."""
    import aiohttp

    result = {
        "available": False,
        "url": "http://localhost:11434",
        "models": [],
        "error": None,
    }

    try:
        async with aiohttp.ClientSession() as session:
            # Check API is up
            async with session.get(f"{result['url']}/api/tags", timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["available"] = True
                    result["models"] = [m["name"] for m in data.get("models", [])]
    except asyncio.TimeoutError:
        result["error"] = "Connection timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def _display_ollama_status(ollama_status: Dict) -> None:
    """Display Ollama status."""
    console.print("\n[bold]Ollama Status:[/]")

    if ollama_status["available"]:
        console.print(f"  [green]✓[/] Ollama is running at {ollama_status['url']}")
        if ollama_status["models"]:
            console.print(f"  [cyan]Models:[/] {', '.join(ollama_status['models'][:5])}")
            if len(ollama_status["models"]) > 5:
                console.print(f"    ... and {len(ollama_status['models']) - 5} more")
        else:
            console.print("  [yellow]No models installed. Run: ollama pull mistral:7b[/]")
    else:
        console.print(f"  [red]✗[/] Ollama not available: {ollama_status.get('error', 'Unknown error')}")
        console.print("    Start Ollama with: ollama serve")


def _display_verify_summary(results: Dict, available: int, total: int) -> None:
    """Display verification summary."""
    summary_text = Text()

    if results["overall_ready"]:
        summary_text.append("✅ System Ready\n\n", style="bold green")
    else:
        summary_text.append("⚠️  System Not Fully Ready\n\n", style="bold yellow")

    summary_text.append(f"Tools: {available}/{total} available\n", style="white")

    if "offline" in results and results["offline"]:
        offline_ready = sum(1 for v in results["offline"].values() if v.get("available"))
        offline_total = len(results["offline"])
        summary_text.append(f"Offline Data: {offline_ready}/{offline_total} ready\n", style="white")

    if "ollama" in results:
        if results["ollama"].get("available"):
            summary_text.append("Ollama: [green]Running[/]\n", style="white")
        else:
            summary_text.append("Ollama: [red]Not Running[/]\n", style="white")

    panel = Panel(
        summary_text,
        title="[bold cyan]Verification Summary",
        border_style="cyan" if results["overall_ready"] else "yellow",
    )
    console.print()
    console.print(panel)


async def _fix_offline_components(missing: List[str]) -> None:
    """Attempt to download missing offline components."""
    from aipt_v2.offline.data_manager import OfflineDataManager

    manager = OfflineDataManager()

    for component in missing:
        console.print(f"[cyan]Downloading {component}...[/]")
        try:
            await manager.download_component(component)
            console.print(f"[green]✓ {component} downloaded[/]")
        except Exception as e:
            console.print(f"[red]✗ Failed to download {component}: {e}[/]")


# ============================================================================
# Tools Command
# ============================================================================

def add_tools_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'tools' subcommand parser."""
    tools_parser = subparsers.add_parser(
        "tools",
        help="List and manage security tools",
        description="View available security tools and their capabilities",
    )

    tools_parser.add_argument(
        "--check",
        action="store_true",
        help="Check tool availability",
    )

    tools_parser.add_argument(
        "--phase",
        type=str,
        choices=["recon", "scan", "exploit", "post_exploit"],
        help="Filter by phase",
    )

    tools_parser.add_argument(
        "--capability",
        type=str,
        help="Filter by capability (e.g., 'sqli_scan', 'xss_scan')",
    )

    tools_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output in JSON format",
    )

    tools_parser.set_defaults(func=run_tools_command)


async def run_tools_command(args: argparse.Namespace) -> int:
    """Execute the tools command."""
    from aipt_v2.execution.tool_registry import (
        get_registry,
        ToolPhase,
        ToolCapability,
        TOOL_REGISTRY,
    )

    registry = get_registry()

    if args.check:
        await registry.discover_tools()

    # Filter tools
    tools = list(TOOL_REGISTRY.values())

    if args.phase:
        phase = ToolPhase(args.phase)
        tools = [t for t in tools if t.phase == phase]

    if args.capability:
        cap = ToolCapability(args.capability)
        tools = [t for t in tools if cap in t.capabilities]

    if args.json_output:
        output = []
        for tool in tools:
            status = registry.get_status(tool.name)
            output.append({
                "name": tool.name,
                "binary": tool.binary,
                "phase": tool.phase.value,
                "capabilities": [c.value for c in tool.capabilities],
                "available": status.available if status else False,
            })
        print(json.dumps(output, indent=2))
    else:
        _display_tools_table(tools, registry)

    return 0


def _display_tools_table(tools: List, registry) -> None:
    """Display tools in a formatted table."""
    table = Table(title="AIPTX Security Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Phase", style="white")
    table.add_column("Capabilities", style="dim")
    table.add_column("Status", style="white")

    for tool in sorted(tools, key=lambda t: (t.phase.value, t.name)):
        status = registry.get_status(tool.name)
        if status and status.available:
            status_str = "[green]✓[/]"
        else:
            status_str = "[red]✗[/]"

        caps = ", ".join(c.value[:15] for c in list(tool.capabilities)[:3])

        table.add_row(
            tool.name,
            tool.phase.value,
            caps,
            status_str,
        )

    console.print(table)


# ============================================================================
# Setup Command
# ============================================================================

def add_setup_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'setup' subcommand parser."""
    setup_parser = subparsers.add_parser(
        "setup",
        help="Setup AIPTX offline data and configuration",
        description="Download wordlists, vulnerability databases, and configure offline mode",
    )

    setup_parser.add_argument(
        "--offline",
        action="store_true",
        help="Setup offline mode (download all required data)",
    )

    setup_parser.add_argument(
        "--wordlists",
        action="store_true",
        help="Download wordlists only",
    )

    setup_parser.add_argument(
        "--databases",
        action="store_true",
        help="Download vulnerability databases only",
    )

    setup_parser.add_argument(
        "--nuclei-templates",
        action="store_true",
        help="Download Nuclei templates",
    )

    setup_parser.add_argument(
        "--data-dir",
        type=str,
        help="Custom data directory (default: ~/.aiptx/data)",
    )

    setup_parser.set_defaults(func=run_setup_command)


async def run_setup_command(args: argparse.Namespace) -> int:
    """Execute the setup command."""
    from aipt_v2.offline.data_manager import OfflineDataManager
    from aipt_v2.offline.wordlists import WordlistManager

    data_dir = Path(args.data_dir) if args.data_dir else Path.home() / ".aiptx" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]Setting up AIPTX data in {data_dir}[/]\n")

    manager = OfflineDataManager(data_path=data_dir)

    if args.offline:
        # Download everything
        components = ["wordlists", "nuclei_templates", "cve_database", "trivy_db"]
    else:
        components = []
        if args.wordlists:
            components.append("wordlists")
        if args.databases:
            components.extend(["cve_database", "trivy_db"])
        if args.nuclei_templates:
            components.append("nuclei_templates")

    if not components:
        console.print("[yellow]No components specified. Use --offline for full setup.[/]")
        return 1

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        for component in components:
            task = progress.add_task(f"[cyan]Downloading {component}...", total=None)
            try:
                await manager.download_component(component)
                progress.update(task, description=f"[green]✓ {component} downloaded")
            except Exception as e:
                progress.update(task, description=f"[red]✗ {component} failed: {e}")

    console.print("\n[green]Setup complete![/]")
    return 0


# ============================================================================
# Main CLI Entry
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="aiptx",
        description="AIPTX - AI-Powered Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  scan      Run penetration testing scan
  verify    Verify system readiness and tools
  tools     List and manage security tools
  setup     Setup offline data and configuration

Examples:
  aiptx scan example.com
  aiptx scan example.com --ai-checkpoints --model mistral:7b
  aiptx verify --offline
  aiptx tools --check
  aiptx setup --offline

For more information on a command:
  aiptx <command> --help
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="AIPTX 2.0.0",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        required=True,
    )

    # Add subcommand parsers
    add_scan_parser(subparsers)
    add_verify_parser(subparsers)
    add_tools_parser(subparsers)
    add_setup_parser(subparsers)

    return parser


def cli_main() -> None:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Run the appropriate command
    if hasattr(args, "func"):
        try:
            exit_code = asyncio.run(args.func(args))
            sys.exit(exit_code)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/]")
            sys.exit(130)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    cli_main()
