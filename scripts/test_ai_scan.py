#!/usr/bin/env python3
"""
AIPTX AI Integration Test Script
=================================

Quick verification that AI-driven scanning is working correctly.
Tests against a target (default: vulnbank.org) and verifies:
1. Tool discovery works
2. AI checkpoints are functional
3. Phase transitions happen correctly
4. Findings are extracted and analyzed

Usage:
    python scripts/test_ai_scan.py
    python scripts/test_ai_scan.py --target http://vulnbank.org
    python scripts/test_ai_scan.py --target http://vulnbank.org --phases recon,scan
"""

import asyncio
import argparse
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


async def check_ollama() -> bool:
    """Check if Ollama is available."""
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:11434/api/version", timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    console.print(f"[green]✓[/] Ollama running: {data.get('version', 'unknown')}")
                    return True
    except Exception as e:
        console.print(f"[yellow]⚠[/] Ollama not available: {e}")
        console.print("   AI checkpoints will use rule-based fallback")
    return False


async def check_tools() -> dict:
    """Check available security tools."""
    from aipt_v2.execution.tool_registry import get_registry, ToolPhase

    registry = get_registry()
    status = await registry.discover_tools()

    available = {k: v for k, v in status.items() if v.available}
    missing = {k: v for k, v in status.items() if not v.available}

    # Display by phase
    table = Table(title="Tool Availability")
    table.add_column("Phase", style="cyan")
    table.add_column("Available", style="green")
    table.add_column("Missing", style="red")

    for phase in ToolPhase:
        phase_tools = [t.name for t in registry.tools.values() if t.phase == phase]
        avail = [t for t in phase_tools if t in available]
        miss = [t for t in phase_tools if t in missing]

        table.add_row(
            phase.value,
            ", ".join(avail[:4]) + ("..." if len(avail) > 4 else ""),
            ", ".join(miss[:3]) + ("..." if len(miss) > 3 else "") if miss else "-"
        )

    console.print(table)
    return {"available": len(available), "missing": len(missing), "tools": available}


async def test_ai_checkpoint(target: str) -> dict:
    """Test AI checkpoint functionality."""
    from aipt_v2.execution.phase_runner import AICheckpointClient, ToolPhase

    client = AICheckpointClient()

    # Simulate recon findings
    test_findings = """TARGET: {target}
FINDINGS: 5 total

[INFO] x3
  [F0001|subdomain|I] api.{target}
  [F0002|port|I] 80/http
  [F0003|port|I] 443/https

[MEDIUM] x2
  [F0004|service|M] Apache/2.4.41
  [F0005|tech|M] PHP/7.4.3
""".format(target=target)

    console.print("\n[cyan]Testing AI Checkpoint...[/]")

    result = await client.analyze_phase(
        phase=ToolPhase.RECON,
        findings_summary=test_findings,
        target=target,
    )

    if result.get("analysis"):
        console.print(f"[green]✓[/] AI Checkpoint working")
        console.print(f"   Source: {'Ollama LLM' if 'Fallback' not in result['analysis'] else 'Rule-based fallback'}")
        if result.get("recommendations"):
            console.print(f"   Recommendations: {len(result['recommendations'])}")
            for rec in result["recommendations"][:3]:
                console.print(f"     - {rec[:60]}...")
        return {"success": True, "source": "llm" if "Fallback" not in result["analysis"] else "fallback"}

    return {"success": False, "error": "No analysis returned"}


async def run_quick_scan(target: str, phases: list) -> dict:
    """Run a quick scan to verify the pipeline."""
    from aipt_v2.execution.phase_runner import PhaseRunner, PipelineConfig, PhaseConfig, ToolPhase

    phase_map = {
        "recon": ToolPhase.RECON,
        "scan": ToolPhase.SCAN,
        "exploit": ToolPhase.EXPLOIT,
    }

    phase_configs = [
        PhaseConfig(phase=phase_map[p], timeout=120, ai_checkpoint=True)
        for p in phases if p in phase_map
    ]

    config = PipelineConfig(
        phases=phase_configs,
        max_parallel_tools=3,
        ai_checkpoints_enabled=True,
    )

    console.print(f"\n[cyan]Running scan against {target}...[/]")
    console.print(f"   Phases: {', '.join(phases)}")

    runner = PhaseRunner(target, config)
    await runner.initialize()

    results = {
        "phases_completed": [],
        "total_findings": 0,
        "critical_findings": 0,
        "attack_paths": 0,
        "ai_recommendations": [],
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for phase_config in phase_configs:
            task = progress.add_task(f"[cyan]Phase: {phase_config.phase.value}...", total=None)

            try:
                report = await runner.run_phase(phase_config.phase, phase_config)

                results["phases_completed"].append({
                    "phase": phase_config.phase.value,
                    "findings": report.findings_count,
                    "critical": report.critical_count,
                    "high": report.high_count,
                    "ai_analysis": bool(report.ai_analysis),
                    "recommendations": report.recommended_actions[:3],
                })

                results["total_findings"] += report.findings_count
                results["critical_findings"] += report.critical_count
                results["ai_recommendations"].extend(report.recommended_actions[:2])

                progress.update(task, description=f"[green]✓ {phase_config.phase.value}: {report.findings_count} findings")

            except Exception as e:
                progress.update(task, description=f"[red]✗ {phase_config.phase.value}: {e}")

    # Check attack paths
    paths = runner.get_results().detect_attack_paths()
    results["attack_paths"] = len(paths)

    return results


async def main():
    parser = argparse.ArgumentParser(description="Test AIPTX AI Integration")
    parser.add_argument("--target", default="http://vulnbank.org", help="Target to scan")
    parser.add_argument("--phases", default="recon", help="Phases to run (comma-separated)")
    parser.add_argument("--skip-scan", action="store_true", help="Skip actual scanning, only test AI")
    args = parser.parse_args()

    phases = [p.strip() for p in args.phases.split(",")]

    console.print(Panel(
        f"[bold cyan]AIPTX AI Integration Test[/]\n\n"
        f"Target: {args.target}\n"
        f"Phases: {', '.join(phases)}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        border_style="cyan",
    ))

    # Step 1: Check Ollama
    console.print("\n[bold]Step 1: Checking Ollama (AI Backend)[/]")
    ollama_ok = await check_ollama()

    # Step 2: Check Tools
    console.print("\n[bold]Step 2: Checking Security Tools[/]")
    tools_result = await check_tools()

    if tools_result["available"] == 0:
        console.print("[red]No security tools available! Install tools first.[/]")
        return 1

    # Step 3: Test AI Checkpoint
    console.print("\n[bold]Step 3: Testing AI Checkpoint[/]")
    ai_result = await test_ai_checkpoint(args.target)

    # Step 4: Run Scan (optional)
    if not args.skip_scan:
        console.print("\n[bold]Step 4: Running Quick Scan[/]")
        try:
            scan_result = await run_quick_scan(args.target, phases)

            # Display results
            summary = Text()
            summary.append("\n✅ Scan Complete\n\n", style="bold green")
            summary.append(f"Phases Completed: {len(scan_result['phases_completed'])}\n")
            summary.append(f"Total Findings: {scan_result['total_findings']}\n")
            summary.append(f"Critical/High: {scan_result['critical_findings']}\n")
            summary.append(f"Attack Paths: {scan_result['attack_paths']}\n")

            if scan_result["ai_recommendations"]:
                summary.append("\nAI Recommendations:\n", style="cyan")
                for rec in scan_result["ai_recommendations"][:5]:
                    summary.append(f"  • {rec[:70]}...\n" if len(rec) > 70 else f"  • {rec}\n")

            console.print(Panel(summary, title="[green]Scan Results", border_style="green"))

        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/]")
            import traceback
            console.print(traceback.format_exc())

    # Final Summary
    console.print("\n[bold]Summary:[/]")
    console.print(f"  Ollama: {'[green]✓[/]' if ollama_ok else '[yellow]⚠ Fallback mode[/]'}")
    console.print(f"  Tools: [green]{tools_result['available']}[/] available")
    console.print(f"  AI Checkpoint: {'[green]✓[/]' if ai_result['success'] else '[red]✗[/]'}")

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
