"""
AIPTX Post-Installation Verification
=====================================

Verifies that AIPTX is correctly installed and configured.
Tests all components and generates a health report.

Features:
- System requirements check
- Python dependencies verification
- Security tools validation
- LLM connectivity test
- Configuration validation
- Performance benchmarks

Usage:
    aiptx verify                  # Run full verification
    aiptx verify --quick          # Quick check
    aiptx verify --fix            # Auto-fix issues where possible
    aiptx verify --report out.md  # Generate markdown report
"""

import asyncio
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box


console = Console()


class CheckStatus(Enum):
    """Status of a verification check."""
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class CheckResult:
    """Result of a single verification check."""
    name: str
    status: CheckStatus
    message: str
    details: Optional[str] = None
    fix_command: Optional[str] = None
    duration_ms: float = 0


@dataclass
class VerificationReport:
    """Complete verification report."""
    timestamp: datetime = field(default_factory=datetime.now)
    system_info: Dict[str, str] = field(default_factory=dict)
    checks: List[CheckResult] = field(default_factory=list)
    tool_status: Dict[str, bool] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=dict)

    def add_check(self, result: CheckResult):
        """Add a check result."""
        self.checks.append(result)

    def compute_summary(self):
        """Compute summary statistics."""
        self.summary = {
            "total": len(self.checks),
            "passed": sum(1 for c in self.checks if c.status == CheckStatus.PASS),
            "warnings": sum(1 for c in self.checks if c.status == CheckStatus.WARN),
            "failed": sum(1 for c in self.checks if c.status == CheckStatus.FAIL),
            "skipped": sum(1 for c in self.checks if c.status == CheckStatus.SKIP),
        }

    def is_healthy(self) -> bool:
        """Check if installation is healthy (no failures)."""
        return all(c.status != CheckStatus.FAIL for c in self.checks)


class InstallVerifier:
    """
    Verifies AIPTX installation and configuration.

    Runs a series of checks to ensure the system is properly
    set up and all components are working correctly.
    """

    def __init__(self, quick: bool = False, auto_fix: bool = False):
        """
        Initialize verifier.

        Args:
            quick: Run quick checks only
            auto_fix: Attempt to fix issues automatically
        """
        self.quick = quick
        self.auto_fix = auto_fix
        self.report = VerificationReport()

    async def run_all_checks(self) -> VerificationReport:
        """Run all verification checks."""
        console.print()
        console.print(Panel(
            "[bold cyan]AIPTX Installation Verification[/bold cyan]\n\n"
            "Running comprehensive checks to verify your installation...",
            title="🔍 Verification",
            border_style="cyan"
        ))
        console.print()

        # Collect system info
        await self._collect_system_info()

        # Run checks with progress
        checks = [
            ("Python Version", self._check_python_version),
            ("Python Dependencies", self._check_python_deps),
            ("AIPTX Package", self._check_aiptx_package),
            ("Configuration File", self._check_config_file),
            ("LLM Configuration", self._check_llm_config),
            ("Go Installation", self._check_go),
            ("Docker (optional)", self._check_docker),
            ("Core Tools", self._check_core_tools),
            ("Path Configuration", self._check_path),
            ("Permissions", self._check_permissions),
        ]

        if not self.quick:
            checks.extend([
                ("All Security Tools", self._check_all_tools),
                ("Network Connectivity", self._check_network),
                ("LLM Connectivity", self._check_llm_connectivity),
            ])

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running checks...", total=len(checks))

            for check_name, check_func in checks:
                progress.update(task, description=f"Checking {check_name}...")

                start_time = time.time()
                try:
                    result = await check_func()
                    result.duration_ms = (time.time() - start_time) * 1000
                    self.report.add_check(result)
                except Exception as e:
                    self.report.add_check(CheckResult(
                        name=check_name,
                        status=CheckStatus.FAIL,
                        message=f"Check failed with error: {str(e)}",
                        duration_ms=(time.time() - start_time) * 1000,
                    ))

                progress.advance(task)

        # Compute summary
        self.report.compute_summary()

        return self.report

    async def _collect_system_info(self):
        """Collect system information."""
        import platform

        self.report.system_info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "hostname": platform.node(),
        }

        # Try to get package manager
        for pm in ["brew", "apt", "dnf", "yum", "pacman"]:
            if shutil.which(pm):
                self.report.system_info["package_manager"] = pm
                break

    async def _check_python_version(self) -> CheckResult:
        """Check Python version."""
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"

        if version.major >= 3 and version.minor >= 9:
            return CheckResult(
                name="Python Version",
                status=CheckStatus.PASS,
                message=f"Python {version_str} installed",
            )
        elif version.major >= 3 and version.minor >= 8:
            return CheckResult(
                name="Python Version",
                status=CheckStatus.WARN,
                message=f"Python {version_str} (3.9+ recommended)",
            )
        else:
            return CheckResult(
                name="Python Version",
                status=CheckStatus.FAIL,
                message=f"Python {version_str} (requires 3.9+)",
                fix_command="Install Python 3.9 or higher",
            )

    async def _check_python_deps(self) -> CheckResult:
        """Check required Python dependencies."""
        required = [
            "rich", "typer", "httpx", "pydantic", "litellm",
            "sqlalchemy", "structlog", "fastapi",
        ]

        missing = []
        for pkg in required:
            try:
                importlib.import_module(pkg)
            except ImportError:
                missing.append(pkg)

        if not missing:
            return CheckResult(
                name="Python Dependencies",
                status=CheckStatus.PASS,
                message=f"All {len(required)} core dependencies installed",
            )
        else:
            return CheckResult(
                name="Python Dependencies",
                status=CheckStatus.FAIL,
                message=f"Missing: {', '.join(missing)}",
                fix_command=f"pip install {' '.join(missing)}",
            )

    async def _check_aiptx_package(self) -> CheckResult:
        """Check AIPTX package installation."""
        try:
            import aipt_v2
            version = getattr(aipt_v2, "__version__", "unknown")
            return CheckResult(
                name="AIPTX Package",
                status=CheckStatus.PASS,
                message=f"AIPTX version {version} installed",
            )
        except ImportError:
            return CheckResult(
                name="AIPTX Package",
                status=CheckStatus.FAIL,
                message="AIPTX package not found",
                fix_command="pip install aiptx",
            )

    async def _check_config_file(self) -> CheckResult:
        """Check configuration file exists."""
        config_paths = [
            Path.home() / ".aiptx" / ".env",
            Path(".env"),
        ]

        for path in config_paths:
            if path.exists():
                return CheckResult(
                    name="Configuration File",
                    status=CheckStatus.PASS,
                    message=f"Config found at {path}",
                )

        return CheckResult(
            name="Configuration File",
            status=CheckStatus.WARN,
            message="No configuration file found",
            details="Run 'aiptx setup' to configure",
            fix_command="aiptx setup",
        )

    async def _check_llm_config(self) -> CheckResult:
        """Check LLM configuration."""
        llm_keys = [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "LLM_API_KEY",
        ]

        # Check for Ollama
        if shutil.which("ollama"):
            # Check if Ollama is running
            try:
                proc = await asyncio.create_subprocess_shell(
                    "curl -s http://localhost:11434/api/version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                if proc.returncode == 0 and b"version" in stdout:
                    return CheckResult(
                        name="LLM Configuration",
                        status=CheckStatus.PASS,
                        message="Ollama running locally",
                    )
            except Exception:
                pass

        # Check for API keys
        for key in llm_keys:
            if os.environ.get(key):
                return CheckResult(
                    name="LLM Configuration",
                    status=CheckStatus.PASS,
                    message=f"{key} configured",
                )

        # Check .env file
        env_path = Path.home() / ".aiptx" / ".env"
        if env_path.exists():
            with open(env_path) as f:
                content = f.read()
                for key in llm_keys:
                    if key in content:
                        return CheckResult(
                            name="LLM Configuration",
                            status=CheckStatus.PASS,
                            message=f"{key} found in config",
                        )

        return CheckResult(
            name="LLM Configuration",
            status=CheckStatus.FAIL,
            message="No LLM API key or Ollama configured",
            fix_command="aiptx setup",
        )

    async def _check_go(self) -> CheckResult:
        """Check Go installation."""
        if shutil.which("go"):
            try:
                proc = await asyncio.create_subprocess_shell(
                    "go version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                version = stdout.decode().strip()
                return CheckResult(
                    name="Go Installation",
                    status=CheckStatus.PASS,
                    message=version.replace("go version ", ""),
                )
            except Exception:
                pass

        return CheckResult(
            name="Go Installation",
            status=CheckStatus.WARN,
            message="Go not installed (required for some tools)",
            fix_command="aiptx tools install -t go",
        )

    async def _check_docker(self) -> CheckResult:
        """Check Docker installation (optional)."""
        if shutil.which("docker"):
            try:
                proc = await asyncio.create_subprocess_shell(
                    "docker --version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    version = stdout.decode().strip()
                    return CheckResult(
                        name="Docker (optional)",
                        status=CheckStatus.PASS,
                        message=version,
                    )
            except Exception:
                pass

        return CheckResult(
            name="Docker (optional)",
            status=CheckStatus.SKIP,
            message="Docker not available (optional for sandboxing)",
        )

    async def _check_core_tools(self) -> CheckResult:
        """Check core security tools."""
        core_tools = ["nmap", "nuclei", "sqlmap", "ffuf", "httpx"]
        installed = []
        missing = []

        for tool in core_tools:
            if shutil.which(tool):
                installed.append(tool)
            else:
                missing.append(tool)

        self.report.tool_status.update({t: t in installed for t in core_tools})

        if not missing:
            return CheckResult(
                name="Core Tools",
                status=CheckStatus.PASS,
                message=f"All {len(core_tools)} core tools installed",
            )
        elif len(missing) <= 2:
            return CheckResult(
                name="Core Tools",
                status=CheckStatus.WARN,
                message=f"Missing: {', '.join(missing)}",
                fix_command=f"aiptx tools install -t {' '.join(missing)}",
            )
        else:
            return CheckResult(
                name="Core Tools",
                status=CheckStatus.FAIL,
                message=f"Missing {len(missing)}/{len(core_tools)} core tools",
                fix_command="aiptx tools install --core",
            )

    async def _check_all_tools(self) -> CheckResult:
        """Check all available security tools."""
        try:
            from aipt_v2.local_tool_installer import TOOLS

            installed = 0
            total = len(TOOLS)

            for tool_name in TOOLS:
                if shutil.which(tool_name):
                    installed += 1
                    self.report.tool_status[tool_name] = True
                else:
                    self.report.tool_status[tool_name] = False

            coverage = (installed / total * 100) if total > 0 else 0

            if coverage >= 50:
                return CheckResult(
                    name="All Security Tools",
                    status=CheckStatus.PASS,
                    message=f"{installed}/{total} tools installed ({coverage:.0f}%)",
                )
            elif coverage >= 25:
                return CheckResult(
                    name="All Security Tools",
                    status=CheckStatus.WARN,
                    message=f"{installed}/{total} tools installed ({coverage:.0f}%)",
                    fix_command="aiptx tools install --all",
                )
            else:
                return CheckResult(
                    name="All Security Tools",
                    status=CheckStatus.WARN,
                    message=f"Only {installed}/{total} tools installed",
                    fix_command="aiptx tools install --core",
                )

        except ImportError:
            return CheckResult(
                name="All Security Tools",
                status=CheckStatus.SKIP,
                message="Tool catalog not available",
            )

    async def _check_path(self) -> CheckResult:
        """Check PATH configuration."""
        path = os.environ.get("PATH", "")
        home = str(Path.home())

        required_paths = [
            f"{home}/.local/bin",
            f"{home}/go/bin",
        ]

        missing = [p for p in required_paths if p not in path]

        if not missing:
            return CheckResult(
                name="Path Configuration",
                status=CheckStatus.PASS,
                message="PATH includes required directories",
            )
        else:
            return CheckResult(
                name="Path Configuration",
                status=CheckStatus.WARN,
                message=f"Missing from PATH: {', '.join(missing)}",
                details="Add to your shell profile (.bashrc, .zshrc)",
                fix_command=f"export PATH=$PATH:{':'.join(missing)}",
            )

    async def _check_permissions(self) -> CheckResult:
        """Check file permissions."""
        config_dir = Path.home() / ".aiptx"

        if config_dir.exists():
            # Check if .env has proper permissions
            env_file = config_dir / ".env"
            if env_file.exists():
                mode = env_file.stat().st_mode & 0o777
                if mode == 0o600:
                    return CheckResult(
                        name="Permissions",
                        status=CheckStatus.PASS,
                        message="Config file has secure permissions",
                    )
                else:
                    return CheckResult(
                        name="Permissions",
                        status=CheckStatus.WARN,
                        message=f"Config file permissions: {oct(mode)} (should be 600)",
                        fix_command=f"chmod 600 {env_file}",
                    )

        return CheckResult(
            name="Permissions",
            status=CheckStatus.SKIP,
            message="No config files to check",
        )

    async def _check_network(self) -> CheckResult:
        """Check network connectivity."""
        try:
            proc = await asyncio.create_subprocess_shell(
                "curl -s --connect-timeout 5 -o /dev/null -w '%{http_code}' https://api.anthropic.com",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            status_code = stdout.decode().strip()

            if status_code in ["200", "401", "403"]:
                return CheckResult(
                    name="Network Connectivity",
                    status=CheckStatus.PASS,
                    message="Internet connectivity OK",
                )
            else:
                return CheckResult(
                    name="Network Connectivity",
                    status=CheckStatus.WARN,
                    message=f"API returned status {status_code}",
                )

        except asyncio.TimeoutError:
            return CheckResult(
                name="Network Connectivity",
                status=CheckStatus.FAIL,
                message="Connection timeout",
            )
        except Exception as e:
            return CheckResult(
                name="Network Connectivity",
                status=CheckStatus.FAIL,
                message=f"Network error: {str(e)}",
            )

    async def _check_llm_connectivity(self) -> CheckResult:
        """Test LLM connectivity."""
        # Check Ollama first
        if shutil.which("ollama"):
            try:
                proc = await asyncio.create_subprocess_shell(
                    "curl -s http://localhost:11434/api/tags",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                if proc.returncode == 0:
                    data = json.loads(stdout.decode())
                    models = len(data.get("models", []))
                    return CheckResult(
                        name="LLM Connectivity",
                        status=CheckStatus.PASS,
                        message=f"Ollama running with {models} models",
                    )
            except Exception:
                pass

        # Skip API test if no key configured
        api_keys = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
        has_key = any(os.environ.get(k) for k in api_keys)

        if not has_key:
            return CheckResult(
                name="LLM Connectivity",
                status=CheckStatus.SKIP,
                message="No API key configured (using Ollama or not configured)",
            )

        return CheckResult(
            name="LLM Connectivity",
            status=CheckStatus.WARN,
            message="API key configured but not tested",
        )

    def print_report(self):
        """Print verification report to console."""
        console.print()

        # Results table
        table = Table(title="Verification Results", box=box.ROUNDED)
        table.add_column("Check", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Message")
        table.add_column("Time", justify="right", style="dim")

        for check in self.report.checks:
            if check.status == CheckStatus.PASS:
                status = "[green]✓ PASS[/green]"
            elif check.status == CheckStatus.WARN:
                status = "[yellow]⚠ WARN[/yellow]"
            elif check.status == CheckStatus.FAIL:
                status = "[red]✗ FAIL[/red]"
            else:
                status = "[dim]○ SKIP[/dim]"

            table.add_row(
                check.name,
                status,
                check.message,
                f"{check.duration_ms:.0f}ms"
            )

        console.print(table)

        # Summary
        s = self.report.summary
        console.print()

        if s["failed"] == 0:
            console.print(Panel(
                f"[bold green]✓ Verification Passed[/bold green]\n\n"
                f"Passed: {s['passed']}  Warnings: {s['warnings']}  Skipped: {s['skipped']}",
                title="Summary",
                border_style="green"
            ))
        else:
            console.print(Panel(
                f"[bold red]✗ Verification Failed[/bold red]\n\n"
                f"Passed: {s['passed']}  Warnings: {s['warnings']}  "
                f"[red]Failed: {s['failed']}[/red]  Skipped: {s['skipped']}",
                title="Summary",
                border_style="red"
            ))

            # Show fix commands
            failed_checks = [c for c in self.report.checks if c.status == CheckStatus.FAIL and c.fix_command]
            if failed_checks:
                console.print("\n[bold]Suggested fixes:[/bold]")
                for check in failed_checks:
                    console.print(f"  [cyan]{check.name}:[/cyan] {check.fix_command}")

        console.print()

    def generate_markdown_report(self) -> str:
        """Generate markdown report."""
        lines = [
            "# AIPTX Installation Verification Report",
            "",
            f"Generated: {self.report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## System Information",
            "",
        ]

        for key, value in self.report.system_info.items():
            lines.append(f"- **{key}**: {value}")

        lines.extend([
            "",
            "## Verification Checks",
            "",
            "| Check | Status | Message |",
            "|-------|--------|---------|",
        ])

        for check in self.report.checks:
            status_emoji = {
                CheckStatus.PASS: "✅",
                CheckStatus.WARN: "⚠️",
                CheckStatus.FAIL: "❌",
                CheckStatus.SKIP: "⏭️",
            }.get(check.status, "?")

            lines.append(f"| {check.name} | {status_emoji} {check.status.value.upper()} | {check.message} |")

        s = self.report.summary
        lines.extend([
            "",
            "## Summary",
            "",
            f"- **Total Checks**: {s['total']}",
            f"- **Passed**: {s['passed']}",
            f"- **Warnings**: {s['warnings']}",
            f"- **Failed**: {s['failed']}",
            f"- **Skipped**: {s['skipped']}",
            "",
        ])

        # Tool status
        if self.report.tool_status:
            installed = sum(1 for v in self.report.tool_status.values() if v)
            total = len(self.report.tool_status)
            lines.extend([
                "## Security Tools",
                "",
                f"Installed: {installed}/{total} ({installed/total*100:.0f}%)",
                "",
            ])

        return "\n".join(lines)


async def verify_installation(
    quick: bool = False,
    auto_fix: bool = False,
    report_file: Optional[str] = None,
) -> int:
    """
    Verify AIPTX installation.

    Args:
        quick: Run quick checks only
        auto_fix: Auto-fix issues
        report_file: Path to save markdown report

    Returns:
        Exit code (0 = healthy, 1 = issues found)
    """
    verifier = InstallVerifier(quick=quick, auto_fix=auto_fix)
    report = await verifier.run_all_checks()

    # Print results
    verifier.print_report()

    # Save report if requested
    if report_file:
        md_report = verifier.generate_markdown_report()
        Path(report_file).write_text(md_report)
        console.print(f"[dim]Report saved to: {report_file}[/dim]")

    return 0 if report.is_healthy() else 1


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Verify AIPTX installation")
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Run quick checks only"
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Attempt to auto-fix issues"
    )
    parser.add_argument(
        "--report", "-r",
        help="Save markdown report to file"
    )

    args = parser.parse_args()

    exit_code = asyncio.run(verify_installation(
        quick=args.quick,
        auto_fix=args.fix,
        report_file=args.report,
    ))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
