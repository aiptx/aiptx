"""
AIPTX Enterprise Prerequisites Checker
======================================

Comprehensive system requirements validation for enterprise deployments.
Checks all dependencies, configurations, and system capabilities before
allowing security operations.

Features:
- Core dependency validation (Python, packages)
- Optional dependency checks (ML, browser automation)
- LLM API key validation
- Security tool availability checks
- System resource verification
- Interactive mode with guided remediation
- Machine-readable exit codes for CI/CD

Usage:
    # CLI
    aiptx check              # Interactive check
    aiptx check --strict     # Fail on warnings
    aiptx check --json       # JSON output for CI/CD

    # Programmatic
    from aipt_v2.prerequisites import PrerequisitesChecker
    checker = PrerequisitesChecker()
    result = await checker.check_all()
"""

import asyncio
import importlib
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.tree import Tree
from rich.text import Text


console = Console()


class CheckStatus(Enum):
    """Status of a prerequisite check."""
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"


class CheckCategory(Enum):
    """Category of prerequisite checks."""
    CORE = "core"           # Required for basic operation
    LLM = "llm"             # LLM/AI functionality
    SECURITY_TOOLS = "tools"  # Security scanning tools
    OPTIONAL = "optional"   # Enhanced features
    SYSTEM = "system"       # System resources


@dataclass
class CheckResult:
    """Result of a single prerequisite check."""
    name: str
    status: CheckStatus
    category: CheckCategory
    message: str
    details: Optional[str] = None
    remediation: Optional[str] = None
    version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "category": self.category.value,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
            "version": self.version,
        }


@dataclass
class PrerequisitesReport:
    """Complete prerequisites check report."""
    checks: List[CheckResult] = field(default_factory=list)
    system_info: Dict[str, str] = field(default_factory=dict)
    timestamp: str = ""

    @property
    def passed(self) -> List[CheckResult]:
        return [c for c in self.checks if c.status == CheckStatus.PASSED]

    @property
    def warnings(self) -> List[CheckResult]:
        return [c for c in self.checks if c.status == CheckStatus.WARNING]

    @property
    def failures(self) -> List[CheckResult]:
        return [c for c in self.checks if c.status == CheckStatus.FAILED]

    @property
    def core_failures(self) -> List[CheckResult]:
        return [c for c in self.failures if c.category == CheckCategory.CORE]

    @property
    def is_ready(self) -> bool:
        """Check if system is ready for basic operation."""
        return len(self.core_failures) == 0

    @property
    def is_fully_ready(self) -> bool:
        """Check if system is ready with all features."""
        return len(self.failures) == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_info": self.system_info,
            "timestamp": self.timestamp,
            "summary": {
                "total": len(self.checks),
                "passed": len(self.passed),
                "warnings": len(self.warnings),
                "failures": len(self.failures),
                "is_ready": self.is_ready,
                "is_fully_ready": self.is_fully_ready,
            },
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class PrerequisitesChecker:
    """
    Enterprise-level prerequisites checker for AIPTX.

    Performs comprehensive validation of system requirements,
    dependencies, and configurations before allowing security
    operations to proceed.
    """

    # Minimum Python version required
    MIN_PYTHON_VERSION = (3, 9)

    # Core packages required for basic operation
    CORE_PACKAGES = [
        ("litellm", ">=1.50.0", "LLM integration"),
        ("rich", ">=13.0.0", "Terminal UI"),
        ("click", ">=8.0.0", "CLI framework"),
        ("pydantic", ">=2.0.0", "Data validation"),
        ("requests", ">=2.31.0", "HTTP client"),
        ("pyyaml", ">=6.0", "YAML parsing"),
    ]

    # Optional packages for enhanced features
    OPTIONAL_PACKAGES = [
        ("numpy", ">=1.24.0", "ML/embeddings support"),
        ("torch", ">=2.0.0", "Deep learning"),
        ("sentence_transformers", ">=2.2.0", "Text embeddings"),
        ("playwright", ">=1.40.0", "Browser automation"),
        ("langchain_core", ">=0.1.0", "LangChain integration"),
        ("asyncssh", ">=2.14.0", "VPS/SSH support"),
        ("docker", ">=7.0.0", "Docker integration"),
    ]

    # Security tools to check
    SECURITY_TOOLS = [
        ("nmap", "Network scanner"),
        ("nuclei", "Vulnerability scanner"),
        ("sqlmap", "SQL injection tool"),
        ("nikto", "Web server scanner"),
        ("gobuster", "Directory bruteforcer"),
        ("ffuf", "Web fuzzer"),
        ("subfinder", "Subdomain finder"),
        ("httpx", "HTTP toolkit"),
        ("amass", "Asset discovery"),
    ]

    # LLM providers and their env vars
    LLM_PROVIDERS = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "google": "GOOGLE_API_KEY",
        "azure": "AZURE_OPENAI_API_KEY",
    }

    def __init__(self, verbose: bool = False):
        """
        Initialize the prerequisites checker.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.report = PrerequisitesReport()

    async def check_all(self, include_optional: bool = True) -> PrerequisitesReport:
        """
        Run all prerequisite checks.

        Args:
            include_optional: Include optional dependency checks

        Returns:
            PrerequisitesReport with all check results
        """
        from datetime import datetime

        self.report = PrerequisitesReport()
        self.report.timestamp = datetime.now().isoformat()
        self.report.system_info = self._get_system_info()

        # Run checks in order of importance
        await self._check_python_version()
        await self._check_core_packages()
        await self._check_llm_configuration()
        await self._check_security_tools()

        if include_optional:
            await self._check_optional_packages()
            await self._check_system_resources()

        return self.report

    def _get_system_info(self) -> Dict[str, str]:
        """Gather system information."""
        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "platform_release": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "hostname": platform.node(),
            "processor": platform.processor() or "Unknown",
        }

    async def _check_python_version(self):
        """Check Python version meets minimum requirements."""
        current = sys.version_info[:2]
        min_ver = self.MIN_PYTHON_VERSION

        if current >= min_ver:
            self.report.checks.append(CheckResult(
                name="Python Version",
                status=CheckStatus.PASSED,
                category=CheckCategory.CORE,
                message=f"Python {current[0]}.{current[1]} meets requirements",
                version=f"{current[0]}.{current[1]}",
            ))
        else:
            self.report.checks.append(CheckResult(
                name="Python Version",
                status=CheckStatus.FAILED,
                category=CheckCategory.CORE,
                message=f"Python {current[0]}.{current[1]} is below minimum {min_ver[0]}.{min_ver[1]}",
                remediation=f"Upgrade Python to version {min_ver[0]}.{min_ver[1]} or higher",
                version=f"{current[0]}.{current[1]}",
            ))

    async def _check_core_packages(self):
        """Check core package dependencies."""
        for package, version_req, description in self.CORE_PACKAGES:
            result = self._check_package(package, version_req, description, CheckCategory.CORE)
            self.report.checks.append(result)

    async def _check_optional_packages(self):
        """Check optional package dependencies."""
        for package, version_req, description in self.OPTIONAL_PACKAGES:
            result = self._check_package(package, version_req, description, CheckCategory.OPTIONAL)
            self.report.checks.append(result)

    def _check_package(
        self,
        package: str,
        version_req: str,
        description: str,
        category: CheckCategory
    ) -> CheckResult:
        """
        Check if a Python package is installed.

        Args:
            package: Package name
            version_req: Version requirement string
            description: Package description
            category: Check category

        Returns:
            CheckResult
        """
        try:
            # Handle package name variations (underscores vs hyphens)
            import_name = package.replace("-", "_")
            mod = importlib.import_module(import_name)

            # Try to get version
            version = getattr(mod, "__version__", None)
            if version is None:
                try:
                    from importlib.metadata import version as get_version
                    version = get_version(package)
                except Exception:
                    version = "unknown"

            return CheckResult(
                name=f"{package}",
                status=CheckStatus.PASSED,
                category=category,
                message=f"{description} - installed",
                version=str(version),
            )

        except ImportError:
            # Determine remediation based on category
            if category == CheckCategory.CORE:
                remediation = f"pip install {package}{version_req}"
            else:
                remediation = f"pip install aiptx[full] or pip install {package}"

            status = CheckStatus.FAILED if category == CheckCategory.CORE else CheckStatus.WARNING

            return CheckResult(
                name=f"{package}",
                status=status,
                category=category,
                message=f"{description} - not installed",
                remediation=remediation,
            )

    async def _check_llm_configuration(self):
        """Check LLM API key configuration."""
        found_providers = []

        for provider, env_var in self.LLM_PROVIDERS.items():
            if os.getenv(env_var):
                found_providers.append(provider)

        if found_providers:
            self.report.checks.append(CheckResult(
                name="LLM API Key",
                status=CheckStatus.PASSED,
                category=CheckCategory.LLM,
                message=f"API key configured for: {', '.join(found_providers)}",
                details=f"Found keys for: {', '.join(found_providers)}",
            ))
        else:
            env_vars = ", ".join(self.LLM_PROVIDERS.values())
            self.report.checks.append(CheckResult(
                name="LLM API Key",
                status=CheckStatus.FAILED,
                category=CheckCategory.LLM,
                message="No LLM API key configured",
                details="AI-powered features require an API key",
                remediation=f"Set one of: {env_vars}\nOr run: aiptx setup",
            ))

        # Check for config file
        config_file = Path.home() / ".aiptx" / ".env"
        if config_file.exists():
            self.report.checks.append(CheckResult(
                name="AIPTX Config",
                status=CheckStatus.PASSED,
                category=CheckCategory.LLM,
                message="Configuration file found",
                details=str(config_file),
            ))
        else:
            self.report.checks.append(CheckResult(
                name="AIPTX Config",
                status=CheckStatus.WARNING,
                category=CheckCategory.LLM,
                message="No configuration file found",
                remediation="Run: aiptx setup",
            ))

    async def _check_security_tools(self):
        """Check security tool availability."""
        installed = []
        missing = []

        for tool, description in self.SECURITY_TOOLS:
            if shutil.which(tool):
                installed.append(tool)
                self.report.checks.append(CheckResult(
                    name=f"Tool: {tool}",
                    status=CheckStatus.PASSED,
                    category=CheckCategory.SECURITY_TOOLS,
                    message=f"{description} - available",
                ))
            else:
                missing.append(tool)
                self.report.checks.append(CheckResult(
                    name=f"Tool: {tool}",
                    status=CheckStatus.WARNING,
                    category=CheckCategory.SECURITY_TOOLS,
                    message=f"{description} - not installed",
                    remediation=f"aiptx tools install -t {tool}",
                ))

        # Summary check
        if len(installed) >= 3:
            status = CheckStatus.PASSED
            message = f"{len(installed)} security tools available"
        elif len(installed) >= 1:
            status = CheckStatus.WARNING
            message = f"Only {len(installed)} security tools available"
        else:
            status = CheckStatus.FAILED
            message = "No security tools installed"

        self.report.checks.append(CheckResult(
            name="Security Tools Summary",
            status=status,
            category=CheckCategory.SECURITY_TOOLS,
            message=message,
            details=f"Installed: {', '.join(installed) if installed else 'None'}",
            remediation="aiptx tools install" if status != CheckStatus.PASSED else None,
        ))

    async def _check_system_resources(self):
        """Check system resource availability."""
        import psutil

        # Memory check
        memory = psutil.virtual_memory()
        total_gb = memory.total / (1024 ** 3)
        available_gb = memory.available / (1024 ** 3)

        if available_gb >= 2:
            status = CheckStatus.PASSED
            message = f"{available_gb:.1f} GB available"
        elif available_gb >= 1:
            status = CheckStatus.WARNING
            message = f"Low memory: {available_gb:.1f} GB available"
        else:
            status = CheckStatus.FAILED
            message = f"Very low memory: {available_gb:.1f} GB available"

        self.report.checks.append(CheckResult(
            name="System Memory",
            status=status,
            category=CheckCategory.SYSTEM,
            message=message,
            details=f"Total: {total_gb:.1f} GB, Available: {available_gb:.1f} GB",
        ))

        # Disk space check
        disk = psutil.disk_usage(str(Path.home()))
        free_gb = disk.free / (1024 ** 3)

        if free_gb >= 5:
            status = CheckStatus.PASSED
            message = f"{free_gb:.1f} GB free disk space"
        elif free_gb >= 1:
            status = CheckStatus.WARNING
            message = f"Low disk space: {free_gb:.1f} GB free"
        else:
            status = CheckStatus.FAILED
            message = f"Very low disk space: {free_gb:.1f} GB free"

        self.report.checks.append(CheckResult(
            name="Disk Space",
            status=status,
            category=CheckCategory.SYSTEM,
            message=message,
            details=f"Free: {free_gb:.1f} GB",
        ))

    def print_report(self, show_passed: bool = True):
        """
        Print a formatted report to the console.

        Args:
            show_passed: Whether to show passed checks
        """
        # Header
        console.print()
        console.print(Panel.fit(
            "[bold cyan]AIPTX Prerequisites Check[/bold cyan]\n"
            "[dim]Enterprise System Validation[/dim]",
            border_style="cyan",
        ))

        # System info
        console.print("\n[bold]System Information[/bold]")
        info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        info_table.add_column("Property", style="dim")
        info_table.add_column("Value", style="green")

        info = self.report.system_info
        info_table.add_row("Platform", f"{info.get('platform', 'Unknown')} {info.get('platform_release', '')}")
        info_table.add_row("Architecture", info.get("architecture", "Unknown"))
        info_table.add_row("Python", info.get("python_version", "Unknown"))

        console.print(info_table)

        # Results by category
        categories = [
            (CheckCategory.CORE, "Core Requirements", "red"),
            (CheckCategory.LLM, "LLM Configuration", "yellow"),
            (CheckCategory.SECURITY_TOOLS, "Security Tools", "blue"),
            (CheckCategory.OPTIONAL, "Optional Features", "dim"),
            (CheckCategory.SYSTEM, "System Resources", "magenta"),
        ]

        for category, title, color in categories:
            checks = [c for c in self.report.checks if c.category == category]
            if not checks:
                continue

            console.print(f"\n[bold {color}]{title}[/bold {color}]")

            table = Table(box=box.ROUNDED, show_header=True, padding=(0, 1))
            table.add_column("Check", style="cyan", min_width=20)
            table.add_column("Status", justify="center", min_width=8)
            table.add_column("Details", min_width=30)
            table.add_column("Remediation", style="dim", min_width=25)

            for check in checks:
                if check.status == CheckStatus.PASSED and not show_passed:
                    continue

                # Status indicator
                if check.status == CheckStatus.PASSED:
                    status = "[green]✓ PASS[/green]"
                elif check.status == CheckStatus.WARNING:
                    status = "[yellow]⚠ WARN[/yellow]"
                elif check.status == CheckStatus.FAILED:
                    status = "[red]✗ FAIL[/red]"
                else:
                    status = "[dim]○ SKIP[/dim]"

                # Version suffix
                name = check.name
                if check.version:
                    name = f"{name} [dim]v{check.version}[/dim]"

                table.add_row(
                    name,
                    status,
                    check.message,
                    check.remediation or "",
                )

            console.print(table)

        # Summary
        console.print()
        self._print_summary()

    def _print_summary(self):
        """Print the results summary."""
        total = len(self.report.checks)
        passed = len(self.report.passed)
        warnings = len(self.report.warnings)
        failures = len(self.report.failures)

        if self.report.is_fully_ready:
            status_panel = Panel(
                "[bold green]✓ All checks passed![/bold green]\n"
                "[dim]System is fully ready for all AIPTX operations[/dim]",
                title="Status",
                border_style="green",
            )
        elif self.report.is_ready:
            status_panel = Panel(
                "[bold yellow]⚠ Ready with warnings[/bold yellow]\n"
                f"[dim]{warnings} warning(s) - some features may be limited[/dim]",
                title="Status",
                border_style="yellow",
            )
        else:
            status_panel = Panel(
                "[bold red]✗ Not ready[/bold red]\n"
                f"[dim]{len(self.report.core_failures)} critical issue(s) must be resolved[/dim]",
                title="Status",
                border_style="red",
            )

        console.print(status_panel)

        # Stats
        console.print(f"\n[dim]Checks: {passed}/{total} passed, {warnings} warnings, {failures} failures[/dim]")

    def get_exit_code(self, strict: bool = False) -> int:
        """
        Get exit code based on check results.

        Args:
            strict: If True, warnings also cause non-zero exit

        Returns:
            0 for success, 1 for warnings (strict), 2 for failures
        """
        if self.report.failures:
            return 2
        if strict and self.report.warnings:
            return 1
        return 0


async def run_prerequisites_check(
    verbose: bool = False,
    strict: bool = False,
    json_output: bool = False,
    include_optional: bool = True,
) -> int:
    """
    Run prerequisites check and display results.

    Args:
        verbose: Show verbose output
        strict: Fail on warnings
        json_output: Output JSON instead of formatted text
        include_optional: Include optional dependency checks

    Returns:
        Exit code (0 = success, 1 = warnings in strict mode, 2 = failures)
    """
    checker = PrerequisitesChecker(verbose=verbose)

    if not json_output:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Running prerequisites checks...", total=None)
            report = await checker.check_all(include_optional=include_optional)
    else:
        report = await checker.check_all(include_optional=include_optional)

    if json_output:
        print(report.to_json())
    else:
        checker.print_report(show_passed=verbose)

    return checker.get_exit_code(strict=strict)


def check_prerequisites_sync(
    require_llm: bool = True,
    require_tools: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Synchronous quick check for prerequisites.

    Args:
        require_llm: Whether LLM API key is required
        require_tools: Whether security tools are required

    Returns:
        Tuple of (is_ready, list of error messages)
    """
    errors = []

    # Python version
    if sys.version_info < (3, 9):
        errors.append(f"Python 3.9+ required (found {sys.version_info.major}.{sys.version_info.minor})")

    # Core packages
    core_packages = ["litellm", "rich", "click", "pydantic"]
    for pkg in core_packages:
        try:
            importlib.import_module(pkg.replace("-", "_"))
        except ImportError:
            errors.append(f"Missing required package: {pkg}")

    # LLM API key
    if require_llm:
        has_key = any(
            os.getenv(var) for var in
            ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY"]
        )
        if not has_key:
            errors.append("No LLM API key configured (run: aiptx setup)")

    # Security tools
    if require_tools:
        tools = ["nmap", "nuclei"]
        missing = [t for t in tools if not shutil.which(t)]
        if missing:
            errors.append(f"Missing security tools: {', '.join(missing)}")

    return len(errors) == 0, errors


def require_prerequisites(
    require_llm: bool = True,
    require_tools: bool = False,
    operation: str = "this operation"
):
    """
    Decorator/function to check prerequisites before running operations.

    Args:
        require_llm: Whether LLM API key is required
        require_tools: Whether security tools are required
        operation: Description of the operation for error messages

    Raises:
        SystemExit: If prerequisites are not met
    """
    is_ready, errors = check_prerequisites_sync(
        require_llm=require_llm,
        require_tools=require_tools,
    )

    if not is_ready:
        console.print(f"\n[bold red]Cannot proceed with {operation}[/bold red]")
        console.print("\n[yellow]Missing prerequisites:[/yellow]")
        for error in errors:
            console.print(f"  [red]•[/red] {error}")
        console.print("\n[dim]Run 'aiptx check' for detailed diagnostics[/dim]\n")
        raise SystemExit(1)


# CLI entry point
def main():
    """CLI entry point for prerequisites check."""
    import argparse

    parser = argparse.ArgumentParser(description="AIPTX Prerequisites Checker")
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show all checks including passed"
    )
    parser.add_argument(
        "--strict", "-s",
        action="store_true",
        help="Exit with error on warnings"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output JSON format"
    )
    parser.add_argument(
        "--minimal", "-m",
        action="store_true",
        help="Skip optional dependency checks"
    )

    args = parser.parse_args()

    exit_code = asyncio.run(run_prerequisites_check(
        verbose=args.verbose,
        strict=args.strict,
        json_output=args.json,
        include_optional=not args.minimal,
    ))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
