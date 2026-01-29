#!/usr/bin/env python3
"""
AIPTx Agent Interface

This module provides the main entry point for AIPTX, handling:
- Environment validation
- LLM connection warmup with retry
- Docker image management
- CLI/TUI mode selection

Uses EventLoopManager for proper asyncio lifecycle management.
"""

import argparse
import asyncio
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import litellm
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from aipt_v2.core.event_loop_manager import EventLoopManager, run_async
from aipt_v2.interface.cli import run_cli
from aipt_v2.interface.tui import run_tui
from aipt_v2.interface.utils import (
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    process_pull_line,
    validate_llm_response,
)
from aipt_v2.runtime.docker_runtime import AIPT_IMAGE
from aipt_v2.telemetry.tracer import get_global_tracer


logging.getLogger().setLevel(logging.ERROR)


def validate_environment() -> None:  # noqa: PLR0912, PLR0915
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    if not os.getenv("AIPT_LLM"):
        missing_required_vars.append("AIPT_LLM")

    has_base_url = any(
        [
            os.getenv("LLM_API_BASE"),
            os.getenv("OPENAI_API_BASE"),
            os.getenv("LITELLM_BASE_URL"),
            os.getenv("OLLAMA_API_BASE"),
        ]
    )

    if not os.getenv("LLM_API_KEY"):
        if not has_base_url:
            missing_required_vars.append("LLM_API_KEY")
        else:
            missing_optional_vars.append("LLM_API_KEY")

    if not has_base_url:
        missing_optional_vars.append("LLM_API_BASE")

    if not os.getenv("PERPLEXITY_API_KEY"):
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if missing_required_vars:
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "AIPT_LLM":
                error_text.append("• ", style="white")
                error_text.append("AIPT_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use with litellm (e.g., 'openai/gpt-5')\n",
                    style="white",
                )
            elif var == "LLM_API_KEY":
                error_text.append("• ", style="white")
                error_text.append("LLM_API_KEY", style="bold cyan")
                error_text.append(
                    " - API key for the LLM provider (required for cloud providers)\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(" - API key for the LLM provider\n", style="white")
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export AIPT_LLM='openai/gpt-5'\n", style="dim white")

        if "LLM_API_KEY" in missing_required_vars:
            error_text.append("export LLM_API_KEY='your-api-key-here'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  # optional with local models\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )

        panel = Panel(
            error_text,
            title="[bold red]🛡️  AIPT CONFIGURATION ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        console = Console()
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold red]🛡️  AIPT STARTUP ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)


class LLMConnectionError(Exception):
    """Custom exception for LLM connection failures."""

    pass


def _validate_api_base(api_base: str | None) -> str | None:
    """Validate the API base URL format."""
    if not api_base:
        return None

    api_base = api_base.strip()
    if not api_base.startswith(("http://", "https://")):
        raise ValueError(
            f"Invalid API base URL: '{api_base}'. "
            "URL must start with 'http://' or 'https://'"
        )
    return api_base


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=10),
    retry=retry_if_exception_type((litellm.APIConnectionError, litellm.Timeout, LLMConnectionError)),
    reraise=True,
)
async def _attempt_llm_connection(completion_kwargs: dict[str, Any]) -> Any:
    """
    Attempt to connect to the LLM with retry logic.

    Retries up to 3 times with exponential backoff (2s, 4s, 8s).
    """
    response = litellm.completion(**completion_kwargs)

    # Check if response content looks like HTML (proxy/firewall interception)
    if response and hasattr(response, "choices") and response.choices:
        content = getattr(response.choices[0].message, "content", "") or ""
        if content.strip().startswith(("<!DOCTYPE", "<html", "<HTML")):
            raise LLMConnectionError(
                "API returned HTML instead of JSON. "
                "Check if a proxy or firewall is intercepting requests."
            )

    return response


async def warm_up_llm() -> None:
    """
    Warm up the LLM connection with retry logic.

    This function:
    1. Validates the API base URL format
    2. Attempts to connect with up to 3 retries
    3. Uses a shorter timeout (30s) for warmup vs regular requests
    4. Provides clear error messages for common failure modes
    """
    console = Console()

    try:
        model_name = os.getenv("AIPT_LLM", "openai/gpt-5")
        api_key = os.getenv("LLM_API_KEY")

        # Get and validate API base URL
        api_base_raw = (
            os.getenv("LLM_API_BASE")
            or os.getenv("OPENAI_API_BASE")
            or os.getenv("LITELLM_BASE_URL")
            or os.getenv("OLLAMA_API_BASE")
        )

        try:
            api_base = _validate_api_base(api_base_raw)
        except ValueError as e:
            _show_llm_error(console, str(e))
            sys.exit(1)

        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Reply with just 'OK'."},
        ]

        # Use shorter timeout for warmup check (30s instead of 600s)
        warmup_timeout = int(os.getenv("LLM_WARMUP_TIMEOUT", "30"))

        completion_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": test_messages,
            "timeout": warmup_timeout,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        # Attempt connection with retry
        console.print("[dim]Testing LLM connection...[/]", end=" ")
        response = await _attempt_llm_connection(completion_kwargs)
        validate_llm_response(response)
        console.print("[green]OK[/]")

    except LLMConnectionError as e:
        _show_llm_error(console, str(e), hint="Check your network proxy settings.")
        sys.exit(1)

    except litellm.AuthenticationError as e:
        _show_llm_error(
            console,
            "Invalid API key",
            details=str(e),
            hint="Verify your LLM_API_KEY environment variable.",
        )
        sys.exit(1)

    except litellm.APIConnectionError as e:
        _show_llm_error(
            console,
            "Could not connect to LLM API",
            details=str(e),
            hint="Check your internet connection and API base URL.",
        )
        sys.exit(1)

    except litellm.Timeout as e:
        _show_llm_error(
            console,
            "LLM connection timed out",
            details=str(e),
            hint="The API may be slow or unreachable. Try increasing LLM_WARMUP_TIMEOUT.",
        )
        sys.exit(1)

    except Exception as e:  # noqa: BLE001
        _show_llm_error(
            console,
            "LLM connection failed",
            details=str(e),
            hint="Check your configuration and try again.",
        )
        sys.exit(1)


def _show_llm_error(
    console: Console,
    message: str,
    details: str | None = None,
    hint: str | None = None,
) -> None:
    """Display a formatted LLM error panel."""
    error_text = Text()
    error_text.append("❌ ", style="bold red")
    error_text.append("LLM CONNECTION FAILED", style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(f"{message}\n", style="white")

    if hint:
        error_text.append(f"\n💡 Hint: {hint}\n", style="yellow")

    if details:
        # Truncate long error details
        truncated_details = details[:500] + "..." if len(details) > 500 else details
        error_text.append(f"\nError: {truncated_details}", style="dim white")

    panel = Panel(
        error_text,
        title="[bold red]🛡️  AIPT STARTUP ERROR",
        title_align="center",
        border_style="red",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AIPTx Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  aipt --target https://example.com

  # GitHub repository analysis
  aipt --target https://github.com/user/repo
  aipt --target git@github.com:user/repo.git

  # Local code analysis
  aipt --target ./my-project

  # Domain penetration test
  aipt --target example.com

  # IP address penetration test
  aipt --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  aipt --target https://github.com/user/repo --target https://example.com
  aipt --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Custom instructions (inline)
  aipt --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  aipt --target example.com --instruction ./instructions.txt
  aipt --target https://app.com --instruction /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues'). "
        "You can also provide a path to a file containing detailed instructions "
        "(e.g., '--instruction ./instructions.txt').",
    )

    parser.add_argument(
        "--run-name",
        type=str,
        help="Custom name for this penetration test run",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    args = parser.parse_args()

    if args.instruction:
        instruction_path = Path(args.instruction)
        if instruction_path.exists() and instruction_path.is_file():
            try:
                with instruction_path.open(encoding="utf-8") as f:
                    args.instruction = f.read().strip()
                    if not args.instruction:
                        parser.error(f"Instruction file '{instruction_path}' is empty")
            except Exception as e:  # noqa: BLE001
                parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.targets_info = []
    for target in args.target:
        try:
            target_type, target_dict = infer_target_type(target)

            if target_type == "local_code":
                display_target = target_dict.get("target_path", target)
            else:
                display_target = target

            args.targets_info.append(
                {"type": target_type, "details": target_dict, "original": display_target}
            )
        except ValueError:
            parser.error(f"Invalid target '{target}'")

    assign_workspace_subdirs(args.targets_info)

    return args


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    tracer = get_global_tracer()

    scan_completed = False
    if tracer and tracer.scan_results:
        scan_completed = tracer.scan_results.get("scan_completed", False)

    has_vulnerabilities = tracer and len(tracer.vulnerability_reports) > 0

    completion_text = Text()
    if scan_completed:
        completion_text.append("🦉 ", style="bold white")
        completion_text.append("AGENT FINISHED", style="bold green")
        completion_text.append(" • ", style="dim white")
        completion_text.append("Penetration test completed", style="white")
    else:
        completion_text.append("🦉 ", style="bold white")
        completion_text.append("SESSION ENDED", style="bold yellow")
        completion_text.append(" • ", style="dim white")
        completion_text.append("Penetration test interrupted by user", style="white")

    stats_text = build_final_stats_text(tracer)

    target_text = Text()
    if len(args.targets_info) == 1:
        target_text.append("🎯 Target: ", style="bold cyan")
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append("🎯 Targets: ", style="bold cyan")
        target_text.append(f"{len(args.targets_info)} targets\n", style="bold white")
        for i, target_info in enumerate(args.targets_info):
            target_text.append("   • ", style="dim white")
            target_text.append(target_info["original"], style="white")
            if i < len(args.targets_info) - 1:
                target_text.append("\n")

    panel_parts = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    if scan_completed or has_vulnerabilities:
        results_text = Text()
        results_text.append("📊 Results Saved To: ", style="bold cyan")
        results_text.append(str(results_path), style="bold yellow")
        panel_parts.extend(["\n\n", results_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "green" if scan_completed else "yellow"

    panel = Panel(
        panel_content,
        title="[bold green]🛡️  AIPT PENETRATION TESTING AGENT",
        title_align="center",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    if image_exists(client, AIPT_IMAGE):
        return

    console.print()
    console.print(f"[bold cyan]🐳 Pulling Docker image:[/] {AIPT_IMAGE}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(AIPT_IMAGE, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            console.print()
            error_text = Text()
            error_text.append("❌ ", style="bold red")
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {AIPT_IMAGE}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold red]🛡️  DOCKER PULL ERROR",
                title_align="center",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    success_text = Text()
    success_text.append("✅ ", style="bold green")
    success_text.append("Successfully pulled Docker image", style="green")
    console.print(success_text)
    console.print()


def main() -> None:
    """
    Main entry point for AIPTX.

    Uses EventLoopManager to ensure a single event loop is used throughout
    the application lifecycle, preventing "event loop is closed" errors.

    Flow:
    1. Parse arguments
    2. Check Docker installation
    3. Validate environment
    4. Warm up LLM connection (with retry)
    5. Clone repositories if needed
    6. Run CLI or TUI mode
    7. Display completion message
    """
    # Windows-specific event loop policy is handled by EventLoopManager
    args = parse_arguments()

    check_docker_installed()
    pull_docker_image()

    validate_environment()

    # Use EventLoopManager for all async operations to maintain a single loop
    try:
        # Warm up LLM with retry logic
        run_async(warm_up_llm())

        if not args.run_name:
            args.run_name = generate_run_name(args.targets_info)

        for target_info in args.targets_info:
            if target_info["type"] == "repository":
                repo_url = target_info["details"]["target_repo"]
                dest_name = target_info["details"].get("workspace_subdir")
                cloned_path = clone_repository(repo_url, args.run_name, dest_name)
                target_info["details"]["cloned_repo_path"] = cloned_path

        args.local_sources = collect_local_sources(args.targets_info)

        # Run the appropriate interface mode using the same event loop
        if args.non_interactive:
            run_async(run_cli(args))
        else:
            run_async(run_tui(args))

    finally:
        # Ensure graceful shutdown of the event loop
        EventLoopManager.shutdown()

    results_path = Path("aipt_runs") / args.run_name
    display_completion_message(args, results_path)

    if args.non_interactive:
        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
