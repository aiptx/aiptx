"""
AIPTX Interactive Setup Wizard
==============================

First-run setup wizard that guides users through configuration.
Collects API keys and settings interactively with a beautiful TUI.

NEW in v2.1:
- Automatic system detection (OS, package manager, architecture)
- Local security tool installation
- Ollama/local LLM support for offline operation
- Prerequisites verification and installation

Usage:
    aiptx setup              # Run setup wizard
    aiptx scan example.com   # Auto-triggers if not configured
"""

import asyncio
import os
import shutil
import sys
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Coroutine, TypeVar, Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

T = TypeVar("T")


def _run_async_safe(coro: Coroutine[Any, Any, T]) -> T:
    """
    Run an async coroutine safely, handling the case where
    we're already inside an event loop.

    This prevents the "Cannot run the event loop while another loop is running" error
    by using different strategies:
    1. If no loop running: create a new one
    2. If loop running but we're not in async context: use thread-safe scheduling
    3. If we're in async context: use nest_asyncio to allow nested loops
    """
    import threading

    # First, check if there's a running loop
    try:
        running_loop = asyncio.get_running_loop()
        loop_is_running = True
    except RuntimeError:
        running_loop = None
        loop_is_running = False

    # If no loop is running, we can safely create one
    if not loop_is_running:
        # Try to use EventLoopManager if available
        try:
            from aipt_v2.core.event_loop_manager import EventLoopManager
            return EventLoopManager.run(coro)
        except ImportError:
            pass

        # Fallback: create a new loop
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    # Loop is running - we need a different strategy
    # Option 1: Try nest_asyncio if available (allows nested event loops)
    try:
        import nest_asyncio
        nest_asyncio.apply()
        # After applying nest_asyncio, we can run nested loops
        return running_loop.run_until_complete(coro)
    except ImportError:
        pass
    except RuntimeError:
        # nest_asyncio might not help in all cases
        pass

    # Option 2: Run in a separate thread with its own event loop
    result = None
    exception = None

    def run_in_thread():
        nonlocal result, exception
        try:
            thread_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(thread_loop)
            try:
                result = thread_loop.run_until_complete(coro)
            finally:
                thread_loop.close()
        except Exception as e:
            exception = e

    thread = threading.Thread(target=run_in_thread)
    thread.start()
    thread.join(timeout=300)  # 5 minute timeout

    if thread.is_alive():
        raise TimeoutError("Async operation timed out after 5 minutes")

    if exception is not None:
        raise exception

    return result

# Enable readline for arrow key support in input prompts
try:
    import readline
    # Configure readline for better input handling
    readline.parse_and_bind('set editing-mode emacs')
except ImportError:
    # readline not available on Windows by default
    pass


console = Console()


def input_with_default(prompt: str, default: str = "", password: bool = False) -> str:
    """
    Get user input with readline support (arrow keys, history).

    Args:
        prompt: The prompt to display
        default: Default value to show/return if empty input
        password: If True, don't echo input (for sensitive data)

    Returns:
        User input or default value
    """
    import getpass

    if default:
        display_prompt = f"{prompt} ({default}): "
    else:
        display_prompt = f"{prompt}: "

    try:
        if password:
            # Use getpass for password input (no echo)
            value = getpass.getpass(display_prompt)
        else:
            # Use standard input with readline support
            value = input(display_prompt)

        return value.strip() if value.strip() else default
    except (EOFError, KeyboardInterrupt):
        console.print()
        return default


# Lazy imports to avoid circular dependencies
def _get_system_detector():
    from aipt_v2.system_detector import SystemDetector, SystemInfo
    return SystemDetector, SystemInfo


def _get_tool_installer():
    from aipt_v2.local_tool_installer import LocalToolInstaller, TOOLS, ToolCategory
    return LocalToolInstaller, TOOLS, ToolCategory


# ============================================================================
# Configuration File Management
# ============================================================================

def get_config_path() -> Path:
    """Get the path to the .env config file."""
    # Check for existing .env in current directory
    local_env = Path(".env")
    if local_env.exists():
        return local_env

    # Check for global config in home directory
    home_env = Path.home() / ".aiptx" / ".env"
    if home_env.exists():
        return home_env

    # Default to home directory for new installations
    return home_env


def load_existing_config() -> dict:
    """Load existing configuration from .env file."""
    config = {}
    config_path = get_config_path()

    if config_path.exists():
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip().strip('"').strip("'")

    return config


def save_config(config: dict, path: Optional[Path] = None) -> Path:
    """Save configuration to .env file."""
    if path is None:
        path = Path.home() / ".aiptx" / ".env"

    # Create directory if needed
    path.parent.mkdir(parents=True, exist_ok=True)

    # Build config content
    lines = [
        "# AIPTX Configuration",
        "# Generated by 'aiptx setup'",
        "# Edit this file or run 'aiptx setup' again to reconfigure",
        "",
    ]

    # Group settings
    sections = {
        "LLM": [
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY",
            "AIPT_LLM__PROVIDER", "AIPT_LLM__MODEL", "AIPT_LLM__OLLAMA_BASE_URL"
        ],
        "Acunetix": ["AIPT_SCANNERS__ACUNETIX_URL", "AIPT_SCANNERS__ACUNETIX_API_KEY"],
        "Burp Suite": ["AIPT_SCANNERS__BURP_URL", "AIPT_SCANNERS__BURP_API_KEY"],
        "Nessus": ["AIPT_SCANNERS__NESSUS_URL", "AIPT_SCANNERS__NESSUS_ACCESS_KEY",
                   "AIPT_SCANNERS__NESSUS_SECRET_KEY"],
        "OWASP ZAP": ["AIPT_SCANNERS__ZAP_URL", "AIPT_SCANNERS__ZAP_API_KEY"],
        "VPS": ["AIPT_VPS__HOST", "AIPT_VPS__USER", "AIPT_VPS__KEY_PATH", "AIPT_VPS__PORT"],
    }

    for section, keys in sections.items():
        section_values = [(k, config.get(k)) for k in keys if config.get(k)]
        if section_values:
            lines.append(f"\n# {section} Configuration")
            for key, value in section_values:
                lines.append(f'{key}="{value}"')

    # Write file
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Secure the file (readable only by owner)
    os.chmod(path, 0o600)

    return path


def is_configured() -> bool:
    """Check if AIPTX has been configured with at least an LLM API key."""
    # Check environment variables
    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY"]:
        if os.getenv(key):
            return True

    # Check .env files
    config = load_existing_config()
    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY"]:
        if config.get(key):
            return True

    return False


# ============================================================================
# Interactive Setup Wizard
# ============================================================================

def print_welcome():
    """Print welcome banner."""
    banner = """
[bold cyan]╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗ ██╗██████╗ ████████╗██╗  ██╗                      ║
║    ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝                      ║
║    ███████║██║██████╔╝   ██║    ╚███╔╝                       ║
║    ██╔══██║██║██╔═══╝    ██║    ██╔██╗                       ║
║    ██║  ██║██║██║        ██║   ██╔╝ ██╗                      ║
║    ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝                      ║
║                                                               ║
║         AI-Powered Penetration Testing Framework              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(banner)
    console.print("[bold green]Welcome to AIPTX Setup![/bold green]")
    console.print("This wizard will help you configure AIPTX for first use.\n")


async def detect_system() -> Optional[object]:
    """
    Detect and display system information.

    Returns:
        SystemInfo object or None if detection fails
    """
    console.print(Panel(
        "[bold]System Detection[/bold]\n\n"
        "Detecting your system configuration to optimize installation...",
        title="🔍 Auto-Detection",
        border_style="cyan"
    ))

    try:
        SystemDetector, SystemInfo = _get_system_detector()
        detector = SystemDetector()

        with console.status("[bold cyan]Detecting system...[/bold cyan]"):
            system_info = await detector.detect()

        # Display results
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Operating System", system_info.os_name)
        table.add_row("Version", f"{system_info.os_version}" +
                     (f" ({system_info.os_codename})" if system_info.os_codename else ""))
        table.add_row("Architecture", system_info.architecture.value)
        table.add_row("Package Manager", system_info.package_manager.value)

        if system_info.is_wsl:
            table.add_row("Environment", "WSL")
        elif system_info.is_container:
            table.add_row("Environment", "Container")

        console.print(table)

        # Show capabilities summary
        caps = system_info.capabilities
        cap_status = []
        if caps.has_python3:
            cap_status.append("[green]Python3[/green]")
        if caps.has_go:
            cap_status.append("[green]Go[/green]")
        else:
            cap_status.append("[yellow]Go (will install)[/yellow]")
        if caps.has_docker:
            cap_status.append("[green]Docker[/green]")
        if caps.has_git:
            cap_status.append("[green]Git[/green]")

        console.print(f"\n[bold]Available runtimes:[/bold] {', '.join(cap_status)}")

        return system_info

    except Exception as e:
        console.print(f"[yellow]Warning: Could not fully detect system: {e}[/yellow]")
        return None


def check_ollama_installed() -> Tuple[bool, str]:
    """Check if Ollama is installed and get version."""
    ollama_path = shutil.which("ollama")
    if ollama_path:
        try:
            import subprocess
            result = subprocess.run(
                ["ollama", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            version = result.stdout.strip() or result.stderr.strip()
            return True, version
        except Exception:
            return True, "unknown version"
    return False, ""


async def check_ollama_running() -> bool:
    """Check if Ollama server is running."""
    try:
        import asyncio
        proc = await asyncio.create_subprocess_shell(
            "curl -s http://localhost:11434/api/version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        return proc.returncode == 0 and b"version" in stdout
    except Exception:
        return False


async def get_ollama_models() -> List[str]:
    """Get list of available Ollama models."""
    try:
        proc = await asyncio.create_subprocess_shell(
            "ollama list",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode == 0:
            lines = stdout.decode().strip().split("\n")[1:]  # Skip header
            models = []
            for line in lines:
                if line.strip():
                    model_name = line.split()[0]
                    models.append(model_name)
            return models
    except Exception:
        pass
    return []


def setup_llm() -> dict:
    """Configure LLM provider and API key."""
    config = {}

    console.print(Panel(
        "[bold]Step 2: LLM Configuration[/bold]\n\n"
        "AIPTX uses AI to guide penetration testing.\n"
        "Choose a cloud provider or run locally with Ollama.",
        title="🤖 AI Provider",
        border_style="cyan"
    ))

    # Check Ollama status
    ollama_installed, ollama_version = check_ollama_installed()

    # Choose provider
    console.print("\n[bold]Select your LLM provider:[/bold]")
    console.print("  [1] Anthropic (Claude) - [green]Recommended for best results[/green]")
    console.print("  [2] OpenAI (GPT-4)")
    console.print("  [3] DeepSeek - [dim]Cost-effective option[/dim]")

    if ollama_installed:
        console.print(f"  [4] Ollama (Local) - [green]✓ Installed ({ollama_version})[/green] - [bold]FREE, runs offline[/bold]")
    else:
        console.print("  [4] Ollama (Local) - [yellow]○ Not installed[/yellow] - [dim]Will install[/dim]")

    console.print("  [5] Other (custom)")

    choice = Prompt.ask(
        "\nEnter choice",
        choices=["1", "2", "3", "4", "5"],
        default="1"
    )

    providers = {
        "1": ("anthropic", "claude-sonnet-4-20250514", "ANTHROPIC_API_KEY"),
        "2": ("openai", "gpt-4o", "OPENAI_API_KEY"),
        "3": ("deepseek", "deepseek-chat", "DEEPSEEK_API_KEY"),
        "4": ("ollama", "llama3.2", None),  # No API key needed
        "5": ("custom", "", "LLM_API_KEY"),
    }

    provider, model, key_name = providers[choice]

    # Handle Ollama setup
    if choice == "4":
        config.update(_setup_ollama(ollama_installed))
        return config

    if choice == "5":
        provider = input_with_default("Enter provider name", "")
        model = input_with_default("Enter model name", "")
        key_name = "LLM_API_KEY"

    config["AIPT_LLM__PROVIDER"] = provider
    config["AIPT_LLM__MODEL"] = model

    # Get API key
    console.print(f"\n[bold]Enter your {provider.title()} API key:[/bold]")

    if provider == "anthropic":
        console.print("[dim]Get one at: https://console.anthropic.com/settings/keys[/dim]")
    elif provider == "openai":
        console.print("[dim]Get one at: https://platform.openai.com/api-keys[/dim]")
    elif provider == "deepseek":
        console.print("[dim]Get one at: https://platform.deepseek.com/api_keys[/dim]")

    api_key = input_with_default("API Key", "", password=True)

    if api_key and key_name:
        config[key_name] = api_key

    return config


def _setup_ollama(ollama_installed: bool) -> dict:
    """Configure Ollama for local LLM."""
    config = {}

    console.print("\n[bold cyan]═══ Ollama Local LLM Setup ═══[/bold cyan]")

    if not ollama_installed:
        console.print("\n[yellow]Ollama is not installed.[/yellow]")
        console.print("Ollama allows you to run LLMs locally for FREE and offline.")

        if Confirm.ask("\nWould you like to install Ollama now?", default=True):
            _install_ollama()
        else:
            console.print("[dim]You can install Ollama later from: https://ollama.ai[/dim]")
            console.print("[yellow]Falling back to cloud provider...[/yellow]")
            return setup_llm()  # Restart LLM setup

    # Check if Ollama is running (use safe async runner to avoid nested loop errors)
    is_running = _run_async_safe(check_ollama_running())

    if not is_running:
        console.print("\n[yellow]Ollama server is not running.[/yellow]")
        console.print("Start it with: [bold]ollama serve[/bold]")

        if Confirm.ask("\nWould you like to start Ollama now?", default=True):
            import subprocess
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            console.print("[green]✓ Ollama server started[/green]")
            import time
            time.sleep(2)  # Wait for server to start

    # Get available models (use safe async runner to avoid nested loop errors)
    models = _run_async_safe(get_ollama_models())

    # Recommended models for pentesting
    recommended_models = [
        ("llama3.2", "Meta Llama 3.2 - Fast, good balance"),
        ("qwen2.5:14b", "Qwen 2.5 14B - Excellent for code/reasoning"),
        ("deepseek-r1:8b", "DeepSeek R1 8B - Strong reasoning"),
        ("codellama:13b", "Code Llama 13B - Optimized for code"),
    ]

    console.print("\n[bold]Select a model:[/bold]")

    # Show installed models first
    if models:
        console.print("\n[dim]Installed models:[/dim]")
        for i, model in enumerate(models[:5], 1):
            console.print(f"  [{i}] {model} [green]✓ Ready[/green]")

    console.print("\n[dim]Recommended models (will download):[/dim]")
    offset = len(models[:5]) + 1
    for i, (model, desc) in enumerate(recommended_models, offset):
        installed = model.split(":")[0] in [m.split(":")[0] for m in models]
        status = "[green]✓[/green]" if installed else "[dim]↓[/dim]"
        console.print(f"  [{i}] {model} - {desc} {status}")

    # Let user choose
    max_choice = offset + len(recommended_models) - 1
    model_choice = Prompt.ask(
        f"\nEnter choice (1-{max_choice}) or model name",
        default="1"
    )

    try:
        idx = int(model_choice)
        if idx <= len(models[:5]):
            selected_model = models[idx - 1]
        else:
            selected_model = recommended_models[idx - offset][0]
    except ValueError:
        selected_model = model_choice

    # Check if model needs to be pulled
    if selected_model not in models:
        console.print(f"\n[cyan]Downloading model: {selected_model}[/cyan]")
        console.print("[dim]This may take a few minutes...[/dim]")

        import subprocess
        try:
            subprocess.run(
                ["ollama", "pull", selected_model],
                check=True
            )
            console.print(f"[green]✓ Model {selected_model} downloaded[/green]")
        except subprocess.CalledProcessError:
            console.print(f"[red]Failed to download {selected_model}[/red]")
            console.print("[yellow]You can download it later with: ollama pull {selected_model}[/yellow]")

    config["AIPT_LLM__PROVIDER"] = "ollama"
    config["AIPT_LLM__MODEL"] = selected_model
    config["AIPT_LLM__OLLAMA_BASE_URL"] = "http://localhost:11434"

    console.print(Panel(
        f"[green]✓ Ollama configured![/green]\n\n"
        f"Model: [bold]{selected_model}[/bold]\n"
        f"Server: http://localhost:11434\n\n"
        f"[dim]Benefits: Free, runs offline, no API limits[/dim]",
        title="🦙 Local LLM Ready",
        border_style="green"
    ))

    return config


def _install_ollama():
    """Install Ollama on the system."""
    import platform
    import subprocess

    system = platform.system().lower()

    console.print("\n[cyan]Installing Ollama...[/cyan]")

    try:
        if system == "darwin":  # macOS
            # Check if Homebrew is available
            if shutil.which("brew"):
                subprocess.run(["brew", "install", "ollama"], check=True)
            else:
                # Use curl installer
                subprocess.run(
                    ["curl", "-fsSL", "https://ollama.ai/install.sh"],
                    stdout=subprocess.PIPE,
                    check=True
                )
        elif system == "linux":
            subprocess.run(
                "curl -fsSL https://ollama.ai/install.sh | sh",
                shell=True,
                check=True
            )
        elif system == "windows":
            console.print("[yellow]Please install Ollama manually from: https://ollama.ai[/yellow]")
            console.print("[dim]After installation, run 'ollama serve' to start the server[/dim]")
            return

        console.print("[green]✓ Ollama installed successfully[/green]")

    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to install Ollama: {e}[/red]")
        console.print("[dim]Please install manually from: https://ollama.ai[/dim]")


def normalize_url(url: str) -> str:
    """Normalize a URL - add protocol if missing, remove trailing slashes."""
    if not url:
        return url
    url = url.strip()
    # Add https:// if no protocol specified (prefer https for security scanners)
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    # Remove trailing slashes
    url = url.rstrip('/')
    return url


def setup_scanners() -> dict:
    """Configure enterprise scanners (optional)."""
    config = {}

    console.print(Panel(
        "[bold]Step 2: Enterprise Scanners (Optional)[/bold]\n\n"
        "AIPTX integrates with enterprise DAST scanners for\n"
        "comprehensive vulnerability assessment.",
        title="🔍 Scanners",
        border_style="cyan"
    ))

    if not Confirm.ask("\nDo you want to configure enterprise scanners?", default=False):
        console.print("[dim]Skipping scanner configuration...[/dim]\n")
        return config

    # Acunetix
    if Confirm.ask("\n[bold]Configure Acunetix?[/bold]", default=False):
        url = input_with_default("  Acunetix URL (e.g., https://your-instance:3443)", "")
        api_key = input_with_default("  Acunetix API Key", "", password=True)
        if url:
            config["AIPT_SCANNERS__ACUNETIX_URL"] = normalize_url(url)
        if api_key:
            config["AIPT_SCANNERS__ACUNETIX_API_KEY"] = api_key

    # Burp Suite
    if Confirm.ask("\n[bold]Configure Burp Suite Enterprise?[/bold]", default=False):
        url = input_with_default("  Burp Suite URL (e.g., https://your-burp:8080)", "")
        api_key = input_with_default("  Burp Suite API Key", "", password=True)
        if url:
            config["AIPT_SCANNERS__BURP_URL"] = normalize_url(url)
        if api_key:
            config["AIPT_SCANNERS__BURP_API_KEY"] = api_key

    # Nessus
    if Confirm.ask("\n[bold]Configure Nessus?[/bold]", default=False):
        url = input_with_default("  Nessus URL (e.g., https://your-nessus:8834)", "")
        access_key = input_with_default("  Nessus Access Key", "", password=True)
        secret_key = input_with_default("  Nessus Secret Key", "", password=True)
        if url:
            config["AIPT_SCANNERS__NESSUS_URL"] = normalize_url(url)
        if access_key:
            config["AIPT_SCANNERS__NESSUS_ACCESS_KEY"] = access_key
        if secret_key:
            config["AIPT_SCANNERS__NESSUS_SECRET_KEY"] = secret_key

    # OWASP ZAP
    if Confirm.ask("\n[bold]Configure OWASP ZAP?[/bold]", default=False):
        url = input_with_default("  ZAP URL (e.g., http://localhost:8080)", "")
        api_key = input_with_default("  ZAP API Key (leave empty if disabled)", "", password=True)
        if url:
            # ZAP typically uses http, not https
            normalized = url.strip()
            if not normalized.startswith(('http://', 'https://')):
                normalized = f"http://{normalized}"
            normalized = normalized.rstrip('/')
            config["AIPT_SCANNERS__ZAP_URL"] = normalized
        if api_key:
            config["AIPT_SCANNERS__ZAP_API_KEY"] = api_key

    return config


def setup_vps() -> dict:
    """Configure VPS for remote execution (optional)."""
    config = {}

    console.print(Panel(
        "[bold]Step 3: VPS Configuration (Optional)[/bold]\n\n"
        "Run security tools on a remote VPS to avoid\n"
        "network restrictions and maintain anonymity.",
        title="🖥️  VPS",
        border_style="cyan"
    ))

    if not Confirm.ask("\nDo you want to configure a VPS for remote execution?", default=False):
        console.print("[dim]Skipping VPS configuration...[/dim]\n")
        return config

    # Use readline-enabled input for arrow key support
    host = input_with_default("  VPS IP or hostname", "")
    user = input_with_default("  SSH username", "ubuntu")
    key_path = input_with_default("  Path to SSH private key (e.g., ~/.ssh/id_rsa)", "")
    port = input_with_default("  SSH port", "22")

    if host:
        config["AIPT_VPS__HOST"] = host
    if user:
        config["AIPT_VPS__USER"] = user
    if key_path:
        # Expand ~ to home directory
        expanded_path = str(Path(key_path).expanduser())
        config["AIPT_VPS__KEY_PATH"] = expanded_path
        # Validate the key file exists
        if not Path(expanded_path).exists():
            console.print(f"[yellow]Warning: SSH key file not found at {expanded_path}[/yellow]")
            console.print("[dim]Make sure the path is correct before testing the connection.[/dim]")
    if port:
        config["AIPT_VPS__PORT"] = port

    return config


async def setup_security_tools(system_info=None) -> Dict[str, bool]:
    """
    Install security tools on the local system.

    Args:
        system_info: Pre-detected system info

    Returns:
        Dict mapping tool names to installation status
    """
    console.print(Panel(
        "[bold]Step 4: Security Tools Installation[/bold]\n\n"
        "AIPTX uses various security tools for penetration testing.\n"
        "These tools will be installed on your local system.",
        title="🔧 Security Tools",
        border_style="cyan"
    ))

    try:
        LocalToolInstaller, TOOLS, ToolCategory = _get_tool_installer()
    except ImportError:
        console.print("[yellow]Tool installer not available. Skipping...[/yellow]")
        return {}

    # Show what will be installed
    core_tools = [name for name, tool in TOOLS.items() if tool.is_core]

    console.print("\n[bold]Core tools to install:[/bold]")
    for tool_name in core_tools[:8]:
        tool = TOOLS.get(tool_name)
        console.print(f"  • {tool_name} - [dim]{tool.description[:50]}...[/dim]")

    console.print(f"\n[dim]Total: {len(core_tools)} core tools, {len(TOOLS)} available[/dim]")

    # Choose installation scope
    console.print("\n[bold]Installation options:[/bold]")
    console.print("  [1] Core tools only - [green]Recommended[/green] - Quick install of essential tools")
    console.print("  [2] Full installation - Install all available security tools")
    console.print("  [3] Custom selection - Choose categories to install")
    console.print("  [4] Skip - Don't install any tools now")

    choice = Prompt.ask("\nEnter choice", choices=["1", "2", "3", "4"], default="1")

    if choice == "4":
        console.print("[dim]Skipping tool installation. You can install later with: aiptx tools install[/dim]")
        return {}

    installer = LocalToolInstaller(system_info)

    # Check if we need sudo
    has_sudo = system_info.capabilities.has_sudo if system_info else True
    if not has_sudo:
        console.print("\n[yellow]Note: Some tools may require sudo/admin privileges.[/yellow]")
        console.print("[dim]You may be prompted for your password.[/dim]")

    results = {}

    if choice == "1":
        # Core tools only
        console.print("\n[cyan]Installing core security tools...[/cyan]")
        results = await installer.install_core_tools()

    elif choice == "2":
        # Full installation
        console.print("\n[cyan]Installing all security tools...[/cyan]")
        console.print("[dim]This may take 10-20 minutes...[/dim]")
        results = await installer.install_all()

    elif choice == "3":
        # Custom selection
        console.print("\n[bold]Select categories to install:[/bold]")
        console.print("  [1] Recon - Subdomain discovery, port scanning, fingerprinting")
        console.print("  [2] Scan - Vulnerability scanning, fuzzing, content discovery")
        console.print("  [3] Exploit - SQL injection, brute forcing, exploitation")
        console.print("  [4] Network - Fast port scanning, network analysis")
        console.print("  [5] API - API security testing tools")

        cat_choice = Prompt.ask(
            "\nEnter categories (comma-separated, e.g., 1,2,3)",
            default="1,2"
        )

        category_map = {
            "1": "recon",
            "2": "scan",
            "3": "exploit",
            "4": "network",
            "5": "api",
        }

        categories = [
            category_map[c.strip()]
            for c in cat_choice.split(",")
            if c.strip() in category_map
        ]

        if categories:
            console.print(f"\n[cyan]Installing {', '.join(categories)} tools...[/cyan]")
            results = await installer.install_tools(categories=categories)
        else:
            console.print("[yellow]No valid categories selected.[/yellow]")

    # Show summary
    if results:
        installed = sum(1 for r in results.values() if r.success and not r.already_installed)
        already = sum(1 for r in results.values() if r.already_installed)
        failed = sum(1 for r in results.values() if not r.success)

        console.print(Panel(
            f"[bold]Installation Complete[/bold]\n\n"
            f"[green]✓ Installed:[/green] {installed}\n"
            f"[dim]○ Already installed:[/dim] {already}\n"
            f"[red]✗ Failed:[/red] {failed}",
            title="📊 Tool Installation Summary",
            border_style="green" if failed == 0 else "yellow"
        ))

    return {name: result.success for name, result in results.items()} if results else {}


def show_summary(config: dict, tools_installed: Dict[str, bool] = None):
    """Show configuration summary."""
    console.print(Panel(
        "[bold]Configuration Summary[/bold]",
        title="📋 Summary",
        border_style="green"
    ))

    table = Table(box=box.ROUNDED)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    # LLM
    provider = config.get("AIPT_LLM__PROVIDER", "Not set")
    model = config.get("AIPT_LLM__MODEL", "Not set")
    has_key = any(k in config for k in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY"])
    is_ollama = provider == "ollama"

    table.add_row("LLM Provider", provider)
    table.add_row("LLM Model", model)
    if is_ollama:
        table.add_row("LLM Mode", "✓ Local (Ollama)")
    else:
        table.add_row("LLM API Key", "✓ Configured" if has_key else "✗ Not set")

    # Scanners
    table.add_row("─" * 20, "─" * 20)
    table.add_row("Acunetix", "✓ Configured" if config.get("AIPT_SCANNERS__ACUNETIX_URL") else "○ Not configured")
    table.add_row("Burp Suite", "✓ Configured" if config.get("AIPT_SCANNERS__BURP_URL") else "○ Not configured")
    table.add_row("Nessus", "✓ Configured" if config.get("AIPT_SCANNERS__NESSUS_URL") else "○ Not configured")
    table.add_row("OWASP ZAP", "✓ Configured" if config.get("AIPT_SCANNERS__ZAP_URL") else "○ Not configured")

    # VPS
    table.add_row("─" * 20, "─" * 20)
    table.add_row("VPS", "✓ " + config.get("AIPT_VPS__HOST", "") if config.get("AIPT_VPS__HOST") else "○ Not configured")

    # Tools
    if tools_installed:
        table.add_row("─" * 20, "─" * 20)
        installed_count = sum(1 for v in tools_installed.values() if v)
        table.add_row("Security Tools", f"✓ {installed_count} tools installed")

    console.print(table)


def run_setup_wizard(force: bool = False) -> bool:
    """
    Run the interactive setup wizard.

    Args:
        force: Run even if already configured

    Returns:
        True if setup completed successfully
    """
    # Use safe async runner to handle nested event loops
    try:
        return _run_async_safe(_run_setup_wizard_async(force))
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled.[/yellow]")
        return False
    except Exception as e:
        console.print(f"\n[red]Setup error: {e}[/red]")
        return False


async def _run_setup_wizard_async(force: bool = False) -> bool:
    """
    Async implementation of the setup wizard.

    Args:
        force: Run even if already configured

    Returns:
        True if setup completed successfully
    """
    try:
        # Check if already configured
        if not force and is_configured():
            console.print("[yellow]AIPTX is already configured.[/yellow]")
            if not Confirm.ask("Do you want to reconfigure?", default=False):
                return False

        print_welcome()

        # Collect configuration
        config = load_existing_config()  # Start with existing config
        tools_installed = {}

        # Step 1: System Detection (NEW)
        console.print()
        system_info = await detect_system()

        # Step 2: LLM Configuration
        console.print()
        llm_config = setup_llm()
        config.update(llm_config)

        # Check if we got an API key or using Ollama
        is_ollama = config.get("AIPT_LLM__PROVIDER") == "ollama"
        has_key = any(k in config for k in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY"])

        if not has_key and not is_ollama:
            console.print("\n[bold red]Error:[/bold red] An LLM API key is required to use AIPTX.")
            console.print("Please run [bold]aiptx setup[/bold] again with a valid API key.")
            return False

        # Step 3: Scanners (optional)
        console.print()
        scanner_config = setup_scanners()
        config.update(scanner_config)

        # Step 4: Security Tools Installation (NEW)
        console.print()
        if Confirm.ask("\nWould you like to install security tools now?", default=True):
            tools_installed = await setup_security_tools(system_info)

        # Step 5: VPS (optional)
        console.print()
        vps_config = setup_vps()
        config.update(vps_config)

        # Show summary
        console.print()
        show_summary(config, tools_installed)

        # Confirm and save
        console.print()
        if Confirm.ask("[bold]Save this configuration?[/bold]", default=True):
            config_path = save_config(config)

            # Build dynamic completion message
            next_steps = []
            if is_ollama:
                next_steps.append("  [bold]ollama serve[/bold]             - Start Ollama (if not running)")
            next_steps.extend([
                "  [bold]aiptx scan example.com[/bold]     - Run a security scan",
                "  [bold]aiptx status[/bold]              - Check configuration",
                "  [bold]aiptx tools install[/bold]       - Install more security tools",
                "  [bold]aiptx setup[/bold]               - Reconfigure AIPTX",
            ])

            console.print(Panel(
                f"[bold green]✓ Configuration saved![/bold green]\n\n"
                f"Config file: [cyan]{config_path}[/cyan]\n\n"
                f"[bold]Next steps:[/bold]\n" +
                "\n".join(next_steps),
                title="🎉 Setup Complete",
                border_style="green"
            ))

            # Load the config into environment for immediate use
            for key, value in config.items():
                os.environ[key] = value

            return True
        else:
            console.print("[yellow]Setup cancelled. No changes saved.[/yellow]")
            return False

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        console.print("\n[yellow]Setup cancelled.[/yellow]")
        return False


def prompt_first_run_setup() -> bool:
    """
    Prompt for setup on first run when configuration is missing.

    Returns:
        True if setup completed and user can proceed
    """
    try:
        console.print(Panel(
            "[bold yellow]⚠ AIPTX is not configured![/bold yellow]\n\n"
            "This appears to be your first time running AIPTX.\n"
            "You need to configure at least an LLM API key to proceed.",
            title="First Run Setup Required",
            border_style="yellow"
        ))

        if Confirm.ask("\nWould you like to run the setup wizard now?", default=True):
            return run_setup_wizard(force=True)
        else:
            console.print("\n[dim]You can run setup later with: [bold]aiptx setup[/bold][/dim]")
            console.print("[dim]Or set environment variables manually:[/dim]")
            console.print("[dim]  export ANTHROPIC_API_KEY=your-key-here[/dim]\n")
            return False
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        return False


# ============================================================================
# CLI Entry Points
# ============================================================================

def main():
    """Standalone setup wizard entry point."""
    run_setup_wizard(force=True)


if __name__ == "__main__":
    main()
