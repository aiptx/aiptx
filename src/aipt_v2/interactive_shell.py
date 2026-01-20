"""
AIPTX Interactive Shell
=======================

Provides an interactive shell environment for running security tools
with enhanced features like command history, output logging, and
real-time display.

Features:
- Interactive command execution
- Tab completion for tool names
- Command history with readline
- Real-time output streaming
- Session logging
- Tool discovery and help
- Environment management
- Cross-platform support (Windows, Linux, macOS)

Usage:
    aiptx shell                    # Start interactive shell
    aiptx shell --log session.log  # With logging
"""

import asyncio
import os
import shlex
import shutil
import signal
import subprocess
import sys
import platform
import threading
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.live import Live
from rich.text import Text
from rich import box


# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# Conditionally import Unix-only modules
if not IS_WINDOWS:
    import pty
    import select
    import termios
    import tty

# Try to import readline (available on Unix, may need pyreadline3 on Windows)
try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False
    # On Windows, try pyreadline3
    if IS_WINDOWS:
        try:
            import pyreadline3 as readline
            HAS_READLINE = True
        except ImportError:
            pass


console = Console()


# Command history file
HISTORY_FILE = Path.home() / ".aiptx" / "shell_history"


class ToolCompleter:
    """Tab completion for tool names and commands."""

    def __init__(self, tools: List[str]):
        self.tools = sorted(tools)
        self.commands = [
            "help", "tools", "exit", "quit", "clear", "history",
            "env", "cd", "pwd", "run", "scan", "export", "log"
        ]
        self.all_completions = self.commands + self.tools
        self.matches = []

    def complete(self, text: str, state: int) -> Optional[str]:
        """Readline completion function."""
        if state == 0:
            if text:
                self.matches = [
                    s for s in self.all_completions
                    if s.startswith(text)
                ]
            else:
                self.matches = self.all_completions[:]

        try:
            return self.matches[state]
        except IndexError:
            return None


class InteractiveShell:
    """
    Interactive shell for running security tools.

    Provides a REPL-like environment with:
    - Tool execution with real-time output
    - Command history and tab completion
    - Session logging
    - Environment management
    - Cross-platform compatibility
    """

    def __init__(
        self,
        log_file: Optional[Path] = None,
        working_dir: Optional[Path] = None,
    ):
        """
        Initialize the interactive shell.

        Args:
            log_file: Optional file to log session output
            working_dir: Working directory (defaults to current)
        """
        self.log_file = log_file
        self.working_dir = working_dir or Path.cwd()
        self.running = False
        self.env = os.environ.copy()
        self.history: List[str] = []
        self._tools: Dict[str, str] = {}
        self._load_tools()
        self._setup_readline()

    def _load_tools(self):
        """Load available tools from the installer."""
        try:
            from aipt_v2.local_tool_installer import TOOLS
            self._tools = {
                name: tool.description
                for name, tool in TOOLS.items()
            }
        except ImportError:
            self._tools = {}

    def _setup_readline(self):
        """Configure readline for history and completion."""
        if not HAS_READLINE:
            return

        # Load history
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        if HISTORY_FILE.exists():
            try:
                readline.read_history_file(str(HISTORY_FILE))
            except Exception:
                pass

        # Set up completion
        tool_names = list(self._tools.keys())
        completer = ToolCompleter(tool_names)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t\n;")

        # Limit history size
        readline.set_history_length(1000)

    def _save_history(self):
        """Save command history to file."""
        if not HAS_READLINE:
            return
        try:
            readline.write_history_file(str(HISTORY_FILE))
        except Exception:
            pass

    def _log(self, message: str):
        """Log message to file if logging is enabled."""
        if self.log_file:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, "a") as f:
                f.write(f"[{timestamp}] {message}\n")

    def print_banner(self):
        """Print welcome banner."""
        banner = """
[bold cyan]╔═══════════════════════════════════════════════════════════════╗
║                    AIPTX Interactive Shell                    ║
║                   AI-Powered Penetration Testing              ║
╚═══════════════════════════════════════════════════════════════╝[/bold cyan]
"""
        console.print(banner)
        console.print("[dim]Type 'help' for commands, 'tools' to list available tools[/dim]")
        console.print(f"[dim]Working directory: {self.working_dir}[/dim]")

        if IS_WINDOWS:
            console.print("[dim yellow]Note: Running on Windows - some interactive features may be limited[/dim yellow]")

        console.print()

    def print_help(self):
        """Print help information."""
        help_text = """
[bold cyan]AIPTX Interactive Shell Commands[/bold cyan]

[bold]Built-in Commands:[/bold]
  help              Show this help message
  tools             List available security tools
  tools <category>  List tools in a category
  clear             Clear the screen
  history           Show command history
  env               Show environment variables
  env SET KEY=VAL   Set an environment variable
  cd <path>         Change working directory
  pwd               Print working directory
  log <file>        Start logging to file
  exit, quit        Exit the shell

[bold]Running Tools:[/bold]
  Just type the tool name and arguments:
    nmap -sV target.com
    nuclei -u https://target.com
    sqlmap -u "http://target.com?id=1"

[bold]Tips:[/bold]
  • Use TAB for auto-completion
  • Use UP/DOWN arrows for history
  • Ctrl+C interrupts running command
  • Ctrl+D exits the shell
"""
        console.print(help_text)

    def list_tools(self, category: Optional[str] = None):
        """List available tools, optionally filtered by category."""
        try:
            from aipt_v2.local_tool_installer import TOOLS, ToolCategory

            table = Table(title="Available Security Tools", box=box.ROUNDED)
            table.add_column("Tool", style="cyan")
            table.add_column("Category", style="dim")
            table.add_column("Installed", justify="center")
            table.add_column("Description")

            for name, tool in sorted(TOOLS.items()):
                if category and tool.category.value != category:
                    continue

                is_installed = shutil.which(name) is not None
                status = "[green]✓[/green]" if is_installed else "[dim]○[/dim]"

                desc = tool.description[:45] + "..." if len(tool.description) > 45 else tool.description

                table.add_row(name, tool.category.value, status, desc)

            console.print()
            console.print(table)
            console.print()

            if not category:
                console.print("[dim]Filter by category: tools <category>[/dim]")
                categories = sorted(set(t.category.value for t in TOOLS.values()))
                console.print(f"[dim]Categories: {', '.join(categories)}[/dim]")

        except ImportError:
            console.print("[yellow]Tool catalog not available[/yellow]")

    def show_history(self, count: int = 20):
        """Show command history."""
        if not HAS_READLINE:
            console.print("[yellow]Readline not available - history limited[/yellow]")
            # Show from our own history list
            recent = self.history[-count:] if len(self.history) > count else self.history
            console.print(f"\n[bold]Last {len(recent)} commands:[/bold]")
            for i, cmd in enumerate(recent, 1):
                console.print(f"  {i:4d}  {cmd}")
            console.print()
            return

        history_len = readline.get_current_history_length()
        start = max(1, history_len - count + 1)

        console.print(f"\n[bold]Last {min(count, history_len)} commands:[/bold]")
        for i in range(start, history_len + 1):
            cmd = readline.get_history_item(i)
            console.print(f"  {i:4d}  {cmd}")
        console.print()

    def show_env(self):
        """Show relevant environment variables."""
        relevant_prefixes = ["AIPT", "PATH", "HOME", "USER", "SHELL", "GOPATH", "GOBIN"]
        table = Table(title="Environment Variables", box=box.ROUNDED)
        table.add_column("Variable", style="cyan")
        table.add_column("Value", style="green", overflow="fold")

        for key, value in sorted(self.env.items()):
            if any(key.startswith(p) for p in relevant_prefixes):
                # Truncate long values
                display_val = value[:80] + "..." if len(value) > 80 else value
                table.add_row(key, display_val)

        console.print()
        console.print(table)
        console.print()

    def set_env(self, key: str, value: str):
        """Set an environment variable."""
        self.env[key] = value
        os.environ[key] = value
        console.print(f"[green]Set {key}={value}[/green]")

    def change_dir(self, path: str):
        """Change working directory."""
        try:
            new_path = Path(path).expanduser().resolve()
            if new_path.is_dir():
                os.chdir(new_path)
                self.working_dir = new_path
                console.print(f"[green]Changed to: {new_path}[/green]")
            else:
                console.print(f"[red]Not a directory: {path}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    async def run_command(self, command: str) -> int:
        """
        Run a command with real-time output.

        Uses PTY on Unix for proper terminal handling, allowing interactive
        tools to work correctly. Uses subprocess with threading on Windows.

        Args:
            command: Command to execute

        Returns:
            Exit code of the command
        """
        self._log(f"$ {command}")

        # Parse the command
        try:
            parts = shlex.split(command)
            if not parts:
                return 0
            program = parts[0]
        except ValueError as e:
            console.print(f"[red]Parse error: {e}[/red]")
            return 1

        # Check if tool exists
        if not shutil.which(program):
            console.print(f"[yellow]Command not found: {program}[/yellow]")

            # Check if it's a known tool that's not installed
            if program in self._tools:
                console.print(f"[dim]This tool is not installed. Run: aiptx tools install -t {program}[/dim]")
            return 127

        console.print()

        if IS_WINDOWS:
            return await self._run_command_windows(command)
        else:
            return await self._run_command_unix(command)

    async def _run_command_windows(self, command: str) -> int:
        """
        Run command on Windows using subprocess with threading.

        Args:
            command: Command to execute

        Returns:
            Exit code
        """
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=self.env,
                cwd=str(self.working_dir),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )

            output_lines = []
            queue = Queue()
            stop_event = threading.Event()

            def reader_thread():
                try:
                    while not stop_event.is_set():
                        line = process.stdout.readline()
                        if line:
                            queue.put(line)
                        elif process.poll() is not None:
                            break
                except Exception:
                    pass
                finally:
                    queue.put(None)

            thread = threading.Thread(target=reader_thread, daemon=True)
            thread.start()

            try:
                while True:
                    try:
                        line = queue.get(timeout=0.1)
                        if line is None:
                            break
                        text = line.decode("utf-8", errors="replace")
                        sys.stdout.write(text)
                        sys.stdout.flush()
                        output_lines.append(text.rstrip())
                        self._log(text.rstrip())
                    except Empty:
                        if process.poll() is not None:
                            # Drain remaining
                            while True:
                                try:
                                    line = queue.get_nowait()
                                    if line is None:
                                        break
                                    text = line.decode("utf-8", errors="replace")
                                    sys.stdout.write(text)
                                    sys.stdout.flush()
                                    output_lines.append(text.rstrip())
                                except Empty:
                                    break
                            break

            except KeyboardInterrupt:
                # Send CTRL_BREAK_EVENT to process group
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                        capture_output=True,
                        timeout=5
                    )
                except Exception:
                    process.kill()
                console.print("\n[yellow]Interrupted[/yellow]")

            finally:
                stop_event.set()
                thread.join(timeout=1)
                process.wait()

            return process.returncode or 0

        except Exception as e:
            console.print(f"[red]Error running command: {e}[/red]")
            return 1

    async def _run_command_unix(self, command: str) -> int:
        """
        Run command on Unix using PTY for full terminal support.

        Args:
            command: Command to execute

        Returns:
            Exit code
        """
        try:
            # Create pseudo-terminal
            master_fd, slave_fd = pty.openpty()

            # Start process
            process = subprocess.Popen(
                command,
                shell=True,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=self.env,
                cwd=str(self.working_dir),
                preexec_fn=os.setsid,
            )

            os.close(slave_fd)

            # Read output in real-time
            output_lines = []
            try:
                while True:
                    ready, _, _ = select.select([master_fd], [], [], 0.1)
                    if ready:
                        try:
                            data = os.read(master_fd, 1024)
                            if not data:
                                break
                            text = data.decode("utf-8", errors="replace")
                            sys.stdout.write(text)
                            sys.stdout.flush()
                            output_lines.append(text)
                            self._log(text.rstrip())
                        except OSError:
                            break

                    # Check if process finished
                    if process.poll() is not None:
                        # Read any remaining output
                        try:
                            while True:
                                ready, _, _ = select.select([master_fd], [], [], 0.1)
                                if not ready:
                                    break
                                data = os.read(master_fd, 1024)
                                if not data:
                                    break
                                text = data.decode("utf-8", errors="replace")
                                sys.stdout.write(text)
                                sys.stdout.flush()
                                output_lines.append(text)
                        except OSError:
                            pass
                        break

            except KeyboardInterrupt:
                # Send SIGINT to process group
                os.killpg(os.getpgid(process.pid), signal.SIGINT)
                console.print("\n[yellow]Interrupted[/yellow]")

            finally:
                os.close(master_fd)
                process.wait()

            return process.returncode or 0

        except Exception as e:
            console.print(f"[red]Error running command: {e}[/red]")
            return 1

    def process_builtin(self, command: str) -> Tuple[bool, int]:
        """
        Process built-in commands.

        Returns:
            Tuple of (is_builtin, exit_code)
        """
        parts = command.strip().split(maxsplit=1)
        if not parts:
            return True, 0

        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd in ("exit", "quit"):
            self.running = False
            return True, 0

        elif cmd == "help":
            self.print_help()
            return True, 0

        elif cmd == "tools":
            self.list_tools(args if args else None)
            return True, 0

        elif cmd == "clear":
            console.clear()
            return True, 0

        elif cmd == "history":
            count = int(args) if args.isdigit() else 20
            self.show_history(count)
            return True, 0

        elif cmd == "env":
            if args.startswith("SET ") or args.startswith("set "):
                # Set environment variable
                var_part = args[4:].strip()
                if "=" in var_part:
                    key, value = var_part.split("=", 1)
                    self.set_env(key.strip(), value.strip())
                else:
                    console.print("[yellow]Usage: env SET KEY=VALUE[/yellow]")
            else:
                self.show_env()
            return True, 0

        elif cmd == "cd":
            if args:
                self.change_dir(args)
            else:
                self.change_dir(str(Path.home()))
            return True, 0

        elif cmd == "pwd":
            console.print(str(self.working_dir))
            return True, 0

        elif cmd == "log":
            if args:
                self.log_file = Path(args).expanduser()
                console.print(f"[green]Logging to: {self.log_file}[/green]")
            else:
                if self.log_file:
                    console.print(f"[dim]Currently logging to: {self.log_file}[/dim]")
                else:
                    console.print("[dim]Logging disabled. Use: log <filename>[/dim]")
            return True, 0

        return False, 0

    async def run(self):
        """Run the interactive shell."""
        self.running = True
        self.print_banner()

        while self.running:
            try:
                # Build prompt
                cwd = str(self.working_dir)
                home = str(Path.home())
                if cwd.startswith(home):
                    cwd = "~" + cwd[len(home):]

                prompt = f"\n[bold green]aiptx[/bold green]:[bold blue]{cwd}[/bold blue]$ "
                console.print(prompt, end="")

                # Read input
                try:
                    command = input().strip()
                except EOFError:
                    console.print()
                    break

                if not command:
                    continue

                # Add to history
                self.history.append(command)

                # Check for built-in commands
                is_builtin, exit_code = self.process_builtin(command)
                if is_builtin:
                    continue

                # Run external command
                exit_code = await self.run_command(command)

                if exit_code != 0:
                    console.print(f"[dim]Exit code: {exit_code}[/dim]")

            except KeyboardInterrupt:
                console.print("\n[dim]Use 'exit' or Ctrl+D to quit[/dim]")
                continue

        # Save history on exit
        self._save_history()
        console.print("\n[dim]Goodbye![/dim]")


async def start_interactive_shell(
    log_file: Optional[str] = None,
    working_dir: Optional[str] = None,
) -> int:
    """
    Start the interactive shell.

    Args:
        log_file: Optional log file path
        working_dir: Optional working directory

    Returns:
        Exit code
    """
    shell = InteractiveShell(
        log_file=Path(log_file) if log_file else None,
        working_dir=Path(working_dir) if working_dir else None,
    )
    await shell.run()
    return 0


def main():
    """CLI entry point for interactive shell."""
    import argparse

    parser = argparse.ArgumentParser(description="AIPTX Interactive Shell")
    parser.add_argument(
        "--log", "-l",
        help="Log session to file"
    )
    parser.add_argument(
        "--dir", "-d",
        help="Working directory"
    )

    args = parser.parse_args()

    asyncio.run(start_interactive_shell(
        log_file=args.log,
        working_dir=args.dir,
    ))


if __name__ == "__main__":
    main()
