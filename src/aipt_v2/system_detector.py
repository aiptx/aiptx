"""
AIPTX System Detector
=====================

Automatically detects the user's operating system, package manager,
and system capabilities for seamless tool installation.

Features:
- OS detection (Linux, macOS, Windows)
- Package manager detection (apt, brew, yum, pacman, choco)
- Architecture detection (x86_64, arm64)
- Capability checks (Docker, Python, Go, Ruby, etc.)
- Sudo/admin privilege detection

Usage:
    detector = SystemDetector()
    info = await detector.detect()
    print(f"OS: {info.os_name}, Package Manager: {info.package_manager}")
"""

import asyncio
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich import box


console = Console()


class OSType(Enum):
    """Supported operating systems."""
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class PackageManager(Enum):
    """Supported package managers."""
    APT = "apt"           # Debian/Ubuntu
    YUM = "yum"           # RHEL/CentOS/Fedora (older)
    DNF = "dnf"           # Fedora/RHEL 8+
    PACMAN = "pacman"     # Arch Linux
    ZYPPER = "zypper"     # openSUSE
    BREW = "brew"         # macOS Homebrew
    MACPORTS = "port"     # macOS MacPorts
    CHOCO = "choco"       # Windows Chocolatey
    SCOOP = "scoop"       # Windows Scoop
    WINGET = "winget"     # Windows Package Manager
    NIX = "nix"           # Nix package manager
    UNKNOWN = "unknown"


class Architecture(Enum):
    """CPU architectures."""
    X86_64 = "x86_64"
    ARM64 = "arm64"
    ARM32 = "arm32"
    X86 = "x86"
    UNKNOWN = "unknown"


@dataclass
class SystemCapabilities:
    """System capabilities and available runtimes."""
    has_docker: bool = False
    has_python3: bool = False
    has_pip: bool = False
    has_go: bool = False
    has_ruby: bool = False
    has_gem: bool = False
    has_node: bool = False
    has_npm: bool = False
    has_git: bool = False
    has_curl: bool = False
    has_wget: bool = False
    has_sudo: bool = False
    has_make: bool = False
    has_gcc: bool = False
    has_cargo: bool = False

    # Version info
    python_version: str = ""
    go_version: str = ""
    docker_version: str = ""

    def to_dict(self) -> Dict[str, bool]:
        """Convert to dictionary."""
        return {
            "docker": self.has_docker,
            "python3": self.has_python3,
            "pip": self.has_pip,
            "go": self.has_go,
            "ruby": self.has_ruby,
            "gem": self.has_gem,
            "node": self.has_node,
            "npm": self.has_npm,
            "git": self.has_git,
            "curl": self.has_curl,
            "wget": self.has_wget,
            "sudo": self.has_sudo,
            "make": self.has_make,
            "gcc": self.has_gcc,
            "cargo": self.has_cargo,
        }


@dataclass
class SystemInfo:
    """Complete system information."""
    os_type: OSType = OSType.UNKNOWN
    os_name: str = ""
    os_version: str = ""
    os_codename: str = ""
    architecture: Architecture = Architecture.UNKNOWN
    package_manager: PackageManager = PackageManager.UNKNOWN
    capabilities: SystemCapabilities = field(default_factory=SystemCapabilities)
    home_dir: Path = field(default_factory=Path.home)
    is_wsl: bool = False
    is_container: bool = False
    shell: str = ""

    def summary(self) -> str:
        """Return a human-readable summary."""
        return (
            f"{self.os_name} {self.os_version} ({self.architecture.value}) "
            f"with {self.package_manager.value}"
        )


class SystemDetector:
    """
    Detects system configuration for optimal tool installation.

    This class automatically detects:
    - Operating system type and version
    - CPU architecture
    - Available package manager
    - Installed runtimes and capabilities
    - Container/WSL environment
    """

    def __init__(self):
        self._info: Optional[SystemInfo] = None

    async def detect(self) -> SystemInfo:
        """
        Perform full system detection.

        Returns:
            SystemInfo with all detected information
        """
        info = SystemInfo()

        # Detect OS
        info.os_type = self._detect_os_type()
        info.os_name, info.os_version, info.os_codename = self._detect_os_details()
        info.architecture = self._detect_architecture()
        info.shell = os.environ.get("SHELL", "")

        # Check for special environments
        info.is_wsl = self._is_wsl()
        info.is_container = self._is_container()

        # Detect package manager
        info.package_manager = await self._detect_package_manager(info.os_type)

        # Detect capabilities
        info.capabilities = await self._detect_capabilities()

        self._info = info
        return info

    def _detect_os_type(self) -> OSType:
        """Detect the operating system type."""
        system = platform.system().lower()

        if system == "linux":
            return OSType.LINUX
        elif system == "darwin":
            return OSType.MACOS
        elif system == "windows":
            return OSType.WINDOWS
        else:
            return OSType.UNKNOWN

    def _detect_os_details(self) -> Tuple[str, str, str]:
        """Detect OS name, version, and codename."""
        system = platform.system().lower()
        version = platform.version()
        codename = ""
        name = platform.system()

        if system == "linux":
            # Try to read /etc/os-release for Linux
            try:
                os_release = {}
                with open("/etc/os-release") as f:
                    for line in f:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            os_release[key] = value.strip('"')

                name = os_release.get("NAME", "Linux")
                version = os_release.get("VERSION_ID", platform.release())
                codename = os_release.get("VERSION_CODENAME", "")
            except FileNotFoundError:
                name = "Linux"
                version = platform.release()

        elif system == "darwin":
            name = "macOS"
            # Get macOS version name
            mac_ver = platform.mac_ver()[0]
            version = mac_ver

            # Map version to codename
            version_codenames = {
                "15": "Sequoia",
                "14": "Sonoma",
                "13": "Ventura",
                "12": "Monterey",
                "11": "Big Sur",
                "10.15": "Catalina",
                "10.14": "Mojave",
            }
            major = mac_ver.split(".")[0] if mac_ver else ""
            codename = version_codenames.get(major, "")

        elif system == "windows":
            name = "Windows"
            version = platform.win32_ver()[0]

        return name, version, codename

    def _detect_architecture(self) -> Architecture:
        """Detect CPU architecture."""
        machine = platform.machine().lower()

        if machine in ("x86_64", "amd64"):
            return Architecture.X86_64
        elif machine in ("arm64", "aarch64"):
            return Architecture.ARM64
        elif machine in ("armv7l", "armv6l"):
            return Architecture.ARM32
        elif machine in ("i386", "i686"):
            return Architecture.X86
        else:
            return Architecture.UNKNOWN

    def _is_wsl(self) -> bool:
        """Check if running in Windows Subsystem for Linux."""
        if platform.system().lower() != "linux":
            return False

        # Check for WSL indicators
        try:
            with open("/proc/version") as f:
                version = f.read().lower()
                return "microsoft" in version or "wsl" in version
        except FileNotFoundError:
            return False

    def _is_container(self) -> bool:
        """Check if running inside a container."""
        # Check for Docker
        if os.path.exists("/.dockerenv"):
            return True

        # Check cgroup for container runtime
        try:
            with open("/proc/1/cgroup") as f:
                cgroup = f.read()
                if "docker" in cgroup or "kubepods" in cgroup or "lxc" in cgroup:
                    return True
        except FileNotFoundError:
            pass

        return False

    async def _detect_package_manager(self, os_type: OSType) -> PackageManager:
        """Detect the available package manager."""
        if os_type == OSType.MACOS:
            # Check for Homebrew first (most common)
            if shutil.which("brew"):
                return PackageManager.BREW
            elif shutil.which("port"):
                return PackageManager.MACPORTS
            elif shutil.which("nix"):
                return PackageManager.NIX

        elif os_type == OSType.LINUX:
            # Check common Linux package managers
            if shutil.which("apt") or shutil.which("apt-get"):
                return PackageManager.APT
            elif shutil.which("dnf"):
                return PackageManager.DNF
            elif shutil.which("yum"):
                return PackageManager.YUM
            elif shutil.which("pacman"):
                return PackageManager.PACMAN
            elif shutil.which("zypper"):
                return PackageManager.ZYPPER
            elif shutil.which("nix"):
                return PackageManager.NIX

        elif os_type == OSType.WINDOWS:
            # Check Windows package managers with fallback detection
            # winget is preferred as it's built into Windows 10/11
            if await self._check_windows_package_manager("winget"):
                return PackageManager.WINGET
            elif await self._check_windows_package_manager("choco"):
                return PackageManager.CHOCO
            elif await self._check_windows_package_manager("scoop"):
                return PackageManager.SCOOP
            # If none found, default to WINGET as it's easiest to install
            # and most Windows 10/11 systems can use it
            return PackageManager.WINGET

        return PackageManager.UNKNOWN

    async def _check_windows_package_manager(self, manager: str) -> bool:
        """Check if a Windows package manager is available."""
        # First check if it's in PATH
        if shutil.which(manager):
            return True

        # Try running via cmd.exe/powershell for managers not in PATH
        check_commands = {
            "winget": [
                "winget --version",
                "powershell -Command \"Get-Command winget -ErrorAction SilentlyContinue\"",
            ],
            "choco": [
                "choco --version",
                "powershell -Command \"Get-Command choco -ErrorAction SilentlyContinue\"",
                "cmd /c \"where choco\"",
            ],
            "scoop": [
                "scoop --version",
                "powershell -Command \"Get-Command scoop -ErrorAction SilentlyContinue\"",
            ],
        }

        for cmd in check_commands.get(manager, []):
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=10)
                if proc.returncode == 0:
                    return True
            except Exception:
                continue

        return False

    async def _detect_capabilities(self) -> SystemCapabilities:
        """Detect available tools and runtimes."""
        caps = SystemCapabilities()

        # Simple binary checks
        caps.has_docker = bool(shutil.which("docker"))
        caps.has_python3 = bool(shutil.which("python3") or shutil.which("python"))
        caps.has_pip = bool(shutil.which("pip3") or shutil.which("pip"))
        caps.has_go = bool(shutil.which("go"))
        caps.has_ruby = bool(shutil.which("ruby"))
        caps.has_gem = bool(shutil.which("gem"))
        caps.has_node = bool(shutil.which("node") or shutil.which("nodejs"))
        caps.has_npm = bool(shutil.which("npm"))
        caps.has_git = bool(shutil.which("git"))
        caps.has_curl = bool(shutil.which("curl"))
        caps.has_wget = bool(shutil.which("wget"))
        caps.has_make = bool(shutil.which("make"))
        caps.has_gcc = bool(shutil.which("gcc") or shutil.which("clang"))
        caps.has_cargo = bool(shutil.which("cargo"))

        # Check sudo/admin privileges
        caps.has_sudo = await self._check_sudo()

        # Get version info for key tools
        if caps.has_python3:
            caps.python_version = await self._get_command_output("python3 --version") or \
                                  await self._get_command_output("python --version") or ""

        if caps.has_go:
            caps.go_version = await self._get_command_output("go version") or ""

        if caps.has_docker:
            caps.docker_version = await self._get_command_output("docker --version") or ""

        return caps

    async def _check_sudo(self) -> bool:
        """Check if user has sudo privileges."""
        if platform.system().lower() == "windows":
            # Check for admin on Windows
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            # Check sudo on Unix
            try:
                proc = await asyncio.create_subprocess_shell(
                    "sudo -n true 2>/dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                return proc.returncode == 0
            except Exception:
                return False

    async def _get_command_output(self, command: str) -> Optional[str]:
        """Run a command and return its output."""
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode == 0:
                return stdout.decode().strip()
        except Exception:
            pass
        return None

    def print_summary(self, info: Optional[SystemInfo] = None):
        """Print a formatted summary of system information."""
        info = info or self._info
        if not info:
            console.print("[red]No system information available. Run detect() first.[/red]")
            return

        console.print()
        console.print("[bold cyan]System Detection Results[/bold cyan]")
        console.print("=" * 50)

        # OS Info
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Operating System", info.os_name)
        table.add_row("Version", f"{info.os_version}" + (f" ({info.os_codename})" if info.os_codename else ""))
        table.add_row("Architecture", info.architecture.value)
        table.add_row("Package Manager", info.package_manager.value)

        if info.is_wsl:
            table.add_row("Environment", "WSL (Windows Subsystem for Linux)")
        elif info.is_container:
            table.add_row("Environment", "Container (Docker/Podman)")

        console.print(table)

        # Capabilities
        console.print("\n[bold cyan]Available Runtimes & Tools[/bold cyan]")

        caps_table = Table(box=box.ROUNDED)
        caps_table.add_column("Tool", style="cyan")
        caps_table.add_column("Status", justify="center")
        caps_table.add_column("Version", style="dim")

        caps = info.capabilities

        caps_table.add_row(
            "Python 3",
            "[green]✓[/green]" if caps.has_python3 else "[red]✗[/red]",
            caps.python_version.replace("Python ", "") if caps.python_version else ""
        )
        caps_table.add_row(
            "pip",
            "[green]✓[/green]" if caps.has_pip else "[red]✗[/red]",
            ""
        )
        caps_table.add_row(
            "Go",
            "[green]✓[/green]" if caps.has_go else "[red]✗[/red]",
            caps.go_version.replace("go version ", "").split()[0] if caps.go_version else ""
        )
        caps_table.add_row(
            "Docker",
            "[green]✓[/green]" if caps.has_docker else "[yellow]○[/yellow]",
            caps.docker_version.replace("Docker version ", "").split(",")[0] if caps.docker_version else ""
        )
        caps_table.add_row(
            "Git",
            "[green]✓[/green]" if caps.has_git else "[red]✗[/red]",
            ""
        )
        caps_table.add_row(
            "Ruby/Gem",
            "[green]✓[/green]" if caps.has_ruby else "[yellow]○[/yellow]",
            ""
        )
        caps_table.add_row(
            "Rust/Cargo",
            "[green]✓[/green]" if caps.has_cargo else "[yellow]○[/yellow]",
            ""
        )
        caps_table.add_row(
            "Node.js",
            "[green]✓[/green]" if caps.has_node else "[yellow]○[/yellow]",
            ""
        )
        caps_table.add_row(
            "sudo/admin",
            "[green]✓[/green]" if caps.has_sudo else "[yellow]○[/yellow]",
            ""
        )

        console.print(caps_table)
        console.print()

        # Show legend
        console.print("[dim]Legend: [green]✓[/green] Available  [yellow]○[/yellow] Optional  [red]✗[/red] Required[/dim]")


# Convenience functions
async def detect_system() -> SystemInfo:
    """Detect system information."""
    detector = SystemDetector()
    return await detector.detect()


async def get_package_manager() -> PackageManager:
    """Get the system's package manager."""
    info = await detect_system()
    return info.package_manager


async def check_prerequisites() -> Tuple[bool, List[str]]:
    """
    Check if system has all prerequisites for AIPTX.

    Returns:
        Tuple of (all_ok, list_of_missing_items)
    """
    info = await detect_system()
    caps = info.capabilities
    missing = []

    # Required
    if not caps.has_python3:
        missing.append("Python 3.9+")
    if not caps.has_pip:
        missing.append("pip")
    if not caps.has_git:
        missing.append("git")
    if not caps.has_curl and not caps.has_wget:
        missing.append("curl or wget")

    # Recommended for full functionality
    if not caps.has_go:
        missing.append("Go (for some security tools)")

    return len(missing) == 0, missing


if __name__ == "__main__":
    # Test detection
    async def main():
        detector = SystemDetector()
        info = await detector.detect()
        detector.print_summary(info)

    asyncio.run(main())
