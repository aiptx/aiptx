"""
AIPTX Banner Display
====================

Beautiful ASCII art banners with module status display.

Usage:
    from aipt_v2.ui import print_banner, Banner

    # Quick print
    print_banner()

    # With module status
    print_banner(modules={
        'recon': True,
        'scan': True,
        'exploit': False,
        'report': True,
    })

    # Custom banner
    banner = Banner(style='cyber')
    banner.print(subtitle="Beast Mode Activated")
"""

from __future__ import annotations

import sys
import time
import random
from dataclasses import dataclass
from typing import Dict, Optional, List

from .animations import Colors


# ASCII Art Banners
BANNERS = {
    "default": r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ██╗██████╗ ████████╗██╗  ██╗                      ║
    ║    ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝                      ║
    ║    ███████║██║██████╔╝   ██║    ╚███╔╝                       ║
    ║    ██╔══██║██║██╔═══╝    ██║    ██╔██╗                       ║
    ║    ██║  ██║██║██║        ██║   ██╔╝ ██╗                      ║
    ║    ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝                      ║
    ║                                                               ║
    ║         AI-Powered Penetration Testing Framework              ║
    ║                     https://aiptx.io                          ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
""",
    "cyber": r"""
    ╭──────────────────────────────────────────────────────────────────╮
    │  ▄▄▄       ██▓ ██▓███  ▄▄▄█████▓▒██   ██▒                       │
    │ ▒████▄    ▓██▒▓██░  ██▒▓  ██▒ ▓▒▒▒ █ █ ▒░                       │
    │ ▒██  ▀█▄  ▒██▒▓██░ ██▓▒▒ ▓██░ ▒░░░  █   ░                       │
    │ ░██▄▄▄▄██ ░██░▒██▄█▓▒ ▒░ ▓██▓ ░  ░ █ █ ▒                        │
    │  ▓█   ▓██▒░██░▒██▒ ░  ░  ▒██▒ ░ ▒██▒ ▒██▒                       │
    │  ▒▒   ▓▒█░░▓  ▒▓▒░ ░  ░  ▒ ░░   ▒▒ ░ ░▓ ░                       │
    │   ▒   ▒▒ ░ ▒ ░░▒ ░         ░    ░░   ░▒ ░                       │
    │   ░   ▒    ▒ ░░░         ░       ░    ░                         │
    │       ░  ░ ░                     ░    ░                         │
    │                                                                  │
    │  ╔══════════════════════════════════════════════════════════╗   │
    │  ║   Beast Mode   │   AI-Powered Penetration Testing        ║   │
    │  ╚══════════════════════════════════════════════════════════╝   │
    ╰──────────────────────────────────────────────────────────────────╯
""",
    "minimal": r"""
    ┌─────────────────────────────────────────────────────────────┐
    │                                                             │
    │       _    ___ ____ _______  __                             │
    │      / \  |_ _|  _ \_   _\ \/ /                             │
    │     / _ \  | || |_) || |  \  /                              │
    │    / ___ \ | ||  __/ | |  /  \                              │
    │   /_/   \_\___|_|    |_| /_/\_\                             │
    │                                                             │
    │          AI-Powered Penetration Testing                     │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘
""",
    "hacker": r"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ║
    ║ ░░   █████╗ ██╗██████╗ ████████╗██╗  ██╗                      ░ ║
    ║ ░░  ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝                      ░ ║
    ║ ░░  ███████║██║██████╔╝   ██║    ╚███╔╝                       ░ ║
    ║ ░░  ██╔══██║██║██╔═══╝    ██║    ██╔██╗                       ░ ║
    ║ ░░  ██║  ██║██║██║        ██║   ██╔╝ ██╗                      ░ ║
    ║ ░░  ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝                      ░ ║
    ║ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ║
    ║                                                                  ║
    ║     ▓▓▓ AUTONOMOUS PENETRATION TESTING FRAMEWORK ▓▓▓            ║
    ║                     [ BEAST MODE READY ]                         ║
    ╚══════════════════════════════════════════════════════════════════╝
""",
    "neon": r"""

    ███╗   ██╗███████╗ ██████╗ ███╗   ██╗
    ████╗  ██║██╔════╝██╔═══██╗████╗  ██║    ╔═════════════════════╗
    ██╔██╗ ██║█████╗  ██║   ██║██╔██╗ ██║    ║  █████╗ ██╗██████╗  ║
    ██║╚██╗██║██╔══╝  ██║   ██║██║╚██╗██║    ║ ██╔══██╗██║██╔══██╗ ║
    ██║ ╚████║███████╗╚██████╔╝██║ ╚████║    ║ ███████║██║██████╔╝ ║
    ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝    ║ ██╔══██║██║██╔═══╝  ║
                                             ║ ██║  ██║██║██║      ║
    ████████╗██╗  ██╗                        ║ ╚═╝  ╚═╝╚═╝╚═╝      ║
    ╚══██╔══╝╚██╗██╔╝                        ╚═════════════════════╝
       ██║    ╚███╔╝   ═══════════════════════════════════════
       ██║    ██╔██╗       AI-Powered Penetration Testing
       ██║   ██╔╝ ██╗  ═══════════════════════════════════════
       ╚═╝   ╚═╝  ╚═╝

""",
    "box": r"""
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃                                                                 ┃
    ┃      █████╗ ██╗██████╗ ████████╗██╗  ██╗                       ┃
    ┃     ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝                       ┃
    ┃     ███████║██║██████╔╝   ██║    ╚███╔╝                        ┃
    ┃     ██╔══██║██║██╔═══╝    ██║    ██╔██╗                        ┃
    ┃     ██║  ██║██║██║        ██║   ██╔╝ ██╗                       ┃
    ┃     ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝                       ┃
    ┃                                                                 ┃
    ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
    ┃        Autonomous AI Penetration Testing Framework              ┃
    ┃                      v3.2.1 • aiptx.io                          ┃
    ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
    ┃                                                                 ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
""",
}

# Module status icons
MODULE_STATUS = {
    True: (f"{Colors.BRIGHT_GREEN}●{Colors.RESET}", "READY"),
    False: (f"{Colors.BRIGHT_RED}○{Colors.RESET}", "OFF"),
    "loading": (f"{Colors.BRIGHT_YELLOW}◐{Colors.RESET}", "LOADING"),
    "error": (f"{Colors.BRIGHT_RED}✗{Colors.RESET}", "ERROR"),
}


class Banner:
    """
    AIPTX Banner display with animations.

    Usage:
        banner = Banner(style='cyber', color=Colors.BRIGHT_CYAN)
        banner.print(subtitle="Beast Mode", animate=True)
    """

    def __init__(
        self,
        style: str = "default",
        color: str = Colors.BRIGHT_CYAN,
        accent_color: str = Colors.AIPTX_PURPLE,
    ):
        self.style = style
        self.color = color
        self.accent_color = accent_color
        self.banner_text = BANNERS.get(style, BANNERS["default"])

    def _apply_gradient(self, text: str) -> str:
        """Apply gradient coloring to banner."""
        lines = text.split("\n")
        result = []

        # Cyan to Purple gradient
        start = (0, 255, 255)  # Cyan
        end = (138, 43, 226)   # Purple

        for i, line in enumerate(lines):
            ratio = i / max(len(lines) - 1, 1)
            r = int(start[0] + (end[0] - start[0]) * ratio)
            g = int(start[1] + (end[1] - start[1]) * ratio)
            b = int(start[2] + (end[2] - start[2]) * ratio)
            result.append(f"\033[38;2;{r};{g};{b}m{line}{Colors.RESET}")

        return "\n".join(result)

    def _animate_reveal(self, text: str, speed: float = 0.01):
        """Animate banner reveal line by line."""
        lines = text.split("\n")
        sys.stdout.write(Colors.HIDE_CURSOR)

        for line in lines:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            time.sleep(speed)

        sys.stdout.write(Colors.SHOW_CURSOR)

    def print(
        self,
        subtitle: str = None,
        animate: bool = False,
        show_version: bool = True,
        modules: Dict[str, bool] = None,
    ):
        """Print the banner."""
        # Apply gradient
        banner = self._apply_gradient(self.banner_text)

        if animate:
            self._animate_reveal(banner, speed=0.02)
        else:
            print(banner)

        # Print subtitle
        if subtitle:
            print(f"    {Colors.BOLD}{self.accent_color}{subtitle}{Colors.RESET}\n")

        # Print module status
        if modules:
            self._print_modules(modules)

    def _print_modules(self, modules: Dict[str, bool]):
        """Print module status grid."""
        print(f"    {Colors.DIM}{'─' * 50}{Colors.RESET}")
        print(f"    {Colors.BOLD}Module Status:{Colors.RESET}")

        # Calculate grid layout
        items = list(modules.items())
        cols = 3
        rows = (len(items) + cols - 1) // cols

        for row in range(rows):
            line = "    "
            for col in range(cols):
                idx = row + col * rows
                if idx < len(items):
                    name, status = items[idx]
                    icon, status_text = MODULE_STATUS.get(status, MODULE_STATUS[False])
                    line += f"  {icon} {name:12} "
            print(line)

        print(f"    {Colors.DIM}{'─' * 50}{Colors.RESET}\n")


def print_banner(
    style: str = "default",
    subtitle: str = None,
    animate: bool = False,
    modules: Dict[str, bool] = None,
    version: str = "3.2.1",
):
    """
    Quick function to print AIPTX banner.

    Args:
        style: Banner style ('default', 'cyber', 'hacker', 'minimal', 'neon', 'box')
        subtitle: Optional subtitle text
        animate: Whether to animate the reveal
        modules: Dict of module names to status (True/False)
        version: Version string to display
    """
    banner = Banner(style=style)
    banner.print(subtitle=subtitle, animate=animate, modules=modules)


def print_startup_banner(target: str = None, mode: str = "scan"):
    """
    Print startup banner with target info.

    Args:
        target: Target URL/domain
        mode: Scan mode (scan, exploit, full)
    """
    print_banner(style="box", animate=False)

    if target:
        print(f"    {Colors.BOLD}Target:{Colors.RESET} {Colors.BRIGHT_CYAN}{target}{Colors.RESET}")
        print(f"    {Colors.BOLD}Mode:{Colors.RESET}   {Colors.BRIGHT_YELLOW}{mode.upper()}{Colors.RESET}")
        print(f"    {Colors.DIM}{'─' * 50}{Colors.RESET}\n")


def print_completion_banner(
    findings: int = 0,
    duration: float = 0,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
):
    """
    Print completion banner with summary.
    """
    print(f"\n    {Colors.DIM}{'═' * 50}{Colors.RESET}")
    print(f"    {Colors.BOLD}{Colors.BRIGHT_GREEN}✓ SCAN COMPLETE{Colors.RESET}")
    print(f"    {Colors.DIM}{'─' * 50}{Colors.RESET}")

    # Duration
    mins = int(duration // 60)
    secs = int(duration % 60)
    print(f"    Duration: {mins}m {secs}s")

    # Findings summary
    print(f"\n    {Colors.BOLD}Findings:{Colors.RESET} {findings} total")

    if critical > 0:
        print(f"    {Colors.BRIGHT_RED}● Critical:{Colors.RESET} {critical}")
    if high > 0:
        print(f"    {Colors.rgb(255, 165, 0)}● High:{Colors.RESET}     {high}")
    if medium > 0:
        print(f"    {Colors.BRIGHT_YELLOW}● Medium:{Colors.RESET}   {medium}")
    if low > 0:
        print(f"    {Colors.BRIGHT_BLUE}● Low:{Colors.RESET}      {low}")

    print(f"    {Colors.DIM}{'═' * 50}{Colors.RESET}\n")


# Demo function
def demo():
    """Demonstrate all banner styles."""
    print(f"\n{Colors.BOLD}Banner Style Demo{Colors.RESET}\n")

    for style in ["default", "cyber", "minimal", "hacker", "box"]:
        print(f"\n{Colors.BRIGHT_YELLOW}Style: {style}{Colors.RESET}")
        print_banner(
            style=style,
            modules={
                "Recon": True,
                "Scan": True,
                "Exploit": False,
                "Report": True,
                "LLM": "loading",
                "VPS": True,
            }
        )
        time.sleep(0.5)


if __name__ == "__main__":
    demo()
