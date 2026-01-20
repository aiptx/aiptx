"""
Cross-Platform Icons Module for AIPTX CLI
==========================================

Provides platform-aware icons and symbols that work correctly across:
- Windows Command Prompt (limited Unicode support)
- Windows PowerShell (better Unicode support)
- Windows Terminal (full Unicode/emoji support)
- macOS Terminal (full Unicode/emoji support)
- Linux terminals (varies by terminal emulator)

The module automatically detects terminal capabilities and provides
appropriate fallbacks for environments with limited Unicode support.
"""

from __future__ import annotations

import os
import sys
from typing import NamedTuple


class IconSet(NamedTuple):
    """A pair of icons: unicode (preferred) and ascii (fallback)."""
    unicode: str
    ascii: str


# Detection of terminal capabilities
def _detect_unicode_support() -> bool:
    """
    Detect if the terminal likely supports Unicode/emoji characters.

    Returns True if Unicode is likely supported, False otherwise.
    """
    # Check if we're in a non-interactive environment
    if not sys.stdout.isatty():
        return False

    # Windows-specific detection
    if sys.platform == "win32":
        # Windows Terminal and modern PowerShell support Unicode
        # Check for Windows Terminal
        if os.environ.get("WT_SESSION"):
            return True
        # Check for ConEmu/Cmder
        if os.environ.get("ConEmuANSI") == "ON":
            return True
        # Check for modern VS Code terminal
        if os.environ.get("TERM_PROGRAM") == "vscode":
            return True
        # Check for mintty (Git Bash, Cygwin)
        if "MSYSTEM" in os.environ:
            return True
        # Default Windows CMD doesn't support emoji well
        # Check codepage - 65001 is UTF-8
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            codepage = kernel32.GetConsoleOutputCP()
            if codepage == 65001:
                return True
        except Exception:
            pass
        # Assume limited support on basic Windows console
        return False

    # Unix-like systems generally support Unicode
    # Check LANG/LC_ALL for UTF-8
    lang = os.environ.get("LANG", "") + os.environ.get("LC_ALL", "")
    if "UTF-8" in lang.upper() or "UTF8" in lang.upper():
        return True

    # Check terminal type
    term = os.environ.get("TERM", "")
    if term in ("xterm-256color", "screen-256color", "tmux-256color"):
        return True

    # Default to True for Unix-like systems
    return sys.platform != "win32"


def _detect_emoji_support() -> bool:
    """
    Detect if the terminal likely supports emoji characters.

    Emoji support is more limited than basic Unicode support.
    """
    # First check basic Unicode support
    if not _detect_unicode_support():
        return False

    # Windows-specific: only modern terminals support emoji well
    if sys.platform == "win32":
        # Windows Terminal supports emoji
        if os.environ.get("WT_SESSION"):
            return True
        # VS Code terminal on Windows
        if os.environ.get("TERM_PROGRAM") == "vscode":
            return True
        # Most other Windows terminals don't render emoji correctly
        return False

    # macOS Terminal and iTerm2 support emoji
    if sys.platform == "darwin":
        return True

    # Linux: most modern terminal emulators support emoji
    term_program = os.environ.get("TERM_PROGRAM", "")
    if term_program in ("iTerm.app", "Apple_Terminal", "vscode", "Hyper"):
        return True

    # Check for common Linux terminals that support emoji
    # GNOME Terminal, Konsole, etc. generally support emoji
    if os.environ.get("COLORTERM") == "truecolor":
        return True

    # Default to True for Unix-like systems with UTF-8
    return True


# Cache the detection results
_UNICODE_SUPPORT: bool | None = None
_EMOJI_SUPPORT: bool | None = None


def supports_unicode() -> bool:
    """Check if the terminal supports Unicode characters."""
    global _UNICODE_SUPPORT
    if _UNICODE_SUPPORT is None:
        _UNICODE_SUPPORT = _detect_unicode_support()
    return _UNICODE_SUPPORT


def supports_emoji() -> bool:
    """Check if the terminal supports emoji characters."""
    global _EMOJI_SUPPORT
    if _EMOJI_SUPPORT is None:
        _EMOJI_SUPPORT = _detect_emoji_support()
    return _EMOJI_SUPPORT


def reset_detection() -> None:
    """Reset cached detection results (useful for testing)."""
    global _UNICODE_SUPPORT, _EMOJI_SUPPORT
    _UNICODE_SUPPORT = None
    _EMOJI_SUPPORT = None


# =============================================================================
# Icon Definitions
# =============================================================================

# Status icons
CHECK = IconSet("✓", "[OK]")
CROSS = IconSet("✗", "[X]")
WARNING = IconSet("⚠", "[!]")
INFO = IconSet("ℹ", "[i]")
BULLET = IconSet("•", "*")
ARROW = IconSet("→", "->")
CIRCLE_EMPTY = IconSet("○", "[ ]")
CIRCLE_FILLED = IconSet("●", "[*]")

# Action icons (emoji with ASCII fallbacks)
ROCKET = IconSet("🚀", "[>]")
SEARCH = IconSet("🔍", "[?]")
TARGET = IconSet("🎯", "[*]")
CLOUD = IconSet("☁️", "[~]")
GEAR = IconSet("⚙️", "[#]")
CHART = IconSet("📊", "[=]")
LIGHTBULB = IconSet("💡", "[!]")
GLOBE = IconSet("🌐", "[@]")
WRENCH = IconSet("🔧", "[+]")
AIRPLANE = IconSet("✈️", "[^]")
DESKTOP = IconSet("🖥️", "[D]")
PACKAGE = IconSet("📦", "[P]")
HOURGLASS = IconSet("⏳", "[.]")
SPARKLES = IconSet("✨", "[*]")

# AI/Tech icons
ROBOT = IconSet("🤖", "[A]")
BRAIN = IconSet("🧠", "[B]")
TOOLS = IconSet("🛠️", "[T]")
BOLT = IconSet("⚡", "[!]")
SHIELD = IconSet("🛡️", "[S]")
MONEY = IconSet("💰", "[$]")
INBOX = IconSet("📥", "[<]")
OUTBOX = IconSet("📤", "[>]")

# Box drawing (these generally work on most terminals)
BOX_H = IconSet("─", "-")
BOX_V = IconSet("│", "|")
BOX_TL = IconSet("╭", "+")
BOX_TR = IconSet("╮", "+")
BOX_BL = IconSet("╰", "+")
BOX_BR = IconSet("╯", "+")


def get_icon(icon: IconSet, prefer_ascii: bool = False) -> str:
    """
    Get the appropriate icon based on terminal capabilities.

    Args:
        icon: The IconSet containing unicode and ascii variants
        prefer_ascii: Force ASCII output regardless of terminal support

    Returns:
        The appropriate icon string for the current terminal
    """
    if prefer_ascii:
        return icon.ascii

    # For emoji icons (those with multi-byte sequences), check emoji support
    if len(icon.unicode.encode('utf-8')) > 3:  # Emoji are typically 4+ bytes
        if supports_emoji():
            return icon.unicode
        return icon.ascii

    # For basic Unicode symbols, check Unicode support
    if supports_unicode():
        return icon.unicode
    return icon.ascii


# =============================================================================
# Convenience Functions
# =============================================================================

def icon(name: str, prefer_ascii: bool = False) -> str:
    """
    Get an icon by name.

    Args:
        name: Icon name (e.g., 'check', 'rocket', 'warning')
        prefer_ascii: Force ASCII output

    Returns:
        The appropriate icon string

    Example:
        >>> print(f"{icon('check')} Task completed")
        ✓ Task completed  # or [OK] Task completed on Windows CMD
    """
    icons_map = {
        # Status
        "check": CHECK,
        "cross": CROSS,
        "warning": WARNING,
        "info": INFO,
        "bullet": BULLET,
        "arrow": ARROW,
        "circle_empty": CIRCLE_EMPTY,
        "circle_filled": CIRCLE_FILLED,
        # Actions
        "rocket": ROCKET,
        "search": SEARCH,
        "target": TARGET,
        "cloud": CLOUD,
        "gear": GEAR,
        "chart": CHART,
        "lightbulb": LIGHTBULB,
        "globe": GLOBE,
        "wrench": WRENCH,
        "airplane": AIRPLANE,
        "desktop": DESKTOP,
        "package": PACKAGE,
        "hourglass": HOURGLASS,
        "sparkles": SPARKLES,
        # AI/Tech
        "robot": ROBOT,
        "brain": BRAIN,
        "tools": TOOLS,
        "bolt": BOLT,
        "shield": SHIELD,
        "money": MONEY,
        "inbox": INBOX,
        "outbox": OUTBOX,
        # Box drawing
        "box_h": BOX_H,
        "box_v": BOX_V,
        "box_tl": BOX_TL,
        "box_tr": BOX_TR,
        "box_bl": BOX_BL,
        "box_br": BOX_BR,
    }

    icon_set = icons_map.get(name.lower())
    if icon_set is None:
        return name  # Return the name itself if not found

    return get_icon(icon_set, prefer_ascii)


# Shorthand functions for common icons
def check() -> str:
    """Get checkmark icon."""
    return get_icon(CHECK)


def cross() -> str:
    """Get cross/X icon."""
    return get_icon(CROSS)


def warning() -> str:
    """Get warning icon."""
    return get_icon(WARNING)


def bullet() -> str:
    """Get bullet point icon."""
    return get_icon(BULLET)


def arrow() -> str:
    """Get arrow icon."""
    return get_icon(ARROW)


def rocket() -> str:
    """Get rocket icon."""
    return get_icon(ROCKET)


def search() -> str:
    """Get search/magnifying glass icon."""
    return get_icon(SEARCH)


def target() -> str:
    """Get target icon."""
    return get_icon(TARGET)


def gear() -> str:
    """Get gear/settings icon."""
    return get_icon(GEAR)


def chart() -> str:
    """Get chart icon."""
    return get_icon(CHART)


def globe() -> str:
    """Get globe icon."""
    return get_icon(GLOBE)


def wrench() -> str:
    """Get wrench/tools icon."""
    return get_icon(WRENCH)


def shield() -> str:
    """Get shield icon."""
    return get_icon(SHIELD)


# =============================================================================
# Rich Console Integration
# =============================================================================

def rich_icon(name: str, style: str = "") -> str:
    """
    Get an icon formatted for Rich console output.

    Args:
        name: Icon name
        style: Optional Rich style string

    Returns:
        Icon string, optionally wrapped in Rich style markup

    Example:
        >>> console.print(f"{rich_icon('check', 'green')} Done!")
    """
    icon_str = icon(name)
    if style:
        return f"[{style}]{icon_str}[/{style}]"
    return icon_str
