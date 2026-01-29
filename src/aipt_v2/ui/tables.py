"""
AIPTX Table Display
===================

Beautiful table formatting for findings, status, and data display.

Usage:
    from aipt_v2.ui import create_table, print_findings_table

    # Simple table
    table = create_table(
        headers=["Tool", "Status", "Findings"],
        rows=[
            ["Nmap", "Complete", "5"],
            ["Nikto", "Running", "2"],
        ]
    )
    print(table)

    # Findings table
    print_findings_table(findings)
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .animations import Colors


@dataclass
class TableStyle:
    """Table border style."""
    top_left: str = "┌"
    top_right: str = "┐"
    bottom_left: str = "└"
    bottom_right: str = "┘"
    horizontal: str = "─"
    vertical: str = "│"
    cross: str = "┼"
    top_t: str = "┬"
    bottom_t: str = "┴"
    left_t: str = "├"
    right_t: str = "┤"


# Predefined styles
TABLE_STYLES = {
    "default": TableStyle(),
    "rounded": TableStyle(
        top_left="╭", top_right="╮",
        bottom_left="╰", bottom_right="╯",
    ),
    "double": TableStyle(
        top_left="╔", top_right="╗",
        bottom_left="╚", bottom_right="╝",
        horizontal="═", vertical="║",
        cross="╬", top_t="╦", bottom_t="╩",
        left_t="╠", right_t="╣",
    ),
    "heavy": TableStyle(
        top_left="┏", top_right="┓",
        bottom_left="┗", bottom_right="┛",
        horizontal="━", vertical="┃",
        cross="╋", top_t="┳", bottom_t="┻",
        left_t="┣", right_t="┫",
    ),
    "minimal": TableStyle(
        top_left=" ", top_right=" ",
        bottom_left=" ", bottom_right=" ",
        horizontal="─", vertical=" ",
        cross="─", top_t="─", bottom_t="─",
        left_t="─", right_t="─",
    ),
}


def create_table(
    headers: List[str],
    rows: List[List[str]],
    style: str = "default",
    header_color: str = Colors.BOLD,
    border_color: str = Colors.DIM,
    min_width: int = 0,
    padding: int = 1,
) -> str:
    """
    Create a formatted table string.

    Args:
        headers: List of header strings
        rows: List of row data (each row is a list of strings)
        style: Table style ('default', 'rounded', 'double', 'heavy', 'minimal')
        header_color: Color for header text
        border_color: Color for borders
        min_width: Minimum column width
        padding: Cell padding

    Returns:
        Formatted table string
    """
    s = TABLE_STYLES.get(style, TABLE_STYLES["default"])

    # Calculate column widths
    col_widths = [max(min_width, len(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                # Strip ANSI codes for width calculation
                clean_cell = _strip_ansi(str(cell))
                col_widths[i] = max(col_widths[i], len(clean_cell))

    # Add padding
    col_widths = [w + padding * 2 for w in col_widths]

    # Build table
    lines = []

    # Top border
    top = s.top_left
    for i, w in enumerate(col_widths):
        top += s.horizontal * w
        top += s.top_t if i < len(col_widths) - 1 else s.top_right
    lines.append(f"{border_color}{top}{Colors.RESET}")

    # Header row
    header_row = s.vertical
    for i, (h, w) in enumerate(zip(headers, col_widths)):
        cell = f"{' ' * padding}{h}{' ' * padding}"
        cell = cell.ljust(w)
        header_row += f"{header_color}{cell}{Colors.RESET}{border_color}{s.vertical}{Colors.RESET}"
    lines.append(header_row)

    # Header separator
    sep = s.left_t
    for i, w in enumerate(col_widths):
        sep += s.horizontal * w
        sep += s.cross if i < len(col_widths) - 1 else s.right_t
    lines.append(f"{border_color}{sep}{Colors.RESET}")

    # Data rows
    for row in rows:
        data_row = f"{border_color}{s.vertical}{Colors.RESET}"
        for i, w in enumerate(col_widths):
            cell_data = str(row[i]) if i < len(row) else ""
            clean_len = len(_strip_ansi(cell_data))
            pad_needed = w - clean_len - padding
            cell = f"{' ' * padding}{cell_data}{' ' * max(0, pad_needed)}"
            data_row += f"{cell}{border_color}{s.vertical}{Colors.RESET}"
        lines.append(data_row)

    # Bottom border
    bottom = s.bottom_left
    for i, w in enumerate(col_widths):
        bottom += s.horizontal * w
        bottom += s.bottom_t if i < len(col_widths) - 1 else s.bottom_right
    lines.append(f"{border_color}{bottom}{Colors.RESET}")

    return "\n".join(lines)


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)


def print_findings_table(
    findings: List[Dict[str, Any]],
    max_rows: int = 20,
    show_details: bool = False,
):
    """
    Print a formatted findings table.

    Args:
        findings: List of finding dictionaries
        max_rows: Maximum rows to display
        show_details: Whether to show detailed info
    """
    if not findings:
        print(f"{Colors.DIM}No findings to display{Colors.RESET}")
        return

    # Severity colors
    severity_colors = {
        "critical": Colors.BRIGHT_RED,
        "high": Colors.rgb(255, 165, 0),
        "medium": Colors.BRIGHT_YELLOW,
        "low": Colors.BRIGHT_BLUE,
        "info": Colors.DIM,
    }

    headers = ["#", "Severity", "Type", "Finding", "Tool"]
    rows = []

    for i, finding in enumerate(findings[:max_rows], 1):
        severity = finding.get("severity", "info").lower()
        sev_color = severity_colors.get(severity, Colors.WHITE)

        rows.append([
            str(i),
            f"{sev_color}{severity.upper()}{Colors.RESET}",
            finding.get("type", "unknown"),
            _truncate(finding.get("value", ""), 40),
            finding.get("tool", ""),
        ])

    table = create_table(headers, rows, style="rounded")
    print(table)

    if len(findings) > max_rows:
        print(f"{Colors.DIM}... and {len(findings) - max_rows} more findings{Colors.RESET}")

    # Summary
    print(f"\n{Colors.BOLD}Summary:{Colors.RESET}")
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in severity_counts:
            color = severity_colors.get(sev, Colors.WHITE)
            print(f"  {color}● {sev.capitalize()}: {severity_counts[sev]}{Colors.RESET}")


def print_status_table(
    scanners: Dict[str, Dict[str, Any]],
    title: str = "Scanner Status",
):
    """
    Print scanner status table.

    Args:
        scanners: Dict of scanner name -> status info
        title: Table title
    """
    print(f"\n{Colors.BOLD}{title}{Colors.RESET}")

    headers = ["Scanner", "Status", "Details"]
    rows = []

    for name, info in scanners.items():
        status = info.get("status", "unknown")

        if status == "ok" or status is True:
            status_str = f"{Colors.BRIGHT_GREEN}[OK]{Colors.RESET}"
        elif status == "fail" or status is False:
            status_str = f"{Colors.BRIGHT_RED}[FAIL]{Colors.RESET}"
        elif status == "skip":
            status_str = f"{Colors.DIM}[SKIP]{Colors.RESET}"
        else:
            status_str = f"{Colors.BRIGHT_YELLOW}[{status.upper()}]{Colors.RESET}"

        details = info.get("message", info.get("error", ""))
        rows.append([name, status_str, _truncate(str(details), 40)])

    table = create_table(headers, rows, style="rounded")
    print(table)


def print_scan_progress_table(
    tools: List[Dict[str, Any]],
    title: str = "Scan Progress",
):
    """
    Print scan progress as a table with progress bars.

    Args:
        tools: List of tool status dicts with 'name', 'progress', 'status'
        title: Table title
    """
    print(f"\n{Colors.BOLD}{title}{Colors.RESET}")

    headers = ["Tool", "Progress", "Status"]
    rows = []

    for tool in tools:
        name = tool.get("name", "Unknown")
        progress = tool.get("progress", 0)
        status = tool.get("status", "pending")

        # Create mini progress bar
        bar_width = 20
        filled = int(bar_width * progress / 100)
        bar = f"{Colors.BRIGHT_CYAN}{'▰' * filled}{Colors.DIM}{'▱' * (bar_width - filled)}{Colors.RESET}"
        bar += f" {progress:3.0f}%"

        # Status color
        if status == "completed":
            status_str = f"{Colors.BRIGHT_GREEN}✓ Done{Colors.RESET}"
        elif status == "running":
            status_str = f"{Colors.BRIGHT_YELLOW}▸ Running{Colors.RESET}"
        elif status == "failed":
            status_str = f"{Colors.BRIGHT_RED}✗ Failed{Colors.RESET}"
        else:
            status_str = f"{Colors.DIM}○ Pending{Colors.RESET}"

        rows.append([name, bar, status_str])

    table = create_table(headers, rows, style="rounded")
    print(table)


def _truncate(text: str, max_len: int, suffix: str = "...") -> str:
    """Truncate text to max length."""
    if len(text) <= max_len:
        return text
    return text[:max_len - len(suffix)] + suffix


# Demo function
def demo():
    """Demonstrate table styles."""
    print(f"\n{Colors.BOLD}Table Demo{Colors.RESET}\n")

    # Basic table
    print(f"{Colors.BRIGHT_YELLOW}Basic Table:{Colors.RESET}")
    table = create_table(
        headers=["Tool", "Status", "Findings"],
        rows=[
            ["Nmap", f"{Colors.BRIGHT_GREEN}Complete{Colors.RESET}", "5"],
            ["Nikto", f"{Colors.BRIGHT_YELLOW}Running{Colors.RESET}", "2"],
            ["Nuclei", f"{Colors.DIM}Pending{Colors.RESET}", "0"],
        ],
        style="rounded"
    )
    print(table)

    # Different styles
    for style in ["default", "double", "heavy", "minimal"]:
        print(f"\n{Colors.BRIGHT_YELLOW}Style: {style}{Colors.RESET}")
        table = create_table(
            headers=["Name", "Value"],
            rows=[["Test", "Data"], ["More", "Info"]],
            style=style
        )
        print(table)

    # Scan progress
    print(f"\n{Colors.BRIGHT_YELLOW}Scan Progress:{Colors.RESET}")
    print_scan_progress_table([
        {"name": "Nmap", "progress": 100, "status": "completed"},
        {"name": "Nikto", "progress": 75, "status": "running"},
        {"name": "Nuclei", "progress": 30, "status": "running"},
        {"name": "SQLMap", "progress": 0, "status": "pending"},
    ])


if __name__ == "__main__":
    demo()
