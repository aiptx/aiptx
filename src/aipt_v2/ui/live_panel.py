"""
AIPTX Live Findings Panel
=========================

Real-time findings display panel that shows vulnerability counts,
severity breakdown, and scan progress during active scans.

Usage:
    from aipt_v2.ui.live_panel import LiveFindingsPanel, ScanDisplay

    # Create panel
    panel = LiveFindingsPanel(estimated_duration=3600)

    # Add findings as they come in
    panel.add_finding(finding)

    # Update current tool/phase
    panel.set_current_tool("nuclei")
    panel.set_current_phase("SCAN")

    # Render the panel (returns formatted string)
    output = panel.render()
"""

from __future__ import annotations

import sys
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .animations import Colors


@dataclass
class FindingSummary:
    """Lightweight finding summary for the live panel."""
    severity: str
    title: str
    url: str = ""
    timestamp: float = field(default_factory=time.time)


class LiveFindingsPanel:
    """
    Real-time findings display panel for AIPTX scans.

    Shows:
    - Severity breakdown (Critical/High/Medium/Low/Info counts)
    - Elapsed time and time remaining
    - Current phase and tool
    - Latest finding

    Thread-safe for use with async scanners.
    """

    # Severity colors and symbols
    SEVERITY_CONFIG = {
        "critical": {"symbol": "\U0001f534", "color": Colors.BRIGHT_RED, "label": "Critical"},
        "high": {"symbol": "\U0001f7e0", "color": Colors.BRIGHT_RED, "label": "High"},
        "medium": {"symbol": "\U0001f7e1", "color": Colors.BRIGHT_YELLOW, "label": "Medium"},
        "low": {"symbol": "\U0001f535", "color": Colors.BRIGHT_BLUE, "label": "Low"},
        "info": {"symbol": "\u26aa", "color": Colors.WHITE, "label": "Info"},
    }

    def __init__(
        self,
        estimated_duration: int = 3600,
        width: int = 32,
    ):
        """
        Initialize the live findings panel.

        Args:
            estimated_duration: Estimated scan duration in seconds (default 1 hour)
            width: Panel width in characters
        """
        self.estimated_duration = estimated_duration
        self.width = width
        self.start_time = time.time()

        # Findings storage by severity
        self.findings: Dict[str, List[FindingSummary]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        # Current state
        self.current_tool = ""
        self.current_phase = ""
        self.latest_finding: Optional[FindingSummary] = None
        self.tools_completed = 0
        self.tools_total = 0

        # Thread safety
        self._lock = threading.Lock()

    def add_finding(self, finding: Any) -> None:
        """
        Add a finding to the panel (thread-safe).

        Args:
            finding: Finding object with 'severity' and 'title' attributes
        """
        with self._lock:
            # Extract severity (handle various finding formats)
            if hasattr(finding, "severity"):
                severity = str(finding.severity).lower()
            elif isinstance(finding, dict):
                severity = str(finding.get("severity", "info")).lower()
            else:
                severity = "info"

            # Normalize severity
            if severity not in self.findings:
                severity = "info"

            # Extract title
            if hasattr(finding, "title"):
                title = finding.title
            elif hasattr(finding, "name"):
                title = finding.name
            elif isinstance(finding, dict):
                title = finding.get("title", finding.get("name", "Unknown"))
            else:
                title = str(finding)[:50]

            # Extract URL
            url = ""
            if hasattr(finding, "url"):
                url = finding.url
            elif hasattr(finding, "target"):
                url = finding.target
            elif isinstance(finding, dict):
                url = finding.get("url", finding.get("target", ""))

            # Create summary and store
            summary = FindingSummary(severity=severity, title=title, url=url)
            self.findings[severity].append(summary)
            self.latest_finding = summary

    def set_current_tool(self, tool: str) -> None:
        """Set the currently running tool name."""
        with self._lock:
            self.current_tool = tool

    def set_current_phase(self, phase: str) -> None:
        """Set the current scan phase."""
        with self._lock:
            self.current_phase = phase

    def set_progress(self, completed: int, total: int) -> None:
        """Set tools progress (completed/total)."""
        with self._lock:
            self.tools_completed = completed
            self.tools_total = total

    def get_total_count(self) -> int:
        """Get total findings count."""
        with self._lock:
            return sum(len(f) for f in self.findings.values())

    def _format_time(self, seconds: float) -> str:
        """Format seconds into HH:MM:SS."""
        if seconds < 0:
            seconds = 0
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    def _truncate(self, text: str, max_len: int) -> str:
        """Truncate text to max length with ellipsis."""
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."

    def render(self) -> str:
        """
        Render the panel as a formatted string.

        Returns:
            Formatted panel string with ANSI colors
        """
        with self._lock:
            elapsed = time.time() - self.start_time
            remaining = max(0, self.estimated_duration - elapsed)

            # Build panel content
            lines = []

            # Header
            header = " LIVE FINDINGS "
            pad = (self.width - len(header) - 2) // 2
            lines.append(
                f"{Colors.BRIGHT_CYAN}\u250c{'─' * pad}{header}{'─' * pad}\u2510{Colors.RESET}"
            )

            # Severity counts
            for sev_key in ["critical", "high", "medium", "low", "info"]:
                cfg = self.SEVERITY_CONFIG[sev_key]
                count = len(self.findings[sev_key])
                label = f"{cfg['label']}:"
                # Use colored count for non-zero
                if count > 0:
                    count_str = f"{cfg['color']}{count:>3}{Colors.RESET}"
                else:
                    count_str = f"{Colors.DIM}{count:>3}{Colors.RESET}"
                line = f"\u2502 {cfg['symbol']} {label:<10} {count_str}".ljust(self.width + 10) + f" {Colors.BRIGHT_CYAN}\u2502{Colors.RESET}"
                lines.append(f"{Colors.BRIGHT_CYAN}{line}")

            # Separator
            lines.append(f"{Colors.BRIGHT_CYAN}\u251c{'─' * (self.width - 2)}\u2524{Colors.RESET}")

            # Time info
            elapsed_str = self._format_time(elapsed)
            remaining_str = self._format_time(remaining)

            elapsed_line = f"\u2502 \u23f1\ufe0f  Elapsed:   {elapsed_str}".ljust(self.width + 8) + f" {Colors.BRIGHT_CYAN}\u2502{Colors.RESET}"
            lines.append(f"{Colors.BRIGHT_CYAN}{elapsed_line}")

            remaining_line = f"\u2502 \u23f3 Remaining: {remaining_str}".ljust(self.width + 8) + f" {Colors.BRIGHT_CYAN}\u2502{Colors.RESET}"
            lines.append(f"{Colors.BRIGHT_CYAN}{remaining_line}")

            # Separator
            lines.append(f"{Colors.BRIGHT_CYAN}\u251c{'─' * (self.width - 2)}\u2524{Colors.RESET}")

            # Current phase/tool
            phase_display = self._truncate(self.current_phase or "INIT", 16)
            phase_line = f"\u2502 \U0001f4cd Phase: {phase_display}".ljust(self.width + 6) + f" {Colors.BRIGHT_CYAN}\u2502{Colors.RESET}"
            lines.append(f"{Colors.BRIGHT_CYAN}{phase_line}")

            tool_display = self._truncate(self.current_tool or "Starting...", 16)
            tool_line = f"\u2502 \U0001f527 Tool:  {tool_display}".ljust(self.width + 6) + f" {Colors.BRIGHT_CYAN}\u2502{Colors.RESET}"
            lines.append(f"{Colors.BRIGHT_CYAN}{tool_line}")

            # Progress (if available)
            if self.tools_total > 0:
                progress_pct = (self.tools_completed / self.tools_total) * 100
                progress_line = f"\u2502 \U0001f4ca Progress: {self.tools_completed}/{self.tools_total} ({progress_pct:.0f}%)".ljust(self.width + 6) + f" {Colors.BRIGHT_CYAN}\u2502{Colors.RESET}"
                lines.append(f"{Colors.BRIGHT_CYAN}{progress_line}")

            # Latest finding (if any)
            if self.latest_finding:
                lines.append(f"{Colors.BRIGHT_CYAN}\u251c{'─' * (self.width - 2)}\u2524{Colors.RESET}")

                cfg = self.SEVERITY_CONFIG.get(self.latest_finding.severity, self.SEVERITY_CONFIG["info"])
                latest_title = self._truncate(self.latest_finding.title, self.width - 12)
                latest_line = f"\u2502 {cfg['symbol']} {Colors.RESET}{latest_title}".ljust(self.width + 10) + f" {Colors.BRIGHT_CYAN}\u2502{Colors.RESET}"
                lines.append(f"{Colors.BRIGHT_CYAN}{latest_line}")

            # Footer
            lines.append(f"{Colors.BRIGHT_CYAN}\u2514{'─' * (self.width - 2)}\u2518{Colors.RESET}")

            return "\n".join(lines)

    def render_compact(self) -> str:
        """
        Render a compact single-line summary.

        Returns:
            Single line summary string
        """
        with self._lock:
            counts = []
            for sev_key in ["critical", "high", "medium", "low"]:
                cfg = self.SEVERITY_CONFIG[sev_key]
                count = len(self.findings[sev_key])
                if count > 0:
                    counts.append(f"{cfg['symbol']}{count}")

            elapsed = time.time() - self.start_time
            elapsed_str = self._format_time(elapsed)

            if counts:
                findings_str = " ".join(counts)
            else:
                findings_str = f"{Colors.DIM}No findings yet{Colors.RESET}"

            return f"[{elapsed_str}] {findings_str} | {self.current_tool or 'Initializing...'}"


class ScanDisplay:
    """
    Split-screen scan display combining tool output with live findings panel.

    Creates a terminal layout with:
    - Left side: Current tool output/progress
    - Right side: Live findings panel

    Usage:
        panel = LiveFindingsPanel()
        display = ScanDisplay(panel)

        display.update_output("Scanning target...")
        display.refresh()
    """

    def __init__(
        self,
        live_panel: LiveFindingsPanel,
        output_width: int = 80,
    ):
        """
        Initialize split-screen display.

        Args:
            live_panel: LiveFindingsPanel instance
            output_width: Width for the main output area
        """
        self.live_panel = live_panel
        self.output_width = output_width
        self.output_lines: List[str] = []
        self.max_output_lines = 20
        self._lock = threading.Lock()
        self._running = False
        self._refresh_thread: Optional[threading.Thread] = None

    def add_output(self, line: str) -> None:
        """Add a line to the output buffer."""
        with self._lock:
            self.output_lines.append(line)
            # Keep only the last N lines
            if len(self.output_lines) > self.max_output_lines:
                self.output_lines = self.output_lines[-self.max_output_lines :]

    def clear_output(self) -> None:
        """Clear the output buffer."""
        with self._lock:
            self.output_lines = []

    def start_refresh(self, interval: float = 0.5) -> None:
        """Start auto-refresh thread."""
        self._running = True
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, args=(interval,), daemon=True
        )
        self._refresh_thread.start()

    def stop_refresh(self) -> None:
        """Stop auto-refresh thread."""
        self._running = False
        if self._refresh_thread:
            self._refresh_thread.join(timeout=1.0)

    def _refresh_loop(self, interval: float) -> None:
        """Refresh loop for auto-updating display."""
        while self._running:
            self.refresh()
            time.sleep(interval)

    def refresh(self) -> None:
        """Refresh the display."""
        with self._lock:
            # Get panel render
            panel_lines = self.live_panel.render().split("\n")

            # Get output lines
            output = self.output_lines[-self.max_output_lines :]

            # Pad output to match panel height
            while len(output) < len(panel_lines):
                output.append("")

            # Combine side by side
            combined_lines = []
            for i, panel_line in enumerate(panel_lines):
                if i < len(output):
                    out_line = output[i][:self.output_width].ljust(self.output_width)
                else:
                    out_line = " " * self.output_width

                combined_lines.append(f"{out_line}  {panel_line}")

            # Clear and redraw
            sys.stdout.write(Colors.HIDE_CURSOR)
            sys.stdout.write(f"\033[{len(combined_lines)}A")  # Move up

            for line in combined_lines:
                sys.stdout.write(Colors.CLEAR_LINE + line + "\n")

            sys.stdout.write(Colors.SHOW_CURSOR)
            sys.stdout.flush()

    def print_status_line(self) -> None:
        """Print a compact status line (for non-split mode)."""
        status = self.live_panel.render_compact()
        sys.stdout.write(f"\r{Colors.CLEAR_LINE}{status}")
        sys.stdout.flush()


# Convenience function
def create_live_panel(
    estimated_duration: int = 3600,
    full_mode: bool = False,
) -> LiveFindingsPanel:
    """
    Create a live findings panel with appropriate settings.

    Args:
        estimated_duration: Estimated scan duration in seconds
        full_mode: Whether this is a full scan (adjusts time estimate)

    Returns:
        Configured LiveFindingsPanel instance
    """
    if full_mode:
        estimated_duration = max(estimated_duration, 3600)  # Minimum 1 hour for full

    return LiveFindingsPanel(estimated_duration=estimated_duration)
