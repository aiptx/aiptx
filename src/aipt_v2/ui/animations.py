"""
AIPTX Terminal Animations
=========================

Beautiful spinner animations, progress bars, and visual effects for CLI.

Usage:
    from aipt_v2.ui import Spinner, ProgressBar, MultiProgress, Colors

    # Spinner
    with Spinner("Scanning target...", style='cyber') as spinner:
        do_work()
        spinner.update("Found vulnerabilities...")

    # Progress Bar
    bar = ProgressBar(total=100, style='hacker')
    for i in range(101):
        bar.update(i, f"Processing {i}%")
    bar.finish()

    # Multi-task Progress
    mp = MultiProgress([
        {'name': 'Nmap', 'total': 100},
        {'name': 'Nikto', 'total': 100},
    ])
    mp.update(0, 50)
    mp.complete(1)
"""

from __future__ import annotations

import sys
import time
import threading
import random
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime


class Colors:
    """ANSI color codes for terminal styling."""

    # Reset
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    HIDDEN = "\033[8m"

    # Regular Colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright Colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background Colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    # Cursor Control
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"
    CLEAR_LINE = "\033[2K"
    MOVE_UP = "\033[1A"
    MOVE_DOWN = "\033[1B"
    SAVE_POS = "\033[s"
    RESTORE_POS = "\033[u"

    # AIPTX Brand Colors
    AIPTX_CYAN = "\033[38;5;51m"
    AIPTX_PURPLE = "\033[38;5;135m"
    AIPTX_ORANGE = "\033[38;5;208m"
    AIPTX_PINK = "\033[38;5;198m"
    AIPTX_GREEN = "\033[38;5;46m"

    @classmethod
    def rgb(cls, r: int, g: int, b: int) -> str:
        """Create RGB color code."""
        return f"\033[38;2;{r};{g};{b}m"

    @classmethod
    def bg_rgb(cls, r: int, g: int, b: int) -> str:
        """Create RGB background color code."""
        return f"\033[48;2;{r};{g};{b}m"

    @classmethod
    def gradient(cls, text: str, start_color: tuple, end_color: tuple) -> str:
        """Apply gradient color to text."""
        result = []
        length = len(text)
        for i, char in enumerate(text):
            ratio = i / max(length - 1, 1)
            r = int(start_color[0] + (end_color[0] - start_color[0]) * ratio)
            g = int(start_color[1] + (end_color[1] - start_color[1]) * ratio)
            b = int(start_color[2] + (end_color[2] - start_color[2]) * ratio)
            result.append(f"\033[38;2;{r};{g};{b}m{char}")
        return "".join(result) + cls.RESET


# Spinner animation frames
SPINNER_STYLES = {
    # Braille dots
    "dots": ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
    "dots2": ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"],
    "dots3": ["⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"],
    "dots4": ["⠃", "⠊", "⠒", "⠢", "⠆", "⠰", "⠤", "⠖", "⠲", "⠴", "⠦", "⠧"],

    # Lines and arrows
    "line": ["-", "\\", "|", "/"],
    "line2": ["◐", "◓", "◑", "◒"],
    "arrow": ["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"],
    "arrow2": ["⬆️ ", "↗️ ", "➡️ ", "↘️ ", "⬇️ ", "↙️ ", "⬅️ ", "↖️ "],

    # Shapes
    "circle": ["◜", "◠", "◝", "◞", "◡", "◟"],
    "square": ["◰", "◳", "◲", "◱"],
    "triangle": ["◢", "◣", "◤", "◥"],
    "star": ["✶", "✸", "✹", "✺", "✹", "✷"],

    # Blocks
    "block": ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃", "▁"],
    "block2": ["▖", "▘", "▝", "▗"],
    "pulse": ["█", "▓", "▒", "░", "▒", "▓"],
    "grow": ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃", "▂"],

    # Cyber/Hacker style
    "cyber": ["◢", "◣", "◤", "◥", "▪", "▫"],
    "hacker": ["⟨⟩", "⟪⟫", "⟬⟭", "⟮⟯"],
    "matrix": ["0", "1", "0", "1", "▓", "░"],
    "snake": ["⠏", "⠛", "⠹", "⢸", "⣰", "⣤", "⣆", "⡇"],

    # Bouncing
    "bounce": ["⠁", "⠂", "⠄", "⠂"],
    "bounce2": [".", "o", "O", "o"],

    # Clock
    "clock": ["🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚", "🕛"],

    # Simple
    "simple": ["◜ ", " ◝", " ◞", "◟ "],
}


class Spinner:
    """
    Animated spinner for terminal.

    Usage:
        # As context manager
        with Spinner("Loading...", style='cyber') as spinner:
            do_work()

        # Manual control
        spinner = Spinner("Scanning...")
        spinner.start()
        do_work()
        spinner.stop(success=True)
    """

    def __init__(
        self,
        message: str = "Loading...",
        style: str = "dots",
        color: str = Colors.BRIGHT_CYAN,
        speed: float = 0.1,
        success_symbol: str = "✓",
        fail_symbol: str = "✗",
        success_color: str = Colors.BRIGHT_GREEN,
        fail_color: str = Colors.BRIGHT_RED,
    ):
        self.message = message
        self.frames = SPINNER_STYLES.get(style, SPINNER_STYLES["dots"])
        self.color = color
        self.speed = speed
        self.success_symbol = success_symbol
        self.fail_symbol = fail_symbol
        self.success_color = success_color
        self.fail_color = fail_color

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._frame_index = 0
        self._start_time: Optional[float] = None

    def start(self) -> "Spinner":
        """Start the spinner animation."""
        if self._running:
            return self

        self._running = True
        self._start_time = time.time()
        sys.stdout.write(Colors.HIDE_CURSOR)
        sys.stdout.flush()

        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self):
        """Spinner animation loop."""
        while self._running:
            frame = self.frames[self._frame_index % len(self.frames)]
            elapsed = time.time() - self._start_time if self._start_time else 0
            elapsed_str = f" ({elapsed:.1f}s)" if elapsed > 1 else ""

            line = f"\r{self.color}{frame}{Colors.RESET} {self.message}{Colors.DIM}{elapsed_str}{Colors.RESET}"
            sys.stdout.write(Colors.CLEAR_LINE + line)
            sys.stdout.flush()

            self._frame_index += 1
            time.sleep(self.speed)

    def update(self, message: str):
        """Update spinner message."""
        self.message = message

    def stop(self, success: bool = True, final_message: str = None):
        """Stop the spinner with success/failure indicator."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)

        elapsed = time.time() - self._start_time if self._start_time else 0
        elapsed_str = f" ({elapsed:.1f}s)"

        symbol = self.success_symbol if success else self.fail_symbol
        color = self.success_color if success else self.fail_color
        msg = final_message if final_message else self.message

        line = f"\r{color}{symbol}{Colors.RESET} {msg}{Colors.DIM}{elapsed_str}{Colors.RESET}\n"
        sys.stdout.write(Colors.CLEAR_LINE + line)
        sys.stdout.write(Colors.SHOW_CURSOR)
        sys.stdout.flush()

    def __enter__(self) -> "Spinner":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop(success=exc_type is None)


# Progress bar styles
PROGRESS_STYLES = {
    "cyber": {
        "left": "【",
        "right": "】",
        "fill": "▰",
        "empty": "▱",
        "fill_color": Colors.BRIGHT_CYAN,
        "empty_color": Colors.DIM,
    },
    "hacker": {
        "left": "⟨",
        "right": "⟩",
        "fill": "█",
        "empty": "░",
        "fill_color": Colors.BRIGHT_GREEN,
        "empty_color": Colors.DIM,
    },
    "modern": {
        "left": "",
        "right": "",
        "fill": "━",
        "empty": "─",
        "fill_color": Colors.BRIGHT_MAGENTA,
        "empty_color": Colors.DIM,
    },
    "blocks": {
        "left": "",
        "right": "",
        "fill": "▓",
        "empty": "░",
        "fill_color": Colors.BRIGHT_YELLOW,
        "empty_color": Colors.DIM,
    },
    "minimal": {
        "left": "[",
        "right": "]",
        "fill": "=",
        "empty": " ",
        "fill_color": Colors.WHITE,
        "empty_color": Colors.DIM,
    },
    "dots": {
        "left": "⟨",
        "right": "⟩",
        "fill": "●",
        "empty": "○",
        "fill_color": Colors.BRIGHT_BLUE,
        "empty_color": Colors.DIM,
    },
    "arrows": {
        "left": "",
        "right": "▶",
        "fill": "═",
        "empty": "─",
        "fill_color": Colors.BRIGHT_CYAN,
        "empty_color": Colors.DIM,
    },
    "pulse": {
        "left": "⟦",
        "right": "⟧",
        "fill": "▮",
        "empty": "▯",
        "fill_color": Colors.AIPTX_CYAN,
        "empty_color": Colors.DIM,
    },
    "neon": {
        "left": "◄",
        "right": "►",
        "fill": "■",
        "empty": "□",
        "fill_color": Colors.AIPTX_PINK,
        "empty_color": Colors.DIM,
    },
    "fire": {
        "left": "🔥",
        "right": "",
        "fill": "█",
        "empty": "░",
        "fill_color": Colors.BRIGHT_RED,
        "empty_color": Colors.DIM,
    },
    "gradient": {
        "left": "",
        "right": "",
        "fill": "█",
        "empty": "░",
        "fill_color": None,  # Special handling
        "empty_color": Colors.DIM,
    },
}


class ProgressBar:
    """
    Beautiful progress bar with multiple styles.

    Usage:
        bar = ProgressBar(total=100, style='cyber')
        for i in range(101):
            bar.update(i, f"Processing {i}%")
            time.sleep(0.05)
        bar.finish("Complete!")
    """

    def __init__(
        self,
        total: int = 100,
        width: int = 30,
        style: str = "cyber",
        show_percentage: bool = True,
        show_eta: bool = True,
        show_count: bool = False,
        prefix: str = "",
        color: str = None,
    ):
        self.total = total
        self.width = width
        self.style_config = PROGRESS_STYLES.get(style, PROGRESS_STYLES["cyber"])
        self.show_percentage = show_percentage
        self.show_eta = show_eta
        self.show_count = show_count
        self.prefix = prefix
        self.color = color or self.style_config.get("fill_color", Colors.BRIGHT_CYAN)

        self.current = 0
        self._start_time = time.time()
        self._hidden_cursor = False

    def _format_time(self, seconds: float) -> str:
        """Format seconds into readable time."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds // 60:.0f}m {seconds % 60:.0f}s"
        else:
            return f"{seconds // 3600:.0f}h {(seconds % 3600) // 60:.0f}m"

    def _get_gradient_char(self, position: float) -> str:
        """Get gradient colored character."""
        # Red -> Yellow -> Green gradient
        if position < 0.5:
            r = 255
            g = int(255 * (position * 2))
            b = 0
        else:
            r = int(255 * (1 - (position - 0.5) * 2))
            g = 255
            b = 0
        return f"\033[38;2;{r};{g};{b}m{self.style_config['fill']}"

    def update(self, current: int, message: str = ""):
        """Update progress bar."""
        if not self._hidden_cursor:
            sys.stdout.write(Colors.HIDE_CURSOR)
            self._hidden_cursor = True

        self.current = min(current, self.total)
        progress = self.current / self.total if self.total > 0 else 0
        filled = int(self.width * progress)
        empty = self.width - filled

        # Build progress bar
        cfg = self.style_config

        if cfg.get("fill_color") is None:  # Gradient style
            bar_fill = "".join(
                self._get_gradient_char(i / self.width) for i in range(filled)
            )
            bar_fill += Colors.RESET
        else:
            bar_fill = f"{self.color}{cfg['fill'] * filled}{Colors.RESET}"

        bar_empty = f"{cfg['empty_color']}{cfg['empty'] * empty}{Colors.RESET}"
        bar = f"{cfg['left']}{bar_fill}{bar_empty}{cfg['right']}"

        # Build info string
        info_parts = []
        if self.show_percentage:
            info_parts.append(f"{progress * 100:5.1f}%")
        if self.show_count:
            info_parts.append(f"{self.current}/{self.total}")
        if self.show_eta and progress > 0:
            elapsed = time.time() - self._start_time
            eta = (elapsed / progress) * (1 - progress) if progress < 1 else 0
            info_parts.append(f"ETA: {self._format_time(eta)}")

        info = " ".join(info_parts)
        prefix = f"{self.prefix} " if self.prefix else ""

        # Build and print line
        line = f"\r{prefix}{bar} {info}"
        if message:
            line += f" {Colors.DIM}{message}{Colors.RESET}"

        sys.stdout.write(Colors.CLEAR_LINE + line)
        sys.stdout.flush()

    def finish(self, message: str = "Complete"):
        """Finish progress bar."""
        self.update(self.total)
        elapsed = time.time() - self._start_time
        sys.stdout.write(f" {Colors.BRIGHT_GREEN}✓{Colors.RESET} {message}")
        sys.stdout.write(f" {Colors.DIM}({self._format_time(elapsed)}){Colors.RESET}\n")
        sys.stdout.write(Colors.SHOW_CURSOR)
        sys.stdout.flush()

    def fail(self, message: str = "Failed"):
        """Mark progress as failed."""
        sys.stdout.write(f" {Colors.BRIGHT_RED}✗{Colors.RESET} {message}\n")
        sys.stdout.write(Colors.SHOW_CURSOR)
        sys.stdout.flush()


@dataclass
class TaskState:
    """State of a task in MultiProgress."""
    name: str
    total: int = 100
    current: int = 0
    status: str = "pending"  # pending, running, completed, failed
    color: str = Colors.BRIGHT_CYAN
    message: str = ""


class MultiProgress:
    """
    Multi-task progress display.

    Usage:
        tasks = [
            {'name': 'Nmap Scan', 'total': 100, 'color': Colors.BRIGHT_CYAN},
            {'name': 'Nikto', 'total': 100, 'color': Colors.BRIGHT_GREEN},
            {'name': 'Nuclei', 'total': 100, 'color': Colors.BRIGHT_YELLOW},
        ]
        mp = MultiProgress(tasks)
        mp.update(0, 50, status='running')
        mp.complete(0)
        mp.update(1, 75, status='running')
        mp.close()
    """

    STATUS_SYMBOLS = {
        "pending": ("○", Colors.DIM),
        "running": ("▸", Colors.BRIGHT_YELLOW),
        "completed": ("✓", Colors.BRIGHT_GREEN),
        "failed": ("✗", Colors.BRIGHT_RED),
        "skipped": ("⊘", Colors.DIM),
    }

    def __init__(
        self,
        tasks: List[Dict[str, Any]],
        bar_width: int = 30,
        name_width: int = 16,
    ):
        self.tasks = [
            TaskState(
                name=t.get("name", f"Task {i}"),
                total=t.get("total", 100),
                color=t.get("color", Colors.BRIGHT_CYAN),
            )
            for i, t in enumerate(tasks)
        ]
        self.bar_width = bar_width
        self.name_width = name_width
        self._displayed = False
        self._lock = threading.Lock()

    def _render_task(self, task: TaskState) -> str:
        """Render a single task line."""
        # Status symbol
        symbol, symbol_color = self.STATUS_SYMBOLS.get(
            task.status, self.STATUS_SYMBOLS["pending"]
        )

        # Name (padded)
        name = task.name[:self.name_width].ljust(self.name_width)

        # Progress bar
        progress = task.current / task.total if task.total > 0 else 0
        filled = int(self.bar_width * progress)
        empty = self.bar_width - filled

        bar = f"{task.color}{'▰' * filled}{Colors.RESET}{Colors.DIM}{'▱' * empty}{Colors.RESET}"

        # Percentage
        pct = f"{progress * 100:5.1f}%"

        return f"  {symbol_color}{symbol}{Colors.RESET} {name} {bar} {pct}"

    def _display(self):
        """Display all tasks."""
        with self._lock:
            if self._displayed:
                # Move cursor up to overwrite
                sys.stdout.write(f"\033[{len(self.tasks)}A")

            sys.stdout.write(Colors.HIDE_CURSOR)

            for task in self.tasks:
                line = self._render_task(task)
                sys.stdout.write(Colors.CLEAR_LINE + line + "\n")

            sys.stdout.flush()
            self._displayed = True

    def update(
        self,
        task_index: int,
        current: int,
        status: str = "running",
        message: str = "",
    ):
        """Update a task's progress."""
        if 0 <= task_index < len(self.tasks):
            self.tasks[task_index].current = current
            self.tasks[task_index].status = status
            self.tasks[task_index].message = message
            self._display()

    def complete(self, task_index: int, message: str = ""):
        """Mark a task as completed."""
        if 0 <= task_index < len(self.tasks):
            self.tasks[task_index].current = self.tasks[task_index].total
            self.tasks[task_index].status = "completed"
            self.tasks[task_index].message = message
            self._display()

    def fail(self, task_index: int, message: str = ""):
        """Mark a task as failed."""
        if 0 <= task_index < len(self.tasks):
            self.tasks[task_index].status = "failed"
            self.tasks[task_index].message = message
            self._display()

    def skip(self, task_index: int, message: str = ""):
        """Mark a task as skipped."""
        if 0 <= task_index < len(self.tasks):
            self.tasks[task_index].status = "skipped"
            self.tasks[task_index].message = message
            self._display()

    def close(self):
        """Close and cleanup."""
        sys.stdout.write(Colors.SHOW_CURSOR)
        sys.stdout.flush()


class TypeWriter:
    """
    Typewriter effect for text.

    Usage:
        TypeWriter.print("Initializing AIPTX...", speed=0.03)
    """

    @staticmethod
    def print(
        text: str,
        speed: float = 0.03,
        color: str = Colors.BRIGHT_GREEN,
        end: str = "\n",
    ):
        """Print text with typewriter effect."""
        sys.stdout.write(color)
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(speed)
        sys.stdout.write(Colors.RESET + end)
        sys.stdout.flush()


class PulseText:
    """
    Pulsing/blinking text effect.

    Usage:
        pulse = PulseText("SCANNING", color=Colors.BRIGHT_RED)
        pulse.start()
        time.sleep(3)
        pulse.stop()
    """

    def __init__(self, text: str, color: str = Colors.BRIGHT_CYAN, speed: float = 0.5):
        self.text = text
        self.color = color
        self.speed = speed
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start pulsing."""
        self._running = True
        self._thread = threading.Thread(target=self._pulse, daemon=True)
        self._thread.start()

    def _pulse(self):
        """Pulse animation loop."""
        bright = True
        while self._running:
            if bright:
                sys.stdout.write(f"\r{self.color}{Colors.BOLD}{self.text}{Colors.RESET}")
            else:
                sys.stdout.write(f"\r{Colors.DIM}{self.text}{Colors.RESET}")
            sys.stdout.flush()
            bright = not bright
            time.sleep(self.speed)

    def stop(self, final_text: str = None):
        """Stop pulsing."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)
        sys.stdout.write(f"\r{Colors.CLEAR_LINE}")
        if final_text:
            sys.stdout.write(final_text + "\n")
        sys.stdout.flush()


class MatrixRain:
    """
    Matrix-style rain effect (for fun loading screens).

    Usage:
        rain = MatrixRain(width=60, height=10)
        rain.start()
        time.sleep(3)
        rain.stop()
    """

    CHARS = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"

    def __init__(
        self,
        width: int = 60,
        height: int = 10,
        color: str = Colors.BRIGHT_GREEN,
        speed: float = 0.05,
    ):
        self.width = width
        self.height = height
        self.color = color
        self.speed = speed
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the rain."""
        self._running = True
        self._thread = threading.Thread(target=self._rain, daemon=True)
        self._thread.start()

    def _rain(self):
        """Rain animation loop."""
        columns = [0] * self.width
        sys.stdout.write(Colors.HIDE_CURSOR)

        while self._running:
            lines = []
            for y in range(self.height):
                line = ""
                for x in range(self.width):
                    if columns[x] == y:
                        line += f"{Colors.BRIGHT_WHITE}{random.choice(self.CHARS)}"
                    elif columns[x] > y and columns[x] - y < 5:
                        intensity = 255 - (columns[x] - y) * 50
                        line += f"\033[38;2;0;{intensity};0m{random.choice(self.CHARS)}"
                    else:
                        line += " "
                lines.append(line + Colors.RESET)

            # Update column positions
            for x in range(self.width):
                if random.random() > 0.95:
                    columns[x] = 0
                else:
                    columns[x] = (columns[x] + 1) % (self.height + 5)

            # Draw
            sys.stdout.write(f"\033[{self.height}A")
            for line in lines:
                sys.stdout.write(Colors.CLEAR_LINE + line + "\n")
            sys.stdout.flush()
            time.sleep(self.speed)

    def stop(self):
        """Stop the rain."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)
        sys.stdout.write(Colors.SHOW_CURSOR)
        # Clear the rain area
        for _ in range(self.height):
            sys.stdout.write(Colors.CLEAR_LINE + "\n")
        sys.stdout.write(f"\033[{self.height}A")
        sys.stdout.flush()


# Convenience functions
def spin(message: str, style: str = "dots", color: str = Colors.BRIGHT_CYAN) -> Spinner:
    """Create and return a started spinner."""
    return Spinner(message, style=style, color=color).start()


def progress(total: int = 100, style: str = "cyber", **kwargs) -> ProgressBar:
    """Create a progress bar."""
    return ProgressBar(total=total, style=style, **kwargs)


# Demo function
def demo():
    """Demonstrate all animations."""
    print(f"\n{Colors.BOLD}AIPTX Animation Demo{Colors.RESET}\n")
    print("=" * 50)

    # Spinner demo
    print(f"\n{Colors.BRIGHT_YELLOW}1. Spinners:{Colors.RESET}")
    for style in ["dots", "cyber", "pulse", "snake"]:
        with Spinner(f"Testing {style} spinner...", style=style) as s:
            time.sleep(1)

    # Progress bar demo
    print(f"\n{Colors.BRIGHT_YELLOW}2. Progress Bars:{Colors.RESET}")
    for style in ["cyber", "hacker", "gradient", "neon"]:
        bar = ProgressBar(total=100, style=style, prefix=f"{style:10}")
        for i in range(101):
            bar.update(i)
            time.sleep(0.01)
        bar.finish()

    # Multi-progress demo
    print(f"\n{Colors.BRIGHT_YELLOW}3. Multi-Task Progress:{Colors.RESET}")
    tasks = [
        {"name": "Nmap Scan", "color": Colors.BRIGHT_CYAN},
        {"name": "Nikto", "color": Colors.BRIGHT_GREEN},
        {"name": "Nuclei", "color": Colors.BRIGHT_YELLOW},
    ]
    mp = MultiProgress(tasks)
    for i in range(101):
        for j, _ in enumerate(tasks):
            progress_val = min(i + j * 10, 100)
            status = "completed" if progress_val >= 100 else "running"
            mp.update(j, progress_val, status=status)
        time.sleep(0.02)
    mp.close()

    # Typewriter demo
    print(f"\n{Colors.BRIGHT_YELLOW}4. Typewriter:{Colors.RESET}")
    TypeWriter.print("Initializing AIPTX Beast Mode...", speed=0.02)

    print(f"\n{Colors.BRIGHT_GREEN}Demo complete!{Colors.RESET}\n")


if __name__ == "__main__":
    demo()
