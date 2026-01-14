"""
AIPT Terminal - Subprocess execution wrapper

Handles tool execution with timeout, output capture, and error handling.

Features:
- Configurable timeout
- Output streaming
- Error capture
- Working directory management
"""
from __future__ import annotations

import subprocess
import shlex
import os
import signal
import time
import asyncio
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecutionResult:
    """Result of command execution"""
    command: str
    output: str
    error: Optional[str]
    return_code: int
    timed_out: bool
    duration: float
    working_dir: str = ""

    @property
    def success(self) -> bool:
        """Check if execution was successful"""
        return self.return_code == 0 and not self.timed_out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "output": self.output,
            "error": self.error,
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "duration": self.duration,
            "success": self.success,
        }


class Terminal:
    """
    Terminal execution wrapper.

    Handles:
    - Command execution with timeout
    - Output capture (stdout + stderr)
    - Working directory management
    - Signal handling for cleanup
    """

    def __init__(
        self,
        default_timeout: int = 300,
        max_output: int = 50000,
        shell: str = "/bin/bash",
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ):
        self.default_timeout = default_timeout
        self.max_output = max_output
        self.shell = shell
        self.working_dir = working_dir or os.getcwd()
        self.default_env = env or {}

        # Ensure working directory exists
        Path(self.working_dir).mkdir(parents=True, exist_ok=True)

    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        capture_stderr: bool = True,
    ) -> ExecutionResult:
        """
        Execute a command and capture output.

        Args:
            command: Command to execute
            timeout: Timeout in seconds (uses default if not specified)
            working_dir: Working directory (uses instance default if not specified)
            env: Additional environment variables
            capture_stderr: Whether to capture stderr

        Returns:
            ExecutionResult with output and status
        """
        timeout = timeout or self.default_timeout
        cwd = working_dir or self.working_dir

        # Prepare environment
        full_env = os.environ.copy()
        full_env.update(self.default_env)
        if env:
            full_env.update(env)

        start_time = time.time()

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                executable=self.shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
                cwd=cwd,
                env=full_env,
                preexec_fn=os.setsid,  # Create new process group for cleanup
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                timed_out = False
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                stdout, stderr = process.communicate()
                timed_out = True

            duration = time.time() - start_time

            output = self._decode_output(stdout)
            error_output = self._decode_output(stderr) if stderr else None

            error = error_output if process.returncode != 0 or error_output else None

            return ExecutionResult(
                command=command,
                output=output,
                error=error,
                return_code=process.returncode,
                timed_out=timed_out,
                duration=duration,
                working_dir=cwd,
            )

        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                command=command,
                output="",
                error=str(e),
                return_code=-1,
                timed_out=False,
                duration=duration,
                working_dir=cwd,
            )

    async def execute_async(
        self,
        command: str,
        timeout: Optional[int] = None,
        **kwargs
    ) -> ExecutionResult:
        """Async version of execute"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.execute(command, timeout, **kwargs)
        )

    def execute_streaming(
        self,
        command: str,
        callback: Callable[[str], None],
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
    ) -> ExecutionResult:
        """
        Execute command with real-time output streaming.

        Args:
            command: Command to execute
            callback: Function called with each output line
            timeout: Timeout in seconds
            working_dir: Working directory

        Returns:
            ExecutionResult with full output
        """
        import select

        timeout = timeout or self.default_timeout
        cwd = working_dir or self.working_dir
        start_time = time.time()
        output_lines = []

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                executable=self.shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=cwd,
                preexec_fn=os.setsid,
            )

            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    return ExecutionResult(
                        command=command,
                        output="\n".join(output_lines),
                        error="Timeout exceeded",
                        return_code=-1,
                        timed_out=True,
                        duration=elapsed,
                        working_dir=cwd,
                    )

                ready, _, _ = select.select([process.stdout], [], [], 0.1)
                if ready:
                    line = process.stdout.readline()
                    if line:
                        decoded = line.decode("utf-8", errors="replace").rstrip()
                        output_lines.append(decoded)
                        callback(decoded)

                if process.poll() is not None:
                    remaining = process.stdout.read()
                    if remaining:
                        decoded = remaining.decode("utf-8", errors="replace")
                        for line in decoded.split("\n"):
                            if line:
                                output_lines.append(line)
                                callback(line)
                    break

            duration = time.time() - start_time
            output = "\n".join(output_lines)

            return ExecutionResult(
                command=command,
                output=output[:self.max_output],
                error=None if process.returncode == 0 else f"Exit code: {process.returncode}",
                return_code=process.returncode,
                timed_out=False,
                duration=duration,
                working_dir=cwd,
            )

        except Exception as e:
            return ExecutionResult(
                command=command,
                output="\n".join(output_lines),
                error=str(e),
                return_code=-1,
                timed_out=False,
                duration=time.time() - start_time,
                working_dir=cwd,
            )

    def execute_background(
        self,
        command: str,
        log_file: Optional[str] = None,
    ) -> int:
        """
        Execute command in background.

        Args:
            command: Command to execute
            log_file: Optional file to log output

        Returns:
            Process ID
        """
        if log_file:
            command = f"{command} > {log_file} 2>&1"

        process = subprocess.Popen(
            command,
            shell=True,
            executable=self.shell,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.working_dir,
            start_new_session=True,
        )

        return process.pid

    def _decode_output(self, data: bytes) -> str:
        """Decode output and truncate if necessary"""
        try:
            decoded = data.decode("utf-8", errors="replace")
        except Exception:
            decoded = str(data)

        if len(decoded) > self.max_output:
            decoded = decoded[:self.max_output] + f"\n\n[Output truncated at {self.max_output} chars]"

        return decoded

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        result = self.execute(f"which {tool_name}", timeout=5)
        return result.return_code == 0

    def get_tool_version(self, tool_name: str) -> Optional[str]:
        """Get version of a tool"""
        for flag in ["--version", "-v", "-V", "version"]:
            result = self.execute(f"{tool_name} {flag} 2>&1 | head -1", timeout=5)
            if result.return_code == 0 and result.output:
                return result.output.strip().split("\n")[0]
        return None

    def list_available_tools(self, tools: list[str]) -> Dict[str, bool]:
        """Check availability of multiple tools"""
        return {tool: self.check_tool_available(tool) for tool in tools}


# Singleton instance
_terminal: Optional[Terminal] = None


def get_terminal(**kwargs) -> Terminal:
    """Get singleton terminal instance"""
    global _terminal
    if _terminal is None:
        _terminal = Terminal(**kwargs)
    return _terminal
