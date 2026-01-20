"""
AIPT Terminal - Subprocess execution wrapper

Handles tool execution with timeout, output capture, and error handling.

Features:
- Configurable timeout
- Output streaming
- Error capture
- Working directory management
- Cross-platform support (Windows, Linux, macOS)
"""
from __future__ import annotations

import subprocess
import shlex
import os
import signal
import time
import asyncio
import platform
import threading
from queue import Queue, Empty
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass
from pathlib import Path


# Platform detection
IS_WINDOWS = platform.system() == "Windows"


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
    - Cross-platform compatibility (Windows/Unix)
    """

    def __init__(
        self,
        default_timeout: int = 300,
        max_output: int = 50000,
        shell: Optional[str] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ):
        self.default_timeout = default_timeout
        self.max_output = max_output
        # Use appropriate shell for platform
        if shell is None:
            self.shell = None if IS_WINDOWS else "/bin/bash"
        else:
            self.shell = shell
        self.working_dir = working_dir or os.getcwd()
        self.default_env = env or {}

        # Ensure working directory exists
        Path(self.working_dir).mkdir(parents=True, exist_ok=True)

    def _get_popen_kwargs(self, cwd: str, full_env: Dict[str, str], capture_stderr: bool = True) -> Dict[str, Any]:
        """
        Get platform-specific Popen kwargs.

        Returns:
            Dictionary of kwargs for subprocess.Popen
        """
        kwargs = {
            "shell": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
            "cwd": cwd,
            "env": full_env,
        }

        if IS_WINDOWS:
            # Windows: Use CREATE_NEW_PROCESS_GROUP for proper process management
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            # Unix: Use shell executable and process group
            kwargs["executable"] = self.shell
            kwargs["preexec_fn"] = os.setsid

        return kwargs

    def _kill_process(self, process: subprocess.Popen) -> None:
        """
        Kill a process and its children in a cross-platform way.

        Args:
            process: The subprocess to kill
        """
        try:
            if IS_WINDOWS:
                # Windows: Use taskkill to kill process tree
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                    timeout=5
                )
            else:
                # Unix: Kill process group
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
            # Process already terminated or other error
            try:
                process.kill()
            except Exception:
                pass

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
            popen_kwargs = self._get_popen_kwargs(cwd, full_env, capture_stderr)
            process = subprocess.Popen(command, **popen_kwargs)

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                timed_out = False
            except subprocess.TimeoutExpired:
                self._kill_process(process)
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

    def _stream_reader_thread(
        self,
        pipe,
        queue: Queue,
        stop_event: threading.Event
    ) -> None:
        """
        Thread function to read from pipe and put lines in queue.
        Used for Windows compatibility where select() doesn't work on pipes.

        Args:
            pipe: The pipe to read from
            queue: Queue to put lines into
            stop_event: Event to signal thread to stop
        """
        try:
            while not stop_event.is_set():
                line = pipe.readline()
                if line:
                    queue.put(line)
                elif pipe.closed or stop_event.is_set():
                    break
        except Exception:
            pass
        finally:
            # Signal end of stream
            queue.put(None)

    def execute_streaming(
        self,
        command: str,
        callback: Callable[[str], None],
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
    ) -> ExecutionResult:
        """
        Execute command with real-time output streaming.

        This method is cross-platform compatible, using threading on Windows
        instead of select.select() which only works with sockets on Windows.

        Args:
            command: Command to execute
            callback: Function called with each output line
            timeout: Timeout in seconds
            working_dir: Working directory

        Returns:
            ExecutionResult with full output
        """
        timeout = timeout or self.default_timeout
        cwd = working_dir or self.working_dir
        start_time = time.time()
        output_lines = []

        # Prepare environment
        full_env = os.environ.copy()
        full_env.update(self.default_env)

        try:
            # Platform-specific Popen arguments
            popen_kwargs = {
                "shell": True,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "cwd": cwd,
                "env": full_env,
            }

            if IS_WINDOWS:
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["executable"] = self.shell
                popen_kwargs["preexec_fn"] = os.setsid

            process = subprocess.Popen(command, **popen_kwargs)

            if IS_WINDOWS:
                # Windows: Use threading-based approach
                output_lines = self._streaming_windows(
                    process, callback, timeout, start_time, cwd
                )
            else:
                # Unix: Use select-based approach
                output_lines = self._streaming_unix(
                    process, callback, timeout, start_time, cwd
                )

            # Check for timeout result (returned as ExecutionResult)
            if isinstance(output_lines, ExecutionResult):
                return output_lines

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
                output="\n".join(output_lines) if isinstance(output_lines, list) else "",
                error=str(e),
                return_code=-1,
                timed_out=False,
                duration=time.time() - start_time,
                working_dir=cwd,
            )

    def _streaming_windows(
        self,
        process: subprocess.Popen,
        callback: Callable[[str], None],
        timeout: int,
        start_time: float,
        cwd: str,
    ):
        """
        Windows-specific streaming implementation using threading.

        Args:
            process: The subprocess
            callback: Output callback function
            timeout: Timeout in seconds
            start_time: When execution started
            cwd: Working directory

        Returns:
            List of output lines or ExecutionResult if timed out
        """
        output_lines = []
        queue = Queue()
        stop_event = threading.Event()

        # Start reader thread
        reader_thread = threading.Thread(
            target=self._stream_reader_thread,
            args=(process.stdout, queue, stop_event),
            daemon=True
        )
        reader_thread.start()

        try:
            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    stop_event.set()
                    self._kill_process(process)
                    return ExecutionResult(
                        command=process.args,
                        output="\n".join(output_lines),
                        error="Timeout exceeded",
                        return_code=-1,
                        timed_out=True,
                        duration=elapsed,
                        working_dir=cwd,
                    )

                try:
                    line = queue.get(timeout=0.1)
                    if line is None:
                        # End of stream
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    output_lines.append(decoded)
                    callback(decoded)
                except Empty:
                    # Check if process has finished
                    if process.poll() is not None:
                        # Drain remaining output
                        while True:
                            try:
                                line = queue.get_nowait()
                                if line is None:
                                    break
                                decoded = line.decode("utf-8", errors="replace").rstrip()
                                output_lines.append(decoded)
                                callback(decoded)
                            except Empty:
                                break
                        break
        finally:
            stop_event.set()
            reader_thread.join(timeout=1)

        process.wait()
        return output_lines

    def _streaming_unix(
        self,
        process: subprocess.Popen,
        callback: Callable[[str], None],
        timeout: int,
        start_time: float,
        cwd: str,
    ):
        """
        Unix-specific streaming implementation using select.

        Args:
            process: The subprocess
            callback: Output callback function
            timeout: Timeout in seconds
            start_time: When execution started
            cwd: Working directory

        Returns:
            List of output lines or ExecutionResult if timed out
        """
        import select

        output_lines = []

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                self._kill_process(process)
                return ExecutionResult(
                    command=process.args,
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

        return output_lines

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
            if IS_WINDOWS:
                command = f"{command} > {log_file} 2>&1"
            else:
                command = f"{command} > {log_file} 2>&1"

        popen_kwargs = {
            "shell": True,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "cwd": self.working_dir,
        }

        if IS_WINDOWS:
            popen_kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP |
                subprocess.DETACHED_PROCESS
            )
        else:
            popen_kwargs["executable"] = self.shell
            popen_kwargs["start_new_session"] = True

        process = subprocess.Popen(command, **popen_kwargs)
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
        # Use platform-appropriate command
        if IS_WINDOWS:
            result = self.execute(f"where {tool_name}", timeout=5)
        else:
            result = self.execute(f"which {tool_name}", timeout=5)
        return result.return_code == 0

    def get_tool_version(self, tool_name: str) -> Optional[str]:
        """Get version of a tool"""
        for flag in ["--version", "-v", "-V", "version"]:
            if IS_WINDOWS:
                result = self.execute(f"{tool_name} {flag}", timeout=5)
            else:
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
