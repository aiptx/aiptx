"""
AIPT Terminal Executor

Async command execution with streaming output, timeouts, and safety controls.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import AsyncIterator, Callable, Optional

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Command execution status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


@dataclass
class ExecutionConfig:
    """Configuration for command execution"""
    timeout: float = 300.0  # 5 minutes default
    working_dir: Optional[str] = None
    environment: dict[str, str] = field(default_factory=dict)
    shell: bool = False  # Run in shell (less secure, but needed for pipes)
    capture_output: bool = True
    stream_output: bool = False
    max_output_size: int = 10 * 1024 * 1024  # 10MB

    # Safety settings
    allow_sudo: bool = False
    blocked_commands: list[str] = field(default_factory=lambda: [
        "rm -rf /",
        "mkfs",
        "dd if=/dev/zero",
        ":(){:|:&};:",  # Fork bomb
    ])

    # Resource limits
    max_memory_mb: int = 1024
    max_cpu_time: int = 300


@dataclass
class CommandResult:
    """Result of a command execution"""
    command: str
    status: ExecutionStatus
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Metadata
    working_dir: str = ""
    pid: Optional[int] = None

    @property
    def success(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS and self.exit_code == 0

    @property
    def output(self) -> str:
        """Combined stdout and stderr"""
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(f"[STDERR]\n{self.stderr}")
        return "\n".join(parts)

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout[:10000] if self.stdout else "",
            "stderr": self.stderr[:5000] if self.stderr else "",
            "duration_seconds": self.duration_seconds,
            "success": self.success,
        }


class TerminalExecutor:
    """
    Async terminal command executor with safety controls.

    Features:
    - Async execution with streaming output
    - Timeout handling
    - Command sanitization
    - Output size limits
    - Resource control

    Example:
        executor = TerminalExecutor()
        result = await executor.run("nmap -sV target.com")
        print(result.stdout)

        # Stream output
        async for line in executor.stream("nikto -h target.com"):
            print(line)
    """

    def __init__(self, config: Optional[ExecutionConfig] = None):
        self.config = config or ExecutionConfig()
        self._processes: dict[int, asyncio.subprocess.Process] = {}
        self._history: list[CommandResult] = []

    async def run(
        self,
        command: str,
        timeout: Optional[float] = None,
        working_dir: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> CommandResult:
        """
        Execute a command and return the result.

        Args:
            command: Command to execute
            timeout: Override default timeout
            working_dir: Working directory
            env: Additional environment variables

        Returns:
            CommandResult with output and status
        """
        # Validate command
        validation_error = self._validate_command(command)
        if validation_error:
            return CommandResult(
                command=command,
                status=ExecutionStatus.FAILED,
                stderr=validation_error,
            )

        timeout = timeout or self.config.timeout
        cwd = working_dir or self.config.working_dir or os.getcwd()

        # Build environment
        environment = os.environ.copy()
        environment.update(self.config.environment)
        if env:
            environment.update(env)

        result = CommandResult(
            command=command,
            status=ExecutionStatus.RUNNING,
            start_time=datetime.utcnow(),
            working_dir=cwd,
        )

        try:
            # Create process
            if self.config.shell:
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE if self.config.capture_output else None,
                    stderr=asyncio.subprocess.PIPE if self.config.capture_output else None,
                    cwd=cwd,
                    env=environment,
                )
            else:
                args = shlex.split(command)
                process = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE if self.config.capture_output else None,
                    stderr=asyncio.subprocess.PIPE if self.config.capture_output else None,
                    cwd=cwd,
                    env=environment,
                )

            result.pid = process.pid
            self._processes[process.pid] = process

            logger.info(f"Executing: {command[:100]}... (PID: {process.pid})")

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )

                result.exit_code = process.returncode
                result.status = ExecutionStatus.SUCCESS if process.returncode == 0 else ExecutionStatus.FAILED

                if stdout:
                    result.stdout = self._limit_output(stdout.decode("utf-8", errors="replace"))
                if stderr:
                    result.stderr = self._limit_output(stderr.decode("utf-8", errors="replace"))

            except asyncio.TimeoutError:
                logger.warning(f"Command timed out after {timeout}s: {command[:50]}")
                process.kill()
                await process.wait()
                result.status = ExecutionStatus.TIMEOUT
                result.stderr = f"Command timed out after {timeout} seconds"

        except FileNotFoundError as e:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"Command not found: {e}"
        except PermissionError as e:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"Permission denied: {e}"
        except Exception as e:
            logger.error(f"Execution error: {e}")
            result.status = ExecutionStatus.FAILED
            result.stderr = str(e)
        finally:
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

            # Cleanup
            if result.pid and result.pid in self._processes:
                del self._processes[result.pid]

        self._history.append(result)
        return result

    async def stream(
        self,
        command: str,
        timeout: Optional[float] = None,
        callback: Optional[Callable[[str], None]] = None,
    ) -> AsyncIterator[str]:
        """
        Execute command and stream output line by line.

        Args:
            command: Command to execute
            timeout: Timeout in seconds
            callback: Optional callback for each line

        Yields:
            Output lines as they're produced
        """
        validation_error = self._validate_command(command)
        if validation_error:
            yield f"[ERROR] {validation_error}"
            return

        timeout = timeout or self.config.timeout
        cwd = self.config.working_dir or os.getcwd()

        environment = os.environ.copy()
        environment.update(self.config.environment)

        try:
            if self.config.shell:
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    cwd=cwd,
                    env=environment,
                )
            else:
                args = shlex.split(command)
                process = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    cwd=cwd,
                    env=environment,
                )

            self._processes[process.pid] = process
            start_time = time.time()
            output_size = 0

            async for line in process.stdout:
                # Check timeout
                if time.time() - start_time > timeout:
                    process.kill()
                    yield "[TIMEOUT] Command execution timed out"
                    break

                # Check output size
                output_size += len(line)
                if output_size > self.config.max_output_size:
                    process.kill()
                    yield "[TRUNCATED] Output exceeded maximum size"
                    break

                decoded = line.decode("utf-8", errors="replace").rstrip()
                if callback:
                    callback(decoded)
                yield decoded

            await process.wait()

        except Exception as e:
            yield f"[ERROR] {str(e)}"
        finally:
            if process.pid in self._processes:
                del self._processes[process.pid]

    async def run_multiple(
        self,
        commands: list[str],
        parallel: bool = False,
        stop_on_error: bool = True,
    ) -> list[CommandResult]:
        """
        Execute multiple commands.

        Args:
            commands: List of commands
            parallel: Run in parallel (True) or sequential (False)
            stop_on_error: Stop on first error (sequential only)

        Returns:
            List of results
        """
        if parallel:
            tasks = [self.run(cmd) for cmd in commands]
            return await asyncio.gather(*tasks)
        else:
            results = []
            for cmd in commands:
                result = await self.run(cmd)
                results.append(result)
                if stop_on_error and not result.success:
                    break
            return results

    async def kill(self, pid: int) -> bool:
        """Kill a running process by PID"""
        if pid in self._processes:
            try:
                self._processes[pid].kill()
                await self._processes[pid].wait()
                del self._processes[pid]
                return True
            except Exception as e:
                logger.error(f"Failed to kill process {pid}: {e}")
        return False

    async def kill_all(self) -> int:
        """Kill all running processes"""
        killed = 0
        for pid in list(self._processes.keys()):
            if await self.kill(pid):
                killed += 1
        return killed

    def _validate_command(self, command: str) -> Optional[str]:
        """Validate command for safety"""
        cmd_lower = command.lower()

        # Check blocked commands
        for blocked in self.config.blocked_commands:
            if blocked.lower() in cmd_lower:
                return f"Blocked command pattern: {blocked}"

        # Check sudo
        if not self.config.allow_sudo and cmd_lower.strip().startswith("sudo"):
            return "sudo commands are not allowed"

        return None

    def _limit_output(self, output: str) -> str:
        """Limit output size"""
        if len(output) > self.config.max_output_size:
            return output[:self.config.max_output_size] + "\n[OUTPUT TRUNCATED]"
        return output

    def get_history(self, limit: int = 100) -> list[CommandResult]:
        """Get command execution history"""
        return self._history[-limit:]

    def clear_history(self) -> None:
        """Clear execution history"""
        self._history.clear()


# Convenience function
async def run_command(command: str, timeout: float = 60.0) -> CommandResult:
    """Quick command execution"""
    executor = TerminalExecutor()
    return await executor.run(command, timeout=timeout)
