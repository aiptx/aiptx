"""
Local Runtime for AIPT v2
=========================

Non-sandboxed local execution runtime.
Implements AbstractRuntime interface for local command execution.

WARNING: This runtime provides NO isolation. Only use for trusted commands.
"""

import asyncio
import uuid
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, List
from pathlib import Path
from datetime import datetime

from aipt_v2.utils.logging import logger


@dataclass
class LocalSandboxInfo:
    """Information about a local 'sandbox' (execution context)."""

    sandbox_id: str
    created_at: datetime = field(default_factory=datetime.now)
    working_dir: str = field(default_factory=lambda: os.getcwd())
    is_local: bool = True
    url: str = "local"


class LocalRuntime:
    """
    Local runtime for command execution without sandboxing.

    This runtime executes commands directly on the local system.
    It provides a consistent interface with sandboxed runtimes
    but does NOT provide any isolation.

    Usage:
        runtime = LocalRuntime()
        sandbox = await runtime.create_sandbox()
        stdout, stderr, code = await runtime.execute(sandbox.sandbox_id, "ls -la")
        await runtime.destroy_sandbox(sandbox.sandbox_id)
    """

    def __init__(self, working_dir: Optional[str] = None):
        """
        Initialize local runtime.

        Args:
            working_dir: Default working directory for commands
        """
        self.working_dir = working_dir or os.getcwd()
        self._sandboxes: Dict[str, LocalSandboxInfo] = {}
        self._processes: Dict[str, asyncio.subprocess.Process] = {}

    async def create_sandbox(
        self,
        image: Optional[str] = None,
        working_dir: Optional[str] = None,
        **kwargs
    ) -> LocalSandboxInfo:
        """
        Create a local execution context.

        Note: For local runtime, this just creates a tracking ID.
        No actual isolation is provided.

        Args:
            image: Ignored for local runtime
            working_dir: Working directory for commands
            **kwargs: Additional options (ignored)

        Returns:
            LocalSandboxInfo with sandbox details
        """
        sandbox_id = f"local-{uuid.uuid4().hex[:8]}"
        work_dir = working_dir or self.working_dir

        # Ensure working directory exists
        Path(work_dir).mkdir(parents=True, exist_ok=True)

        info = LocalSandboxInfo(
            sandbox_id=sandbox_id,
            working_dir=work_dir,
        )

        self._sandboxes[sandbox_id] = info
        logger.info("Created local execution context", sandbox_id=sandbox_id, working_dir=work_dir)

        return info

    async def get_sandbox_url(self, sandbox_id: str) -> str:
        """
        Get sandbox URL.

        Args:
            sandbox_id: Sandbox identifier

        Returns:
            URL string ('local' for local runtime)

        Raises:
            ValueError: If sandbox not found
        """
        if sandbox_id not in self._sandboxes:
            raise ValueError(f"Unknown sandbox: {sandbox_id}")
        return "local"

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """
        Destroy sandbox and cleanup resources.

        Args:
            sandbox_id: Sandbox identifier
        """
        if sandbox_id in self._sandboxes:
            # Kill any running processes
            if sandbox_id in self._processes:
                try:
                    self._processes[sandbox_id].kill()
                    await self._processes[sandbox_id].wait()
                except ProcessLookupError:
                    pass
                del self._processes[sandbox_id]

            del self._sandboxes[sandbox_id]
            logger.info("Destroyed local sandbox", sandbox_id=sandbox_id)

    async def execute(
        self,
        sandbox_id: str,
        command: str,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, str, int]:
        """
        Execute command in sandbox.

        Args:
            sandbox_id: Sandbox identifier
            command: Shell command to execute
            timeout: Command timeout in seconds
            env: Additional environment variables

        Returns:
            Tuple of (stdout, stderr, exit_code)

        Raises:
            ValueError: If sandbox not found
        """
        if sandbox_id not in self._sandboxes:
            raise ValueError(f"Unknown sandbox: {sandbox_id}")

        sandbox = self._sandboxes[sandbox_id]

        # Prepare environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)

        logger.debug(
            "Executing command",
            sandbox_id=sandbox_id,
            command=command[:100] + "..." if len(command) > 100 else command,
            timeout=timeout,
        )

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=sandbox.working_dir,
                env=cmd_env,
            )

            self._processes[sandbox_id] = proc

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )

                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                exit_code = proc.returncode or 0

                logger.debug(
                    "Command completed",
                    sandbox_id=sandbox_id,
                    exit_code=exit_code,
                    stdout_len=len(stdout),
                    stderr_len=len(stderr),
                )

                return stdout, stderr, exit_code

            except asyncio.TimeoutError:
                logger.warning(
                    "Command timed out",
                    sandbox_id=sandbox_id,
                    command=command[:50],
                    timeout=timeout,
                )
                proc.kill()
                await proc.wait()
                return "", f"Command timed out after {timeout} seconds", 124

        except Exception as e:
            logger.error(
                "Command execution failed",
                sandbox_id=sandbox_id,
                command=command[:50],
                error=str(e),
                exc_info=True,
            )
            return "", str(e), 1

        finally:
            if sandbox_id in self._processes:
                del self._processes[sandbox_id]

    async def execute_background(
        self,
        sandbox_id: str,
        command: str,
        env: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Execute command in background.

        Args:
            sandbox_id: Sandbox identifier
            command: Shell command to execute
            env: Additional environment variables

        Returns:
            Process ID as string
        """
        if sandbox_id not in self._sandboxes:
            raise ValueError(f"Unknown sandbox: {sandbox_id}")

        sandbox = self._sandboxes[sandbox_id]

        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)

        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=sandbox.working_dir,
            env=cmd_env,
        )

        proc_id = f"{sandbox_id}-{proc.pid}"
        self._processes[proc_id] = proc

        logger.info(
            "Started background process",
            sandbox_id=sandbox_id,
            proc_id=proc_id,
            command=command[:50],
        )

        return proc_id

    async def check_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available locally.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is available
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                f"which {tool_name}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return proc.returncode == 0 and len(stdout.strip()) > 0
        except Exception:
            return False

    async def get_available_tools(self, tool_list: List[str]) -> Dict[str, bool]:
        """
        Check availability of multiple tools.

        Args:
            tool_list: List of tool names to check

        Returns:
            Dict mapping tool names to availability
        """
        results = {}
        for tool in tool_list:
            results[tool] = await self.check_tool_available(tool)
        return results

    def get_sandbox_info(self, sandbox_id: str) -> Optional[LocalSandboxInfo]:
        """
        Get information about a sandbox.

        Args:
            sandbox_id: Sandbox identifier

        Returns:
            LocalSandboxInfo or None if not found
        """
        return self._sandboxes.get(sandbox_id)

    async def cleanup_all(self) -> int:
        """
        Cleanup all sandboxes and processes.

        Returns:
            Number of sandboxes cleaned up
        """
        count = len(self._sandboxes)

        for sandbox_id in list(self._sandboxes.keys()):
            await self.destroy_sandbox(sandbox_id)

        logger.info("Cleaned up all local sandboxes", count=count)
        return count


# Singleton instance for convenience
_default_runtime: Optional[LocalRuntime] = None


def get_local_runtime() -> LocalRuntime:
    """Get or create the default local runtime instance."""
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = LocalRuntime()
    return _default_runtime
