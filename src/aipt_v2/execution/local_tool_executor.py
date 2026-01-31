"""
AIPTX Local Tool Executor
=========================

Enhanced executor for local security tools with:
- Parallel execution with concurrency limits
- Real-time progress tracking and streaming
- Automatic result parsing and normalization
- Error handling and retry logic
- Resource monitoring
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, AsyncIterator
from pathlib import Path

from .tool_registry import ToolRegistry, ToolConfig, ToolPhase, get_registry
from .parser import OutputParser, Finding
from .terminal import Terminal, ExecutionResult

logger = logging.getLogger(__name__)


class ExecutionState(str, Enum):
    """State of a tool execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ToolExecution:
    """
    Represents a single tool execution with full lifecycle tracking.
    """
    id: str
    tool: ToolConfig
    target: str
    command: str
    args: List[str] = field(default_factory=list)

    # State
    state: ExecutionState = ExecutionState.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    # Results
    output: str = ""
    error: str = ""
    return_code: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)

    # Metadata
    duration_seconds: float = 0.0
    retry_count: int = 0

    @property
    def is_complete(self) -> bool:
        return self.state in {
            ExecutionState.COMPLETED,
            ExecutionState.FAILED,
            ExecutionState.TIMEOUT,
            ExecutionState.CANCELLED,
        }

    @property
    def is_success(self) -> bool:
        return self.state == ExecutionState.COMPLETED and self.return_code == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool.name,
            "target": self.target,
            "command": self.command,
            "state": self.state.value,
            "duration": self.duration_seconds,
            "findings_count": len(self.findings),
            "return_code": self.return_code,
        }


@dataclass
class ExecutionBatch:
    """
    A batch of tool executions to run together.
    """
    id: str
    phase: ToolPhase
    executions: List[ToolExecution] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def is_complete(self) -> bool:
        return all(e.is_complete for e in self.executions)

    @property
    def success_count(self) -> int:
        return sum(1 for e in self.executions if e.is_success)

    @property
    def total_findings(self) -> int:
        return sum(len(e.findings) for e in self.executions)


class ProgressCallback:
    """Callback interface for execution progress updates."""

    def on_start(self, execution: ToolExecution) -> None:
        """Called when a tool starts executing."""
        pass

    def on_output(self, execution: ToolExecution, line: str) -> None:
        """Called for each line of output."""
        pass

    def on_complete(self, execution: ToolExecution) -> None:
        """Called when a tool completes."""
        pass

    def on_error(self, execution: ToolExecution, error: str) -> None:
        """Called on error."""
        pass


class LocalToolExecutor:
    """
    Enhanced executor for running local security tools.

    Features:
    - Parallel execution with configurable concurrency
    - Real-time output streaming
    - Automatic parsing of tool outputs
    - Retry logic for transient failures
    - Progress tracking and callbacks

    Example:
        executor = LocalToolExecutor()
        await executor.initialize()

        # Run a single tool
        result = await executor.run_tool(
            "nmap",
            target="example.com",
            args=["-F", "-sV"]
        )

        # Run multiple tools in parallel
        results = await executor.run_phase(
            ToolPhase.RECON,
            target="example.com"
        )

        for result in results:
            print(f"{result.tool.name}: {len(result.findings)} findings")
    """

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        max_parallel: int = 5,
        default_timeout: int = 300,
        max_retries: int = 1,
        parser: Optional[OutputParser] = None,
    ):
        self.registry = registry or get_registry()
        self.max_parallel = max_parallel
        self.default_timeout = default_timeout
        self.max_retries = max_retries
        self.parser = parser or OutputParser()

        self._terminal = Terminal()
        self._semaphore = asyncio.Semaphore(max_parallel)
        self._running: Dict[str, ToolExecution] = {}
        self._execution_counter = 0

        self._callbacks: List[ProgressCallback] = []

    async def initialize(self) -> None:
        """Initialize the executor and discover tools."""
        await self.registry.discover_tools()

    def add_callback(self, callback: ProgressCallback) -> None:
        """Add a progress callback."""
        self._callbacks.append(callback)

    def remove_callback(self, callback: ProgressCallback) -> None:
        """Remove a progress callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _next_execution_id(self) -> str:
        """Generate unique execution ID."""
        self._execution_counter += 1
        return f"exec_{self._execution_counter:04d}"

    # =========================================================================
    # Single Tool Execution
    # =========================================================================

    async def run_tool(
        self,
        tool_name: str,
        target: str,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
        stream_output: bool = False,
    ) -> ToolExecution:
        """
        Run a single tool against a target.

        Args:
            tool_name: Name of the tool to run
            target: Target URL, domain, or IP
            args: Additional command-line arguments
            timeout: Execution timeout (uses tool default if not specified)
            stream_output: Whether to stream output in real-time

        Returns:
            ToolExecution with results
        """
        tool = self.registry.get_tool(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_name}")

        if not self.registry.is_available(tool_name):
            raise RuntimeError(f"Tool not available: {tool_name}")

        # Build command
        command_args = self._build_command(tool, target, args or [])
        command = " ".join(command_args)

        # Create execution record
        execution = ToolExecution(
            id=self._next_execution_id(),
            tool=tool,
            target=target,
            command=command,
            args=args or [],
        )

        # Execute with retries
        for attempt in range(self.max_retries + 1):
            execution.retry_count = attempt
            try:
                await self._execute(
                    execution,
                    timeout or tool.default_timeout,
                    stream_output,
                )
                break
            except Exception as e:
                if attempt < self.max_retries:
                    logger.warning(f"Retry {attempt + 1}/{self.max_retries} for {tool_name}: {e}")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    execution.state = ExecutionState.FAILED
                    execution.error = str(e)
                    self._notify_error(execution, str(e))

        return execution

    def _build_command(
        self,
        tool: ToolConfig,
        target: str,
        extra_args: List[str],
    ) -> List[str]:
        """Build the command line for a tool."""
        cmd = [tool.binary]

        # Add default args
        cmd.extend(tool.default_args)

        # Add JSON output if available
        if tool.json_output_flag:
            if " " in tool.json_output_flag:
                cmd.extend(tool.json_output_flag.split())
            else:
                cmd.append(tool.json_output_flag)

        # Add silent flag if available
        if tool.silent_flag:
            cmd.append(tool.silent_flag)

        # Add extra args
        cmd.extend(extra_args)

        # Add target (tool-specific placement)
        if tool.name in ["nmap", "masscan", "httpx", "nuclei"]:
            cmd.extend(["-u" if tool.name in ["httpx", "nuclei", "katana"] else "", target])
            cmd = [c for c in cmd if c]  # Remove empty strings
        elif tool.name == "ffuf":
            # FUZZ keyword handling
            if "FUZZ" not in " ".join(cmd):
                cmd.extend(["-u", f"{target.rstrip('/')}/FUZZ"])
            else:
                cmd.extend(["-u", target])
        elif tool.name == "sqlmap":
            cmd.extend(["-u", target])
        elif tool.name == "hydra":
            cmd.append(target)
        else:
            # Default: append target
            cmd.append(target)

        return cmd

    async def _execute(
        self,
        execution: ToolExecution,
        timeout: int,
        stream_output: bool,
    ) -> None:
        """Execute a tool and capture results."""
        async with self._semaphore:
            execution.state = ExecutionState.RUNNING
            execution.start_time = datetime.utcnow()
            self._running[execution.id] = execution
            self._notify_start(execution)

            try:
                if stream_output:
                    result = await self._execute_streaming(execution, timeout)
                else:
                    result = await self._execute_simple(execution, timeout)

                execution.output = result.output
                execution.error = result.error or ""
                execution.return_code = result.return_code

                if result.timed_out:
                    execution.state = ExecutionState.TIMEOUT
                else:
                    execution.state = ExecutionState.COMPLETED

                # Parse output
                execution.findings = self.parser.parse(
                    execution.output,
                    execution.tool.name,
                )

            except asyncio.CancelledError:
                execution.state = ExecutionState.CANCELLED
                raise
            except Exception as e:
                execution.state = ExecutionState.FAILED
                execution.error = str(e)
                raise
            finally:
                execution.end_time = datetime.utcnow()
                if execution.start_time:
                    execution.duration_seconds = (
                        execution.end_time - execution.start_time
                    ).total_seconds()
                self._running.pop(execution.id, None)
                self._notify_complete(execution)

    async def _execute_simple(
        self,
        execution: ToolExecution,
        timeout: int,
    ) -> ExecutionResult:
        """Simple execution without streaming."""
        proc = await asyncio.create_subprocess_shell(
            execution.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            return ExecutionResult(
                command=execution.command,
                output=stdout.decode("utf-8", errors="replace"),
                error=stderr.decode("utf-8", errors="replace"),
                return_code=proc.returncode,
                timed_out=False,
                duration=0,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ExecutionResult(
                command=execution.command,
                output="",
                error="Execution timed out",
                return_code=-1,
                timed_out=True,
                duration=timeout,
            )

    async def _execute_streaming(
        self,
        execution: ToolExecution,
        timeout: int,
    ) -> ExecutionResult:
        """Execute with streaming output."""
        proc = await asyncio.create_subprocess_shell(
            execution.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        output_lines = []
        start_time = time.time()

        try:
            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    proc.kill()
                    return ExecutionResult(
                        command=execution.command,
                        output="\n".join(output_lines),
                        error="Execution timed out",
                        return_code=-1,
                        timed_out=True,
                        duration=timeout,
                    )

                try:
                    line = await asyncio.wait_for(
                        proc.stdout.readline(),
                        timeout=min(10, timeout - elapsed),
                    )
                    if not line:
                        break

                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    output_lines.append(decoded)
                    self._notify_output(execution, decoded)

                except asyncio.TimeoutError:
                    if proc.returncode is not None:
                        break
                    continue

            await proc.wait()

            stderr = await proc.stderr.read()

            return ExecutionResult(
                command=execution.command,
                output="\n".join(output_lines),
                error=stderr.decode("utf-8", errors="replace"),
                return_code=proc.returncode,
                timed_out=False,
                duration=time.time() - start_time,
            )

        except asyncio.CancelledError:
            proc.kill()
            await proc.wait()
            raise

    # =========================================================================
    # Batch Execution
    # =========================================================================

    async def run_tools(
        self,
        tools: List[str],
        target: str,
        args_map: Optional[Dict[str, List[str]]] = None,
    ) -> List[ToolExecution]:
        """
        Run multiple tools against a target in parallel.

        Args:
            tools: List of tool names
            target: Target URL, domain, or IP
            args_map: Optional mapping of tool name to extra args

        Returns:
            List of ToolExecution results
        """
        args_map = args_map or {}

        tasks = [
            self.run_tool(
                tool_name=tool,
                target=target,
                args=args_map.get(tool, []),
            )
            for tool in tools
            if self.registry.is_available(tool)
        ]

        return await asyncio.gather(*tasks, return_exceptions=False)

    async def run_phase(
        self,
        phase: ToolPhase,
        target: str,
        tool_filter: Optional[Callable[[ToolConfig], bool]] = None,
    ) -> ExecutionBatch:
        """
        Run all tools for a specific phase.

        Args:
            phase: The phase to run (RECON, SCAN, EXPLOIT)
            target: Target URL, domain, or IP
            tool_filter: Optional filter to select specific tools

        Returns:
            ExecutionBatch with all results
        """
        tools = self.registry.get_tools_by_phase(phase)

        if tool_filter:
            tools = [t for t in tools if tool_filter(t)]

        batch = ExecutionBatch(
            id=f"batch_{phase.value}_{int(time.time())}",
            phase=phase,
        )
        batch.start_time = datetime.utcnow()

        tasks = [
            self.run_tool(tool.name, target)
            for tool in tools
        ]

        batch.executions = await asyncio.gather(*tasks, return_exceptions=False)
        batch.end_time = datetime.utcnow()

        logger.info(
            f"Phase {phase.value} complete: "
            f"{batch.success_count}/{len(batch.executions)} tools successful, "
            f"{batch.total_findings} findings"
        )

        return batch

    async def run_pipeline(
        self,
        target: str,
        phases: Optional[List[ToolPhase]] = None,
    ) -> Dict[ToolPhase, ExecutionBatch]:
        """
        Run complete pipeline through specified phases.

        Args:
            target: Target URL, domain, or IP
            phases: Phases to run (default: RECON, SCAN, EXPLOIT)

        Returns:
            Dict mapping phase to ExecutionBatch
        """
        phases = phases or [ToolPhase.RECON, ToolPhase.SCAN, ToolPhase.EXPLOIT]
        results = {}

        for phase in phases:
            logger.info(f"Starting phase: {phase.value}")
            batch = await self.run_phase(phase, target)
            results[phase] = batch

            # Small delay between phases
            await asyncio.sleep(1)

        return results

    # =========================================================================
    # Progress Notifications
    # =========================================================================

    def _notify_start(self, execution: ToolExecution) -> None:
        for callback in self._callbacks:
            try:
                callback.on_start(execution)
            except Exception:
                pass

    def _notify_output(self, execution: ToolExecution, line: str) -> None:
        for callback in self._callbacks:
            try:
                callback.on_output(execution, line)
            except Exception:
                pass

    def _notify_complete(self, execution: ToolExecution) -> None:
        for callback in self._callbacks:
            try:
                callback.on_complete(execution)
            except Exception:
                pass

    def _notify_error(self, execution: ToolExecution, error: str) -> None:
        for callback in self._callbacks:
            try:
                callback.on_error(execution, error)
            except Exception:
                pass

    # =========================================================================
    # Status and Control
    # =========================================================================

    def get_running(self) -> List[ToolExecution]:
        """Get currently running executions."""
        return list(self._running.values())

    async def cancel_all(self) -> int:
        """Cancel all running executions."""
        count = 0
        for execution in list(self._running.values()):
            execution.state = ExecutionState.CANCELLED
            count += 1
        return count


class ConsoleProgressCallback(ProgressCallback):
    """Progress callback that prints to console."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def on_start(self, execution: ToolExecution) -> None:
        print(f"[*] Starting {execution.tool.name} on {execution.target}")

    def on_output(self, execution: ToolExecution, line: str) -> None:
        if self.verbose:
            print(f"    {line[:120]}")

    def on_complete(self, execution: ToolExecution) -> None:
        status = "✓" if execution.is_success else "✗"
        print(
            f"[{status}] {execution.tool.name}: "
            f"{len(execution.findings)} findings in {execution.duration_seconds:.1f}s"
        )

    def on_error(self, execution: ToolExecution, error: str) -> None:
        print(f"[!] {execution.tool.name} error: {error[:100]}")
