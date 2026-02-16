"""
AIPTX Runner Base - Abstract interface for scanner execution

This module defines the abstract base class and common data structures
for all runner implementations.

Key concepts:
- RunnerStatus: Tracks execution outcome (COMPLETED, FAILED, TIMEOUT, etc.)
- RunnerResult: Standardized result container with output and findings
- BaseRunner: Abstract interface all runners must implement
"""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class RunnerStatus(Enum):
    """
    Status of runner execution.

    This replaces ad-hoc status tracking with a consistent enum.
    FAILED tools are properly tracked, not shown as "0 findings".
    """
    PENDING = "pending"              # Not yet started
    RUNNING = "running"              # Currently executing
    COMPLETED = "completed"          # Finished successfully
    FAILED = "failed"                # Execution failed (error)
    TIMEOUT = "timeout"              # Exceeded time limit
    UNAVAILABLE = "unavailable"      # Tool not installed/reachable
    SKIPPED = "skipped"              # Intentionally skipped


@dataclass
class RunnerConfig:
    """Configuration for runner execution"""
    # Timeouts
    default_timeout: int = 300       # 5 minutes default
    max_timeout: int = 3600          # 1 hour max

    # Output handling
    capture_stdout: bool = True
    capture_stderr: bool = True
    output_dir: Optional[Path] = None

    # Environment
    env_vars: dict[str, str] = field(default_factory=dict)
    working_dir: Optional[Path] = None

    # Retry configuration
    max_retries: int = 0
    retry_delay: float = 5.0

    # Resource limits
    max_memory_mb: Optional[int] = None
    max_cpu_percent: Optional[float] = None


@dataclass
class RunnerResult:
    """
    Standardized result from runner execution.

    All runners return this format, enabling consistent handling
    regardless of execution context (local, VPS, API).
    """
    # Identification
    tool: str
    runner_type: str                  # "local", "vps", "api_enterprise"

    # Execution status
    status: RunnerStatus
    exit_code: Optional[int] = None
    error_message: Optional[str] = None

    # Output
    stdout: str = ""
    stderr: str = ""

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Findings (if available)
    findings: list[dict[str, Any]] = field(default_factory=list)
    findings_count: int = 0

    # Raw output files
    output_files: list[Path] = field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        """Check if execution was successful"""
        return self.status == RunnerStatus.COMPLETED

    @property
    def is_failure(self) -> bool:
        """Check if execution failed"""
        return self.status in [
            RunnerStatus.FAILED,
            RunnerStatus.TIMEOUT,
            RunnerStatus.UNAVAILABLE,
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "tool": self.tool,
            "runner_type": self.runner_type,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "error_message": self.error_message,
            "stdout_length": len(self.stdout),
            "stderr_length": len(self.stderr),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings_count": self.findings_count,
            "output_files": [str(p) for p in self.output_files],
            "metadata": self.metadata,
        }


class BaseRunner(ABC):
    """
    Abstract base class for scanner execution.

    All runner implementations (local, VPS, API) must implement this interface.
    This ensures consistent behavior and result handling across execution contexts.
    """

    def __init__(self, config: Optional[RunnerConfig] = None):
        self.config = config or RunnerConfig()
        self.runner_type = "base"

    @abstractmethod
    async def execute(
        self,
        tool: str,
        args: list[str],
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """
        Execute a tool and return results.

        Args:
            tool: Name of the tool to execute
            args: Command line arguments
            timeout: Optional timeout override (seconds)
            **kwargs: Additional runner-specific options

        Returns:
            RunnerResult with execution status and output
        """
        pass

    @abstractmethod
    async def get_status(self) -> dict[str, Any]:
        """
        Get current status of the runner.

        Returns:
            Dictionary with status information:
            - healthy: bool
            - available_tools: list[str]
            - resource_usage: dict
        """
        pass

    @abstractmethod
    async def check_tool_available(self, tool: str) -> bool:
        """
        Check if a tool is available for execution.

        Args:
            tool: Name of the tool to check

        Returns:
            True if tool is available
        """
        pass

    async def execute_with_retry(
        self,
        tool: str,
        args: list[str],
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """
        Execute with automatic retry on transient failures.

        Uses retry settings from config.
        """
        last_result: Optional[RunnerResult] = None

        for attempt in range(self.config.max_retries + 1):
            result = await self.execute(tool, args, timeout, **kwargs)

            if result.is_success:
                return result

            last_result = result

            # Check if failure is retryable
            if result.status == RunnerStatus.UNAVAILABLE:
                break  # Don't retry if tool is unavailable

            if attempt < self.config.max_retries:
                logger.warning(
                    f"Attempt {attempt + 1} failed for {tool}, "
                    f"retrying in {self.config.retry_delay}s..."
                )
                await asyncio.sleep(self.config.retry_delay)

        return last_result or RunnerResult(
            tool=tool,
            runner_type=self.runner_type,
            status=RunnerStatus.FAILED,
            error_message="All retry attempts exhausted",
        )

    def _create_result(
        self,
        tool: str,
        status: RunnerStatus,
        **kwargs: Any,
    ) -> RunnerResult:
        """Helper to create RunnerResult with defaults"""
        return RunnerResult(
            tool=tool,
            runner_type=self.runner_type,
            status=status,
            **kwargs,
        )
