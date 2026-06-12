"""
AIPT Execution Module

Command execution with security and isolation:
- Terminal wrapper for subprocess execution
- Output parser for structured findings
- Sandbox integration for Docker isolation
- Result handling and error management
- Tool registry and discovery
- Local tool executor with parallel execution
- Result collection and aggregation
- Phase-based pipeline orchestration
"""

from __future__ import annotations

from .executor import ExecutionEngine, ExecutionMode

# Local Tool Executor
from .local_tool_executor import (
    ConsoleProgressCallback,
    ExecutionBatch,
    ExecutionState,
    LocalToolExecutor,
    ProgressCallback,
    ToolExecution,
)
from .parser import Finding, OutputParser

# Phase Runner
from .phase_runner import (
    PhaseConfig,
    PhaseReport,
    PhaseRunner,
    PipelineConfig,
    PipelineReport,
    PipelineState,
    run_full_scan,
    run_quick_scan,
)

# Result Collector
from .result_collector import (
    AttackPath,
    FindingSeverity,
    NormalizedFinding,
    PhaseResults,
    ResultCollector,
)
from .terminal import ExecutionResult, Terminal

# Tool Registry
from .tool_registry import (
    TOOL_REGISTRY,
    ToolCapability,
    ToolConfig,
    ToolPhase,
    ToolRegistry,
    ToolStatus,
    discover_tools,
    get_registry,
)

__all__ = [
    # Core execution
    "Terminal",
    "ExecutionResult",
    "OutputParser",
    "Finding",
    "ExecutionEngine",
    "ExecutionMode",
    # Tool registry
    "ToolRegistry",
    "ToolConfig",
    "ToolPhase",
    "ToolCapability",
    "ToolStatus",
    "get_registry",
    "discover_tools",
    "TOOL_REGISTRY",
    # Executor
    "LocalToolExecutor",
    "ToolExecution",
    "ExecutionBatch",
    "ExecutionState",
    "ProgressCallback",
    "ConsoleProgressCallback",
    # Result collection
    "ResultCollector",
    "NormalizedFinding",
    "PhaseResults",
    "AttackPath",
    "FindingSeverity",
    # Phase runner
    "PhaseRunner",
    "PipelineConfig",
    "PhaseConfig",
    "PipelineReport",
    "PhaseReport",
    "PipelineState",
    "run_quick_scan",
    "run_full_scan",
]
