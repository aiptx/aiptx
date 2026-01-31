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

from .terminal import Terminal, ExecutionResult
from .parser import OutputParser, Finding
from .executor import ExecutionEngine, ExecutionMode

# Tool Registry
from .tool_registry import (
    ToolRegistry,
    ToolConfig,
    ToolPhase,
    ToolCapability,
    ToolStatus,
    get_registry,
    discover_tools,
    TOOL_REGISTRY,
)

# Local Tool Executor
from .local_tool_executor import (
    LocalToolExecutor,
    ToolExecution,
    ExecutionBatch,
    ExecutionState,
    ProgressCallback,
    ConsoleProgressCallback,
)

# Result Collector
from .result_collector import (
    ResultCollector,
    NormalizedFinding,
    PhaseResults,
    AttackPath,
    FindingSeverity,
)

# Phase Runner
from .phase_runner import (
    PhaseRunner,
    PipelineConfig,
    PhaseConfig,
    PipelineReport,
    PhaseReport,
    PipelineState,
    run_quick_scan,
    run_full_scan,
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
