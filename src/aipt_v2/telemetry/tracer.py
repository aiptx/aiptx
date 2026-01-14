"""
AIPT Telemetry Tracer - Agent execution tracking and monitoring

Provides comprehensive tracking of:
- Agent creation and status
- Tool executions
- Chat messages
- Vulnerability findings
- LLM usage statistics
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


@dataclass
class ToolExecution:
    """Record of a tool execution"""
    execution_id: int
    agent_id: str
    tool_name: str
    args: dict
    status: str = "running"
    result: Any = None
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None


@dataclass
class AgentRecord:
    """Record of an agent"""
    agent_id: str
    name: str
    task: str
    parent_id: Optional[str] = None
    status: str = "running"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class Tracer:
    """
    Tracer for agent execution telemetry.

    Tracks:
    - Agent lifecycle events
    - Tool executions
    - Chat messages
    - Vulnerability discoveries
    - LLM token usage and costs
    """

    def __init__(self, scan_id: str = ""):
        self.scan_id = scan_id
        self.scan_config: dict = {}

        # Agent tracking
        self.agents: dict[str, AgentRecord] = {}

        # Tool execution tracking
        self._next_execution_id: int = 0
        self.tool_executions: dict[int, ToolExecution] = {}

        # Vulnerability tracking
        self.vulnerability_reports: list[dict[str, Any]] = []
        self.vulnerability_found_callback: Optional[Callable[[str, str, str, str], None]] = None

        # Chat message tracking
        self.chat_messages: list[dict[str, Any]] = []

        # LLM usage tracking
        self._llm_stats: dict[str, Any] = {
            "total": {
                "input_tokens": 0,
                "output_tokens": 0,
                "cached_tokens": 0,
                "cache_creation_tokens": 0,
                "cost": 0.0,
                "requests": 0,
            },
            "by_agent": {},
        }

        # Final result storage
        self.final_scan_result: Optional[str] = None

        # Output directory
        self.output_dir = Path(f"aipt_runs/{scan_id}") if scan_id else None
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def set_scan_config(self, config: dict) -> None:
        """Set the scan configuration."""
        self.scan_config = config
        self.scan_id = config.get("scan_id", self.scan_id)

        if self.scan_id and not self.output_dir:
            self.output_dir = Path(f"aipt_runs/{self.scan_id}")
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def log_agent_creation(
        self,
        agent_id: str,
        name: str,
        task: str,
        parent_id: Optional[str] = None,
    ) -> None:
        """Log agent creation event."""
        record = AgentRecord(
            agent_id=agent_id,
            name=name,
            task=task,
            parent_id=parent_id,
        )
        self.agents[agent_id] = record

        logger.info(f"Agent created: {name} ({agent_id})")

    def log_tool_execution_start(
        self,
        agent_id: str,
        tool_name: str,
        args: dict,
    ) -> int:
        """Log start of tool execution."""
        self._next_execution_id += 1
        execution_id = self._next_execution_id

        execution = ToolExecution(
            execution_id=execution_id,
            agent_id=agent_id,
            tool_name=tool_name,
            args=args,
        )
        self.tool_executions[execution_id] = execution

        logger.info(f"Tool execution started: {tool_name} (exec_id={execution_id})")

        return execution_id

    def update_tool_execution(
        self,
        execution_id: int,
        status: str,
        result: Any = None,
    ) -> None:
        """Update tool execution status."""
        if execution_id in self.tool_executions:
            execution = self.tool_executions[execution_id]
            execution.status = status
            execution.result = result
            if status in ("completed", "failed"):
                execution.completed_at = datetime.now().isoformat()

            logger.info(f"Tool execution updated: exec_id={execution_id} status={status}")

    def update_agent_status(
        self,
        agent_id: str,
        status: str,
        error: Optional[str] = None,
    ) -> None:
        """Update agent status."""
        if agent_id in self.agents:
            self.agents[agent_id].status = status

            if error:
                logger.warning(f"Agent {agent_id} error: {error}")
            else:
                logger.info(f"Agent {agent_id} status: {status}")

    def log_chat_message(
        self,
        content: str,
        role: str,
        agent_id: str,
    ) -> None:
        """Log chat message."""
        message = {
            "agent_id": agent_id,
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
        }
        self.chat_messages.append(message)

    def report_vulnerability(
        self,
        report_id: str,
        title: str,
        content: str,
        severity: str,
    ) -> None:
        """Report a discovered vulnerability."""
        report = {
            "report_id": report_id,
            "title": title,
            "content": content,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        }
        self.vulnerability_reports.append(report)

        logger.warning(f"Vulnerability found: [{severity.upper()}] {title}")

        # Call the callback if registered
        if self.vulnerability_found_callback:
            try:
                self.vulnerability_found_callback(report_id, title, content, severity)
            except Exception as e:
                logger.error(f"Vulnerability callback failed: {e}")

    def update_llm_stats(
        self,
        agent_id: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached_tokens: int = 0,
        cache_creation_tokens: int = 0,
        cost: float = 0.0,
    ) -> None:
        """Update LLM usage statistics."""
        # Update total stats
        self._llm_stats["total"]["input_tokens"] += input_tokens
        self._llm_stats["total"]["output_tokens"] += output_tokens
        self._llm_stats["total"]["cached_tokens"] += cached_tokens
        self._llm_stats["total"]["cache_creation_tokens"] += cache_creation_tokens
        self._llm_stats["total"]["cost"] += cost
        self._llm_stats["total"]["requests"] += 1

        # Update per-agent stats
        if agent_id not in self._llm_stats["by_agent"]:
            self._llm_stats["by_agent"][agent_id] = {
                "input_tokens": 0,
                "output_tokens": 0,
                "cached_tokens": 0,
                "cache_creation_tokens": 0,
                "cost": 0.0,
                "requests": 0,
            }

        agent_stats = self._llm_stats["by_agent"][agent_id]
        agent_stats["input_tokens"] += input_tokens
        agent_stats["output_tokens"] += output_tokens
        agent_stats["cached_tokens"] += cached_tokens
        agent_stats["cache_creation_tokens"] += cache_creation_tokens
        agent_stats["cost"] += cost
        agent_stats["requests"] += 1

    def get_total_llm_stats(self) -> dict[str, Any]:
        """Get total LLM usage statistics."""
        return self._llm_stats

    def get_real_tool_count(self) -> int:
        """Get count of real tool executions (excluding internal tools)."""
        internal_tools = {
            "scan_start_info",
            "subagent_start_info",
            "llm_error_details",
        }
        count = 0
        for execution in self.tool_executions.values():
            if execution.tool_name not in internal_tools:
                count += 1
        return count

    def set_final_result(self, result: str) -> None:
        """Set the final scan result."""
        self.final_scan_result = result

    def cleanup(self) -> None:
        """Cleanup tracer resources and save final state."""
        if self.output_dir:
            try:
                # Save vulnerability reports
                vuln_file = self.output_dir / "vulnerabilities.json"
                with open(vuln_file, "w") as f:
                    json.dump(self.vulnerability_reports, f, indent=2)

                # Save tool executions
                tools_file = self.output_dir / "tool_executions.json"
                tool_data = [
                    {
                        "execution_id": e.execution_id,
                        "agent_id": e.agent_id,
                        "tool_name": e.tool_name,
                        "args": e.args,
                        "status": e.status,
                        "started_at": e.started_at,
                        "completed_at": e.completed_at,
                    }
                    for e in self.tool_executions.values()
                ]
                with open(tools_file, "w") as f:
                    json.dump(tool_data, f, indent=2)

                # Save LLM stats
                stats_file = self.output_dir / "llm_stats.json"
                with open(stats_file, "w") as f:
                    json.dump(self._llm_stats, f, indent=2)

                # Save final result
                if self.final_scan_result:
                    result_file = self.output_dir / "final_result.txt"
                    with open(result_file, "w") as f:
                        f.write(self.final_scan_result)

                logger.info(f"Tracer data saved to {self.output_dir}")

            except Exception as e:
                logger.error(f"Failed to save tracer data: {e}")

    def get_summary(self) -> dict[str, Any]:
        """Get summary of the scan."""
        return {
            "scan_id": self.scan_id,
            "agents_count": len(self.agents),
            "tool_executions_count": self.get_real_tool_count(),
            "vulnerabilities_count": len(self.vulnerability_reports),
            "chat_messages_count": len(self.chat_messages),
            "llm_stats": self._llm_stats["total"],
        }


# Global tracer instance
_global_tracer: Optional[Tracer] = None


def get_global_tracer() -> Optional[Tracer]:
    """Get the global tracer instance."""
    return _global_tracer


def set_global_tracer(tracer: Tracer) -> None:
    """Set the global tracer instance."""
    global _global_tracer
    _global_tracer = tracer


__all__ = ["Tracer", "get_global_tracer", "set_global_tracer"]
