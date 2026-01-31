"""
AIPTX Agent Pool - Concurrent Agent Execution Manager

Manages parallel execution of specialized agents:
- Async task management
- Progress tracking
- Graceful cancellation
- Result aggregation

Replaces thread-based execution with async for better performance.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from aipt_v2.agents.specialized.base_specialized import SpecializedAgent

logger = logging.getLogger(__name__)


class AgentStatus(str, Enum):
    """Status of an agent in the pool."""
    PENDING = "pending"        # Waiting to start
    INITIALIZING = "initializing"  # Setting up
    RUNNING = "running"        # Actively executing
    PAUSED = "paused"          # Temporarily paused
    COMPLETED = "completed"    # Finished successfully
    FAILED = "failed"          # Failed with error
    CANCELLED = "cancelled"    # Cancelled by user/coordinator


@dataclass
class AgentResult:
    """Result from agent execution."""
    agent_id: str
    agent_name: str
    status: AgentStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    error: Optional[str] = None
    result_data: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get execution duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


@dataclass
class AgentEntry:
    """Internal entry for tracking an agent."""
    agent: "SpecializedAgent"
    task: Optional[asyncio.Task] = None
    status: AgentStatus = AgentStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[AgentResult] = None


class AgentPool:
    """
    Manages concurrent execution of multiple specialized agents.

    Features:
    - Parallel agent execution with configurable concurrency
    - Real-time status tracking
    - Graceful cancellation
    - Result aggregation
    - Progress callbacks

    Usage:
        pool = AgentPool(max_concurrent=5)

        # Add agents
        pool.add_agent(recon_agent)
        pool.add_agent(dast_agent)
        pool.add_agent(sast_agent)

        # Run all agents
        results = await pool.run_all()

        # Or run with progress callback
        async def on_progress(status):
            print(f"Progress: {status}")

        results = await pool.run_all(progress_callback=on_progress)
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        timeout: Optional[float] = None,
    ):
        """
        Initialize agent pool.

        Args:
            max_concurrent: Maximum agents to run concurrently
            timeout: Optional timeout for entire pool execution (seconds)
        """
        self._agents: dict[str, AgentEntry] = {}
        self._max_concurrent = max_concurrent
        self._timeout = timeout
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running = False
        self._cancelled = False
        self._progress_callback: Optional[callable] = None

    def add_agent(self, agent: "SpecializedAgent") -> str:
        """
        Add an agent to the pool.

        Args:
            agent: Agent to add

        Returns:
            Agent ID
        """
        agent_id = agent.agent_id
        self._agents[agent_id] = AgentEntry(agent=agent)
        logger.debug(f"Added agent {agent.name} ({agent_id}) to pool")
        return agent_id

    def remove_agent(self, agent_id: str) -> bool:
        """
        Remove an agent from the pool.

        Args:
            agent_id: ID of agent to remove

        Returns:
            True if agent was found and removed
        """
        if agent_id in self._agents:
            entry = self._agents[agent_id]
            if entry.status == AgentStatus.RUNNING:
                logger.warning(f"Cannot remove running agent {agent_id}")
                return False
            del self._agents[agent_id]
            return True
        return False

    async def run_all(
        self,
        progress_callback: Optional[callable] = None,
    ) -> list[AgentResult]:
        """
        Run all agents concurrently.

        Args:
            progress_callback: Called with status updates

        Returns:
            List of agent results
        """
        self._running = True
        self._cancelled = False
        self._progress_callback = progress_callback

        try:
            if self._timeout:
                results = await asyncio.wait_for(
                    self._run_agents(),
                    timeout=self._timeout
                )
            else:
                results = await self._run_agents()
        except asyncio.TimeoutError:
            logger.warning("Agent pool timed out")
            await self.cancel_all()
            results = self._collect_results()
        finally:
            self._running = False

        return results

    async def _run_agents(self) -> list[AgentResult]:
        """Execute all agents with semaphore-based concurrency."""
        tasks = []

        for agent_id, entry in self._agents.items():
            task = asyncio.create_task(
                self._run_single_agent(agent_id, entry),
                name=f"agent_{entry.agent.name}"
            )
            entry.task = task
            tasks.append(task)

        # Wait for all tasks
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return self._collect_results()

    async def _run_single_agent(
        self,
        agent_id: str,
        entry: AgentEntry,
    ) -> None:
        """Run a single agent with semaphore control."""
        async with self._semaphore:
            if self._cancelled:
                entry.status = AgentStatus.CANCELLED
                return

            entry.status = AgentStatus.RUNNING
            entry.started_at = datetime.now()
            await self._notify_progress()

            try:
                # Run the agent
                result = await entry.agent.run()

                entry.status = AgentStatus.COMPLETED
                entry.completed_at = datetime.now()
                entry.result = AgentResult(
                    agent_id=agent_id,
                    agent_name=entry.agent.name,
                    status=AgentStatus.COMPLETED,
                    started_at=entry.started_at,
                    completed_at=entry.completed_at,
                    findings_count=result.get("findings_count", 0),
                    result_data=result,
                )

            except asyncio.CancelledError:
                entry.status = AgentStatus.CANCELLED
                entry.completed_at = datetime.now()
                entry.result = AgentResult(
                    agent_id=agent_id,
                    agent_name=entry.agent.name,
                    status=AgentStatus.CANCELLED,
                    started_at=entry.started_at,
                    completed_at=entry.completed_at,
                )

            except Exception as e:
                logger.error(f"Agent {entry.agent.name} failed: {e}", exc_info=True)
                entry.status = AgentStatus.FAILED
                entry.completed_at = datetime.now()
                entry.error = str(e)
                entry.result = AgentResult(
                    agent_id=agent_id,
                    agent_name=entry.agent.name,
                    status=AgentStatus.FAILED,
                    started_at=entry.started_at,
                    completed_at=entry.completed_at,
                    error=str(e),
                )

            await self._notify_progress()

    async def _notify_progress(self) -> None:
        """Notify progress callback with current status."""
        if self._progress_callback:
            try:
                status = self.get_status()
                if asyncio.iscoroutinefunction(self._progress_callback):
                    await self._progress_callback(status)
                else:
                    self._progress_callback(status)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")

    def _collect_results(self) -> list[AgentResult]:
        """Collect results from all agents."""
        results = []
        for entry in self._agents.values():
            if entry.result:
                results.append(entry.result)
            else:
                # Create result for agents that didn't complete
                results.append(AgentResult(
                    agent_id=entry.agent.agent_id,
                    agent_name=entry.agent.name,
                    status=entry.status,
                    started_at=entry.started_at,
                    completed_at=entry.completed_at,
                    error=entry.error,
                ))
        return results

    async def cancel_all(self) -> None:
        """Cancel all running agents."""
        self._cancelled = True

        async with self._lock:
            for entry in self._agents.values():
                if entry.task and not entry.task.done():
                    entry.task.cancel()
                    try:
                        await entry.task
                    except asyncio.CancelledError:
                        pass
                    entry.status = AgentStatus.CANCELLED

        logger.info("Cancelled all agents in pool")

    async def cancel_agent(self, agent_id: str) -> bool:
        """
        Cancel a specific agent.

        Args:
            agent_id: ID of agent to cancel

        Returns:
            True if agent was found and cancelled
        """
        if agent_id not in self._agents:
            return False

        entry = self._agents[agent_id]
        if entry.task and not entry.task.done():
            entry.task.cancel()
            try:
                await entry.task
            except asyncio.CancelledError:
                pass
            entry.status = AgentStatus.CANCELLED
            return True
        return False

    def get_status(self) -> dict:
        """Get current pool status."""
        status_counts = {s: 0 for s in AgentStatus}
        agent_statuses = {}

        for agent_id, entry in self._agents.items():
            status_counts[entry.status] += 1
            agent_statuses[agent_id] = {
                "name": entry.agent.name,
                "status": entry.status.value,
                "started_at": entry.started_at.isoformat() if entry.started_at else None,
                "completed_at": entry.completed_at.isoformat() if entry.completed_at else None,
                "error": entry.error,
            }

        total = len(self._agents)
        completed = status_counts[AgentStatus.COMPLETED]
        failed = status_counts[AgentStatus.FAILED]
        running = status_counts[AgentStatus.RUNNING]

        return {
            "total_agents": total,
            "running": running,
            "completed": completed,
            "failed": failed,
            "pending": status_counts[AgentStatus.PENDING],
            "cancelled": status_counts[AgentStatus.CANCELLED],
            "progress_percent": (completed + failed) / total * 100 if total > 0 else 0,
            "is_running": self._running,
            "agents": agent_statuses,
        }

    def get_agent_status(self, agent_id: str) -> Optional[dict]:
        """Get status of a specific agent."""
        if agent_id not in self._agents:
            return None

        entry = self._agents[agent_id]
        return {
            "agent_id": agent_id,
            "name": entry.agent.name,
            "status": entry.status.value,
            "started_at": entry.started_at.isoformat() if entry.started_at else None,
            "completed_at": entry.completed_at.isoformat() if entry.completed_at else None,
            "error": entry.error,
        }

    @property
    def is_running(self) -> bool:
        """Check if pool is currently running."""
        return self._running

    @property
    def agent_count(self) -> int:
        """Get number of agents in pool."""
        return len(self._agents)
