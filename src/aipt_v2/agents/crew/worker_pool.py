"""
Worker Pool for Managing Concurrent Agent Execution.

Provides a pool of worker agents that can execute tasks
in parallel with dependency management and result collection.
"""

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .models import AgentStatus, AgentWorker, CrewConfig, WorkerCallback

if TYPE_CHECKING:
    from aipt_v2.llm import LLM

logger = logging.getLogger(__name__)


class WorkerPool:
    """
    Manages concurrent execution of worker agents.

    Features:
    - Spawn workers with tasks
    - Dependency-based execution ordering
    - Parallel execution with configurable limits
    - Event callbacks for progress tracking
    - Result collection and aggregation
    """

    def __init__(
        self,
        llm: Optional["LLM"] = None,
        tools: Optional[List[Any]] = None,
        target: str = "",
        config: Optional[CrewConfig] = None,
        on_worker_event: Optional[WorkerCallback] = None,
    ):
        """
        Initialize the worker pool.

        Args:
            llm: LLM instance for worker agents
            tools: Available tools for workers
            target: Target being tested
            config: Crew configuration
            on_worker_event: Callback for worker events
        """
        self.llm = llm
        self.tools = tools or []
        self.target = target
        self.config = config or CrewConfig()
        self.on_worker_event = on_worker_event

        self._workers: Dict[str, AgentWorker] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._results: Dict[str, str] = {}
        self._findings: List[Dict[str, Any]] = []
        self._next_id = 0
        self._lock = asyncio.Lock()

    def _emit(self, worker_id: str, event: str, data: Dict[str, Any]) -> None:
        """Emit event to callback if registered."""
        if self.on_worker_event:
            try:
                self.on_worker_event(worker_id, event, data)
            except Exception as e:
                logger.warning(f"Worker event callback failed: {e}")

    def _generate_id(self) -> str:
        """Generate unique worker ID."""
        worker_id = f"worker-{self._next_id}"
        self._next_id += 1
        return worker_id

    async def spawn(
        self,
        task: str,
        priority: int = 1,
        depends_on: Optional[List[str]] = None,
        max_iterations: int = 50,
    ) -> str:
        """
        Spawn a new worker agent.

        Args:
            task: The task description for the agent
            priority: Higher priority runs first
            depends_on: List of worker IDs that must complete first
            max_iterations: Maximum iterations for this worker

        Returns:
            The worker ID
        """
        async with self._lock:
            worker_id = self._generate_id()

            worker = AgentWorker(
                id=worker_id,
                task=task,
                priority=priority,
                depends_on=depends_on or [],
                max_iterations=max_iterations,
            )
            self._workers[worker_id] = worker

            # Emit spawn event
            self._emit(
                worker_id,
                "spawn",
                {
                    "task": task,
                    "priority": priority,
                    "depends_on": depends_on or [],
                },
            )

            # Start the worker task
            self._tasks[worker_id] = asyncio.create_task(self._run_worker(worker))

            logger.info(f"Spawned worker {worker_id}: {task[:50]}...")
            return worker_id

    async def _run_worker(self, worker: AgentWorker) -> None:
        """Run a single worker agent."""
        # Wait for dependencies
        if worker.depends_on:
            await self._wait_for_dependencies(worker.depends_on)

        worker.status = AgentStatus.RUNNING
        worker.started_at = time.time()
        self._emit(worker.id, "status", {"status": "running"})

        try:
            # Execute the worker task
            result = await self._execute_worker_task(worker)

            worker.result = result
            worker.completed_at = time.time()
            self._results[worker.id] = result

            # Determine final status
            if worker.iterations >= worker.max_iterations:
                worker.status = AgentStatus.WARNING
                self._emit(
                    worker.id,
                    "warning",
                    {
                        "summary": result[:200] if result else "No result",
                        "reason": "Max iterations reached",
                    },
                )
            else:
                worker.status = AgentStatus.COMPLETE
                self._emit(
                    worker.id,
                    "complete",
                    {"summary": result[:200] if result else "No result"},
                )

            logger.info(f"Worker {worker.id} completed: {worker.status.value}")

        except asyncio.CancelledError:
            worker.status = AgentStatus.CANCELLED
            worker.completed_at = time.time()
            self._emit(worker.id, "cancelled", {})
            logger.info(f"Worker {worker.id} cancelled")
            raise

        except Exception as e:
            logger.exception(f"Worker {worker.id} failed: {e}")
            worker.error = str(e)
            worker.status = AgentStatus.ERROR
            worker.completed_at = time.time()
            self._emit(worker.id, "error", {"error": str(e)})

    async def _execute_worker_task(self, worker: AgentWorker) -> str:
        """
        Execute the worker's task.

        This is a simplified implementation that processes the task.
        In a full implementation, this would use the LLM and tools.

        Args:
            worker: The worker to execute

        Returns:
            Task result string
        """
        # If LLM is available, use it for task execution
        if self.llm:
            return await self._execute_with_llm(worker)

        # Simple execution without LLM (for testing/basic use)
        return await self._execute_simple(worker)

    async def _execute_with_llm(self, worker: AgentWorker) -> str:
        """Execute task using LLM."""
        # Build context with target and findings
        context = f"Target: {self.target}\n\nTask: {worker.task}"

        if self.config.share_findings and self._findings:
            findings_text = "\n".join(
                f"- {f.get('title', 'Finding')}: {f.get('description', '')[:100]}"
                for f in self._findings[-10:]  # Last 10 findings
            )
            context += f"\n\nPrevious Findings:\n{findings_text}"

        results = []
        iteration = 0

        while iteration < worker.max_iterations:
            iteration += 1
            worker.iterations = iteration

            try:
                # Generate response
                response = await self.llm.generate(
                    prompt=context,
                    tools=self.tools,
                )

                # Track tokens
                if hasattr(response, "usage") and response.usage:
                    tokens = response.usage.get("total_tokens", 0)
                    worker.tokens_used += tokens
                    self._emit(worker.id, "tokens", {"tokens": tokens})

                # Process tool calls if any
                if hasattr(response, "tool_calls") and response.tool_calls:
                    for tc in response.tool_calls:
                        tool_name = tc.name if hasattr(tc, "name") else tc.get("name", "")
                        if tool_name and tool_name not in worker.tools_used:
                            worker.tools_used.append(tool_name)
                            self._emit(worker.id, "tool", {"tool": tool_name})

                    # Continue loop for tool execution
                    continue

                # No tool calls - this is the final response
                if hasattr(response, "content") and response.content:
                    results.append(response.content)
                    break

            except Exception as e:
                logger.warning(f"Worker {worker.id} iteration {iteration} error: {e}")
                if iteration >= worker.max_iterations:
                    raise

        return "\n\n".join(results) if results else "No results generated"

    async def _execute_simple(self, worker: AgentWorker) -> str:
        """Simple task execution without LLM (for testing)."""
        # Simulate some work
        await asyncio.sleep(0.1)
        worker.iterations = 1
        return f"Task completed: {worker.task}"

    async def _wait_for_dependencies(self, depends_on: List[str]) -> None:
        """Wait for dependent workers to complete."""
        for dep_id in depends_on:
            if dep_id in self._tasks:
                try:
                    await self._tasks[dep_id]
                except (asyncio.CancelledError, Exception) as e:
                    logger.warning(f"Dependency {dep_id} failed: {e}")
                    # Continue anyway - dependency failed but we proceed

    async def wait_for(
        self,
        worker_ids: Optional[List[str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Wait for specified workers (or all) to complete.

        Args:
            worker_ids: List of worker IDs to wait for. None = wait for all.
            timeout: Maximum time to wait (seconds)

        Returns:
            Dict mapping worker_id to result info
        """
        if worker_ids is None:
            worker_ids = list(self._tasks.keys())

        tasks_to_wait = [self._tasks[wid] for wid in worker_ids if wid in self._tasks]

        if not tasks_to_wait:
            return {}

        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks_to_wait, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for workers")

        # Collect results
        results = {}
        for worker_id in worker_ids:
            worker = self._workers.get(worker_id)
            if worker:
                results[worker_id] = {
                    "task": worker.task,
                    "status": worker.status.value,
                    "result": worker.result,
                    "error": worker.error,
                    "tools_used": worker.tools_used,
                    "duration": worker.duration,
                    "iterations": worker.iterations,
                    "tokens_used": worker.tokens_used,
                }

        return results

    def get_status(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific worker."""
        worker = self._workers.get(worker_id)
        if not worker:
            return None
        return worker.to_dict()

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all workers."""
        return {wid: w.to_dict() for wid, w in self._workers.items()}

    async def cancel(self, worker_id: str) -> bool:
        """Cancel a running worker."""
        if worker_id not in self._tasks:
            return False

        task = self._tasks[worker_id]
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return True
        return False

    async def cancel_all(self) -> None:
        """Cancel all running workers."""
        for task in self._tasks.values():
            if not task.done():
                task.cancel()

        # Wait for all to finish
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

        logger.info("All workers cancelled")

    def get_results(self) -> Dict[str, str]:
        """Get results from all completed workers."""
        return dict(self._results)

    def get_workers(self) -> List[AgentWorker]:
        """Get all workers."""
        return list(self._workers.values())

    def get_active_workers(self) -> List[AgentWorker]:
        """Get currently running workers."""
        return [w for w in self._workers.values() if w.status == AgentStatus.RUNNING]

    def get_pending_workers(self) -> List[AgentWorker]:
        """Get pending workers."""
        return [w for w in self._workers.values() if w.status == AgentStatus.PENDING]

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the shared findings list."""
        self._findings.append(finding)

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings from workers."""
        return list(self._findings)

    def reset(self) -> None:
        """Reset the pool for a new task."""
        self._workers.clear()
        self._tasks.clear()
        self._results.clear()
        self._findings.clear()
        self._next_id = 0
        logger.info("Worker pool reset")

    @property
    def is_idle(self) -> bool:
        """Check if all workers are complete."""
        return all(w.is_terminal for w in self._workers.values())

    @property
    def total_tokens(self) -> int:
        """Get total tokens used by all workers."""
        return sum(w.tokens_used for w in self._workers.values())

    def summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        statuses = {}
        for worker in self._workers.values():
            status = worker.status.value
            statuses[status] = statuses.get(status, 0) + 1

        return {
            "total_workers": len(self._workers),
            "status_counts": statuses,
            "total_tokens": self.total_tokens,
            "total_findings": len(self._findings),
            "total_results": len(self._results),
        }
