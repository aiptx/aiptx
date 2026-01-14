"""
AIPT Task Scheduler - Priority-based task scheduling

Provides task scheduling with:
- Priority queues
- Rate limiting
- Concurrent execution limits
- Task dependencies
"""
from __future__ import annotations

import asyncio
import heapq
from typing import Optional, List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field
from enum import IntEnum
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class TaskPriority(IntEnum):
    """Task priority levels (lower value = higher priority)"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


class TaskStatus(str):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(order=True)
class ScheduledTask:
    """A task in the scheduler queue"""
    priority: TaskPriority
    task_id: str = field(compare=False)
    name: str = field(compare=False)
    handler: Callable[..., Awaitable[Any]] = field(compare=False)
    args: tuple = field(default_factory=tuple, compare=False)
    kwargs: Dict[str, Any] = field(default_factory=dict, compare=False)
    timeout: int = field(default=300, compare=False)
    retries: int = field(default=0, compare=False)
    depends_on: List[str] = field(default_factory=list, compare=False)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(), compare=False)
    status: str = field(default=TaskStatus.PENDING, compare=False)
    result: Any = field(default=None, compare=False)
    error: Optional[str] = field(default=None, compare=False)


class TaskScheduler:
    """
    Priority-based task scheduler with concurrency control.

    Example:
        scheduler = TaskScheduler(max_concurrent=5)

        # Add tasks
        scheduler.add_task(ScheduledTask(
            priority=TaskPriority.HIGH,
            task_id="scan_1",
            name="Port Scan",
            handler=port_scan,
            args=("192.168.1.1",),
        ))

        # Start scheduler
        await scheduler.run()
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        rate_limit: Optional[float] = None,  # Tasks per second
        on_task_start: Optional[Callable[[ScheduledTask], None]] = None,
        on_task_complete: Optional[Callable[[ScheduledTask], None]] = None,
    ):
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.on_task_start = on_task_start
        self.on_task_complete = on_task_complete

        self._queue: List[ScheduledTask] = []
        self._tasks: Dict[str, ScheduledTask] = {}
        self._running: Dict[str, asyncio.Task] = {}
        self._completed: Dict[str, ScheduledTask] = {}
        self._last_task_time: float = 0
        self._shutdown = False
        self._task_id_counter = 0

    def add_task(self, task: ScheduledTask) -> str:
        """Add task to the scheduler"""
        if not task.task_id:
            self._task_id_counter += 1
            task.task_id = f"task_{self._task_id_counter}"

        self._tasks[task.task_id] = task
        task.status = TaskStatus.QUEUED
        heapq.heappush(self._queue, task)

        logger.debug(f"Task {task.task_id} added to queue with priority {task.priority.name}")
        return task.task_id

    def create_task(
        self,
        name: str,
        handler: Callable[..., Awaitable[Any]],
        priority: TaskPriority = TaskPriority.NORMAL,
        **kwargs
    ) -> str:
        """Create and add a task"""
        task = ScheduledTask(
            priority=priority,
            task_id="",
            name=name,
            handler=handler,
            **kwargs
        )
        return self.add_task(task)

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending or running task"""
        if task_id in self._running:
            self._running[task_id].cancel()
            return True

        if task_id in self._tasks:
            task = self._tasks[task_id]
            task.status = TaskStatus.CANCELLED
            return True

        return False

    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """Get task by ID"""
        return self._tasks.get(task_id) or self._completed.get(task_id)

    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        return {
            "queued": len(self._queue),
            "running": len(self._running),
            "completed": len(self._completed),
            "total": len(self._tasks),
        }

    async def run(self) -> Dict[str, ScheduledTask]:
        """
        Run the scheduler until all tasks complete.

        Returns:
            Dict mapping task_id to completed task
        """
        self._shutdown = False

        while not self._shutdown:
            # Check if we're done
            if not self._queue and not self._running:
                break

            # Start new tasks if we have capacity
            while (
                self._queue
                and len(self._running) < self.max_concurrent
                and self._can_run_next()
            ):
                task = self._get_next_runnable_task()
                if task:
                    await self._start_task(task)
                else:
                    break

            # Wait for any task to complete
            if self._running:
                done, _ = await asyncio.wait(
                    self._running.values(),
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for future in done:
                    # Find the task_id for this future
                    for task_id, task_future in list(self._running.items()):
                        if task_future == future:
                            await self._handle_task_complete(task_id, future)
                            break
            else:
                await asyncio.sleep(0.1)

        return self._completed

    async def run_all(self, tasks: List[ScheduledTask]) -> Dict[str, ScheduledTask]:
        """Add all tasks and run until completion"""
        for task in tasks:
            self.add_task(task)
        return await self.run()

    def shutdown(self) -> None:
        """Signal scheduler to stop after current tasks"""
        self._shutdown = True

    async def _start_task(self, task: ScheduledTask) -> None:
        """Start executing a task"""
        task.status = TaskStatus.RUNNING

        if self.on_task_start:
            self.on_task_start(task)

        # Respect rate limit
        if self.rate_limit:
            import time
            now = time.time()
            min_interval = 1.0 / self.rate_limit
            if now - self._last_task_time < min_interval:
                await asyncio.sleep(min_interval - (now - self._last_task_time))
            self._last_task_time = time.time()

        # Create async task
        async_task = asyncio.create_task(
            self._execute_task(task)
        )
        self._running[task.task_id] = async_task

    async def _execute_task(self, task: ScheduledTask) -> Any:
        """Execute task with timeout and retries"""
        retries = 0
        last_error = None

        while retries <= task.retries:
            try:
                result = await asyncio.wait_for(
                    task.handler(*task.args, **task.kwargs),
                    timeout=task.timeout,
                )
                task.result = result
                task.status = TaskStatus.COMPLETED
                return result

            except asyncio.TimeoutError:
                last_error = f"Task timed out after {task.timeout}s"
            except asyncio.CancelledError:
                task.status = TaskStatus.CANCELLED
                raise
            except Exception as e:
                last_error = str(e)
                logger.error(f"Task {task.task_id} failed: {last_error}")

            retries += 1

        task.status = TaskStatus.FAILED
        task.error = last_error
        raise Exception(last_error)

    async def _handle_task_complete(self, task_id: str, future: asyncio.Task) -> None:
        """Handle task completion"""
        del self._running[task_id]
        task = self._tasks.pop(task_id, None)

        if task:
            try:
                future.result()
            except Exception:
                pass  # Error already recorded in task

            self._completed[task_id] = task

            if self.on_task_complete:
                self.on_task_complete(task)

    def _get_next_runnable_task(self) -> Optional[ScheduledTask]:
        """Get next task that has all dependencies met"""
        for i, task in enumerate(self._queue):
            if task.status == TaskStatus.CANCELLED:
                self._queue.pop(i)
                continue

            deps_met = all(
                dep_id in self._completed and self._completed[dep_id].status == TaskStatus.COMPLETED
                for dep_id in task.depends_on
            )

            if deps_met:
                return heapq.heappop(self._queue)

        return None

    def _can_run_next(self) -> bool:
        """Check if we can run the next task"""
        return len(self._running) < self.max_concurrent
