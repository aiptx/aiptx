"""
AIPT Pipeline - Flexible stage-based execution pipeline

Provides a configurable pipeline for pentest workflows with:
- Custom stage definitions
- Conditional execution
- Parallel stage support
- Progress callbacks
"""
from __future__ import annotations

import asyncio
from typing import Optional, List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class StageStatus(str, Enum):
    """Stage execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PipelineStage:
    """
    A stage in the pipeline.

    Attributes:
        name: Stage identifier
        description: Human-readable description
        handler: Async function to execute
        depends_on: List of stage names this depends on
        condition: Optional function to check if stage should run
        timeout: Stage timeout in seconds
        retry_count: Number of retries on failure
    """
    name: str
    description: str
    handler: Callable[..., Awaitable[Any]]
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[Callable[[Dict], bool]] = None
    timeout: int = 600
    retry_count: int = 0
    parallel_group: Optional[str] = None  # Stages in same group run in parallel


@dataclass
class StageResult:
    """Result of stage execution"""
    stage_name: str
    status: StageStatus
    output: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    retries: int = 0


@dataclass
class PipelineResult:
    """Result of pipeline execution"""
    success: bool
    stages: Dict[str, StageResult]
    total_duration: float
    started_at: str
    completed_at: str
    context: Dict[str, Any] = field(default_factory=dict)

    @property
    def failed_stages(self) -> List[str]:
        return [name for name, result in self.stages.items() if result.status == StageStatus.FAILED]

    @property
    def completed_stages(self) -> List[str]:
        return [name for name, result in self.stages.items() if result.status == StageStatus.COMPLETED]


class Pipeline:
    """
    Flexible execution pipeline for pentest workflows.

    Example:
        pipeline = Pipeline("recon_pipeline")

        pipeline.add_stage(PipelineStage(
            name="subdomain_enum",
            description="Enumerate subdomains",
            handler=enumerate_subdomains,
        ))

        pipeline.add_stage(PipelineStage(
            name="port_scan",
            description="Scan ports",
            handler=scan_ports,
            depends_on=["subdomain_enum"],
        ))

        result = await pipeline.run(context={"target": "example.com"})
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        on_stage_start: Optional[Callable[[str], None]] = None,
        on_stage_complete: Optional[Callable[[str, StageResult], None]] = None,
        on_progress: Optional[Callable[[float, str], None]] = None,
    ):
        self.name = name
        self.description = description
        self.stages: Dict[str, PipelineStage] = {}
        self.stage_order: List[str] = []

        # Callbacks
        self.on_stage_start = on_stage_start
        self.on_stage_complete = on_stage_complete
        self.on_progress = on_progress

    def add_stage(self, stage: PipelineStage) -> "Pipeline":
        """Add a stage to the pipeline"""
        self.stages[stage.name] = stage
        if stage.name not in self.stage_order:
            self.stage_order.append(stage.name)
        return self

    def remove_stage(self, name: str) -> "Pipeline":
        """Remove a stage from the pipeline"""
        if name in self.stages:
            del self.stages[name]
            self.stage_order.remove(name)
        return self

    async def run(
        self,
        context: Optional[Dict[str, Any]] = None,
        start_from: Optional[str] = None,
        stop_at: Optional[str] = None,
    ) -> PipelineResult:
        """
        Execute the pipeline.

        Args:
            context: Shared context passed to all stages
            start_from: Start from this stage (skip previous)
            stop_at: Stop after this stage

        Returns:
            PipelineResult with all stage results
        """
        import time

        start_time = time.time()
        started_at = datetime.now().isoformat()
        context = context or {}
        results: Dict[str, StageResult] = {}

        # Determine execution order respecting dependencies
        execution_order = self._get_execution_order()

        # Filter stages if start_from/stop_at specified
        if start_from:
            try:
                start_idx = execution_order.index(start_from)
                execution_order = execution_order[start_idx:]
            except ValueError:
                pass

        if stop_at:
            try:
                stop_idx = execution_order.index(stop_at) + 1
                execution_order = execution_order[:stop_idx]
            except ValueError:
                pass

        total_stages = len(execution_order)
        completed_count = 0

        # Group parallel stages
        parallel_groups = self._group_parallel_stages(execution_order)

        for group in parallel_groups:
            # Check if all dependencies are met
            deps_met = all(
                all(
                    dep in results and results[dep].status == StageStatus.COMPLETED
                    for dep in self.stages[stage_name].depends_on
                )
                for stage_name in group
            )

            if not deps_met:
                for stage_name in group:
                    results[stage_name] = StageResult(
                        stage_name=stage_name,
                        status=StageStatus.SKIPPED,
                        error="Dependencies not met",
                    )
                continue

            # Execute group (parallel if multiple, sequential if single)
            if len(group) > 1:
                group_results = await self._run_parallel_stages(group, context, results)
            else:
                stage_name = group[0]
                result = await self._run_stage(stage_name, context, results)
                group_results = {stage_name: result}

            results.update(group_results)
            completed_count += len(group)

            # Progress callback
            if self.on_progress:
                progress = completed_count / total_stages
                self.on_progress(progress, f"Completed {completed_count}/{total_stages} stages")

        completed_at = datetime.now().isoformat()
        total_duration = time.time() - start_time

        # Determine overall success
        success = all(
            r.status in [StageStatus.COMPLETED, StageStatus.SKIPPED]
            for r in results.values()
        )

        return PipelineResult(
            success=success,
            stages=results,
            total_duration=total_duration,
            started_at=started_at,
            completed_at=completed_at,
            context=context,
        )

    async def _run_stage(
        self,
        stage_name: str,
        context: Dict[str, Any],
        previous_results: Dict[str, StageResult],
    ) -> StageResult:
        """Execute a single stage"""
        import time

        stage = self.stages[stage_name]
        start_time = time.time()
        started_at = datetime.now().isoformat()
        retries = 0

        # Check condition
        if stage.condition and not stage.condition(context):
            return StageResult(
                stage_name=stage_name,
                status=StageStatus.SKIPPED,
                started_at=started_at,
                completed_at=datetime.now().isoformat(),
            )

        # Notify start
        if self.on_stage_start:
            self.on_stage_start(stage_name)

        while retries <= stage.retry_count:
            try:
                # Execute with timeout
                output = await asyncio.wait_for(
                    stage.handler(context, previous_results),
                    timeout=stage.timeout,
                )

                result = StageResult(
                    stage_name=stage_name,
                    status=StageStatus.COMPLETED,
                    output=output,
                    duration=time.time() - start_time,
                    started_at=started_at,
                    completed_at=datetime.now().isoformat(),
                    retries=retries,
                )

                # Notify complete
                if self.on_stage_complete:
                    self.on_stage_complete(stage_name, result)

                return result

            except asyncio.TimeoutError:
                error = f"Stage timed out after {stage.timeout}s"
            except Exception as e:
                error = str(e)
                logger.error(f"Stage {stage_name} failed: {error}")

            retries += 1

        # All retries failed
        result = StageResult(
            stage_name=stage_name,
            status=StageStatus.FAILED,
            error=error,
            duration=time.time() - start_time,
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            retries=retries - 1,
        )

        if self.on_stage_complete:
            self.on_stage_complete(stage_name, result)

        return result

    async def _run_parallel_stages(
        self,
        stage_names: List[str],
        context: Dict[str, Any],
        previous_results: Dict[str, StageResult],
    ) -> Dict[str, StageResult]:
        """Execute multiple stages in parallel"""
        tasks = [
            self._run_stage(name, context, previous_results)
            for name in stage_names
        ]
        results = await asyncio.gather(*tasks)
        return dict(zip(stage_names, results))

    def _get_execution_order(self) -> List[str]:
        """Topological sort of stages based on dependencies"""
        visited = set()
        order = []

        def visit(name: str):
            if name in visited:
                return
            visited.add(name)

            stage = self.stages.get(name)
            if stage:
                for dep in stage.depends_on:
                    if dep in self.stages:
                        visit(dep)
                order.append(name)

        for stage_name in self.stage_order:
            visit(stage_name)

        return order

    def _group_parallel_stages(self, execution_order: List[str]) -> List[List[str]]:
        """Group stages that can run in parallel"""
        groups = []
        current_group = []
        current_parallel_group = None

        for stage_name in execution_order:
            stage = self.stages[stage_name]

            if stage.parallel_group:
                if stage.parallel_group == current_parallel_group:
                    current_group.append(stage_name)
                else:
                    if current_group:
                        groups.append(current_group)
                    current_group = [stage_name]
                    current_parallel_group = stage.parallel_group
            else:
                if current_group:
                    groups.append(current_group)
                groups.append([stage_name])
                current_group = []
                current_parallel_group = None

        if current_group:
            groups.append(current_group)

        return groups

    def visualize(self) -> str:
        """Generate ASCII visualization of the pipeline"""
        lines = [f"Pipeline: {self.name}"]
        lines.append("=" * 50)

        execution_order = self._get_execution_order()

        for i, stage_name in enumerate(execution_order):
            stage = self.stages[stage_name]
            prefix = "└── " if i == len(execution_order) - 1 else "├── "
            deps = f" (depends on: {', '.join(stage.depends_on)})" if stage.depends_on else ""
            lines.append(f"{prefix}{stage_name}{deps}")
            if stage.description:
                lines.append(f"    {stage.description}")

        return "\n".join(lines)
