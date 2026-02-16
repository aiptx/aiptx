"""
AIPTX Crew - Parallel Worker Agent Management
=============================================

Provides a worker pool for executing multiple agent tasks
in parallel with dependency management and result collection.

Example usage:
    from aipt_v2.agents.crew import WorkerPool, CrewConfig

    # Create a worker pool
    config = CrewConfig(max_workers=5, parallel_execution=True)
    pool = WorkerPool(llm=llm, tools=tools, target="http://example.com", config=config)

    # Spawn workers
    recon_id = await pool.spawn("Enumerate subdomains and endpoints")
    scan_id = await pool.spawn("Scan for SQL injection", depends_on=[recon_id])
    xss_id = await pool.spawn("Scan for XSS vulnerabilities", depends_on=[recon_id])

    # Wait for all to complete
    results = await pool.wait_for()

    # Get summary
    print(pool.summary())

Features:
    - Parallel execution with configurable limits
    - Dependency-based execution ordering
    - Event callbacks for progress tracking
    - Result and finding aggregation
    - Graceful cancellation
"""

from .models import (
    AgentStatus,
    AgentWorker,
    CrewConfig,
    CrewState,
    Finding,
    WorkerCallback,
    WorkerEvent,
)
from .worker_pool import WorkerPool

__all__ = [
    # Enums
    "AgentStatus",
    "CrewState",
    # Data models
    "AgentWorker",
    "CrewConfig",
    "Finding",
    "WorkerEvent",
    # Type aliases
    "WorkerCallback",
    # Main class
    "WorkerPool",
]
