"""
AIPTX Runners - Unified Scanner Execution Abstraction

This module provides a unified interface for executing security scanners
across different environments:

- LocalRunner: Execute tools locally via subprocess
- VPSRunner: Execute tools on remote VPS via SSH
- EnterpriseAPIRunner: Execute via enterprise scanner APIs (Acunetix, Burp, Nessus, ZAP)

Each runner implements the BaseRunner interface and returns standardized
RunnerResult objects with proper status tracking.

Usage:
    from aipt_v2.runners import LocalRunner, RunnerResult

    runner = LocalRunner()
    result = await runner.execute("nuclei", ["-u", "https://example.com"])

    if result.status == RunnerStatus.COMPLETED:
        print(f"Found {len(result.findings)} findings")
    else:
        print(f"Tool failed: {result.stderr}")
"""

from .base import (
    BaseRunner,
    RunnerResult,
    RunnerStatus,
    RunnerConfig,
)
from .local import LocalRunner
from .vps import VPSRunner
from .enterprise import EnterpriseAPIRunner

__all__ = [
    # Base
    "BaseRunner",
    "RunnerResult",
    "RunnerStatus",
    "RunnerConfig",
    # Implementations
    "LocalRunner",
    "VPSRunner",
    "EnterpriseAPIRunner",
]
