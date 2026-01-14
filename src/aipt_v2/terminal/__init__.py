"""
AIPT Terminal Module

Secure shell command execution with:
- Async subprocess management
- Output streaming
- Timeout handling
- Command sanitization
- Docker sandboxing support
"""

from .executor import (
    TerminalExecutor,
    CommandResult,
    ExecutionConfig,
)
from .sandbox import (
    DockerSandbox,
    SandboxConfig,
)

__all__ = [
    "TerminalExecutor",
    "CommandResult",
    "ExecutionConfig",
    "DockerSandbox",
    "SandboxConfig",
]
