"""
AIPT Docker Module

Container management for secure execution:
- Docker sandbox for isolated command execution
- Pre-configured images for security tools
- Resource limits and network isolation
- Container lifecycle management
"""

from __future__ import annotations

from .builder import ImageBuilder
from .manager import ContainerManager, SecurityImage
from .sandbox import DockerSandbox, SandboxConfig, SandboxResult

__all__ = [
    "DockerSandbox",
    "SandboxConfig",
    "SandboxResult",
    "ContainerManager",
    "SecurityImage",
    "ImageBuilder",
]
