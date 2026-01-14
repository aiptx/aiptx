"""
AIPT Runtime Module - Docker sandbox, VPS, and local execution environments
"""

from aipt_v2.runtime.base import AbstractRuntime, SandboxInfo

# Lazy import for DockerRuntime and VPSRuntime to avoid dependency issues
_runtime = None


def __getattr__(name):
    """Lazy import for optional dependencies"""
    if name == "DockerRuntime":
        from aipt_v2.runtime.docker import DockerRuntime
        return DockerRuntime
    elif name == "VPSRuntime":
        from aipt_v2.runtime.vps import VPSRuntime
        return VPSRuntime
    elif name == "LocalRuntime":
        from aipt_v2.runtime.local import LocalRuntime
        return LocalRuntime
    elif name == "generate_vps_setup_script":
        from aipt_v2.runtime.vps import generate_vps_setup_script
        return generate_vps_setup_script
    raise AttributeError(f"module 'aipt_v2.runtime' has no attribute '{name}'")


def get_runtime():
    """Get or create the global runtime instance"""
    global _runtime
    if _runtime is None:
        from aipt_v2.runtime.docker import DockerRuntime
        _runtime = DockerRuntime()
    return _runtime


def set_runtime(runtime: AbstractRuntime) -> None:
    """Set the global runtime instance"""
    global _runtime
    _runtime = runtime


# Alias for backwards compatibility
BaseRuntime = AbstractRuntime


__all__ = [
    "AbstractRuntime",
    "BaseRuntime",
    "SandboxInfo",
    "get_runtime",
    "set_runtime",
]
