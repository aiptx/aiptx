"""
AIPT Agents Module - Agent orchestration and task tracking
"""

# Core components that don't require external dependencies
from aipt_v2.agents.ptt import PTT, Task, Phase, TaskStatus, PhaseType
from aipt_v2.agents.state import AgentState

__all__ = [
    "PTT",
    "Task",
    "Phase",
    "PhaseType",
    "TaskStatus",
    "AgentState",
]


def __getattr__(name):
    """Lazy import for components with external dependencies"""
    if name == "BaseAgent":
        from aipt_v2.agents.base import BaseAgent
        return BaseAgent
    raise AttributeError(f"module 'aipt_v2.agents' has no attribute '{name}'")
