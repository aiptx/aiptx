"""
AIPT Agents Module - Agent orchestration and task tracking

Includes:
- PTT (Penetration Testing Tracker) for task management
- BaseAgent for general agent functionality
- ExploitReasoningAgent for LLM-powered exploitation
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
    "BaseAgent",
    "ExploitReasoningAgent",
    "ExploitResult",
    "ExploitStep",
    "ExploitAction",
]


def __getattr__(name):
    """Lazy import for components with external dependencies"""
    if name == "BaseAgent":
        from aipt_v2.agents.base import BaseAgent
        return BaseAgent
    if name == "ExploitReasoningAgent":
        from aipt_v2.agents.exploit_agent import ExploitReasoningAgent
        return ExploitReasoningAgent
    if name == "ExploitResult":
        from aipt_v2.agents.exploit_agent import ExploitResult
        return ExploitResult
    if name == "ExploitStep":
        from aipt_v2.agents.exploit_agent import ExploitStep
        return ExploitStep
    if name == "ExploitAction":
        from aipt_v2.agents.exploit_agent import ExploitAction
        return ExploitAction
    raise AttributeError(f"module 'aipt_v2.agents' has no attribute '{name}'")
