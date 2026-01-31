"""
AIPT Agents Module - Agent orchestration and task tracking

Includes:
- PTT (Penetration Testing Tracker) for task management
- BaseAgent for general agent functionality
- ExploitReasoningAgent for LLM-powered exploitation
- CoordinatorAgent for multi-agent orchestration
- Specialized agents (Recon, SAST, DAST, BusinessLogic, WebSocket)
- Shared components (MessageBus, FindingRepository, AgentPool)
"""

# Core components that don't require external dependencies
from aipt_v2.agents.ptt import PTT, Task, Phase, TaskStatus, PhaseType
from aipt_v2.agents.state import AgentState

__all__ = [
    # Legacy components
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
    # Multi-agent architecture
    "CoordinatorAgent",
    "scan",
    "TargetProfile",
    "ScanStrategy",
    "ScanResult",
    # Shared components
    "MessageBus",
    "AgentMessage",
    "get_message_bus",
    "FindingRepository",
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "VulnerabilityType",
    "get_finding_repository",
    "AgentPool",
    "AgentStatus",
    "AgentResult",
    # Specialized agents
    "SpecializedAgent",
    "AgentCapability",
    "AgentConfig",
    "ReconAgent",
    "SASTAgent",
    "DASTAgent",
    "BusinessLogicAgent",
    "WebSocketAgent",
]


def __getattr__(name):
    """Lazy import for components with external dependencies"""
    # Legacy components
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

    # Multi-agent coordinator
    if name == "CoordinatorAgent":
        from aipt_v2.agents.coordinator import CoordinatorAgent
        return CoordinatorAgent
    if name == "scan":
        from aipt_v2.agents.coordinator import scan
        return scan
    if name == "TargetProfile":
        from aipt_v2.agents.coordinator import TargetProfile
        return TargetProfile
    if name == "ScanStrategy":
        from aipt_v2.agents.coordinator import ScanStrategy
        return ScanStrategy
    if name == "ScanResult":
        from aipt_v2.agents.coordinator import ScanResult
        return ScanResult

    # Shared components
    if name == "MessageBus":
        from aipt_v2.agents.shared.message_bus import MessageBus
        return MessageBus
    if name == "AgentMessage":
        from aipt_v2.agents.shared.message_bus import AgentMessage
        return AgentMessage
    if name == "get_message_bus":
        from aipt_v2.agents.shared.message_bus import get_message_bus
        return get_message_bus
    if name == "FindingRepository":
        from aipt_v2.agents.shared.finding_repository import FindingRepository
        return FindingRepository
    if name == "Finding":
        from aipt_v2.agents.shared.finding_repository import Finding
        return Finding
    if name == "FindingSeverity":
        from aipt_v2.agents.shared.finding_repository import FindingSeverity
        return FindingSeverity
    if name == "FindingStatus":
        from aipt_v2.agents.shared.finding_repository import FindingStatus
        return FindingStatus
    if name == "VulnerabilityType":
        from aipt_v2.agents.shared.finding_repository import VulnerabilityType
        return VulnerabilityType
    if name == "get_finding_repository":
        from aipt_v2.agents.shared.finding_repository import get_finding_repository
        return get_finding_repository
    if name == "AgentPool":
        from aipt_v2.agents.shared.agent_pool import AgentPool
        return AgentPool
    if name == "AgentStatus":
        from aipt_v2.agents.shared.agent_pool import AgentStatus
        return AgentStatus
    if name == "AgentResult":
        from aipt_v2.agents.shared.agent_pool import AgentResult
        return AgentResult

    # Specialized agents
    if name == "SpecializedAgent":
        from aipt_v2.agents.specialized.base_specialized import SpecializedAgent
        return SpecializedAgent
    if name == "AgentCapability":
        from aipt_v2.agents.specialized.base_specialized import AgentCapability
        return AgentCapability
    if name == "AgentConfig":
        from aipt_v2.agents.specialized.base_specialized import AgentConfig
        return AgentConfig
    if name == "ReconAgent":
        from aipt_v2.agents.specialized.recon_agent import ReconAgent
        return ReconAgent
    if name == "SASTAgent":
        from aipt_v2.agents.specialized.sast_agent import SASTAgent
        return SASTAgent
    if name == "DASTAgent":
        from aipt_v2.agents.specialized.dast_agent import DASTAgent
        return DASTAgent
    if name == "BusinessLogicAgent":
        from aipt_v2.agents.specialized.business_logic_agent import BusinessLogicAgent
        return BusinessLogicAgent
    if name == "WebSocketAgent":
        from aipt_v2.agents.specialized.websocket_agent import WebSocketAgent
        return WebSocketAgent

    raise AttributeError(f"module 'aipt_v2.agents' has no attribute '{name}'")
