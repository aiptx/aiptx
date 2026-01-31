"""
AIPTX Shared Agent Components

Core infrastructure for multi-agent collaboration:
- MessageBus: Pub-sub system for inter-agent communication
- FindingRepository: Central storage for security findings
- AgentPool: Concurrent agent execution management
"""

from aipt_v2.agents.shared.message_bus import (
    MessageBus,
    AgentMessage,
    MessagePriority,
    MessageType,
    get_message_bus,
)
from aipt_v2.agents.shared.finding_repository import (
    FindingRepository,
    Finding,
    FindingSeverity,
    FindingStatus,
    get_finding_repository,
)
from aipt_v2.agents.shared.agent_pool import (
    AgentPool,
    AgentStatus,
    AgentResult,
)

__all__ = [
    # Message Bus
    "MessageBus",
    "AgentMessage",
    "MessagePriority",
    "MessageType",
    "get_message_bus",
    # Finding Repository
    "FindingRepository",
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "get_finding_repository",
    # Agent Pool
    "AgentPool",
    "AgentStatus",
    "AgentResult",
]
