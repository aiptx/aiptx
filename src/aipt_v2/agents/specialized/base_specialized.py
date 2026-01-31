"""
AIPTX Specialized Agent Base Class

Base class for all specialized security testing agents.
Provides:
- Message bus integration for inter-agent communication
- Finding repository integration
- Common scanning patterns
- Progress reporting
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Callable, Coroutine

from aipt_v2.agents.shared.message_bus import (
    MessageBus,
    AgentMessage,
    MessageType,
    MessagePriority,
    get_message_bus,
)
from aipt_v2.agents.shared.finding_repository import (
    FindingRepository,
    Finding,
    FindingSeverity,
    get_finding_repository,
)

logger = logging.getLogger(__name__)


class AgentCapability(str, Enum):
    """Capabilities that agents can have."""
    # Reconnaissance
    SUBDOMAIN_ENUM = "subdomain_enumeration"
    PORT_SCAN = "port_scanning"
    TECH_DETECTION = "technology_detection"
    DIRECTORY_ENUM = "directory_enumeration"

    # SAST
    CODE_ANALYSIS = "code_analysis"
    SECRET_DETECTION = "secret_detection"
    DEPENDENCY_SCAN = "dependency_scanning"
    TAINT_ANALYSIS = "taint_analysis"

    # DAST
    INJECTION_TESTING = "injection_testing"
    AUTH_TESTING = "authentication_testing"
    XSS_TESTING = "xss_testing"
    FUZZING = "fuzzing"

    # Business Logic
    WORKFLOW_ANALYSIS = "workflow_analysis"
    RACE_CONDITION = "race_condition_testing"
    PRICE_MANIPULATION = "price_manipulation_testing"
    ACCESS_CONTROL = "access_control_testing"

    # WebSocket
    WS_INTERCEPTION = "websocket_interception"
    WS_FUZZING = "websocket_fuzzing"
    WS_INJECTION = "websocket_injection"

    # GraphQL
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    GRAPHQL_INJECTION = "graphql_injection"

    # General
    BROWSER_AUTOMATION = "browser_automation"
    API_TESTING = "api_testing"


@dataclass
class AgentConfig:
    """Configuration for specialized agents."""
    target: str
    timeout: int = 300
    max_findings: int = 1000
    capabilities: list[AgentCapability] = field(default_factory=list)
    enabled_tools: list[str] = field(default_factory=list)
    disabled_tools: list[str] = field(default_factory=list)
    auth_config: Optional[dict] = None
    scope_config: Optional[dict] = None
    custom_config: dict = field(default_factory=dict)


@dataclass
class AgentProgress:
    """Progress tracking for agent execution."""
    agent_id: str
    agent_name: str
    status: str
    current_task: str = ""
    progress_percent: float = 0.0
    findings_count: int = 0
    started_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    metadata: dict = field(default_factory=dict)


class SpecializedAgent(ABC):
    """
    Base class for specialized security testing agents.

    Specialized agents:
    - Focus on specific testing domain (recon, SAST, DAST, etc.)
    - Integrate with message bus for collaboration
    - Push findings to central repository
    - Report progress to coordinator

    Subclasses must implement:
    - `run()`: Main execution method
    - `get_capabilities()`: Return supported capabilities
    - `name`: Agent name property

    Usage:
        class MyAgent(SpecializedAgent):
            name = "MyAgent"

            def get_capabilities(self):
                return [AgentCapability.XSS_TESTING]

            async def run(self):
                # Perform testing
                await self.add_finding(finding)
                return {"success": True}
    """

    name: str = "SpecializedAgent"

    def __init__(
        self,
        config: AgentConfig,
        message_bus: Optional[MessageBus] = None,
        finding_repository: Optional[FindingRepository] = None,
    ):
        """
        Initialize specialized agent.

        Args:
            config: Agent configuration
            message_bus: Message bus for communication (uses global if None)
            finding_repository: Finding repository (uses global if None)
        """
        self.config = config
        self.target = config.target
        self.agent_id = str(uuid.uuid4())
        self._message_bus = message_bus or get_message_bus()
        self._finding_repository = finding_repository or get_finding_repository()
        self._running = False
        self._cancelled = False
        self._started_at: Optional[datetime] = None
        self._progress = AgentProgress(
            agent_id=self.agent_id,
            agent_name=self.name,
            status="pending",
        )
        self._subscriptions: list[str] = []
        self._findings_count = 0

    @abstractmethod
    def get_capabilities(self) -> list[AgentCapability]:
        """Return list of capabilities this agent provides."""
        pass

    @abstractmethod
    async def run(self) -> dict[str, Any]:
        """
        Execute the agent's main task.

        Returns:
            Dictionary with execution results
        """
        pass

    async def initialize(self) -> None:
        """Initialize agent before execution."""
        # Subscribe to relevant messages
        await self._subscribe_to_messages()

        # Publish agent started message
        await self._publish_status(MessageType.AGENT_STARTED)

        logger.info(f"Agent {self.name} ({self.agent_id}) initialized for {self.target}")

    async def _subscribe_to_messages(self) -> None:
        """Subscribe to relevant message bus topics."""
        # Subscribe to coordination messages
        sub_id = await self._message_bus.subscribe(
            topic="coordination.response.*",
            callback=self._handle_coordination_response,
            subscriber_id=self.agent_id,
        )
        self._subscriptions.append(sub_id)

        # Subscribe to findings from other agents (for correlation)
        sub_id = await self._message_bus.subscribe(
            topic="findings.new",
            callback=self._handle_new_finding,
            subscriber_id=self.agent_id,
        )
        self._subscriptions.append(sub_id)

    async def _handle_coordination_response(self, message: AgentMessage) -> None:
        """Handle coordination response from coordinator."""
        # Override in subclass if needed
        logger.debug(f"Agent {self.name} received coordination response: {message.content}")

    async def _handle_new_finding(self, message: AgentMessage) -> None:
        """Handle new finding from another agent."""
        # Override in subclass if needed for cross-agent correlation
        pass

    async def cleanup(self) -> None:
        """Cleanup after agent execution."""
        # Unsubscribe from all topics
        for sub_id in self._subscriptions:
            await self._message_bus.unsubscribe(sub_id)

        # Publish agent completed message
        status = MessageType.AGENT_COMPLETED if not self._cancelled else MessageType.AGENT_FAILED
        await self._publish_status(status)

        logger.info(f"Agent {self.name} ({self.agent_id}) cleaned up")

    async def add_finding(
        self,
        finding: Finding,
        notify: bool = True,
    ) -> str:
        """
        Add a finding to the central repository.

        Args:
            finding: Finding to add
            notify: Whether to publish to message bus

        Returns:
            Finding ID
        """
        # Set agent info
        finding.discovered_by = self.agent_id
        finding.agent_name = self.name
        finding.target = self.target

        # Add to repository
        was_added, finding_id = await self._finding_repository.add(
            finding=finding,
            source_agent=self.agent_id,
        )

        if was_added:
            self._findings_count += 1
            self._progress.findings_count = self._findings_count

            logger.info(
                f"Agent {self.name} found: {finding.title} "
                f"({finding.severity.value})"
            )

        return finding_id or finding.id

    async def request_coordination(
        self,
        request_type: str,
        data: Any,
    ) -> str:
        """
        Request coordination from the coordinator agent.

        Args:
            request_type: Type of request (e.g., "need_help", "share_findings")
            data: Request data

        Returns:
            Correlation ID for tracking response
        """
        return await self._message_bus.request_coordination(
            request_type=request_type,
            content=data,
            sender_id=self.agent_id,
            sender_name=self.name,
        )

    async def update_progress(
        self,
        current_task: str,
        progress_percent: float,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Update and publish progress.

        Args:
            current_task: Description of current task
            progress_percent: Completion percentage (0-100)
            metadata: Optional additional data
        """
        self._progress.current_task = current_task
        self._progress.progress_percent = progress_percent
        if metadata:
            self._progress.metadata.update(metadata)

        await self._publish_status(MessageType.AGENT_PROGRESS)

    async def _publish_status(self, message_type: MessageType) -> None:
        """Publish status update to message bus."""
        message = AgentMessage(
            topic=f"agent.status.{self.agent_id}",
            message_type=message_type,
            sender_id=self.agent_id,
            sender_name=self.name,
            content={
                "agent_id": self.agent_id,
                "agent_name": self.name,
                "status": self._progress.status,
                "current_task": self._progress.current_task,
                "progress_percent": self._progress.progress_percent,
                "findings_count": self._progress.findings_count,
                "target": self.target,
            },
            priority=MessagePriority.NORMAL,
        )
        await self._message_bus.publish(message)

    def cancel(self) -> None:
        """Request cancellation of agent execution."""
        self._cancelled = True
        logger.info(f"Agent {self.name} cancellation requested")

    @property
    def is_cancelled(self) -> bool:
        """Check if cancellation was requested."""
        return self._cancelled

    def check_cancelled(self) -> None:
        """Check if cancelled and raise if so."""
        if self._cancelled:
            raise asyncio.CancelledError(f"Agent {self.name} was cancelled")

    async def wait_with_cancel_check(
        self,
        coro: Coroutine,
        check_interval: float = 1.0,
    ) -> Any:
        """
        Wait for a coroutine with periodic cancellation checks.

        Args:
            coro: Coroutine to wait for
            check_interval: How often to check for cancellation

        Returns:
            Result of the coroutine
        """
        task = asyncio.create_task(coro)

        while not task.done():
            self.check_cancelled()
            try:
                return await asyncio.wait_for(
                    asyncio.shield(task),
                    timeout=check_interval
                )
            except asyncio.TimeoutError:
                continue

        return await task

    def has_capability(self, capability: AgentCapability) -> bool:
        """Check if agent has a specific capability."""
        return capability in self.get_capabilities()

    def get_enabled_tools(self) -> list[str]:
        """Get list of enabled tools for this agent."""
        return self.config.enabled_tools

    def get_auth_config(self) -> Optional[dict]:
        """Get authentication configuration."""
        return self.config.auth_config
