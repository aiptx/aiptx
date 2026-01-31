"""
AIPTX Message Bus - Inter-Agent Communication System

Provides publish-subscribe messaging for multi-agent collaboration:
- Topic-based message routing
- Priority-based delivery
- Async message handling
- Message history and replay

Topics:
- findings.new: New finding discovered
- findings.validated: Finding validated with PoC
- agent.status: Agent status updates
- coordination.request: Agent requests help from coordinator
- coordination.response: Coordinator responds to requests
- scan.progress: Overall scan progress updates
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger(__name__)


class MessagePriority(str, Enum):
    """Message priority levels for delivery ordering."""
    CRITICAL = "critical"  # Security critical findings
    HIGH = "high"          # Important findings, agent requests
    NORMAL = "normal"      # Standard messages
    LOW = "low"            # Informational updates


class MessageType(str, Enum):
    """Standard message types for agent communication."""
    # Finding messages
    FINDING_NEW = "findings.new"
    FINDING_VALIDATED = "findings.validated"
    FINDING_REJECTED = "findings.rejected"

    # Agent status
    AGENT_STARTED = "agent.started"
    AGENT_PROGRESS = "agent.progress"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    AGENT_PAUSED = "agent.paused"

    # Coordination
    COORD_REQUEST = "coordination.request"
    COORD_RESPONSE = "coordination.response"
    COORD_TASK_ASSIGN = "coordination.task_assign"

    # Scan progress
    SCAN_STARTED = "scan.started"
    SCAN_PHASE_CHANGE = "scan.phase_change"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"

    # PoC Validation
    POC_REQUESTED = "poc.requested"
    POC_VALIDATED = "poc.validated"
    POC_FAILED = "poc.failed"


@dataclass
class AgentMessage:
    """Message structure for inter-agent communication."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    topic: str = ""
    message_type: MessageType = MessageType.AGENT_PROGRESS
    sender_id: str = ""
    sender_name: str = ""
    content: Any = None
    priority: MessagePriority = MessagePriority.NORMAL
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None  # For request-response correlation
    reply_to: Optional[str] = None  # Topic to reply to
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert message to dictionary for serialization."""
        return {
            "id": self.id,
            "topic": self.topic,
            "message_type": self.message_type.value,
            "sender_id": self.sender_id,
            "sender_name": self.sender_name,
            "content": self.content,
            "priority": self.priority.value,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "reply_to": self.reply_to,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AgentMessage":
        """Create message from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            topic=data.get("topic", ""),
            message_type=MessageType(data.get("message_type", "agent.progress")),
            sender_id=data.get("sender_id", ""),
            sender_name=data.get("sender_name", ""),
            content=data.get("content"),
            priority=MessagePriority(data.get("priority", "normal")),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(),
            correlation_id=data.get("correlation_id"),
            reply_to=data.get("reply_to"),
            metadata=data.get("metadata", {}),
        )


Callback = Callable[[AgentMessage], Coroutine[Any, Any, None]]


@dataclass
class Subscription:
    """Represents a topic subscription."""
    id: str
    topic: str
    callback: Callback
    subscriber_id: str
    filter_fn: Optional[Callable[[AgentMessage], bool]] = None
    active: bool = True


class MessageBus:
    """
    Pub-sub message bus for multi-agent communication.

    Provides:
    - Topic-based publish/subscribe
    - Priority-based message delivery
    - Message history for replay
    - Pattern-based topic matching (e.g., "findings.*")

    Usage:
        bus = MessageBus()

        # Subscribe to a topic
        await bus.subscribe("findings.new", my_callback, agent_id="agent1")

        # Publish a message
        await bus.publish(AgentMessage(
            topic="findings.new",
            message_type=MessageType.FINDING_NEW,
            sender_id="scanner1",
            content={"vuln": "SQLi", "url": "..."}
        ))
    """

    def __init__(self, max_history: int = 1000):
        self._subscriptions: dict[str, list[Subscription]] = {}
        self._message_history: list[AgentMessage] = []
        self._max_history = max_history
        self._lock = asyncio.Lock()
        self._running = True
        self._pending_messages: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._delivery_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the message delivery loop."""
        if self._delivery_task is None or self._delivery_task.done():
            self._running = True
            self._delivery_task = asyncio.create_task(self._delivery_loop())
            logger.debug("MessageBus delivery loop started")

    async def stop(self) -> None:
        """Stop the message delivery loop."""
        self._running = False
        if self._delivery_task and not self._delivery_task.done():
            self._delivery_task.cancel()
            try:
                await self._delivery_task
            except asyncio.CancelledError:
                pass
        logger.debug("MessageBus delivery loop stopped")

    async def _delivery_loop(self) -> None:
        """Background loop for message delivery."""
        while self._running:
            try:
                # Wait for messages with timeout
                try:
                    message = await asyncio.wait_for(
                        self._pending_messages.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                await self._deliver_message(message)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in message delivery: {e}")

    async def _deliver_message(self, message: AgentMessage) -> None:
        """Deliver message to all matching subscribers."""
        # Get all matching subscriptions
        matching_subs = await self._get_matching_subscriptions(message.topic)

        # Sort by priority
        priority_order = {
            MessagePriority.CRITICAL: 0,
            MessagePriority.HIGH: 1,
            MessagePriority.NORMAL: 2,
            MessagePriority.LOW: 3,
        }

        # Deliver to each subscriber
        delivery_tasks = []
        for sub in matching_subs:
            if not sub.active:
                continue

            # Apply filter if present
            if sub.filter_fn and not sub.filter_fn(message):
                continue

            # Skip self-delivery
            if sub.subscriber_id == message.sender_id:
                continue

            delivery_tasks.append(
                self._safe_deliver(sub, message)
            )

        if delivery_tasks:
            await asyncio.gather(*delivery_tasks, return_exceptions=True)

    async def _safe_deliver(self, sub: Subscription, message: AgentMessage) -> None:
        """Safely deliver message to subscriber with error handling."""
        try:
            await sub.callback(message)
        except Exception as e:
            logger.error(
                f"Error delivering message to {sub.subscriber_id}: {e}",
                exc_info=True
            )

    async def _get_matching_subscriptions(self, topic: str) -> list[Subscription]:
        """Get all subscriptions matching the topic pattern."""
        matching = []
        async with self._lock:
            for pattern, subs in self._subscriptions.items():
                if self._topic_matches(pattern, topic):
                    matching.extend(subs)
        return matching

    def _topic_matches(self, pattern: str, topic: str) -> bool:
        """Check if topic matches pattern (supports wildcard *)."""
        if pattern == topic:
            return True

        # Handle wildcards
        if "*" in pattern:
            parts = pattern.split(".")
            topic_parts = topic.split(".")

            if len(parts) > len(topic_parts):
                return False

            for i, part in enumerate(parts):
                if part == "*":
                    continue
                if part == "**":
                    return True
                if i >= len(topic_parts) or part != topic_parts[i]:
                    return False

            return len(parts) == len(topic_parts)

        return False

    async def subscribe(
        self,
        topic: str,
        callback: Callback,
        subscriber_id: str,
        filter_fn: Optional[Callable[[AgentMessage], bool]] = None,
    ) -> str:
        """
        Subscribe to a topic.

        Args:
            topic: Topic to subscribe to (supports wildcards like "findings.*")
            callback: Async function called when message is received
            subscriber_id: ID of the subscribing agent
            filter_fn: Optional filter function to filter messages

        Returns:
            Subscription ID
        """
        sub_id = str(uuid.uuid4())
        subscription = Subscription(
            id=sub_id,
            topic=topic,
            callback=callback,
            subscriber_id=subscriber_id,
            filter_fn=filter_fn,
        )

        async with self._lock:
            if topic not in self._subscriptions:
                self._subscriptions[topic] = []
            self._subscriptions[topic].append(subscription)

        logger.debug(f"Agent {subscriber_id} subscribed to {topic}")
        return sub_id

    async def unsubscribe(self, subscription_id: str) -> bool:
        """
        Unsubscribe from a topic.

        Args:
            subscription_id: ID returned from subscribe()

        Returns:
            True if subscription was found and removed
        """
        async with self._lock:
            for topic, subs in self._subscriptions.items():
                for sub in subs:
                    if sub.id == subscription_id:
                        subs.remove(sub)
                        logger.debug(f"Unsubscribed {subscription_id} from {topic}")
                        return True
        return False

    async def publish(self, message: AgentMessage) -> None:
        """
        Publish a message to a topic.

        Args:
            message: Message to publish
        """
        # Add to history
        async with self._lock:
            self._message_history.append(message)
            # Trim history if needed
            if len(self._message_history) > self._max_history:
                self._message_history = self._message_history[-self._max_history:]

        # Queue for delivery
        await self._pending_messages.put(message)

        logger.debug(
            f"Published message {message.id} to {message.topic} "
            f"from {message.sender_name}"
        )

    async def publish_finding(
        self,
        finding: Any,
        sender_id: str,
        sender_name: str,
        validated: bool = False,
    ) -> None:
        """
        Convenience method to publish a finding.

        Args:
            finding: Finding object to publish
            sender_id: ID of the agent that found it
            sender_name: Name of the agent
            validated: Whether the finding has been validated
        """
        message_type = MessageType.FINDING_VALIDATED if validated else MessageType.FINDING_NEW
        topic = "findings.validated" if validated else "findings.new"

        message = AgentMessage(
            topic=topic,
            message_type=message_type,
            sender_id=sender_id,
            sender_name=sender_name,
            content=finding,
            priority=MessagePriority.HIGH,
        )

        await self.publish(message)

    async def request_coordination(
        self,
        request_type: str,
        content: Any,
        sender_id: str,
        sender_name: str,
    ) -> str:
        """
        Request coordination from the coordinator agent.

        Args:
            request_type: Type of coordination request
            content: Request content
            sender_id: Requesting agent's ID
            sender_name: Requesting agent's name

        Returns:
            Correlation ID for tracking the response
        """
        correlation_id = str(uuid.uuid4())

        message = AgentMessage(
            topic="coordination.request",
            message_type=MessageType.COORD_REQUEST,
            sender_id=sender_id,
            sender_name=sender_name,
            content={
                "request_type": request_type,
                "data": content,
            },
            priority=MessagePriority.HIGH,
            correlation_id=correlation_id,
            reply_to=f"coordination.response.{sender_id}",
        )

        await self.publish(message)
        return correlation_id

    async def get_history(
        self,
        topic: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AgentMessage]:
        """
        Get message history, optionally filtered.

        Args:
            topic: Filter by topic (supports wildcards)
            since: Only messages after this time
            limit: Maximum messages to return

        Returns:
            List of matching messages
        """
        async with self._lock:
            messages = self._message_history.copy()

        # Filter by topic
        if topic:
            messages = [m for m in messages if self._topic_matches(topic, m.topic)]

        # Filter by time
        if since:
            messages = [m for m in messages if m.timestamp >= since]

        # Apply limit
        return messages[-limit:]

    def get_subscription_count(self, topic: Optional[str] = None) -> int:
        """Get number of active subscriptions."""
        if topic:
            return len(self._subscriptions.get(topic, []))
        return sum(len(subs) for subs in self._subscriptions.values())

    def clear_history(self) -> None:
        """Clear message history."""
        self._message_history.clear()


# Global singleton instance
_message_bus: Optional[MessageBus] = None


def get_message_bus() -> MessageBus:
    """Get the global message bus instance."""
    global _message_bus
    if _message_bus is None:
        _message_bus = MessageBus()
    return _message_bus


async def reset_message_bus() -> None:
    """Reset the global message bus (for testing)."""
    global _message_bus
    if _message_bus:
        await _message_bus.stop()
    _message_bus = MessageBus()
