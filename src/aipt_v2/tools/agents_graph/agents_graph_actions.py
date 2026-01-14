"""
AIPT Agents Graph Actions - State management for agent graph
"""

from typing import Any, Optional

# Global state for agent graph
_agent_graph: dict[str, Any] = {
    "nodes": {},
    "edges": [],
}

_agent_instances: dict[str, Any] = {}
_agent_states: dict[str, Any] = {}
_agent_messages: dict[str, list[dict]] = {}
_root_agent_id: Optional[str] = None


def reset_graph() -> None:
    """Reset the agent graph to initial state"""
    global _agent_graph, _agent_instances, _agent_states, _agent_messages, _root_agent_id
    _agent_graph = {"nodes": {}, "edges": []}
    _agent_instances = {}
    _agent_states = {}
    _agent_messages = {}
    _root_agent_id = None


def send_message(
    from_agent_id: str,
    to_agent_id: str,
    content: str,
    message_type: str = "information",
    priority: str = "normal",
) -> bool:
    """Send a message from one agent to another"""
    from datetime import datetime

    if to_agent_id not in _agent_messages:
        _agent_messages[to_agent_id] = []

    _agent_messages[to_agent_id].append({
        "from": from_agent_id,
        "content": content,
        "message_type": message_type,
        "priority": priority,
        "timestamp": datetime.now().isoformat(),
        "read": False,
    })
    return True


def get_agent_status(agent_id: str) -> Optional[str]:
    """Get the current status of an agent"""
    if agent_id in _agent_graph["nodes"]:
        return _agent_graph["nodes"][agent_id].get("status")
    return None


__all__ = [
    "_agent_graph",
    "_agent_instances",
    "_agent_states",
    "_agent_messages",
    "_root_agent_id",
    "reset_graph",
    "send_message",
    "get_agent_status",
]
