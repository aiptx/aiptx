"""
AIPTX Enhanced Multi-Agent System - Agent Graph Actions

Enables parent agents to spawn specialized child agents with skills for parallel
attack execution. Features:
- Thread-based parallel execution
- Skills inheritance to child agents
- XML-formatted task delegation
- Completion reports back to parent
- Inter-agent messaging
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

# Global state for agent graph
_agent_graph: dict[str, Any] = {
    "nodes": {},
    "edges": [],
}

_root_agent_id: str | None = None
_agent_messages: dict[str, list[dict[str, Any]]] = {}
_running_agents: dict[str, threading.Thread] = {}
_agent_instances: dict[str, Any] = {}
_agent_states: dict[str, Any] = {}


def reset_graph() -> None:
    """Reset the agent graph to initial state."""
    global _agent_graph, _agent_instances, _agent_states, _agent_messages, _root_agent_id, _running_agents
    _agent_graph = {"nodes": {}, "edges": []}
    _agent_instances = {}
    _agent_states = {}
    _agent_messages = {}
    _running_agents = {}
    _root_agent_id = None
    logger.info("Agent graph reset")


def register_root_agent(agent_id: str, agent_name: str, task: str, agent_instance: Any = None) -> None:
    """
    Register the root/main agent in the graph.

    Args:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        task: The agent's task/mission
        agent_instance: Optional agent object reference
    """
    global _root_agent_id
    _root_agent_id = agent_id

    _agent_graph["nodes"][agent_id] = {
        "name": agent_name,
        "task": task,
        "status": "running",
        "parent_id": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "result": None,
    }

    if agent_instance:
        _agent_instances[agent_id] = agent_instance

    logger.info(f"Registered root agent: {agent_name} ({agent_id})")


def _run_agent_in_thread(
    agent: Any,
    state: Any,
    inherited_messages: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Run a child agent in a separate thread.

    Args:
        agent: The agent instance to run
        state: Agent state object
        inherited_messages: Context messages from parent

    Returns:
        Agent execution result
    """
    try:
        # Inject inherited context
        if inherited_messages and hasattr(state, "add_message"):
            state.add_message("user", "<inherited_context_from_parent>")
            for msg in inherited_messages:
                state.add_message(msg.get("role", "user"), msg.get("content", ""))
            state.add_message("user", "</inherited_context_from_parent>")

        # Get parent info
        parent_info = _agent_graph["nodes"].get(state.parent_id, {})
        parent_name = parent_info.get("name", "Unknown Parent")

        context_status = (
            "inherited conversation context from your parent for background understanding"
            if inherited_messages
            else "started with a fresh context"
        )

        # Create task delegation XML
        task_xml = f"""<agent_delegation>
    <identity>
        You are a NEW, SEPARATE sub-agent (not root).

        Your Info: {state.agent_name} ({state.agent_id})
        Parent Info: {parent_name} ({state.parent_id})
    </identity>

    <your_task>{state.task}</your_task>

    <instructions>
        - You have {context_status}
        - Inherited context is for BACKGROUND ONLY - don't continue parent's work
        - Maintain strict self-identity: never speak as or for your parent
        - Focus EXCLUSIVELY on your delegated task above
        - Work independently with your own approach
        - Use agent_finish when complete to report back to parent
        - You are a SPECIALIST for this specific task
        - All agents share /workspace directory for collaboration
        - You can see files created by other agents
        - Build upon previous work but focus on your specific delegated task
    </instructions>
</agent_delegation>"""

        if hasattr(state, "add_message"):
            state.add_message("user", task_xml)

        _agent_states[state.agent_id] = state

        # Update graph node
        if state.agent_id in _agent_graph["nodes"]:
            _agent_graph["nodes"][state.agent_id]["state"] = (
                state.model_dump() if hasattr(state, "model_dump") else str(state)
            )

        # Run the agent loop
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(agent.agent_loop(state.task))
        finally:
            loop.close()

        # Update status on success
        if hasattr(state, "stop_requested") and state.stop_requested:
            _agent_graph["nodes"][state.agent_id]["status"] = "stopped"
        else:
            _agent_graph["nodes"][state.agent_id]["status"] = "completed"

        _agent_graph["nodes"][state.agent_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
        _agent_graph["nodes"][state.agent_id]["result"] = result

        # Cleanup
        _running_agents.pop(state.agent_id, None)
        _agent_instances.pop(state.agent_id, None)

        logger.info(f"Agent {state.agent_name} ({state.agent_id}) completed")
        return {"result": result}

    except Exception as e:
        logger.exception(f"Agent {state.agent_id} failed")
        _agent_graph["nodes"][state.agent_id]["status"] = "error"
        _agent_graph["nodes"][state.agent_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
        _agent_graph["nodes"][state.agent_id]["result"] = {"error": str(e)}
        _running_agents.pop(state.agent_id, None)
        _agent_instances.pop(state.agent_id, None)
        raise


def create_agent(
    agent_state: Any,
    task: str,
    name: str,
    inherit_context: bool = True,
    skills: str | None = None,
) -> dict[str, Any]:
    """
    Create and spawn a child agent with specific skills.

    Args:
        agent_state: Parent agent's state object
        task: Task description for the child agent
        name: Human-readable name for the child agent
        inherit_context: Whether to pass parent's conversation context
        skills: Comma-separated skill names (e.g., "xss,sql_injection,ssrf")

    Returns:
        dict with agent_id and status
    """
    try:
        parent_id = agent_state.agent_id if hasattr(agent_state, "agent_id") else str(uuid4())[:8]

        # Parse skills
        skill_list = []
        if skills:
            skill_list = [s.strip() for s in skills.split(",") if s.strip()]

        if len(skill_list) > 5:
            return {
                "success": False,
                "error": "Cannot specify more than 5 skills for an agent",
                "agent_id": None,
            }

        # Validate skills if specified
        if skill_list:
            try:
                from aipt_v2.skills import get_available_skills

                available = get_available_skills()
                invalid = [s for s in skill_list if s not in available]
                if invalid:
                    return {
                        "success": False,
                        "error": f"Invalid skills: {invalid}. Available: {list(available.keys())}",
                        "agent_id": None,
                    }
            except ImportError:
                logger.warning("Skills validation skipped - module not available")

        # Create agent ID
        agent_id = f"agent_{uuid4().hex[:8]}"

        # Create agent state
        try:
            from aipt_v2.agents.base import AgentState

            child_state = AgentState(
                task=task,
                agent_name=name,
                agent_id=agent_id,
                parent_id=parent_id,
                max_iterations=300,
            )
        except ImportError:
            # Fallback simple state
            class SimpleState:
                def __init__(self, **kwargs):
                    for k, v in kwargs.items():
                        setattr(self, k, v)
                    self.messages = []

                def add_message(self, role, content):
                    self.messages.append({"role": role, "content": content})

                def model_dump(self):
                    return self.__dict__

            child_state = SimpleState(
                task=task,
                agent_name=name,
                agent_id=agent_id,
                parent_id=parent_id,
                max_iterations=300,
                stop_requested=False,
            )

        # Register in graph
        _agent_graph["nodes"][agent_id] = {
            "name": name,
            "task": task,
            "status": "running",
            "parent_id": parent_id,
            "skills": skill_list,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "result": None,
        }

        # Add delegation edge
        _agent_graph["edges"].append({
            "from": parent_id,
            "to": agent_id,
            "type": "delegation",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

        # Get inherited messages
        inherited_messages = []
        if inherit_context and hasattr(agent_state, "get_conversation_history"):
            inherited_messages = agent_state.get_conversation_history()
        elif inherit_context and hasattr(agent_state, "messages"):
            inherited_messages = agent_state.messages

        # Try to create and run agent
        try:
            from aipt_v2.agents.base import BaseAgent
            from aipt_v2.llm.config import LLMConfig

            # Get parent config
            parent_agent = _agent_instances.get(parent_id)
            llm_config = None

            if parent_agent and hasattr(parent_agent, "llm_config"):
                # Clone parent config with child skills
                llm_config = LLMConfig(
                    skills=skill_list,
                    timeout=getattr(parent_agent.llm_config, "timeout", None),
                )
            else:
                llm_config = LLMConfig(skills=skill_list)

            agent = BaseAgent(
                llm_config=llm_config,
                state=child_state,
            )

            _agent_instances[agent_id] = agent

            # Start agent in thread
            thread = threading.Thread(
                target=_run_agent_in_thread,
                args=(agent, child_state, inherited_messages),
                daemon=True,
                name=f"Agent-{name}-{agent_id}",
            )
            thread.start()
            _running_agents[agent_id] = thread

            logger.info(f"Created child agent: {name} ({agent_id}) with skills: {skill_list}")

        except ImportError as e:
            logger.warning(f"Could not create full agent, using placeholder: {e}")
            # Agent created but not running (for testing without full agent infrastructure)
            _agent_graph["nodes"][agent_id]["status"] = "pending"

        return {
            "success": True,
            "agent_id": agent_id,
            "message": f"Agent '{name}' created and started asynchronously",
            "agent_info": {
                "id": agent_id,
                "name": name,
                "status": _agent_graph["nodes"][agent_id]["status"],
                "parent_id": parent_id,
                "skills": skill_list,
            },
        }

    except Exception as e:
        logger.exception("Failed to create agent")
        return {"success": False, "error": f"Failed to create agent: {e}", "agent_id": None}


def send_message_to_agent(
    agent_state: Any,
    target_agent_id: str,
    message: str,
    message_type: Literal["query", "instruction", "information"] = "information",
    priority: Literal["low", "normal", "high", "urgent"] = "normal",
) -> dict[str, Any]:
    """
    Send a message from current agent to another agent.

    Args:
        agent_state: Current agent's state
        target_agent_id: Target agent's ID
        message: Message content
        message_type: Type of message (query, instruction, information)
        priority: Message priority (low, normal, high, urgent)

    Returns:
        dict with message_id and delivery status
    """
    try:
        if target_agent_id not in _agent_graph["nodes"]:
            return {
                "success": False,
                "error": f"Target agent '{target_agent_id}' not found in graph",
                "message_id": None,
            }

        sender_id = agent_state.agent_id if hasattr(agent_state, "agent_id") else "unknown"

        message_id = f"msg_{uuid4().hex[:8]}"
        message_data = {
            "id": message_id,
            "from": sender_id,
            "to": target_agent_id,
            "content": message,
            "message_type": message_type,
            "priority": priority,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "delivered": False,
            "read": False,
        }

        if target_agent_id not in _agent_messages:
            _agent_messages[target_agent_id] = []

        _agent_messages[target_agent_id].append(message_data)

        # Record in graph edges
        _agent_graph["edges"].append({
            "from": sender_id,
            "to": target_agent_id,
            "type": "message",
            "message_id": message_id,
            "message_type": message_type,
            "priority": priority,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

        message_data["delivered"] = True

        target_name = _agent_graph["nodes"][target_agent_id]["name"]
        sender_name = _agent_graph["nodes"].get(sender_id, {}).get("name", "Unknown")

        logger.info(f"Message {message_id} sent from {sender_name} to {target_name}")

        return {
            "success": True,
            "message_id": message_id,
            "message": f"Message sent from '{sender_name}' to '{target_name}'",
            "delivery_status": "delivered",
            "target_agent": {
                "id": target_agent_id,
                "name": target_name,
                "status": _agent_graph["nodes"][target_agent_id]["status"],
            },
        }

    except Exception as e:
        logger.exception("Failed to send message")
        return {"success": False, "error": f"Failed to send message: {e}", "message_id": None}


def wait_for_message(
    agent_state: Any,
    reason: str = "Waiting for messages from other agents",
) -> dict[str, Any]:
    """
    Enter waiting state for inter-agent communication.

    Args:
        agent_state: Current agent's state
        reason: Reason for waiting

    Returns:
        dict with waiting status
    """
    try:
        agent_id = agent_state.agent_id if hasattr(agent_state, "agent_id") else "unknown"
        agent_name = agent_state.agent_name if hasattr(agent_state, "agent_name") else "Unknown"

        # Update state if method exists
        if hasattr(agent_state, "enter_waiting_state"):
            agent_state.enter_waiting_state()

        # Update graph
        if agent_id in _agent_graph["nodes"]:
            _agent_graph["nodes"][agent_id]["status"] = "waiting"
            _agent_graph["nodes"][agent_id]["waiting_reason"] = reason

        logger.info(f"Agent {agent_name} ({agent_id}) entered waiting state: {reason}")

        return {
            "success": True,
            "status": "waiting",
            "message": f"Agent '{agent_name}' is now waiting for messages",
            "reason": reason,
            "agent_info": {
                "id": agent_id,
                "name": agent_name,
                "status": "waiting",
            },
            "resume_conditions": [
                "Message from another agent",
                "Message from user",
                "Direct communication",
                "Waiting timeout reached",
            ],
        }

    except Exception as e:
        logger.exception("Failed to enter waiting state")
        return {"success": False, "error": f"Failed to enter waiting state: {e}", "status": "error"}


def agent_finish(
    agent_state: Any,
    result_summary: str,
    findings: list[str] | None = None,
    success: bool = True,
    report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> dict[str, Any]:
    """
    Complete a subagent and report back to parent.

    Args:
        agent_state: Current agent's state
        result_summary: Summary of work completed
        findings: List of findings/discoveries
        success: Whether the task succeeded
        report_to_parent: Whether to send completion report to parent
        final_recommendations: Recommendations for next steps

    Returns:
        dict with completion status
    """
    try:
        parent_id = getattr(agent_state, "parent_id", None)
        if parent_id is None:
            return {
                "agent_completed": False,
                "error": "This tool can only be used by subagents. Root agents must use finish_scan.",
                "parent_notified": False,
            }

        agent_id = agent_state.agent_id if hasattr(agent_state, "agent_id") else "unknown"

        if agent_id not in _agent_graph["nodes"]:
            return {"agent_completed": False, "error": "Current agent not found in graph"}

        agent_node = _agent_graph["nodes"][agent_id]

        # Update node status
        agent_node["status"] = "finished" if success else "failed"
        agent_node["finished_at"] = datetime.now(timezone.utc).isoformat()
        agent_node["result"] = {
            "summary": result_summary,
            "findings": findings or [],
            "success": success,
            "recommendations": final_recommendations or [],
        }

        parent_notified = False

        # Report to parent if requested
        if report_to_parent and parent_id in _agent_graph["nodes"]:
            findings_xml = "\n".join(
                f"        <finding>{finding}</finding>" for finding in (findings or [])
            )
            recommendations_xml = "\n".join(
                f"        <recommendation>{rec}</recommendation>"
                for rec in (final_recommendations or [])
            )

            report_message = f"""<agent_completion_report>
    <agent_info>
        <agent_name>{agent_node["name"]}</agent_name>
        <agent_id>{agent_id}</agent_id>
        <task>{agent_node["task"]}</task>
        <status>{"SUCCESS" if success else "FAILED"}</status>
        <completion_time>{agent_node["finished_at"]}</completion_time>
    </agent_info>
    <results>
        <summary>{result_summary}</summary>
        <findings>
{findings_xml}
        </findings>
        <recommendations>
{recommendations_xml}
        </recommendations>
    </results>
</agent_completion_report>"""

            if parent_id not in _agent_messages:
                _agent_messages[parent_id] = []

            _agent_messages[parent_id].append({
                "id": f"report_{uuid4().hex[:8]}",
                "from": agent_id,
                "to": parent_id,
                "content": report_message,
                "message_type": "completion_report",
                "priority": "high",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "delivered": True,
                "read": False,
            })

            parent_notified = True
            logger.info(f"Agent {agent_id} reported completion to parent {parent_id}")

        # Cleanup
        _running_agents.pop(agent_id, None)

        return {
            "agent_completed": True,
            "parent_notified": parent_notified,
            "completion_summary": {
                "agent_id": agent_id,
                "agent_name": agent_node["name"],
                "task": agent_node["task"],
                "success": success,
                "findings_count": len(findings or []),
                "has_recommendations": bool(final_recommendations),
                "finished_at": agent_node["finished_at"],
            },
        }

    except Exception as e:
        logger.exception("Failed to complete agent")
        return {
            "agent_completed": False,
            "error": f"Failed to complete agent: {e}",
            "parent_notified": False,
        }


def view_agent_graph(agent_state: Any) -> dict[str, Any]:
    """
    View the current agent graph structure.

    Args:
        agent_state: Current agent's state (for highlighting current position)

    Returns:
        dict with graph structure and summary
    """
    try:
        current_agent_id = agent_state.agent_id if hasattr(agent_state, "agent_id") else None
        structure_lines = ["=== AGENT GRAPH STRUCTURE ==="]

        def _build_tree(agent_id: str, depth: int = 0) -> None:
            node = _agent_graph["nodes"][agent_id]
            indent = "  " * depth

            you_indicator = " ← (YOU)" if agent_id == current_agent_id else ""
            skills_str = f" [skills: {', '.join(node.get('skills', []))}]" if node.get("skills") else ""

            structure_lines.append(f"{indent}* {node['name']} ({agent_id}){you_indicator}{skills_str}")
            structure_lines.append(f"{indent}  Task: {node['task'][:80]}...")
            structure_lines.append(f"{indent}  Status: {node['status']}")

            # Find children
            children = [
                edge["to"]
                for edge in _agent_graph["edges"]
                if edge["from"] == agent_id and edge["type"] == "delegation"
            ]

            if children:
                structure_lines.append(f"{indent}  Children:")
                for child_id in children:
                    if child_id in _agent_graph["nodes"]:
                        _build_tree(child_id, depth + 2)

        # Find root
        root_id = _root_agent_id
        if not root_id and _agent_graph["nodes"]:
            for aid, node in _agent_graph["nodes"].items():
                if node.get("parent_id") is None:
                    root_id = aid
                    break

        if root_id and root_id in _agent_graph["nodes"]:
            _build_tree(root_id)
        else:
            structure_lines.append("No agents in the graph yet")

        # Calculate summary
        nodes = _agent_graph["nodes"]
        summary = {
            "total_agents": len(nodes),
            "running": sum(1 for n in nodes.values() if n["status"] == "running"),
            "waiting": sum(1 for n in nodes.values() if n["status"] == "waiting"),
            "completed": sum(1 for n in nodes.values() if n["status"] in ["completed", "finished"]),
            "failed": sum(1 for n in nodes.values() if n["status"] in ["failed", "error"]),
            "stopped": sum(1 for n in nodes.values() if n["status"] == "stopped"),
        }

        return {
            "graph_structure": "\n".join(structure_lines),
            "summary": summary,
        }

    except Exception as e:
        logger.exception("Failed to view agent graph")
        return {
            "error": f"Failed to view agent graph: {e}",
            "graph_structure": "Error retrieving graph structure",
        }


def stop_agent(agent_id: str) -> dict[str, Any]:
    """
    Stop a running agent gracefully.

    Args:
        agent_id: ID of the agent to stop

    Returns:
        dict with stop status
    """
    try:
        if agent_id not in _agent_graph["nodes"]:
            return {
                "success": False,
                "error": f"Agent '{agent_id}' not found in graph",
                "agent_id": agent_id,
            }

        agent_node = _agent_graph["nodes"][agent_id]

        if agent_node["status"] in ["completed", "error", "failed", "stopped", "finished"]:
            return {
                "success": True,
                "message": f"Agent '{agent_node['name']}' was already stopped",
                "agent_id": agent_id,
                "previous_status": agent_node["status"],
            }

        # Request stop on state
        if agent_id in _agent_states:
            state = _agent_states[agent_id]
            if hasattr(state, "request_stop"):
                state.request_stop()
            elif hasattr(state, "stop_requested"):
                state.stop_requested = True

        # Request stop on instance
        if agent_id in _agent_instances:
            instance = _agent_instances[agent_id]
            if hasattr(instance, "state") and hasattr(instance.state, "request_stop"):
                instance.state.request_stop()

        agent_node["status"] = "stopping"
        agent_node["result"] = {
            "summary": "Agent stop requested by user",
            "success": False,
            "stopped_by_user": True,
        }

        logger.info(f"Stop requested for agent {agent_id}")

        return {
            "success": True,
            "message": f"Stop request sent to agent '{agent_node['name']}'",
            "agent_id": agent_id,
            "agent_name": agent_node["name"],
            "note": "Agent will stop gracefully after current iteration",
        }

    except Exception as e:
        logger.exception("Failed to stop agent")
        return {
            "success": False,
            "error": f"Failed to stop agent: {e}",
            "agent_id": agent_id,
        }


def get_agent_messages(agent_id: str, mark_as_read: bool = True) -> list[dict[str, Any]]:
    """
    Get pending messages for an agent.

    Args:
        agent_id: Agent ID to get messages for
        mark_as_read: Whether to mark messages as read

    Returns:
        List of message dicts
    """
    messages = _agent_messages.get(agent_id, [])
    unread = [m for m in messages if not m.get("read")]

    if mark_as_read:
        for m in unread:
            m["read"] = True

    return unread


def get_agent_status(agent_id: str) -> str | None:
    """Get the current status of an agent."""
    if agent_id in _agent_graph["nodes"]:
        return _agent_graph["nodes"][agent_id].get("status")
    return None


def get_all_agents() -> dict[str, Any]:
    """Get all agents in the graph."""
    return {
        "nodes": _agent_graph["nodes"],
        "edges": _agent_graph["edges"],
        "root_agent_id": _root_agent_id,
    }


__all__ = [
    # State
    "_agent_graph",
    "_agent_instances",
    "_agent_states",
    "_agent_messages",
    "_root_agent_id",
    # Setup
    "reset_graph",
    "register_root_agent",
    # Core actions (for LLM tools)
    "create_agent",
    "send_message_to_agent",
    "wait_for_message",
    "agent_finish",
    "view_agent_graph",
    "stop_agent",
    # Utilities
    "get_agent_messages",
    "get_agent_status",
    "get_all_agents",
]
