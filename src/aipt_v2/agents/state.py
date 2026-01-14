from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict

from pydantic import BaseModel, Field


def _generate_agent_id() -> str:
    return f"agent_{uuid.uuid4().hex[:8]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentState(BaseModel):
    agent_id: str = Field(default_factory=_generate_agent_id)
    agent_name: str = "AIPT Agent"
    parent_id: Optional[str] = None
    sandbox_id: Optional[str] = None
    sandbox_token: Optional[str] = None
    sandbox_info: Optional[Dict[str, Any]] = None

    task: str = ""
    iteration: int = 0
    max_iterations: int = 300
    completed: bool = False
    stop_requested: bool = False
    waiting_for_input: bool = False
    llm_failed: bool = False
    waiting_start_time: Optional[datetime] = None
    final_result: Optional[Dict[str, Any]] = None
    max_iterations_warning_sent: bool = False

    messages: List[Dict[str, Any]] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)

    start_time: str = Field(default_factory=_now_iso)
    last_updated: str = Field(default_factory=_now_iso)

    actions_taken: List[Dict[str, Any]] = Field(default_factory=list)
    observations: List[Dict[str, Any]] = Field(default_factory=list)

    errors: List[str] = Field(default_factory=list)

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = _now_iso()

    def add_message(self, role: str, content: Any) -> None:
        self.messages.append({"role": role, "content": content})
        self.last_updated = _now_iso()

    def add_action(self, action: Dict[str, Any]) -> None:
        self.actions_taken.append(
            {
                "iteration": self.iteration,
                "timestamp": _now_iso(),
                "action": action,
            }
        )

    def add_observation(self, observation: Dict[str, Any]) -> None:
        self.observations.append(
            {
                "iteration": self.iteration,
                "timestamp": _now_iso(),
                "observation": observation,
            }
        )

    def add_error(self, error: str) -> None:
        self.errors.append(f"Iteration {self.iteration}: {error}")
        self.last_updated = _now_iso()

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value
        self.last_updated = _now_iso()

    def set_completed(self, final_result: Optional[Dict[str, Any]] = None) -> None:
        self.completed = True
        self.final_result = final_result
        self.last_updated = _now_iso()

    def request_stop(self) -> None:
        self.stop_requested = True
        self.last_updated = _now_iso()

    def should_stop(self) -> bool:
        return self.stop_requested or self.completed or self.has_reached_max_iterations()

    def is_waiting_for_input(self) -> bool:
        return self.waiting_for_input

    def enter_waiting_state(self, llm_failed: bool = False) -> None:
        self.waiting_for_input = True
        self.waiting_start_time = datetime.now(timezone.utc)
        self.llm_failed = llm_failed
        self.last_updated = _now_iso()

    def resume_from_waiting(self, new_task: Optional[str] = None) -> None:
        self.waiting_for_input = False
        self.waiting_start_time = None
        self.stop_requested = False
        self.completed = False
        self.llm_failed = False
        if new_task:
            self.task = new_task
        self.last_updated = _now_iso()

    def has_reached_max_iterations(self) -> bool:
        return self.iteration >= self.max_iterations

    def is_approaching_max_iterations(self, threshold: float = 0.85) -> bool:
        return self.iteration >= int(self.max_iterations * threshold)

    def has_waiting_timeout(self) -> bool:
        if not self.waiting_for_input or not self.waiting_start_time:
            return False

        if (
            self.stop_requested
            or self.llm_failed
            or self.completed
            or self.has_reached_max_iterations()
        ):
            return False

        elapsed = (datetime.now(timezone.utc) - self.waiting_start_time).total_seconds()
        return elapsed > 600

    def has_empty_last_messages(self, count: int = 3) -> bool:
        if len(self.messages) < count:
            return False

        last_messages = self.messages[-count:]

        for message in last_messages:
            content = message.get("content", "")
            if isinstance(content, str) and content.strip():
                return False

        return True

    def get_conversation_history(self) -> list[dict[str, Any]]:
        return self.messages

    def get_execution_summary(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "sandbox_id": self.sandbox_id,
            "sandbox_info": self.sandbox_info,
            "task": self.task,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "completed": self.completed,
            "final_result": self.final_result,
            "start_time": self.start_time,
            "last_updated": self.last_updated,
            "total_actions": len(self.actions_taken),
            "total_observations": len(self.observations),
            "total_errors": len(self.errors),
            "has_errors": len(self.errors) > 0,
            "max_iterations_reached": self.has_reached_max_iterations() and not self.completed,
        }
