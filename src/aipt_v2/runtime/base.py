from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TypedDict, Optional, List, Dict


class SandboxInfo(TypedDict):
    workspace_id: str
    api_url: str
    auth_token: Optional[str]
    tool_server_port: int
    agent_id: str


class AbstractRuntime(ABC):
    @abstractmethod
    async def create_sandbox(
        self,
        agent_id: str,
        existing_token: Optional[str] = None,
        local_sources: Optional[List[Dict[str, str]]] = None,
    ) -> SandboxInfo:
        raise NotImplementedError

    @abstractmethod
    async def get_sandbox_url(self, container_id: str, port: int) -> str:
        raise NotImplementedError

    @abstractmethod
    async def destroy_sandbox(self, container_id: str) -> None:
        raise NotImplementedError
