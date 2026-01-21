"""
AIPTX Beast Mode - Route Manager
================================

Manage internal network routing for lateral movement.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class InternalRoute:
    """Represents a route to an internal network."""
    network: str
    gateway: str
    interface: str | None = None
    metric: int = 100
    via_session: str | None = None  # Pivot session ID
    status: str = "inactive"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "network": self.network,
            "gateway": self.gateway,
            "interface": self.interface,
            "metric": self.metric,
            "via_session": self.via_session,
            "status": self.status,
            "metadata": self.metadata,
        }


class RouteManager:
    """
    Manage routing for internal network access.

    Tracks routes through pivot points and generates
    routing commands for various scenarios.
    """

    def __init__(self):
        """Initialize route manager."""
        self._routes: list[InternalRoute] = []
        self._discovered_networks: list[str] = []

    def add_route(
        self,
        network: str,
        gateway: str,
        interface: str | None = None,
        via_session: str | None = None,
    ) -> InternalRoute:
        """
        Add a new route.

        Args:
            network: Target network CIDR
            gateway: Gateway address
            interface: Network interface
            via_session: Pivot session ID

        Returns:
            Created InternalRoute
        """
        route = InternalRoute(
            network=network,
            gateway=gateway,
            interface=interface,
            via_session=via_session,
            status="inactive",
        )
        self._routes.append(route)
        return route

    def get_linux_route_commands(
        self,
        network: str,
        gateway: str,
        interface: str | None = None,
    ) -> dict[str, str]:
        """
        Get Linux route commands.

        Args:
            network: Target network CIDR
            gateway: Gateway address
            interface: Optional interface

        Returns:
            Route command configuration
        """
        base_add = f"ip route add {network} via {gateway}"
        base_del = f"ip route del {network} via {gateway}"

        if interface:
            base_add += f" dev {interface}"
            base_del += f" dev {interface}"

        return {
            "add_command": base_add,
            "delete_command": base_del,
            "legacy_add": f"route add -net {network} gw {gateway}",
            "legacy_del": f"route del -net {network} gw {gateway}",
            "check_command": f"ip route show {network}",
        }

    def get_windows_route_commands(
        self,
        network: str,
        gateway: str,
        interface_idx: int | None = None,
    ) -> dict[str, str]:
        """
        Get Windows route commands.

        Args:
            network: Target network CIDR
            gateway: Gateway address
            interface_idx: Interface index

        Returns:
            Route command configuration
        """
        # Parse CIDR
        try:
            net = ipaddress.ip_network(network, strict=False)
            network_addr = str(net.network_address)
            netmask = str(net.netmask)
        except ValueError:
            network_addr = network
            netmask = "255.255.255.0"

        add_cmd = f"route add {network_addr} mask {netmask} {gateway}"
        del_cmd = f"route delete {network_addr}"

        if interface_idx:
            add_cmd += f" IF {interface_idx}"

        return {
            "add_command": add_cmd,
            "add_persistent": add_cmd + " -p",
            "delete_command": del_cmd,
            "print_command": "route print",
        }

    def get_metasploit_route_commands(
        self,
        network: str,
        session_id: int,
    ) -> dict[str, str]:
        """
        Get Metasploit routing commands.

        Args:
            network: Target network CIDR
            session_id: Meterpreter session ID

        Returns:
            Metasploit route commands
        """
        return {
            "autoroute_add": f"run autoroute -s {network}",
            "autoroute_session": f"run autoroute -s {network} -n {network.split('/')[1] if '/' in network else '24'}",
            "route_add": f"route add {network} {session_id}",
            "route_print": "route print",
            "route_delete": f"route remove {network}",
            "description": f"Route {network} through session {session_id}",
        }

    def get_ligolo_route_commands(
        self,
        network: str,
        interface: str = "ligolo",
    ) -> dict[str, str]:
        """
        Get Ligolo-ng route commands.

        Args:
            network: Target network CIDR
            interface: Ligolo interface name

        Returns:
            Ligolo route commands
        """
        return {
            "add_interface": f"sudo ip tuntap add user $(whoami) mode tun {interface}",
            "enable_interface": f"sudo ip link set {interface} up",
            "add_route": f"sudo ip route add {network} dev {interface}",
            "delete_route": f"sudo ip route del {network} dev {interface}",
            "ligolo_start": "session",  # In ligolo proxy console
            "ligolo_tunnel": "start",   # Start the tunnel
            "notes": "Run these commands on attacker machine after ligolo connection",
        }

    def analyze_network_range(
        self,
        network: str,
    ) -> dict[str, Any]:
        """
        Analyze a network range for scanning.

        Args:
            network: Network CIDR

        Returns:
            Analysis of the network
        """
        try:
            net = ipaddress.ip_network(network, strict=False)

            # Get key addresses
            hosts = list(net.hosts())

            return {
                "network": str(net.network_address),
                "netmask": str(net.netmask),
                "broadcast": str(net.broadcast_address),
                "total_hosts": net.num_addresses - 2,
                "first_host": str(hosts[0]) if hosts else None,
                "last_host": str(hosts[-1]) if hosts else None,
                "gateway_candidates": [
                    str(hosts[0]) if hosts else None,  # First IP
                    str(hosts[-1]) if hosts else None,  # Last IP
                    str(net.network_address).rsplit(".", 1)[0] + ".1",  # .1
                    str(net.network_address).rsplit(".", 1)[0] + ".254",  # .254
                ],
                "scan_command": f"nmap -sn {network}",
                "fast_scan": f"nmap -sn -T4 {network}",
            }
        except ValueError as e:
            return {"error": str(e)}

    def get_common_internal_networks(self) -> list[dict[str, str]]:
        """
        Get list of common internal network ranges.

        Returns:
            List of common RFC1918 networks
        """
        return [
            {
                "network": "10.0.0.0/8",
                "description": "Class A private (10.x.x.x)",
                "scan_priority": 3,
            },
            {
                "network": "172.16.0.0/12",
                "description": "Class B private (172.16-31.x.x)",
                "scan_priority": 2,
            },
            {
                "network": "192.168.0.0/16",
                "description": "Class C private (192.168.x.x)",
                "scan_priority": 1,
            },
            {
                "network": "169.254.0.0/16",
                "description": "Link-local (APIPA)",
                "scan_priority": 4,
            },
        ]

    def get_network_discovery_commands(self) -> list[dict[str, str]]:
        """
        Get commands to discover internal networks.

        Returns:
            List of network discovery commands
        """
        return [
            # Linux
            {
                "name": "linux_interfaces",
                "command": "ip addr show",
                "description": "Show all interfaces and IPs",
                "os": "linux",
            },
            {
                "name": "linux_routes",
                "command": "ip route show",
                "description": "Show routing table",
                "os": "linux",
            },
            {
                "name": "linux_arp",
                "command": "arp -a",
                "description": "Show ARP cache (discovered hosts)",
                "os": "linux",
            },
            {
                "name": "linux_netstat",
                "command": "netstat -rn",
                "description": "Show routing table (legacy)",
                "os": "linux",
            },
            {
                "name": "linux_neighbors",
                "command": "ip neigh show",
                "description": "Show neighbor cache",
                "os": "linux",
            },
            # Windows
            {
                "name": "windows_interfaces",
                "command": "ipconfig /all",
                "description": "Show all interfaces",
                "os": "windows",
            },
            {
                "name": "windows_routes",
                "command": "route print",
                "description": "Show routing table",
                "os": "windows",
            },
            {
                "name": "windows_arp",
                "command": "arp -a",
                "description": "Show ARP cache",
                "os": "windows",
            },
            {
                "name": "windows_netstat",
                "command": "netstat -rn",
                "description": "Show routing table",
                "os": "windows",
            },
        ]

    def parse_interface_output(self, output: str, os_type: str = "linux") -> list[dict[str, str]]:
        """
        Parse interface output to find networks.

        Args:
            output: Command output
            os_type: Operating system type

        Returns:
            List of discovered networks
        """
        networks = []

        if os_type == "linux":
            # Parse ip addr output
            import re
            # Match: inet 192.168.1.5/24
            pattern = r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)"
            for match in re.finditer(pattern, output):
                ip, prefix = match.groups()
                try:
                    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    networks.append({
                        "ip": ip,
                        "network": str(net),
                        "prefix": prefix,
                    })
                except ValueError:
                    pass
        else:
            # Parse Windows ipconfig
            import re
            # Match IPv4 Address and Subnet Mask
            ip_pattern = r"IPv4 Address[.\s]+:\s*(\d+\.\d+\.\d+\.\d+)"
            mask_pattern = r"Subnet Mask[.\s]+:\s*(\d+\.\d+\.\d+\.\d+)"

            ips = re.findall(ip_pattern, output)
            masks = re.findall(mask_pattern, output)

            for ip, mask in zip(ips, masks):
                try:
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    networks.append({
                        "ip": ip,
                        "network": str(net),
                        "netmask": mask,
                    })
                except ValueError:
                    pass

        # Record discovered networks
        for net in networks:
            if net["network"] not in self._discovered_networks:
                self._discovered_networks.append(net["network"])

        return networks

    def get_discovered_networks(self) -> list[str]:
        """Get all discovered networks."""
        return self._discovered_networks.copy()

    def get_routes(self) -> list[InternalRoute]:
        """Get all configured routes."""
        return self._routes.copy()


__all__ = [
    "InternalRoute",
    "RouteManager",
]
