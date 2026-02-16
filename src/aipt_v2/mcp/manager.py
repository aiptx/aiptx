"""
MCP Server Connection Manager for AIPTX.

Manages connections to MCP (Model Context Protocol) servers
and exposes their tools to AIPTX agents.

Configuration is stored at ~/.aiptx/mcp_servers.json in standard MCP format:
{
    "mcpServers": {
        "server-name": {
            "command": "npx",
            "args": ["-y", "package-name"],
            "env": {"VAR": "value"},
            "enabled": true,
            "description": "Server description"
        }
    }
}
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .transport import MCPTransport, StdioTransport
from .tools import create_mcp_tool

logger = logging.getLogger(__name__)


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""

    name: str
    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    description: str = ""


@dataclass
class MCPServer:
    """Represents a connected MCP server."""

    name: str
    config: MCPServerConfig
    transport: MCPTransport
    tools: List[Dict[str, Any]] = field(default_factory=list)
    connected: bool = False
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def disconnect(self) -> None:
        """Disconnect from the server."""
        if self.connected:
            await self.transport.disconnect()
            self.connected = False


class MCPManager:
    """
    Manages MCP server connections and exposes tools to agents.

    Provides methods to:
    - Configure MCP servers
    - Connect/disconnect servers
    - Call tools on connected servers
    - List available tools
    """

    DEFAULT_CONFIG_PATHS = [
        Path.cwd() / "mcp_servers.json",
        Path.cwd() / "mcp.json",
        Path.home() / ".aiptx" / "mcp_servers.json",
    ]

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the MCP manager.

        Args:
            config_path: Optional path to config file. If not provided,
                        searches default locations.
        """
        self.config_path = config_path or self._find_config()
        self.servers: Dict[str, MCPServer] = {}
        self._message_id = 0

    def _find_config(self) -> Path:
        """Find existing config file or return default path."""
        for path in self.DEFAULT_CONFIG_PATHS:
            if path.exists():
                return path
        # Return default user config path
        return Path.home() / ".aiptx" / "mcp_servers.json"

    def _get_next_id(self) -> int:
        """Generate unique message ID."""
        self._message_id += 1
        return self._message_id

    def _load_config(self) -> Dict[str, MCPServerConfig]:
        """Load server configurations from file."""
        if not self.config_path.exists():
            return {}

        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
            servers = {}
            mcp_servers = raw.get("mcpServers", {})

            for name, config in mcp_servers.items():
                if not config.get("command"):
                    continue

                servers[name] = MCPServerConfig(
                    name=name,
                    command=config["command"],
                    args=config.get("args", []),
                    env=config.get("env", {}),
                    enabled=config.get("enabled", True),
                    description=config.get("description", ""),
                )

            return servers

        except json.JSONDecodeError as e:
            logger.error(f"Error loading MCP config: {e}")
            return {}

    def _save_config(self, servers: Dict[str, MCPServerConfig]) -> None:
        """Save server configurations to file."""
        config = {"mcpServers": {}}

        for name, server in servers.items():
            server_config = {
                "command": server.command,
                "args": server.args,
            }
            if server.env:
                server_config["env"] = server.env
            if server.description:
                server_config["description"] = server.description
            if not server.enabled:
                server_config["enabled"] = False

            config["mcpServers"][name] = server_config

        # Ensure directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    def add_server(
        self,
        name: str,
        command: str,
        args: List[str] = None,
        env: Dict[str, str] = None,
        description: str = "",
    ) -> None:
        """
        Add a new MCP server configuration.

        Args:
            name: Unique server name
            command: Command to execute
            args: Command arguments
            env: Environment variables
            description: Server description
        """
        servers = self._load_config()
        servers[name] = MCPServerConfig(
            name=name,
            command=command,
            args=args or [],
            env=env or {},
            description=description,
        )
        self._save_config(servers)
        logger.info(f"Added MCP server: {name}")

    def remove_server(self, name: str) -> bool:
        """
        Remove an MCP server configuration.

        Args:
            name: Server name to remove

        Returns:
            True if removed, False if not found
        """
        servers = self._load_config()
        if name in servers:
            del servers[name]
            self._save_config(servers)
            logger.info(f"Removed MCP server: {name}")
            return True
        return False

    def list_configured_servers(self) -> List[Dict[str, Any]]:
        """
        List all configured MCP servers.

        Returns:
            List of server configuration dicts
        """
        servers = self._load_config()
        return [
            {
                "name": n,
                "command": s.command,
                "args": s.args,
                "env": s.env,
                "enabled": s.enabled,
                "description": s.description,
                "connected": n in self.servers and self.servers[n].connected,
            }
            for n, s in servers.items()
        ]

    async def connect_all(self) -> List[Dict[str, Any]]:
        """
        Connect to all enabled MCP servers.

        Returns:
            List of tool configurations from all connected servers
        """
        servers_config = self._load_config()
        all_tools = []

        for name, config in servers_config.items():
            if not config.enabled:
                continue

            server = await self._connect_server(config)
            if server:
                self.servers[name] = server
                # Create AIPTX-compatible tool configs
                for tool_def in server.tools:
                    tool_config = create_mcp_tool(tool_def, server, self)
                    all_tools.append(tool_config)

                logger.info(f"Connected to MCP server '{name}' with {len(server.tools)} tools")

        return all_tools

    async def connect_server(self, name: str) -> Optional[MCPServer]:
        """
        Connect to a specific MCP server by name.

        Args:
            name: Server name

        Returns:
            Connected server or None if failed
        """
        servers_config = self._load_config()
        if name not in servers_config:
            logger.error(f"MCP server not configured: {name}")
            return None

        config = servers_config[name]
        server = await self._connect_server(config)
        if server:
            self.servers[name] = server
        return server

    async def _connect_server(self, config: MCPServerConfig) -> Optional[MCPServer]:
        """Connect to a server and initialize it."""
        transport = None

        try:
            # Merge environment
            env = {**os.environ, **config.env}

            transport = StdioTransport(
                command=config.command,
                args=config.args,
                env=env,
            )
            await transport.connect()

            # Initialize MCP protocol
            await transport.send(
                {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "aiptx", "version": "5.0.6"},
                    },
                    "id": self._get_next_id(),
                }
            )

            # Send initialized notification
            await transport.send(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )

            # Get available tools
            tools_response = await transport.send(
                {"jsonrpc": "2.0", "method": "tools/list", "id": self._get_next_id()}
            )
            tools = tools_response.get("result", {}).get("tools", [])

            return MCPServer(
                name=config.name,
                config=config,
                transport=transport,
                tools=tools,
                connected=True,
            )

        except Exception as e:
            logger.error(f"Failed to connect to MCP server '{config.name}': {e}")
            if transport:
                try:
                    await transport.disconnect()
                except Exception:
                    pass
            return None

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: float = 300.0,
    ) -> Any:
        """
        Call a tool on an MCP server.

        Args:
            server_name: Name of the server
            tool_name: Name of the tool (original MCP name)
            arguments: Tool arguments
            timeout: Maximum execution time (seconds)

        Returns:
            Tool execution result

        Raises:
            ValueError: If server not connected
            RuntimeError: If tool call fails
        """
        server = self.servers.get(server_name)
        if not server or not server.connected:
            raise ValueError(f"MCP server '{server_name}' not connected")

        # Serialize communication with this server
        async with server._lock:
            response = await server.transport.send(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": arguments},
                    "id": self._get_next_id(),
                },
                timeout=timeout,
            )

        if "error" in response:
            error_msg = response["error"].get("message", "Unknown error")
            raise RuntimeError(f"MCP tool error: {error_msg}")

        return response.get("result", {}).get("content", [])

    async def disconnect_server(self, name: str) -> None:
        """Disconnect a specific server."""
        server = self.servers.get(name)
        if server:
            await server.disconnect()
            del self.servers[name]
            logger.info(f"Disconnected from MCP server: {name}")

    async def disconnect_all(self) -> None:
        """Disconnect all connected servers."""
        for server in list(self.servers.values()):
            await server.disconnect()
        self.servers.clear()
        logger.info("Disconnected from all MCP servers")

    async def reconnect_all(self) -> List[Dict[str, Any]]:
        """
        Reconnect all servers (useful after cancellation).

        Returns:
            List of tool configurations
        """
        await self.disconnect_all()
        return await self.connect_all()

    def get_server(self, name: str) -> Optional[MCPServer]:
        """Get a connected server by name."""
        return self.servers.get(name)

    def get_all_servers(self) -> List[MCPServer]:
        """Get all connected servers."""
        return list(self.servers.values())

    def is_connected(self, name: str) -> bool:
        """Check if a server is connected."""
        server = self.servers.get(name)
        return server is not None and server.connected

    def get_all_tools(self) -> List[Dict[str, Any]]:
        """
        Get all tools from all connected servers.

        Returns:
            List of tool configurations
        """
        all_tools = []
        for server in self.servers.values():
            if server.connected:
                for tool_def in server.tools:
                    tool_config = create_mcp_tool(tool_def, server, self)
                    all_tools.append(tool_config)
        return all_tools
