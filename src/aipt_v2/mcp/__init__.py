"""
AIPTX MCP (Model Context Protocol) Integration
==============================================

Provides integration with MCP-compatible tool servers,
allowing AIPTX to use external tools without code changes.

MCP enables:
- Dynamic tool discovery from external servers
- Standardized tool execution protocol
- Easy integration of community tools

Example usage:
    from aipt_v2.mcp import MCPManager

    # Initialize and connect
    manager = MCPManager()
    tools = await manager.connect_all()

    # Call a tool
    result = await manager.call_tool("nmap", "scan_ports", {"target": "192.168.1.1"})

Configuration:
    MCP servers are configured in ~/.aiptx/mcp_servers.json:
    {
        "mcpServers": {
            "nmap": {
                "command": "npx",
                "args": ["-y", "nmap-mcp"],
                "description": "Nmap scanning via MCP"
            }
        }
    }

CLI Commands:
    aiptx mcp list              # List configured servers
    aiptx mcp add <name> ...    # Add a server
    aiptx mcp remove <name>     # Remove a server
"""

from .manager import MCPManager, MCPServer, MCPServerConfig
from .tools import create_mcp_tool, execute_mcp_tool, format_mcp_result, parse_mcp_tool_name
from .transport import MCPTransport, StdioTransport

__all__ = [
    # Manager
    "MCPManager",
    "MCPServer",
    "MCPServerConfig",
    # Transport
    "MCPTransport",
    "StdioTransport",
    # Tools
    "create_mcp_tool",
    "execute_mcp_tool",
    "format_mcp_result",
    "parse_mcp_tool_name",
]
