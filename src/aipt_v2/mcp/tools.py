"""
MCP Tool Wrapper - Convert MCP tools to AIPTX Tool instances.

Bridges MCP tool definitions to AIPTX's tool execution system.
"""

from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from .manager import MCPManager, MCPServer


def create_mcp_tool(
    tool_def: Dict[str, Any],
    server: "MCPServer",
    manager: "MCPManager",
) -> Dict[str, Any]:
    """
    Create an AIPTX-compatible tool dict from an MCP tool definition.

    Args:
        tool_def: The MCP tool definition from tools/list
        server: The MCP server providing this tool
        manager: The MCP manager for making calls

    Returns:
        A tool configuration dict compatible with AIPTX's tool registry
    """
    original_name = tool_def.get("name", "unknown")
    tool_name = f"mcp_{server.name}_{original_name}"

    # Extract input schema
    input_schema = tool_def.get("inputSchema", {})
    properties = input_schema.get("properties", {})
    required = input_schema.get("required", [])

    # Build AIPTX-compatible tool config
    tool_config = {
        "name": tool_name,
        "description": tool_def.get("description", f"MCP tool from {server.name}"),
        "category": f"mcp:{server.name}",
        "phase": "any",  # MCP tools can be used in any phase
        "parameters": properties,
        "required_params": required,
        "metadata": {
            "mcp_server": server.name,
            "mcp_tool": original_name,
            "original_schema": input_schema,
        },
    }

    return tool_config


async def execute_mcp_tool(
    manager: "MCPManager",
    server_name: str,
    tool_name: str,
    arguments: Dict[str, Any],
) -> str:
    """
    Execute an MCP tool and return formatted result.

    Args:
        manager: The MCP manager instance
        server_name: Name of the MCP server
        tool_name: Name of the tool (without mcp_ prefix)
        arguments: Tool arguments

    Returns:
        Formatted result string
    """
    try:
        result = await manager.call_tool(server_name, tool_name, arguments)
        return format_mcp_result(result)
    except Exception as e:
        return f"MCP tool error: {str(e)}"


def format_mcp_result(result: Any) -> str:
    """
    Format an MCP tool result for display.

    MCP results typically come as a list of content blocks
    with types like "text", "image", "resource".

    Args:
        result: The raw MCP result (usually list of content blocks)

    Returns:
        Formatted string
    """
    if isinstance(result, list):
        parts = []
        for item in result:
            if isinstance(item, dict):
                content_type = item.get("type", "unknown")

                if content_type == "text":
                    parts.append(item.get("text", ""))
                elif content_type == "image":
                    mime = item.get("mimeType", "unknown")
                    parts.append(f"[Image ({mime})]")
                elif content_type == "resource":
                    uri = item.get("uri", "unknown")
                    parts.append(f"[Resource: {uri}]")
                else:
                    parts.append(str(item))
            else:
                parts.append(str(item))

        return "\n".join(parts)

    elif isinstance(result, dict):
        if "content" in result:
            return format_mcp_result(result["content"])
        return str(result)

    return str(result) if result else ""


def parse_mcp_tool_name(full_name: str) -> tuple[str, str]:
    """
    Parse an MCP tool name to extract server and tool name.

    Args:
        full_name: Full tool name (e.g., "mcp_nmap_scan_ports")

    Returns:
        Tuple of (server_name, tool_name)
    """
    if not full_name.startswith("mcp_"):
        raise ValueError(f"Not an MCP tool name: {full_name}")

    # Remove mcp_ prefix
    rest = full_name[4:]

    # Find first underscore to split server from tool name
    parts = rest.split("_", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid MCP tool name format: {full_name}")

    return parts[0], parts[1]
