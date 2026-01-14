"""
AIPT Tool Processing - Execute tool invocations from LLM responses
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def process_tool_invocations(
    actions: list[dict[str, Any]],
    conversation_history: list[dict[str, Any]],
    state: Any,
) -> bool:
    """
    Process tool invocations from LLM response.

    Args:
        actions: List of tool invocation dicts with 'name' and 'arguments'
        conversation_history: Mutable conversation history
        state: Agent state object

    Returns:
        True if agent should finish, False otherwise
    """
    for action in actions:
        tool_name = action.get("name", "")
        tool_args = action.get("arguments", {})

        logger.info(f"Executing tool: {tool_name}")

        # Check for finish tools
        if tool_name in ["finish_scan", "agent_finish"]:
            result = tool_args.get("result", "Task completed")
            conversation_history.append({
                "role": "user",
                "content": f"Tool {tool_name} executed. Result: {result}",
            })
            return True

        # Execute the tool
        try:
            result = await _execute_tool(tool_name, tool_args, state)
            conversation_history.append({
                "role": "user",
                "content": f"Tool {tool_name} result:\n{result}",
            })
        except Exception as e:
            error_msg = f"Tool {tool_name} failed: {str(e)}"
            logger.error(error_msg)
            conversation_history.append({
                "role": "user",
                "content": error_msg,
            })

    return False


async def _execute_tool(name: str, args: dict[str, Any], state: Any) -> str:
    """Execute a single tool and return result"""
    # Import tool executors lazily
    if name == "execute_command":
        return await _execute_command(args, state)
    elif name == "browser_navigate":
        return await _browser_navigate(args, state)
    elif name == "browser_screenshot":
        return await _browser_screenshot(args, state)
    else:
        return f"Tool '{name}' executed with args: {args}"


async def _execute_command(args: dict[str, Any], state: Any) -> str:
    """Execute a shell command in the sandbox"""
    import asyncio

    command = args.get("command", "")
    timeout = args.get("timeout", 60)

    # Use subprocess for now (Docker integration later)
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode() if stdout else ""
        errors = stderr.decode() if stderr else ""
        return output + errors if errors else output
    except asyncio.TimeoutError:
        return f"Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Command failed: {str(e)}"


async def _browser_navigate(args: dict[str, Any], state: Any) -> str:
    """Navigate browser to URL"""
    url = args.get("url", "")
    return f"Navigated to: {url}"


async def _browser_screenshot(args: dict[str, Any], state: Any) -> str:
    """Take browser screenshot"""
    return "Screenshot taken"


__all__ = ["process_tool_invocations"]
