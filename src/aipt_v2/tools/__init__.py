"""
AIPT Tools Module - Terminal, Browser, Proxy, and Output Parsing
"""

from aipt_v2.tools.parser import OutputParser, Finding
from aipt_v2.tools.tool_processing import process_tool_invocations


def get_tools_prompt() -> str:
    """Get the tools prompt for the agent."""
    return """
You have access to the following security tools:

## Terminal Tools
- execute_command: Run shell commands in isolated Docker sandbox
- terminal_session: Manage persistent terminal sessions

## Browser Tools
- browser_navigate: Navigate to URLs
- browser_click: Click elements
- browser_type: Type text into inputs
- browser_screenshot: Take screenshots

## Proxy Tools
- proxy_intercept: Intercept HTTP traffic
- proxy_modify: Modify requests/responses

## Security Tools
- nmap: Port scanning and service detection
- gobuster: Directory brute-forcing
- nuclei: Vulnerability scanning
- hydra: Credential brute-forcing
- sqlmap: SQL injection testing

Use these tools to accomplish your penetration testing objectives.
"""


__all__ = [
    "OutputParser",
    "Finding",
    "process_tool_invocations",
    "get_tools_prompt",
]
