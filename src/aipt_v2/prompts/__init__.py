"""
AIPT Prompts Module - System prompts and prompt templates
"""

from typing import Any
from jinja2 import Environment


def load_prompt_modules(module_names: list[str], jinja_env: Environment) -> dict[str, str]:
    """
    Load prompt modules by name.

    Args:
        module_names: List of module names to load
        jinja_env: Jinja2 environment for template rendering

    Returns:
        Dictionary mapping module names to their content
    """
    modules = {}
    for name in module_names:
        try:
            template = jinja_env.get_template(f"{name}.jinja")
            modules[name] = template.render()
        except Exception:
            modules[name] = ""
    return modules


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


__all__ = ["load_prompt_modules", "get_tools_prompt"]
