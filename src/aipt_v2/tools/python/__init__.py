"""
AIPTX Python Sandbox Module
===========================

Provides sandboxed Python execution for exploit validation.
Allows agents to run Python code safely with memory/time limits.

Integrated from Strix's Python runtime.

Usage:
    from aipt_v2.tools.python import execute_python, install_package

    # Execute Python code
    result = await execute_python('''
        import requests
        response = requests.get("http://target.local/api/users")
        print(response.json())
    ''')

    # Install a package
    await install_package("beautifulsoup4")
"""

from .python_actions import (
    execute_python,
    execute_python_sync,
    install_package,
    PythonExecutionResult,
)
from .sandbox import (
    PythonSandbox,
    SandboxConfig,
    RESTRICTED_IMPORTS,
)

__all__ = [
    "execute_python",
    "execute_python_sync",
    "install_package",
    "PythonExecutionResult",
    "PythonSandbox",
    "SandboxConfig",
    "RESTRICTED_IMPORTS",
]
