"""
Python Execution Actions
========================

Tool actions for executing Python code in the sandbox.
Used by agents to validate exploits and run analysis code.

Integrated from Strix's Python runtime.

Example:
    # Execute simple code
    result = await execute_python("print(2 + 2)")

    # Execute complex exploit validation
    result = await execute_python('''
        import requests
        response = requests.post(
            "http://target.local/api/login",
            json={"username": "admin' OR '1'='1", "password": "x"}
        )
        print(f"Status: {response.status_code}")
        print(f"Body: {response.text}")
    ''')
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class PythonExecutionResult:
    """Result of Python code execution."""

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "error": self.error,
        }


async def execute_python(
    code: str,
    timeout: int = 30,
    allow_network: bool = True,
) -> dict[str, Any]:
    """
    Execute Python code in a sandbox.

    This is the main entry point for agents to run Python code.
    The code runs in a subprocess with configurable restrictions.

    Args:
        code: Python code to execute.
        timeout: Maximum execution time in seconds.
        allow_network: Whether to allow network access.

    Returns:
        Dict with:
        - success: Whether execution succeeded.
        - stdout: Captured standard output.
        - stderr: Captured standard error.
        - exit_code: Process exit code.
        - execution_time: Time taken in seconds.
        - error: Error message if failed.

    Example:
        result = await execute_python('''
            import json
            data = {"key": "value"}
            print(json.dumps(data, indent=2))
        ''')
        print(result["stdout"])  # {"key": "value"}
    """
    from .sandbox import PythonSandbox, SandboxConfig

    config = SandboxConfig(
        timeout=timeout,
        allow_network=allow_network,
    )

    sandbox = PythonSandbox(config)

    # Use context manager for temp directory cleanup
    with sandbox:
        result = await sandbox.execute(code)

    return result


def execute_python_sync(
    code: str,
    timeout: int = 30,
    allow_network: bool = True,
) -> dict[str, Any]:
    """
    Execute Python code synchronously.

    Same as execute_python but for synchronous contexts.

    Args:
        code: Python code to execute.
        timeout: Maximum execution time in seconds.
        allow_network: Whether to allow network access.

    Returns:
        Dict with execution results.
    """
    from .sandbox import PythonSandbox, SandboxConfig

    config = SandboxConfig(
        timeout=timeout,
        allow_network=allow_network,
    )

    sandbox = PythonSandbox(config)

    with sandbox:
        result = sandbox.execute_sync(code)

    return result


async def install_package(
    package_name: str,
    timeout: int = 60,
) -> dict[str, Any]:
    """
    Install a Python package in the sandbox.

    Args:
        package_name: Name of the package to install.
        timeout: Maximum time for installation.

    Returns:
        Dict with installation result.
    """
    # Validate package name (basic security check)
    if not package_name or not package_name.replace("-", "").replace("_", "").isalnum():
        return {
            "success": False,
            "message": f"Invalid package name: {package_name}",
            "error": "invalid_package_name",
        }

    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "pip",
            "install",
            "--user",
            "--quiet",
            package_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {
                "success": False,
                "message": f"Package installation timed out after {timeout} seconds",
                "error": "timeout",
            }

        if process.returncode == 0:
            return {
                "success": True,
                "message": f"Package '{package_name}' installed successfully",
                "stdout": stdout.decode("utf-8", errors="replace"),
            }
        else:
            return {
                "success": False,
                "message": f"Failed to install package '{package_name}'",
                "stderr": stderr.decode("utf-8", errors="replace"),
                "exit_code": process.returncode,
            }

    except Exception as e:
        return {
            "success": False,
            "message": f"Package installation failed: {e}",
            "error": str(e),
        }


def get_python_info() -> dict[str, Any]:
    """
    Get information about the Python environment.

    Returns:
        Dict with Python version and available packages.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            timeout=10,
        )

        packages = []
        if result.returncode == 0:
            import json

            packages = json.loads(result.stdout.decode("utf-8"))

        return {
            "python_version": sys.version,
            "python_executable": sys.executable,
            "packages": packages[:50],  # Limit to first 50
            "package_count": len(packages),
        }

    except Exception as e:
        return {
            "python_version": sys.version,
            "python_executable": sys.executable,
            "packages": [],
            "error": str(e),
        }
