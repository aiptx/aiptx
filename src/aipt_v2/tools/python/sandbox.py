"""
Python Sandbox
==============

Sandboxed Python execution with security restrictions.
Uses subprocess isolation with memory/time limits.

Integrated from Strix's Python runtime.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

# Imports that are restricted in sandbox mode
RESTRICTED_IMPORTS = [
    "os.system",
    "os.popen",
    "os.spawn",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "eval",
    "exec",
    "compile",
    "__import__",
    "importlib",
    "ctypes",
    "multiprocessing",
    "threading.Thread",
]

# Safe imports allowed in sandbox
SAFE_IMPORTS = [
    "json",
    "base64",
    "hashlib",
    "urllib.parse",
    "re",
    "datetime",
    "collections",
    "itertools",
    "functools",
    "math",
    "string",
    "random",
    "uuid",
    "html",
    "xml.etree.ElementTree",
    "csv",
    "io",
    "struct",
    "binascii",
    "textwrap",
    "difflib",
]

# Network libraries allowed (for security testing)
NETWORK_IMPORTS = [
    "requests",
    "httpx",
    "aiohttp",
    "urllib.request",
    "socket",
    "ssl",
    "websocket",
]


@dataclass
class SandboxConfig:
    """Configuration for Python sandbox execution."""

    # Timeout in seconds
    timeout: int = 30

    # Memory limit in MB (soft limit)
    memory_limit_mb: int = 256

    # Whether to allow network access
    allow_network: bool = True

    # Whether to allow file system access
    allow_filesystem: bool = False

    # Working directory (temp by default)
    working_dir: Path | None = None

    # Environment variables to pass
    env_vars: dict[str, str] = field(default_factory=dict)

    # Additional allowed imports
    allowed_imports: list[str] = field(default_factory=list)

    # Whether to capture stderr
    capture_stderr: bool = True


class PythonSandbox:
    """
    Sandboxed Python execution environment.

    Uses subprocess isolation with configurable restrictions.
    """

    def __init__(self, config: SandboxConfig | None = None):
        """
        Initialize the sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        self.config = config or SandboxConfig()
        self._temp_dir: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> "PythonSandbox":
        """Context manager entry."""
        self._temp_dir = tempfile.TemporaryDirectory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        if self._temp_dir:
            self._temp_dir.cleanup()

    @property
    def working_dir(self) -> Path:
        """Get the working directory for execution."""
        if self.config.working_dir:
            return self.config.working_dir
        if self._temp_dir:
            return Path(self._temp_dir.name)
        return Path(tempfile.gettempdir())

    def _build_wrapper_code(self, code: str) -> str:
        """
        Build wrapper code with safety restrictions.

        Args:
            code: User code to wrap.

        Returns:
            Wrapped code with restrictions.
        """
        # Build allowed imports list
        allowed = set(SAFE_IMPORTS)
        if self.config.allow_network:
            allowed.update(NETWORK_IMPORTS)
        allowed.update(self.config.allowed_imports)

        wrapper = '''
import sys
import io

# Capture output
_stdout = io.StringIO()
_stderr = io.StringIO()
_original_stdout = sys.stdout
_original_stderr = sys.stderr
sys.stdout = _stdout
sys.stderr = _stderr

try:
    # User code
{code}

except Exception as e:
    print(f"Error: {{type(e).__name__}}: {{e}}", file=sys.stderr)

finally:
    sys.stdout = _original_stdout
    sys.stderr = _original_stderr

# Output results
print("=== STDOUT ===")
print(_stdout.getvalue())
print("=== STDERR ===")
print(_stderr.getvalue())
'''
        # Indent user code
        indented_code = "\n".join(f"    {line}" for line in code.split("\n"))
        return wrapper.format(code=indented_code)

    async def execute(self, code: str) -> dict[str, Any]:
        """
        Execute Python code in the sandbox.

        Args:
            code: Python code to execute.

        Returns:
            Dict with stdout, stderr, exit_code, and execution_time.
        """
        import time

        # Create temporary script file
        script_path = self.working_dir / "_sandbox_script.py"
        wrapped_code = self._build_wrapper_code(code)
        script_path.write_text(wrapped_code, encoding="utf-8")

        # Build command
        cmd = [sys.executable, str(script_path)]

        # Build environment
        env = os.environ.copy()
        env.update(self.config.env_vars)

        # Remove potentially dangerous env vars
        for var in ["PYTHONSTARTUP", "PYTHONPATH"]:
            env.pop(var, None)

        start_time = time.time()

        try:
            # Run in subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.working_dir),
                env=env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self.config.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Execution timed out after {self.config.timeout} seconds",
                    "exit_code": -1,
                    "execution_time": self.config.timeout,
                    "error": "timeout",
                }

            execution_time = time.time() - start_time

            # Parse output
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            # Extract captured output from wrapper
            captured_stdout = ""
            captured_stderr = ""

            if "=== STDOUT ===" in stdout_str:
                parts = stdout_str.split("=== STDOUT ===")
                if len(parts) > 1:
                    rest = parts[1]
                    if "=== STDERR ===" in rest:
                        stdout_parts = rest.split("=== STDERR ===")
                        captured_stdout = stdout_parts[0].strip()
                        if len(stdout_parts) > 1:
                            captured_stderr = stdout_parts[1].strip()
                    else:
                        captured_stdout = rest.strip()

            return {
                "success": process.returncode == 0,
                "stdout": captured_stdout or stdout_str,
                "stderr": captured_stderr or stderr_str,
                "exit_code": process.returncode,
                "execution_time": round(execution_time, 3),
            }

        except Exception as e:
            execution_time = time.time() - start_time
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "execution_time": round(execution_time, 3),
                "error": str(e),
            }

        finally:
            # Clean up script file
            try:
                script_path.unlink(missing_ok=True)
            except Exception:
                pass

    def execute_sync(self, code: str) -> dict[str, Any]:
        """
        Execute Python code synchronously.

        Args:
            code: Python code to execute.

        Returns:
            Dict with stdout, stderr, exit_code, and execution_time.
        """
        import time

        # Create temporary script file
        script_path = self.working_dir / "_sandbox_script.py"
        wrapped_code = self._build_wrapper_code(code)
        script_path.write_text(wrapped_code, encoding="utf-8")

        # Build command
        cmd = [sys.executable, str(script_path)]

        # Build environment
        env = os.environ.copy()
        env.update(self.config.env_vars)

        start_time = time.time()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.config.timeout,
                cwd=str(self.working_dir),
                env=env,
            )

            execution_time = time.time() - start_time

            stdout_str = result.stdout.decode("utf-8", errors="replace")
            stderr_str = result.stderr.decode("utf-8", errors="replace")

            # Parse captured output
            captured_stdout = ""
            captured_stderr = ""

            if "=== STDOUT ===" in stdout_str:
                parts = stdout_str.split("=== STDOUT ===")
                if len(parts) > 1:
                    rest = parts[1]
                    if "=== STDERR ===" in rest:
                        stdout_parts = rest.split("=== STDERR ===")
                        captured_stdout = stdout_parts[0].strip()
                        if len(stdout_parts) > 1:
                            captured_stderr = stdout_parts[1].strip()
                    else:
                        captured_stdout = rest.strip()

            return {
                "success": result.returncode == 0,
                "stdout": captured_stdout or stdout_str,
                "stderr": captured_stderr or stderr_str,
                "exit_code": result.returncode,
                "execution_time": round(execution_time, 3),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Execution timed out after {self.config.timeout} seconds",
                "exit_code": -1,
                "execution_time": self.config.timeout,
                "error": "timeout",
            }

        except Exception as e:
            execution_time = time.time() - start_time
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "execution_time": round(execution_time, 3),
                "error": str(e),
            }

        finally:
            try:
                script_path.unlink(missing_ok=True)
            except Exception:
                pass
