"""
PowerShell Execution Engine for WinPwn

Handles PowerShell script execution with proper process management,
output capture, and timeout handling.

Supports:
- Local PowerShell execution (Windows)
- PowerShell Core (cross-platform)
- WinRM remote execution
- Process isolation and cleanup

Usage:
    from aipt_v2.tools.winpwn import PowerShellExecutor

    executor = PowerShellExecutor()
    result = await executor.execute_script("Get-Process")
"""

import asyncio
import logging
import os
import platform
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PowerShellResult:
    """Result of PowerShell execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    command: str = ""
    script_path: str = ""
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def output(self) -> str:
        """Combined output."""
        return f"{self.stdout}\n{self.stderr}".strip()


class PowerShellExecutor:
    """
    PowerShell script execution engine.

    Provides async execution of PowerShell commands and scripts
    with proper output capture and error handling.
    """

    def __init__(
        self,
        powershell_path: Optional[str] = None,
        use_pwsh_core: bool = False,
        execution_policy: str = "Bypass",
        encoding: str = "utf-8",
        working_dir: Optional[str] = None,
    ):
        """
        Initialize PowerShell executor.

        Args:
            powershell_path: Custom path to PowerShell executable
            use_pwsh_core: Use PowerShell Core (pwsh) instead of Windows PowerShell
            execution_policy: PowerShell execution policy
            encoding: Output encoding
            working_dir: Working directory for execution
        """
        self.powershell_path = self._detect_powershell(powershell_path, use_pwsh_core)
        self.execution_policy = execution_policy
        self.encoding = encoding
        self.working_dir = working_dir or os.getcwd()
        self._temp_scripts: List[str] = []
        self._running_processes: List[asyncio.subprocess.Process] = []

    def _detect_powershell(self, custom_path: Optional[str], use_pwsh_core: bool) -> str:
        """Detect available PowerShell executable."""
        if custom_path and Path(custom_path).exists():
            return custom_path

        # Check for PowerShell Core first if preferred
        if use_pwsh_core:
            pwsh_paths = ["/usr/bin/pwsh", "/usr/local/bin/pwsh", "pwsh", "pwsh.exe"]
            for path in pwsh_paths:
                if self._command_exists(path):
                    return path

        # Windows PowerShell
        if platform.system() == "Windows":
            return "powershell.exe"

        # Default to pwsh on non-Windows
        return "pwsh"

    @staticmethod
    def _command_exists(cmd: str) -> bool:
        """Check if command exists on system."""
        try:
            subprocess.run([cmd, "-Version"], capture_output=True, timeout=5)
            return True
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _build_command(
        self, script: str, script_file: bool = False, additional_args: List[str] = None
    ) -> List[str]:
        """Build PowerShell command line."""
        cmd = [
            self.powershell_path,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            self.execution_policy,
        ]

        if additional_args:
            cmd.extend(additional_args)

        if script_file:
            cmd.extend(["-File", script])
        else:
            cmd.extend(["-Command", script])

        return cmd

    async def execute_command(
        self, command: str, timeout: int = 120, env: Dict[str, str] = None
    ) -> PowerShellResult:
        """
        Execute a PowerShell command.

        Args:
            command: PowerShell command to execute
            timeout: Timeout in seconds
            env: Additional environment variables

        Returns:
            PowerShellResult with execution details
        """
        start_time = asyncio.get_event_loop().time()
        cmd = self._build_command(command)

        # Merge environment
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.working_dir,
                env=exec_env,
            )
            self._running_processes.append(process)

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

                execution_time = asyncio.get_event_loop().time() - start_time

                return PowerShellResult(
                    success=process.returncode == 0,
                    exit_code=process.returncode or 0,
                    stdout=stdout.decode(self.encoding, errors="replace"),
                    stderr=stderr.decode(self.encoding, errors="replace"),
                    execution_time=execution_time,
                    command=command,
                )

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                execution_time = asyncio.get_event_loop().time() - start_time

                return PowerShellResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr=f"Timeout after {timeout} seconds",
                    execution_time=execution_time,
                    command=command,
                    metadata={"timeout": True},
                )

            finally:
                if process in self._running_processes:
                    self._running_processes.remove(process)

        except FileNotFoundError:
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"PowerShell not found: {self.powershell_path}",
                execution_time=0,
                command=command,
            )
        except Exception as e:
            logger.exception(f"PowerShell execution error: {e}")
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time,
                command=command,
            )

    async def execute_script(
        self,
        script_content: str,
        timeout: int = 300,
        env: Dict[str, str] = None,
        cleanup: bool = True,
    ) -> PowerShellResult:
        """
        Execute a PowerShell script from content.

        Creates a temporary file and executes it.

        Args:
            script_content: PowerShell script content
            timeout: Timeout in seconds
            env: Additional environment variables
            cleanup: Remove temp file after execution

        Returns:
            PowerShellResult with execution details
        """
        # Create temp script file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ps1", delete=False, encoding=self.encoding
        ) as f:
            f.write(script_content)
            script_path = f.name
            self._temp_scripts.append(script_path)

        try:
            result = await self.execute_script_file(script_path, timeout=timeout, env=env)
            result.script_path = script_path
            return result

        finally:
            if cleanup:
                self._cleanup_temp_script(script_path)

    async def execute_script_file(
        self,
        script_path: str,
        timeout: int = 300,
        arguments: List[str] = None,
        env: Dict[str, str] = None,
    ) -> PowerShellResult:
        """
        Execute a PowerShell script file.

        Args:
            script_path: Path to .ps1 script
            timeout: Timeout in seconds
            arguments: Script arguments
            env: Additional environment variables

        Returns:
            PowerShellResult with execution details
        """
        if not Path(script_path).exists():
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Script not found: {script_path}",
                execution_time=0,
                script_path=script_path,
            )

        start_time = asyncio.get_event_loop().time()

        cmd = self._build_command(script_path, script_file=True)
        if arguments:
            cmd.extend(arguments)

        # Merge environment
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.working_dir,
                env=exec_env,
            )
            self._running_processes.append(process)

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

                execution_time = asyncio.get_event_loop().time() - start_time

                return PowerShellResult(
                    success=process.returncode == 0,
                    exit_code=process.returncode or 0,
                    stdout=stdout.decode(self.encoding, errors="replace"),
                    stderr=stderr.decode(self.encoding, errors="replace"),
                    execution_time=execution_time,
                    script_path=script_path,
                )

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                execution_time = asyncio.get_event_loop().time() - start_time

                return PowerShellResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr=f"Script timeout after {timeout} seconds",
                    execution_time=execution_time,
                    script_path=script_path,
                    metadata={"timeout": True},
                )

            finally:
                if process in self._running_processes:
                    self._running_processes.remove(process)

        except Exception as e:
            logger.exception(f"Script execution error: {e}")
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time,
                script_path=script_path,
            )

    async def execute_with_loader(
        self,
        loader_command: str,
        function_call: str,
        timeout: int = 300,
        env: Dict[str, str] = None,
    ) -> PowerShellResult:
        """
        Execute with a script loader (IEX pattern).

        First loads a script via IEX, then calls a function.

        Args:
            loader_command: Command to load script (e.g., IEX download)
            function_call: Function to call after loading
            timeout: Timeout in seconds
            env: Additional environment variables

        Returns:
            PowerShellResult with execution details
        """
        script = f"""
{loader_command}
{function_call}
"""
        return await self.execute_command(script, timeout=timeout, env=env)

    def _cleanup_temp_script(self, script_path: str) -> None:
        """Remove temporary script file."""
        try:
            if script_path in self._temp_scripts:
                self._temp_scripts.remove(script_path)
            Path(script_path).unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp script: {e}")

    async def cleanup(self) -> None:
        """Cleanup all temporary files and kill running processes."""
        # Kill any running processes
        for process in self._running_processes:
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
        self._running_processes.clear()

        # Remove temp scripts
        for script_path in self._temp_scripts.copy():
            self._cleanup_temp_script(script_path)


class WinRMExecutor:
    """
    WinRM-based remote PowerShell executor.

    Executes PowerShell on remote Windows hosts via WinRM.
    """

    def __init__(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "",
        ssl: bool = False,
        port: int = 5985,
    ):
        """
        Initialize WinRM executor.

        Args:
            target: Target hostname/IP
            username: Username for authentication
            password: Password for authentication
            domain: Domain name (optional)
            ssl: Use SSL/HTTPS
            port: WinRM port
        """
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.ssl = ssl
        self.port = port if not ssl else 5986

        self._session = None

    def _get_connection_url(self) -> str:
        """Build WinRM connection URL."""
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.target}:{self.port}/wsman"

    async def execute_command(self, command: str, timeout: int = 120) -> PowerShellResult:
        """
        Execute command on remote host via WinRM.

        Note: Requires pywinrm package.

        Args:
            command: PowerShell command
            timeout: Timeout in seconds

        Returns:
            PowerShellResult with execution details
        """
        start_time = asyncio.get_event_loop().time()

        try:
            import winrm
        except ImportError:
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="pywinrm package not installed. Install with: pip install pywinrm",
                execution_time=0,
                command=command,
            )

        try:
            # Run in thread pool to not block async loop
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._execute_winrm, command), timeout=timeout
            )

            execution_time = asyncio.get_event_loop().time() - start_time
            return PowerShellResult(
                success=result.status_code == 0,
                exit_code=result.status_code,
                stdout=result.std_out.decode("utf-8", errors="replace"),
                stderr=result.std_err.decode("utf-8", errors="replace"),
                execution_time=execution_time,
                command=command,
                metadata={"remote": True, "target": self.target},
            )

        except asyncio.TimeoutError:
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"WinRM timeout after {timeout} seconds",
                execution_time=asyncio.get_event_loop().time() - start_time,
                command=command,
                metadata={"timeout": True, "target": self.target},
            )
        except Exception as e:
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time,
                command=command,
                metadata={"target": self.target},
            )

    def _execute_winrm(self, command: str):
        """Execute WinRM command (blocking)."""
        import winrm

        if self.domain:
            user = f"{self.domain}\\{self.username}"
        else:
            user = self.username

        session = winrm.Session(
            self._get_connection_url(),
            auth=(user, self.password),
            server_cert_validation="ignore" if self.ssl else "validate",
        )

        return session.run_ps(command)


__all__ = [
    "PowerShellExecutor",
    "PowerShellResult",
    "WinRMExecutor",
]
