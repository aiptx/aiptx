"""
AIPT Docker Sandbox

Isolated command execution in Docker containers for safety.
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .executor import CommandResult, ExecutionStatus

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Docker sandbox configuration"""
    image: str = "python:3.11-slim"  # Base image
    network_mode: str = "bridge"  # none, bridge, host
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    timeout: float = 300.0

    # Volume mounts
    mount_workspace: bool = True
    workspace_path: str = "/workspace"
    read_only_root: bool = True

    # Security
    no_new_privileges: bool = True
    drop_capabilities: list[str] = field(default_factory=lambda: ["ALL"])
    add_capabilities: list[str] = field(default_factory=list)

    # Cleanup
    auto_remove: bool = True


class DockerSandbox:
    """
    Docker-based sandbox for isolated command execution.

    Provides secure execution environment with:
    - Network isolation
    - Resource limits
    - Filesystem isolation
    - Capability dropping

    Example:
        sandbox = DockerSandbox()
        await sandbox.start()
        result = await sandbox.execute("python exploit.py")
        await sandbox.stop()

        # Or use context manager
        async with DockerSandbox() as sandbox:
            result = await sandbox.execute("nmap -sV target.com")
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._container_id: Optional[str] = None
        self._temp_dir: Optional[str] = None
        self._is_running = False

    async def __aenter__(self) -> "DockerSandbox":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    async def start(self) -> bool:
        """Start the sandbox container"""
        if self._is_running:
            return True

        # Check Docker availability
        if not await self._check_docker():
            logger.error("Docker is not available")
            return False

        # Create temp directory for workspace
        self._temp_dir = tempfile.mkdtemp(prefix="aipt_sandbox_")

        # Build docker run command
        cmd_parts = ["docker", "run", "-d"]

        # Resource limits
        cmd_parts.extend(["--memory", self.config.memory_limit])
        cmd_parts.extend(["--cpus", str(self.config.cpu_limit)])

        # Network
        cmd_parts.extend(["--network", self.config.network_mode])

        # Security
        if self.config.no_new_privileges:
            cmd_parts.append("--security-opt=no-new-privileges")

        for cap in self.config.drop_capabilities:
            cmd_parts.extend(["--cap-drop", cap])
        for cap in self.config.add_capabilities:
            cmd_parts.extend(["--cap-add", cap])

        if self.config.read_only_root:
            cmd_parts.append("--read-only")
            cmd_parts.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=100m"])

        # Workspace mount
        if self.config.mount_workspace:
            cmd_parts.extend([
                "-v", f"{self._temp_dir}:{self.config.workspace_path}:rw"
            ])
            cmd_parts.extend(["-w", self.config.workspace_path])

        # Auto-remove
        if self.config.auto_remove:
            cmd_parts.append("--rm")

        # Image and keep alive command
        cmd_parts.extend([self.config.image, "tail", "-f", "/dev/null"])

        # Start container
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Failed to start container: {stderr.decode()}")
                return False

            self._container_id = stdout.decode().strip()[:12]
            self._is_running = True
            logger.info(f"Sandbox started: {self._container_id}")
            return True

        except Exception as e:
            logger.error(f"Error starting sandbox: {e}")
            return False

    async def stop(self) -> bool:
        """Stop and cleanup the sandbox"""
        if not self._is_running or not self._container_id:
            return True

        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "stop", "-t", "5", self._container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            self._is_running = False
            self._container_id = None

            # Cleanup temp dir
            if self._temp_dir and os.path.exists(self._temp_dir):
                import shutil
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                self._temp_dir = None

            logger.info("Sandbox stopped")
            return True

        except Exception as e:
            logger.error(f"Error stopping sandbox: {e}")
            return False

    async def execute(
        self,
        command: str,
        timeout: Optional[float] = None,
        user: str = "root",
    ) -> CommandResult:
        """
        Execute command inside the sandbox.

        Args:
            command: Command to execute
            timeout: Override timeout
            user: User to run as

        Returns:
            CommandResult
        """
        if not self._is_running:
            return CommandResult(
                command=command,
                status=ExecutionStatus.FAILED,
                stderr="Sandbox not running",
            )

        timeout = timeout or self.config.timeout
        result = CommandResult(
            command=command,
            status=ExecutionStatus.RUNNING,
            start_time=datetime.utcnow(),
        )

        try:
            # Docker exec command
            exec_cmd = [
                "docker", "exec",
                "-u", user,
                self._container_id,
                "sh", "-c", command,
            ]

            process = await asyncio.create_subprocess_exec(
                *exec_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )

                result.exit_code = process.returncode
                result.status = (
                    ExecutionStatus.SUCCESS
                    if process.returncode == 0
                    else ExecutionStatus.FAILED
                )
                result.stdout = stdout.decode("utf-8", errors="replace")
                result.stderr = stderr.decode("utf-8", errors="replace")

            except asyncio.TimeoutError:
                process.kill()
                result.status = ExecutionStatus.TIMEOUT
                result.stderr = f"Command timed out after {timeout}s"

        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.stderr = str(e)
        finally:
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    async def copy_to(self, local_path: str, container_path: str) -> bool:
        """Copy file into sandbox"""
        if not self._is_running:
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "cp", local_path, f"{self._container_id}:{container_path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    async def copy_from(self, container_path: str, local_path: str) -> bool:
        """Copy file from sandbox"""
        if not self._is_running:
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "cp", f"{self._container_id}:{container_path}", local_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    def write_to_workspace(self, filename: str, content: str) -> Optional[str]:
        """Write file to workspace directory"""
        if not self._temp_dir:
            return None
        filepath = os.path.join(self._temp_dir, filename)
        with open(filepath, "w") as f:
            f.write(content)
        return os.path.join(self.config.workspace_path, filename)

    async def _check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except FileNotFoundError:
            return False

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def container_id(self) -> Optional[str]:
        return self._container_id


# Security-focused sandbox presets
def create_network_scanner_sandbox() -> DockerSandbox:
    """Sandbox configured for network scanning tools"""
    return DockerSandbox(SandboxConfig(
        image="instrumentisto/nmap:latest",
        network_mode="host",  # Need host networking for scanning
        memory_limit="1g",
        timeout=600.0,
        add_capabilities=["NET_RAW", "NET_ADMIN"],
    ))


def create_web_scanner_sandbox() -> DockerSandbox:
    """Sandbox configured for web scanning"""
    return DockerSandbox(SandboxConfig(
        image="python:3.11-slim",
        network_mode="bridge",
        memory_limit="512m",
        timeout=300.0,
    ))


def create_exploit_sandbox() -> DockerSandbox:
    """Highly isolated sandbox for running exploits"""
    return DockerSandbox(SandboxConfig(
        image="python:3.11-slim",
        network_mode="none",  # No network access
        memory_limit="256m",
        cpu_limit=0.5,
        timeout=60.0,
        read_only_root=True,
        drop_capabilities=["ALL"],
    ))
