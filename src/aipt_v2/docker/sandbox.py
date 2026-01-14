"""
AIPT Docker Sandbox - Secure command execution in containers

Provides isolated execution environment for security tools:
- Network-isolated containers
- Resource limits (CPU, memory)
- Timeout enforcement
- Output capture and streaming
"""
from __future__ import annotations

import subprocess
import json
import os
import time
import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path


@dataclass
class SandboxResult:
    """Result from sandbox execution"""
    output: str
    return_code: int
    duration: float
    container_id: Optional[str] = None
    error: Optional[str] = None
    truncated: bool = False


@dataclass
class SandboxConfig:
    """Docker sandbox configuration"""
    image: str = "kalilinux/kali-rolling"
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    network_mode: str = "bridge"  # bridge, host, none
    timeout: int = 300
    working_dir: str = "/workspace"
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: Dict[str, str] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)  # NET_RAW, etc.
    privileged: bool = False
    remove_after: bool = True


class DockerSandbox:
    """
    Docker-based sandbox for secure command execution.

    Provides isolated execution environment with:
    - Resource limits (memory, CPU)
    - Network isolation options
    - Timeout enforcement
    - Output streaming
    """

    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        auto_pull: bool = True,
    ):
        self.config = config or SandboxConfig()
        self.auto_pull = auto_pull
        self._docker_available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if Docker is available"""
        if self._docker_available is not None:
            return self._docker_available

        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
            self._docker_available = False

        return self._docker_available

    def image_exists(self, image: str) -> bool:
        """Check if Docker image exists locally"""
        try:
            result = subprocess.run(
                ["docker", "images", "-q", image],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return bool(result.stdout.strip())
        except Exception:
            return False

    def pull_image(self, image: Optional[str] = None) -> bool:
        """Pull Docker image"""
        image = image or self.config.image
        try:
            result = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=600,
            )
            return result.returncode == 0
        except Exception:
            return False

    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        image: Optional[str] = None,
        network: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        volumes: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """
        Execute command in Docker container.

        Args:
            command: Command to execute
            timeout: Execution timeout in seconds
            image: Docker image (overrides config)
            network: Network mode (overrides config)
            env: Additional environment variables
            volumes: Additional volume mounts

        Returns:
            SandboxResult with output and status
        """
        start_time = time.time()

        if not self.is_available():
            return SandboxResult(
                output="",
                return_code=-1,
                duration=0,
                error="Docker is not available",
            )

        image = image or self.config.image

        if self.auto_pull and not self.image_exists(image):
            if not self.pull_image(image):
                return SandboxResult(
                    output="",
                    return_code=-1,
                    duration=0,
                    error=f"Failed to pull image: {image}",
                )

        docker_cmd = self._build_docker_command(
            command=command,
            image=image,
            network=network,
            env=env,
            volumes=volumes,
        )

        timeout = timeout or self.config.timeout

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration = time.time() - start_time
            output = result.stdout

            if result.stderr:
                output = f"{output}\n[STDERR]\n{result.stderr}"

            truncated = False
            if len(output) > 100000:
                output = output[:100000] + "\n... [OUTPUT TRUNCATED]"
                truncated = True

            return SandboxResult(
                output=output,
                return_code=result.returncode,
                duration=duration,
                truncated=truncated,
            )

        except subprocess.TimeoutExpired:
            return SandboxResult(
                output="",
                return_code=-1,
                duration=timeout,
                error=f"Command timed out after {timeout}s",
            )
        except Exception as e:
            return SandboxResult(
                output="",
                return_code=-1,
                duration=time.time() - start_time,
                error=str(e),
            )

    async def execute_async(
        self,
        command: str,
        timeout: Optional[int] = None,
        image: Optional[str] = None,
        **kwargs
    ) -> SandboxResult:
        """Async version of execute"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.execute(command, timeout, image, **kwargs)
        )

    def execute_streaming(
        self,
        command: str,
        callback: Callable[[str], None],
        timeout: Optional[int] = None,
        image: Optional[str] = None,
    ) -> SandboxResult:
        """
        Execute command with streaming output.

        Args:
            command: Command to execute
            callback: Function to call with each output line
            timeout: Execution timeout
            image: Docker image

        Returns:
            SandboxResult
        """
        start_time = time.time()
        image = image or self.config.image
        timeout = timeout or self.config.timeout

        if not self.is_available():
            return SandboxResult(
                output="",
                return_code=-1,
                duration=0,
                error="Docker is not available",
            )

        docker_cmd = self._build_docker_command(command, image)

        try:
            process = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            output_lines = []

            while True:
                if time.time() - start_time > timeout:
                    process.kill()
                    return SandboxResult(
                        output="\n".join(output_lines),
                        return_code=-1,
                        duration=timeout,
                        error=f"Command timed out after {timeout}s",
                    )

                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break

                if line:
                    line = line.rstrip()
                    output_lines.append(line)
                    callback(line)

            return SandboxResult(
                output="\n".join(output_lines),
                return_code=process.returncode,
                duration=time.time() - start_time,
            )

        except Exception as e:
            return SandboxResult(
                output="",
                return_code=-1,
                duration=time.time() - start_time,
                error=str(e),
            )

    def _build_docker_command(
        self,
        command: str,
        image: str,
        network: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        volumes: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Build docker run command"""
        docker_cmd = [
            "docker", "run",
            "--memory", self.config.memory_limit,
            "--cpus", str(self.config.cpu_limit),
            "--network", network or self.config.network_mode,
            "-w", self.config.working_dir,
        ]

        if self.config.remove_after:
            docker_cmd.append("--rm")

        if self.config.privileged:
            docker_cmd.append("--privileged")

        for cap in self.config.capabilities:
            docker_cmd.extend(["--cap-add", cap])

        all_env = {**self.config.environment, **(env or {})}
        for key, value in all_env.items():
            docker_cmd.extend(["-e", f"{key}={value}"])

        all_volumes = {**self.config.volumes, **(volumes or {})}
        for host_path, container_path in all_volumes.items():
            docker_cmd.extend(["-v", f"{host_path}:{container_path}"])

        docker_cmd.extend([image, "sh", "-c", command])

        return docker_cmd

    def list_containers(self, all_containers: bool = False) -> List[Dict[str, str]]:
        """List running containers"""
        cmd = ["docker", "ps", "--format", "{{json .}}"]
        if all_containers:
            cmd.append("-a")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            containers = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    containers.append(json.loads(line))
            return containers
        except Exception:
            return []

    def stop_container(self, container_id: str, force: bool = False) -> bool:
        """Stop a running container"""
        cmd = ["docker", "kill" if force else "stop", container_id]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            return result.returncode == 0
        except Exception:
            return False

    def cleanup_containers(self, image_filter: Optional[str] = None) -> int:
        """Remove stopped containers"""
        cmd = ["docker", "container", "prune", "-f"]
        if image_filter:
            cmd.extend(["--filter", f"ancestor={image_filter}"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode
        except Exception:
            return -1
