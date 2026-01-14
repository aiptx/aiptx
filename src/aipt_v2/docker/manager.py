"""
AIPT Container Manager - Manages multiple sandbox configurations

Provides pre-configured sandboxes for different use cases:
- Recon tools (nmap, masscan)
- Web tools (nuclei, httpx)
- Exploitation (metasploit)
- Post-exploitation (linpeas)
"""
from __future__ import annotations

from typing import Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum

from .sandbox import DockerSandbox, SandboxConfig, SandboxResult


class SecurityImage(str, Enum):
    """Pre-defined security tool images"""
    KALI = "kalilinux/kali-rolling"
    NMAP = "instrumentisto/nmap"
    NUCLEI = "projectdiscovery/nuclei"
    HTTPX = "projectdiscovery/httpx"
    SUBFINDER = "projectdiscovery/subfinder"
    MASSCAN = "adarnimrod/masscan"
    METASPLOIT = "metasploitframework/metasploit-framework"
    SQLMAP = "paoloo/sqlmap"
    NIKTO = "sullo/nikto"


@dataclass
class PhaseConfig:
    """Configuration for a pentest phase"""
    memory_limit: str = "1g"
    cpu_limit: float = 2.0
    timeout: int = 600
    network_mode: str = "bridge"
    capabilities: List[str] = field(default_factory=list)


class ContainerManager:
    """
    Manages multiple sandbox configurations for different use cases.

    Provides pre-configured sandboxes for:
    - Recon tools (nmap, masscan)
    - Web tools (nuclei, httpx)
    - Exploitation (metasploit)
    - Post-exploitation (linpeas)
    """

    # Tool to image mapping
    TOOL_IMAGES: Dict[str, SecurityImage] = {
        "nmap": SecurityImage.NMAP,
        "masscan": SecurityImage.MASSCAN,
        "nuclei": SecurityImage.NUCLEI,
        "httpx": SecurityImage.HTTPX,
        "subfinder": SecurityImage.SUBFINDER,
        "metasploit": SecurityImage.METASPLOIT,
        "msfconsole": SecurityImage.METASPLOIT,
        "sqlmap": SecurityImage.SQLMAP,
        "nikto": SecurityImage.NIKTO,
    }

    # Phase configurations
    PHASE_CONFIGS: Dict[str, PhaseConfig] = {
        "recon": PhaseConfig(
            memory_limit="1g",
            cpu_limit=2.0,
            timeout=600,
            network_mode="bridge",
            capabilities=["NET_RAW"],
        ),
        "enum": PhaseConfig(
            memory_limit="2g",
            cpu_limit=2.0,
            timeout=900,
            network_mode="bridge",
        ),
        "exploit": PhaseConfig(
            memory_limit="4g",
            cpu_limit=4.0,
            timeout=1800,
            network_mode="host",  # May need host network for reverse shells
        ),
        "post": PhaseConfig(
            memory_limit="2g",
            cpu_limit=2.0,
            timeout=600,
            network_mode="none",  # Isolated for safety
        ),
    }

    def __init__(self, default_image: str = SecurityImage.KALI.value):
        self.default_image = default_image
        self.sandboxes: Dict[str, DockerSandbox] = {}
        self._active_containers: List[str] = []

    def get_sandbox(self, phase: str = "recon") -> DockerSandbox:
        """Get or create sandbox for phase"""
        if phase not in self.sandboxes:
            phase_config = self.PHASE_CONFIGS.get(phase, PhaseConfig())

            config = SandboxConfig(
                image=self.default_image,
                memory_limit=phase_config.memory_limit,
                cpu_limit=phase_config.cpu_limit,
                timeout=phase_config.timeout,
                network_mode=phase_config.network_mode,
                capabilities=phase_config.capabilities,
            )

            self.sandboxes[phase] = DockerSandbox(config)

        return self.sandboxes[phase]

    def get_image_for_tool(self, tool_name: str) -> str:
        """Get appropriate Docker image for tool"""
        tool_lower = tool_name.lower()

        # Check direct mapping
        if tool_lower in self.TOOL_IMAGES:
            return self.TOOL_IMAGES[tool_lower].value

        # Check partial match
        for key, image in self.TOOL_IMAGES.items():
            if key in tool_lower:
                return image.value

        # Default to Kali for unknown tools
        return self.default_image

    def execute_tool(
        self,
        tool_name: str,
        command: str,
        phase: str = "recon",
        **kwargs,
    ) -> SandboxResult:
        """
        Execute a security tool in appropriate sandbox.

        Args:
            tool_name: Name of the tool
            command: Full command to execute
            phase: Pentest phase (recon, enum, exploit, post)
            **kwargs: Additional sandbox options

        Returns:
            SandboxResult
        """
        sandbox = self.get_sandbox(phase)
        image = self.get_image_for_tool(tool_name)
        return sandbox.execute(command, image=image, **kwargs)

    def execute_with_callback(
        self,
        tool_name: str,
        command: str,
        callback,
        phase: str = "recon",
    ) -> SandboxResult:
        """Execute tool with streaming output callback"""
        sandbox = self.get_sandbox(phase)
        image = self.get_image_for_tool(tool_name)
        return sandbox.execute_streaming(command, callback, image=image)

    def is_available(self) -> bool:
        """Check if Docker is available"""
        sandbox = self.get_sandbox("recon")
        return sandbox.is_available()

    def pull_security_images(self, images: Optional[List[SecurityImage]] = None) -> Dict[str, bool]:
        """
        Pull security tool images.

        Args:
            images: List of images to pull (pulls all if None)

        Returns:
            Dict mapping image name to success status
        """
        images_to_pull = images or list(SecurityImage)
        results = {}

        sandbox = DockerSandbox()

        for image in images_to_pull:
            image_name = image.value if isinstance(image, SecurityImage) else image
            results[image_name] = sandbox.pull_image(image_name)

        return results

    def list_pulled_images(self) -> List[str]:
        """List pulled security images"""
        sandbox = DockerSandbox()
        pulled = []

        for image in SecurityImage:
            if sandbox.image_exists(image.value):
                pulled.append(image.value)

        return pulled

    def cleanup(self) -> None:
        """Cleanup all sandboxes and containers"""
        for sandbox in self.sandboxes.values():
            sandbox.cleanup_containers()
        self.sandboxes.clear()


# Singleton instance
_container_manager: Optional[ContainerManager] = None


def get_container_manager() -> ContainerManager:
    """Get singleton container manager"""
    global _container_manager
    if _container_manager is None:
        _container_manager = ContainerManager()
    return _container_manager
