"""
AIPT Image Builder - Custom Docker image building for security tools

Provides utilities to build custom images with:
- Multiple security tools pre-installed
- Custom configurations
- Optimized for pentest workflows
"""
from __future__ import annotations

import subprocess
import tempfile
from typing import Optional, List, Dict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ImageSpec:
    """Specification for a custom Docker image"""
    name: str
    tag: str = "latest"
    base_image: str = "kalilinux/kali-rolling"
    packages: List[str] = field(default_factory=list)
    pip_packages: List[str] = field(default_factory=list)
    go_packages: List[str] = field(default_factory=list)
    custom_commands: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    workdir: str = "/workspace"


class ImageBuilder:
    """
    Build custom Docker images for security testing.

    Example:
        builder = ImageBuilder()
        spec = ImageSpec(
            name="aipt-recon",
            packages=["nmap", "masscan", "subfinder"],
            pip_packages=["httpx", "dnspython"],
        )
        builder.build(spec)
    """

    # Pre-defined tool sets
    TOOL_SETS = {
        "recon": {
            "packages": ["nmap", "masscan", "dnsutils", "whois", "curl", "wget"],
            "pip_packages": ["httpx", "dnspython", "shodan"],
            "go_packages": [
                "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "github.com/tomnomnom/assetfinder@latest",
            ],
        },
        "enum": {
            "packages": ["nikto", "dirb", "gobuster", "ffuf"],
            "pip_packages": ["wappalyzer", "whatweb"],
            "go_packages": [
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "github.com/ffuf/ffuf/v2@latest",
            ],
        },
        "exploit": {
            "packages": ["sqlmap", "hydra", "john", "hashcat"],
            "pip_packages": ["impacket", "pwntools"],
        },
        "post": {
            "packages": ["netcat-openbsd", "socat", "python3-pip"],
            "pip_packages": ["linpeas", "pspy"],
        },
    }

    def __init__(self, registry: Optional[str] = None):
        """
        Initialize image builder.

        Args:
            registry: Optional Docker registry (e.g., "ghcr.io/myorg")
        """
        self.registry = registry

    def generate_dockerfile(self, spec: ImageSpec) -> str:
        """Generate Dockerfile content from spec"""
        lines = [
            f"FROM {spec.base_image}",
            "",
            "# Update and install base packages",
            "RUN apt-get update && apt-get install -y \\",
            "    curl wget git python3 python3-pip golang-go \\",
            "    && rm -rf /var/lib/apt/lists/*",
            "",
        ]

        # Install system packages
        if spec.packages:
            lines.extend([
                "# Install security tools",
                "RUN apt-get update && apt-get install -y \\",
                "    " + " \\\n    ".join(spec.packages) + " \\",
                "    && rm -rf /var/lib/apt/lists/*",
                "",
            ])

        # Install pip packages
        if spec.pip_packages:
            lines.extend([
                "# Install Python packages",
                "RUN pip3 install --no-cache-dir \\",
                "    " + " \\\n    ".join(spec.pip_packages),
                "",
            ])

        # Install Go packages
        if spec.go_packages:
            lines.extend([
                "# Install Go tools",
                "ENV GOPATH=/go",
                "ENV PATH=$PATH:/go/bin",
            ])
            for pkg in spec.go_packages:
                lines.append(f"RUN go install {pkg}")
            lines.append("")

        # Custom commands
        if spec.custom_commands:
            lines.extend([
                "# Custom commands",
            ])
            for cmd in spec.custom_commands:
                lines.append(f"RUN {cmd}")
            lines.append("")

        # Environment variables
        if spec.environment:
            lines.append("# Environment variables")
            for key, value in spec.environment.items():
                lines.append(f"ENV {key}={value}")
            lines.append("")

        # Set workdir
        lines.extend([
            f"WORKDIR {spec.workdir}",
            "",
            "# Default command",
            'CMD ["/bin/bash"]',
        ])

        return "\n".join(lines)

    def build(
        self,
        spec: ImageSpec,
        push: bool = False,
        no_cache: bool = False,
    ) -> bool:
        """
        Build Docker image from spec.

        Args:
            spec: Image specification
            push: Push to registry after build
            no_cache: Build without cache

        Returns:
            True if successful
        """
        dockerfile_content = self.generate_dockerfile(spec)

        # Create temp directory with Dockerfile
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = Path(tmpdir) / "Dockerfile"
            dockerfile_path.write_text(dockerfile_content)

            # Build image
            image_name = f"{spec.name}:{spec.tag}"
            if self.registry:
                image_name = f"{self.registry}/{image_name}"

            cmd = ["docker", "build", "-t", image_name, "."]
            if no_cache:
                cmd.append("--no-cache")

            try:
                result = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 min timeout for builds
                )

                if result.returncode != 0:
                    print(f"Build failed: {result.stderr}")
                    return False

                if push and self.registry:
                    return self.push(image_name)

                return True

            except subprocess.TimeoutExpired:
                print("Build timed out")
                return False
            except Exception as e:
                print(f"Build error: {e}")
                return False

    def push(self, image_name: str) -> bool:
        """Push image to registry"""
        try:
            result = subprocess.run(
                ["docker", "push", image_name],
                capture_output=True,
                text=True,
                timeout=600,
            )
            return result.returncode == 0
        except Exception:
            return False

    def build_preset(
        self,
        preset: str,
        name: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Build image from preset tool set.

        Args:
            preset: One of "recon", "enum", "exploit", "post"
            name: Image name (defaults to "aipt-{preset}")
            **kwargs: Additional ImageSpec parameters

        Returns:
            True if successful
        """
        if preset not in self.TOOL_SETS:
            raise ValueError(f"Unknown preset: {preset}. Choose from: {list(self.TOOL_SETS.keys())}")

        tools = self.TOOL_SETS[preset]

        spec = ImageSpec(
            name=name or f"aipt-{preset}",
            packages=tools.get("packages", []),
            pip_packages=tools.get("pip_packages", []),
            go_packages=tools.get("go_packages", []),
            **kwargs
        )

        return self.build(spec)

    def build_all_presets(self, **kwargs) -> Dict[str, bool]:
        """Build all preset images"""
        results = {}
        for preset in self.TOOL_SETS:
            results[preset] = self.build_preset(preset, **kwargs)
        return results
