"""
AIPTX Tool Registry
===================

Central registry of local security tools with capabilities,
configurations, and status tracking.

Provides:
- Tool discovery and availability checking
- Capability-based tool selection
- Phase-specific tool grouping
- Configuration templates for each tool
"""

import asyncio
import shutil
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolPhase(str, Enum):
    """Penetration testing phases."""
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"


class ToolCapability(str, Enum):
    """Tool capabilities for smart selection."""
    # Recon capabilities
    SUBDOMAIN_ENUM = "subdomain_enum"
    PORT_SCAN = "port_scan"
    SERVICE_DETECT = "service_detect"
    DNS_ENUM = "dns_enum"
    WEB_CRAWL = "web_crawl"
    TECH_DETECT = "tech_detect"

    # Scan capabilities
    VULN_SCAN = "vuln_scan"
    WEB_FUZZ = "web_fuzz"
    DIR_ENUM = "dir_enum"
    PARAM_FUZZ = "param_fuzz"
    XSS_SCAN = "xss_scan"
    SQLI_SCAN = "sqli_scan"

    # Exploit capabilities
    SQLI_EXPLOIT = "sqli_exploit"
    BRUTE_FORCE = "brute_force"
    CRED_SPRAY = "cred_spray"

    # Post-exploit capabilities
    PRIV_ESC = "priv_esc"
    LATERAL_MOVE = "lateral_move"
    DATA_EXFIL = "data_exfil"


@dataclass
class ToolConfig:
    """Configuration template for a tool."""
    name: str
    binary: str  # Executable name
    description: str
    phase: ToolPhase
    capabilities: Set[ToolCapability]

    # Execution settings
    default_timeout: int = 300
    max_parallel: int = 1  # How many instances can run in parallel
    requires_root: bool = False
    safe_for_local: bool = True  # Can run without sandbox

    # Output handling
    json_output_flag: Optional[str] = None  # e.g., "-json", "--format=json"
    silent_flag: Optional[str] = None  # e.g., "-silent", "--quiet"
    output_file_flag: Optional[str] = None  # e.g., "-o", "--output"

    # Default arguments
    default_args: List[str] = field(default_factory=list)

    # Metadata
    install_cmd: Optional[str] = None
    docs_url: Optional[str] = None

    def __hash__(self):
        return hash(self.name)


# ============================================================================
# Tool Definitions
# ============================================================================

TOOL_REGISTRY: Dict[str, ToolConfig] = {
    # ========== RECON TOOLS ==========
    "httpx": ToolConfig(
        name="httpx",
        binary="httpx",
        description="Fast HTTP probing for live hosts and tech detection",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.TECH_DETECT, ToolCapability.SERVICE_DETECT},
        default_timeout=180,
        max_parallel=3,
        json_output_flag="-json",
        silent_flag="-silent",
        default_args=["-sc", "-title", "-td", "-server"],
        install_cmd="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        docs_url="https://github.com/projectdiscovery/httpx",
    ),

    "dnsx": ToolConfig(
        name="dnsx",
        binary="dnsx",
        description="Fast DNS toolkit for resolution and enumeration",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.DNS_ENUM, ToolCapability.SUBDOMAIN_ENUM},
        default_timeout=120,
        max_parallel=3,
        json_output_flag="-json",
        silent_flag="-silent",
        default_args=["-a", "-aaaa", "-cname", "-mx", "-txt"],
        install_cmd="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    ),

    "katana": ToolConfig(
        name="katana",
        binary="katana",
        description="Fast web crawler for endpoint discovery",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.WEB_CRAWL},
        default_timeout=300,
        max_parallel=2,
        json_output_flag="-jsonl",
        silent_flag="-silent",
        default_args=["-jc", "-d", "3"],
        install_cmd="go install github.com/projectdiscovery/katana/cmd/katana@latest",
    ),

    "subfinder": ToolConfig(
        name="subfinder",
        binary="subfinder",
        description="Subdomain discovery tool",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.SUBDOMAIN_ENUM},
        default_timeout=180,
        max_parallel=2,
        json_output_flag="-json",
        silent_flag="-silent",
        install_cmd="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),

    "amass": ToolConfig(
        name="amass",
        binary="amass",
        description="Attack surface mapping and subdomain discovery",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.SUBDOMAIN_ENUM, ToolCapability.DNS_ENUM},
        default_timeout=900,
        max_parallel=1,
        json_output_flag="-json",
        silent_flag="-silent",
        install_cmd="go install github.com/owasp-amass/amass/v4/...@latest",
        docs_url="https://github.com/owasp-amass/amass",
    ),

    "nmap": ToolConfig(
        name="nmap",
        binary="nmap",
        description="Network mapper for port scanning and service detection",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.PORT_SCAN, ToolCapability.SERVICE_DETECT},
        default_timeout=600,
        max_parallel=1,
        requires_root=True,  # For SYN scans
        output_file_flag="-oX",
        default_args=["-sV", "-sC", "--open"],
        docs_url="https://nmap.org/",
    ),

    "masscan": ToolConfig(
        name="masscan",
        binary="masscan",
        description="Fast port scanner",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.PORT_SCAN},
        default_timeout=300,
        max_parallel=1,
        requires_root=True,
        output_file_flag="-oJ",
        default_args=["--rate", "1000"],
    ),

    # ========== SCAN TOOLS ==========
    "nuclei": ToolConfig(
        name="nuclei",
        binary="nuclei",
        description="Template-based vulnerability scanner",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.VULN_SCAN},
        default_timeout=600,
        max_parallel=2,
        json_output_flag="-json",
        silent_flag="-silent",
        default_args=["-rl", "150", "-c", "25"],
        install_cmd="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),

    "ffuf": ToolConfig(
        name="ffuf",
        binary="ffuf",
        description="Fast web fuzzer for directories and parameters",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.DIR_ENUM, ToolCapability.WEB_FUZZ, ToolCapability.PARAM_FUZZ},
        default_timeout=300,
        max_parallel=2,
        json_output_flag="-of json",
        silent_flag="-s",
        output_file_flag="-o",
        default_args=["-ac", "-mc", "200,204,301,302,307,401,403,405"],
        install_cmd="go install github.com/ffuf/ffuf/v2@latest",
    ),

    "dalfox": ToolConfig(
        name="dalfox",
        binary="dalfox",
        description="XSS vulnerability scanner",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.XSS_SCAN, ToolCapability.VULN_SCAN},
        default_timeout=300,
        max_parallel=2,
        json_output_flag="--format=json",
        silent_flag="--silence",
        default_args=["--mining-dom", "--grep"],
        install_cmd="go install github.com/hahwul/dalfox/v2@latest",
    ),

    "nikto": ToolConfig(
        name="nikto",
        binary="nikto",
        description="Web server scanner",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.VULN_SCAN},
        default_timeout=600,
        max_parallel=1,
        output_file_flag="-o",
        default_args=["-Format", "json"],
    ),

    "wpscan": ToolConfig(
        name="wpscan",
        binary="wpscan",
        description="WordPress vulnerability scanner",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.VULN_SCAN},
        default_timeout=300,
        max_parallel=1,
        json_output_flag="-f json",
        output_file_flag="-o",
        default_args=["--enumerate", "vp,vt,u"],
    ),

    "trivy": ToolConfig(
        name="trivy",
        binary="trivy",
        description="Container and filesystem vulnerability scanner",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.VULN_SCAN},
        default_timeout=600,
        max_parallel=2,
        json_output_flag="--format json",
        default_args=["--scanners", "vuln,secret,misconfig"],
        install_cmd="brew install trivy || apt install trivy",
        docs_url="https://github.com/aquasecurity/trivy",
    ),

    "gobuster": ToolConfig(
        name="gobuster",
        binary="gobuster",
        description="Directory and DNS brute-forcing tool",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.DIR_ENUM, ToolCapability.SUBDOMAIN_ENUM},
        default_timeout=300,
        max_parallel=2,
        silent_flag="--no-progress",
        default_args=["-t", "10", "--no-color"],
        install_cmd="go install github.com/OJ/gobuster/v3@latest",
    ),

    "testssl": ToolConfig(
        name="testssl",
        binary="testssl.sh",
        description="SSL/TLS security testing",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.VULN_SCAN},
        default_timeout=300,
        max_parallel=2,
        json_output_flag="--jsonfile-pretty -",
        default_args=["--quiet", "--warnings", "batch"],
        docs_url="https://github.com/drwetter/testssl.sh",
    ),

    # ========== EXPLOIT TOOLS ==========
    "sqlmap": ToolConfig(
        name="sqlmap",
        binary="sqlmap",
        description="Automatic SQL injection exploitation",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.SQLI_EXPLOIT, ToolCapability.SQLI_SCAN},
        default_timeout=900,
        max_parallel=1,
        safe_for_local=False,  # Prefer sandbox
        default_args=["--batch", "--answers=Y"],
    ),

    "hydra": ToolConfig(
        name="hydra",
        binary="hydra",
        description="Network login cracker",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.BRUTE_FORCE, ToolCapability.CRED_SPRAY},
        default_timeout=600,
        max_parallel=1,
        safe_for_local=False,
        default_args=["-f", "-V"],
    ),

    # ========== POST-EXPLOIT TOOLS ==========
    "linpeas": ToolConfig(
        name="linpeas",
        binary="linpeas.sh",
        description="Linux privilege escalation checker",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.PRIV_ESC},
        default_timeout=300,
        max_parallel=1,
    ),

    "crackmapexec": ToolConfig(
        name="crackmapexec",
        binary="crackmapexec",
        description="Network penetration testing tool",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.LATERAL_MOVE, ToolCapability.CRED_SPRAY},
        default_timeout=300,
        max_parallel=1,
        safe_for_local=False,
    ),
}


@dataclass
class ToolStatus:
    """Runtime status of a tool."""
    name: str
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


class ToolRegistry:
    """
    Central registry for local security tools.

    Provides:
    - Tool discovery and availability checking
    - Capability-based tool selection
    - Phase-specific tool grouping
    - Real-time status monitoring

    Example:
        registry = ToolRegistry()
        await registry.discover_tools()

        # Get all available recon tools
        recon_tools = registry.get_tools_by_phase(ToolPhase.RECON)

        # Find tool with specific capability
        xss_scanner = registry.get_tools_by_capability(ToolCapability.XSS_SCAN)[0]
    """

    def __init__(self, tools: Optional[Dict[str, ToolConfig]] = None):
        self.tools = tools or TOOL_REGISTRY.copy()
        self._status: Dict[str, ToolStatus] = {}
        self._discovered = False

    async def discover_tools(self, force: bool = False) -> Dict[str, ToolStatus]:
        """
        Discover available tools on the system.

        Args:
            force: Re-discover even if already done

        Returns:
            Dict mapping tool name to status
        """
        if self._discovered and not force:
            return self._status

        logger.info("Discovering available security tools...")

        tasks = []
        for name, config in self.tools.items():
            tasks.append(self._check_tool(name, config))

        results = await asyncio.gather(*tasks)

        for status in results:
            self._status[status.name] = status

        self._discovered = True

        available_count = sum(1 for s in self._status.values() if s.available)
        logger.info(f"Discovered {available_count}/{len(self.tools)} tools available")

        return self._status

    async def _check_tool(self, name: str, config: ToolConfig) -> ToolStatus:
        """Check if a tool is available."""
        path = shutil.which(config.binary)

        if not path:
            return ToolStatus(
                name=name,
                available=False,
                error=f"Binary '{config.binary}' not found in PATH"
            )

        # Try to get version
        version = await self._get_version(config.binary)

        return ToolStatus(
            name=name,
            available=True,
            version=version,
            path=path,
        )

    async def _get_version(self, binary: str) -> Optional[str]:
        """Get tool version string."""
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = (stdout or stderr).decode("utf-8", errors="replace")

            # Extract first line as version
            first_line = output.strip().split("\n")[0]
            return first_line[:100]
        except Exception:
            return None

    def get_tool(self, name: str) -> Optional[ToolConfig]:
        """Get tool configuration by name."""
        return self.tools.get(name)

    def get_status(self, name: str) -> Optional[ToolStatus]:
        """Get tool status by name."""
        return self._status.get(name)

    def is_available(self, name: str) -> bool:
        """Check if a tool is available."""
        status = self._status.get(name)
        return status.available if status else False

    def get_tools_by_phase(self, phase: ToolPhase) -> List[ToolConfig]:
        """Get all tools for a specific phase."""
        return [
            config for config in self.tools.values()
            if config.phase == phase and self.is_available(config.name)
        ]

    def get_tools_by_capability(self, capability: ToolCapability) -> List[ToolConfig]:
        """Get all tools with a specific capability."""
        return [
            config for config in self.tools.values()
            if capability in config.capabilities and self.is_available(config.name)
        ]

    def get_available_tools(self) -> List[ToolConfig]:
        """Get all available tools."""
        return [
            config for config in self.tools.values()
            if self.is_available(config.name)
        ]

    def get_missing_tools(self) -> List[ToolConfig]:
        """Get tools that are not available."""
        return [
            config for config in self.tools.values()
            if not self.is_available(config.name)
        ]

    def get_phase_summary(self) -> Dict[ToolPhase, Dict[str, int]]:
        """Get summary of tools per phase."""
        summary = {}
        for phase in ToolPhase:
            all_tools = [t for t in self.tools.values() if t.phase == phase]
            available = [t for t in all_tools if self.is_available(t.name)]
            summary[phase] = {
                "total": len(all_tools),
                "available": len(available),
            }
        return summary

    def select_tools_for_target(
        self,
        target: str,
        phases: Optional[List[ToolPhase]] = None,
        required_capabilities: Optional[Set[ToolCapability]] = None,
    ) -> List[ToolConfig]:
        """
        Smart tool selection based on target and requirements.

        Args:
            target: Target URL or domain
            phases: Phases to include (default: all)
            required_capabilities: Required tool capabilities

        Returns:
            List of recommended tools in execution order
        """
        phases = phases or list(ToolPhase)
        selected = []

        for phase in phases:
            phase_tools = self.get_tools_by_phase(phase)

            if required_capabilities:
                phase_tools = [
                    t for t in phase_tools
                    if t.capabilities & required_capabilities
                ]

            # Add core tools for each phase
            selected.extend(phase_tools)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for tool in selected:
            if tool.name not in seen:
                seen.add(tool.name)
                unique.append(tool)

        return unique

    def to_dict(self) -> Dict[str, Any]:
        """Export registry state as dictionary."""
        return {
            "tools": {
                name: {
                    "config": {
                        "name": config.name,
                        "binary": config.binary,
                        "description": config.description,
                        "phase": config.phase.value,
                        "capabilities": [c.value for c in config.capabilities],
                    },
                    "status": {
                        "available": self.is_available(name),
                        "version": self._status.get(name, ToolStatus(name, False)).version,
                        "path": self._status.get(name, ToolStatus(name, False)).path,
                    }
                }
                for name, config in self.tools.items()
            },
            "summary": {
                phase.value: stats
                for phase, stats in self.get_phase_summary().items()
            }
        }


# Singleton instance
_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


async def discover_tools() -> Dict[str, ToolStatus]:
    """Discover available tools using the global registry."""
    registry = get_registry()
    return await registry.discover_tools()
