"""
VPS Runtime for AIPT v2
=======================

Remote execution runtime via SSH for running security tools on a VPS.
Provides automatic tool installation, command execution, and result retrieval.

Architecture:
    Local AIPTX  <--SSH-->  VPS (Security Tools)
         |                        |
    Orchestrator              Tool Execution
         |                        |
    Result Parser  <--SCP--  JSON Results

Usage:
    runtime = VPSRuntime(host="1.2.3.4", user="ubuntu", key_path="~/.ssh/id_rsa")
    await runtime.connect()
    await runtime.ensure_tools_installed()
    stdout, stderr, code = await runtime.execute(sandbox_id, "nmap -sV target.com")
    results = await runtime.retrieve_results(sandbox_id)
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Tuple, List, Any

try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False

from aipt_v2.utils.logging import logger
from aipt_v2.config import get_config


# =============================================================================
# Tool Definitions - Security tools to install on VPS
# =============================================================================

# Tool-specific timeouts for version/availability checks (in seconds)
# Some tools like Metasploit take longer to initialize
TOOL_CHECK_TIMEOUTS: dict[str, int] = {
    "default": 10,
    # Metasploit loads Ruby VM and database on startup
    "metasploit": 60,
    "msfconsole": 60,
    # Network scanners may need time for initialization
    "nikto": 30,
    "nuclei": 30,
    # Amass loads data on first run
    "amass": 30,
    # WPScan updates on first run
    "wpscan": 45,
    # John loads wordlists
    "john": 20,
    # Hashcat loads OpenCL
    "hashcat": 30,
}


def get_tool_check_timeout(tool_name: str) -> int:
    """Get the appropriate timeout for checking if a tool is installed."""
    return TOOL_CHECK_TIMEOUTS.get(tool_name, TOOL_CHECK_TIMEOUTS["default"])


VPS_TOOLS = {
    # Phase 1: RECON
    "recon": {
        "subfinder": {"install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "check": "subfinder -version"},
        "assetfinder": {"install": "go install -v github.com/tomnomnom/assetfinder@latest", "check": "assetfinder -h 2>&1 | head -1"},
        "amass": {"install": "go install -v github.com/owasp-amass/amass/v4/...@master", "check": "amass -version"},
        "httpx": {"install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "check": "httpx -version"},
        "nmap": {"install": "apt-get install -y nmap", "check": "nmap --version | head -1"},
        "waybackurls": {"install": "go install -v github.com/tomnomnom/waybackurls@latest", "check": "waybackurls -h 2>&1 | head -1"},
        "theHarvester": {"install": "pip3 install theHarvester", "check": "theHarvester -h 2>&1 | head -1"},
        "dnsrecon": {"install": "pip3 install dnsrecon", "check": "dnsrecon -h 2>&1 | head -1"},
        "wafw00f": {"install": "pip3 install wafw00f", "check": "wafw00f -h 2>&1 | head -1"},
        "whatweb": {"install": "apt-get install -y whatweb", "check": "whatweb --version"},
        "dnsx": {"install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "check": "dnsx -version"},
        "katana": {"install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest", "check": "katana -version"},
    },
    # Phase 2: SCAN
    "scan": {
        "nuclei": {"install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates", "check": "nuclei -version"},
        "nikto": {"install": "apt-get install -y nikto", "check": "nikto -Version"},
        "wpscan": {"install": "gem install wpscan", "check": "wpscan --version"},
        "ffuf": {"install": "go install -v github.com/ffuf/ffuf/v2@latest", "check": "ffuf -V"},
        "gobuster": {"install": "go install -v github.com/OJ/gobuster/v3@latest", "check": "gobuster version"},
        "dirsearch": {"install": "pip3 install dirsearch", "check": "dirsearch -h 2>&1 | head -1"},
        "sslscan": {"install": "apt-get install -y sslscan", "check": "sslscan --version"},
        "testssl": {"install": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl", "check": "test -f /opt/testssl/testssl.sh && echo 'installed'"},
        "gitleaks": {"install": "go install github.com/gitleaks/gitleaks/v8@latest", "check": "gitleaks version"},
        "trufflehog": {"install": "pip3 install trufflehog", "check": "trufflehog --version 2>&1 | head -1"},
        "trivy": {"install": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin", "check": "trivy --version"},
        "feroxbuster": {"install": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin", "check": "feroxbuster --version"},
    },
    # Phase 3: EXPLOIT
    "exploit": {
        "sqlmap": {"install": "apt-get install -y sqlmap", "check": "sqlmap --version"},
        "commix": {"install": "pip3 install commix", "check": "commix --version 2>&1 | head -1"},
        "xsstrike": {"install": "pip3 install xsstrike", "check": "xsstrike -h 2>&1 | head -1"},
        "hydra": {"install": "apt-get install -y hydra", "check": "hydra -h 2>&1 | head -1"},
        "searchsploit": {"install": "git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/", "check": "searchsploit -h 2>&1 | head -1"},
        "metasploit": {"install": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall", "check": "msfconsole -v"},
        "john": {"install": "apt-get install -y john", "check": "john --version"},
        "hashcat": {"install": "apt-get install -y hashcat", "check": "hashcat --version"},
    },
    # Phase 4: POST-EXPLOIT
    "post_exploit": {
        "linpeas": {"install": "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh && chmod +x /opt/linpeas.sh", "check": "test -f /opt/linpeas.sh && echo 'installed'"},
        "pspy": {"install": "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy64 && chmod +x /opt/pspy64", "check": "test -f /opt/pspy64 && echo 'installed'"},
    },
    # API Security
    "api": {
        "arjun": {"install": "pip3 install arjun", "check": "arjun -h 2>&1 | head -1"},
        "kiterunner": {"install": "go install github.com/assetnote/kiterunner/cmd/kr@latest", "check": "kr -h 2>&1 | head -1"},
        "jwt_tool": {"install": "pip3 install jwt_tool", "check": "jwt_tool -h 2>&1 | head -1"},
    },
    # Network
    "network": {
        "masscan": {"install": "apt-get install -y masscan", "check": "masscan --version"},
        "rustscan": {"install": "cargo install rustscan || (wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.1.1_amd64.deb && dpkg -i rustscan_2.1.1_amd64.deb)", "check": "rustscan --version"},
        "naabu": {"install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "check": "naabu -version"},
    },
}


@dataclass
class VPSSandboxInfo:
    """Information about a VPS execution context."""
    sandbox_id: str
    created_at: datetime = field(default_factory=datetime.now)
    working_dir: str = "/tmp/aiptx"
    results_dir: str = "/tmp/aiptx/results"
    host: str = ""
    is_local: bool = False
    url: str = ""


class VPSRuntime:
    """
    VPS Runtime for remote command execution via SSH.

    Features:
    - Automatic tool installation
    - Parallel command execution
    - Result retrieval via SCP
    - Connection pooling for performance
    - Automatic reconnection on failure
    """

    def __init__(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        results_dir: str = "/var/tmp/aiptx_results",
    ):
        """
        Initialize VPS runtime.

        Args:
            host: VPS hostname or IP
            user: SSH username
            key_path: Path to SSH private key
            port: SSH port
            results_dir: Remote directory for results
        """
        if not ASYNCSSH_AVAILABLE:
            raise ImportError(
                "asyncssh is required for VPS runtime. "
                "Install with: pip install aiptx[full] or pip install asyncssh"
            )

        # Load from config if not provided
        config = get_config()
        self.host = host or config.vps.host
        self.user = user or config.vps.user
        self.key_path = key_path or config.vps.key_path
        self.port = port or config.vps.port
        self.results_dir = results_dir or config.vps.results_dir

        # Expand key path
        if self.key_path:
            self.key_path = str(Path(self.key_path).expanduser().resolve())

        # Connection state
        self._conn: Optional[asyncssh.SSHClientConnection] = None
        self._sandboxes: Dict[str, VPSSandboxInfo] = {}
        self._connected = False
        self._tools_installed = False

    async def connect(self) -> bool:
        """
        Establish SSH connection to VPS.

        Returns:
            True if connection successful
        """
        if not self.host:
            raise ValueError("VPS host not configured. Run 'aiptx setup' or set VPS_HOST.")

        if not self.key_path or not Path(self.key_path).exists():
            raise ValueError(f"SSH key not found: {self.key_path}")

        try:
            logger.info("Connecting to VPS", host=self.host, user=self.user, port=self.port)

            self._conn = await asyncssh.connect(
                self.host,
                port=self.port,
                username=self.user,
                client_keys=[self.key_path],
                known_hosts=None,  # Skip host key verification (for flexibility)
            )

            self._connected = True
            logger.info("Connected to VPS successfully", host=self.host)

            # Create results directory
            await self._run_command(f"mkdir -p {self.results_dir}")

            return True

        except Exception as e:
            logger.error("Failed to connect to VPS", host=self.host, error=str(e))
            raise ConnectionError(f"Failed to connect to VPS {self.host}: {e}")

    async def disconnect(self) -> None:
        """Close SSH connection."""
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None
            self._connected = False
            logger.info("Disconnected from VPS", host=self.host)

    async def _run_command(
        self,
        command: str,
        timeout: int = 300,
        check: bool = False,
    ) -> Tuple[str, str, int]:
        """
        Run command on VPS.

        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds
            check: Raise exception on non-zero exit

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not self._connected or not self._conn:
            await self.connect()

        try:
            result = await asyncio.wait_for(
                self._conn.run(command, check=check),
                timeout=timeout
            )

            return (
                result.stdout or "",
                result.stderr or "",
                result.exit_status or 0
            )

        except asyncio.TimeoutError:
            logger.warning("Command timed out on VPS", command=command[:50], timeout=timeout)
            return "", f"Command timed out after {timeout}s", 124
        except Exception as e:
            logger.error("Command failed on VPS", command=command[:50], error=str(e))
            return "", str(e), 1

    async def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed on VPS."""
        stdout, stderr, code = await self._run_command(f"which {tool_name} 2>/dev/null || command -v {tool_name} 2>/dev/null")
        return code == 0 and len(stdout.strip()) > 0

    async def get_installed_tools(self) -> Dict[str, bool]:
        """Get status of all security tools on VPS."""
        results = {}

        for category, tools in VPS_TOOLS.items():
            for tool_name, tool_info in tools.items():
                check_cmd = tool_info.get("check", f"which {tool_name}")
                # Use tool-specific timeout to handle slow-starting tools
                timeout = get_tool_check_timeout(tool_name)
                stdout, stderr, code = await self._run_command(check_cmd, timeout=timeout)
                results[tool_name] = code == 0

        return results

    async def install_tool(self, tool_name: str, category: str = None) -> bool:
        """
        Install a specific tool on VPS.

        Args:
            tool_name: Name of tool to install
            category: Tool category (recon, scan, exploit, etc.)

        Returns:
            True if installation successful
        """
        # Find tool definition
        tool_info = None
        for cat, tools in VPS_TOOLS.items():
            if tool_name in tools:
                tool_info = tools[tool_name]
                break

        if not tool_info:
            logger.warning(f"Unknown tool: {tool_name}")
            return False

        install_cmd = tool_info["install"]
        check_cmd = tool_info.get("check", f"which {tool_name}")
        # Use tool-specific timeout for checks
        check_timeout = get_tool_check_timeout(tool_name)

        # Check if already installed
        stdout, stderr, code = await self._run_command(check_cmd, timeout=check_timeout)
        if code == 0:
            logger.info(f"Tool already installed: {tool_name}")
            return True

        # Install
        logger.info(f"Installing tool: {tool_name}")
        stdout, stderr, code = await self._run_command(
            f"sudo {install_cmd}",
            timeout=600  # 10 minute timeout for installation
        )

        if code != 0:
            logger.error(f"Failed to install {tool_name}", stderr=stderr[:200])
            return False

        # Verify installation with tool-specific timeout
        stdout, stderr, code = await self._run_command(check_cmd, timeout=check_timeout)
        success = code == 0

        if success:
            logger.info(f"Successfully installed: {tool_name}")
        else:
            logger.error(f"Tool installed but verification failed: {tool_name}")

        return success

    async def ensure_tools_installed(
        self,
        categories: Optional[List[str]] = None,
        tools: Optional[List[str]] = None,
        parallel: int = 4,
    ) -> Dict[str, bool]:
        """
        Ensure required security tools are installed on VPS.

        Args:
            categories: List of categories to install (recon, scan, exploit, etc.)
            tools: Specific tools to install (overrides categories)
            parallel: Number of parallel installations

        Returns:
            Dict mapping tool names to installation status
        """
        # First, set up base dependencies
        logger.info("Setting up VPS base dependencies...")

        setup_script = """
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq git curl wget python3-pip golang-go ruby-full build-essential libssl-dev libffi-dev

        # Set up Go path
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> ~/.bashrc
        mkdir -p $GOPATH/bin
        """

        await self._run_command(f"sudo bash -c '{setup_script}'", timeout=300)

        # Determine which tools to install
        tools_to_install = []

        if tools:
            tools_to_install = tools
        elif categories:
            for cat in categories:
                if cat in VPS_TOOLS:
                    tools_to_install.extend(VPS_TOOLS[cat].keys())
        else:
            # Install all tools
            for cat_tools in VPS_TOOLS.values():
                tools_to_install.extend(cat_tools.keys())

        # Install tools in parallel batches
        results = {}

        for i in range(0, len(tools_to_install), parallel):
            batch = tools_to_install[i:i + parallel]
            tasks = [self.install_tool(tool) for tool in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for tool, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results[tool] = False
                    logger.error(f"Failed to install {tool}: {result}")
                else:
                    results[tool] = result

        self._tools_installed = True

        # Summary
        installed = sum(1 for v in results.values() if v)
        failed = sum(1 for v in results.values() if not v)
        logger.info(f"Tool installation complete: {installed} installed, {failed} failed")

        return results

    async def create_sandbox(
        self,
        working_dir: Optional[str] = None,
        **kwargs
    ) -> VPSSandboxInfo:
        """
        Create a VPS execution context (sandbox).

        Args:
            working_dir: Working directory on VPS

        Returns:
            VPSSandboxInfo with sandbox details
        """
        if not self._connected:
            await self.connect()

        sandbox_id = f"vps-{uuid.uuid4().hex[:8]}"
        work_dir = working_dir or f"/tmp/aiptx/{sandbox_id}"
        results_dir = f"{work_dir}/results"

        # Create directories on VPS
        await self._run_command(f"mkdir -p {work_dir} {results_dir}")

        info = VPSSandboxInfo(
            sandbox_id=sandbox_id,
            working_dir=work_dir,
            results_dir=results_dir,
            host=self.host,
            url=f"ssh://{self.user}@{self.host}:{self.port}",
        )

        self._sandboxes[sandbox_id] = info
        logger.info("Created VPS sandbox", sandbox_id=sandbox_id, host=self.host)

        return info

    async def execute(
        self,
        sandbox_id: str,
        command: str,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
        save_output: bool = True,
    ) -> Tuple[str, str, int]:
        """
        Execute command in VPS sandbox.

        Args:
            sandbox_id: Sandbox identifier
            command: Shell command to execute
            timeout: Command timeout in seconds
            env: Additional environment variables
            save_output: Save output to results directory

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if sandbox_id not in self._sandboxes:
            raise ValueError(f"Unknown sandbox: {sandbox_id}")

        sandbox = self._sandboxes[sandbox_id]

        # Build command with environment
        env_prefix = ""
        if env:
            env_prefix = " ".join(f"{k}={v}" for k, v in env.items()) + " "

        # Add Go path to environment
        full_command = f"""
        export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
        cd {sandbox.working_dir}
        {env_prefix}{command}
        """

        logger.debug(
            "Executing on VPS",
            sandbox_id=sandbox_id,
            command=command[:100] + "..." if len(command) > 100 else command,
        )

        stdout, stderr, code = await self._run_command(full_command, timeout=timeout)

        # Save output to results directory
        if save_output:
            output_id = uuid.uuid4().hex[:8]
            output_file = f"{sandbox.results_dir}/output_{output_id}.json"
            output_data = {
                "command": command,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": code,
                "timestamp": datetime.now().isoformat(),
            }
            await self._run_command(
                f"echo '{json.dumps(output_data)}' > {output_file}",
                timeout=10
            )

        return stdout, stderr, code

    async def retrieve_results(
        self,
        sandbox_id: str,
        local_dir: Optional[str] = None,
    ) -> Path:
        """
        Retrieve results from VPS to local machine.

        Args:
            sandbox_id: Sandbox identifier
            local_dir: Local directory to save results

        Returns:
            Path to local results directory
        """
        if sandbox_id not in self._sandboxes:
            raise ValueError(f"Unknown sandbox: {sandbox_id}")

        sandbox = self._sandboxes[sandbox_id]

        # Default local directory
        if local_dir is None:
            local_dir = Path(f"./results/{sandbox_id}")
        else:
            local_dir = Path(local_dir)

        local_dir.mkdir(parents=True, exist_ok=True)

        # Use SCP to retrieve results
        logger.info("Retrieving results from VPS", sandbox_id=sandbox_id, local_dir=str(local_dir))

        async with self._conn.start_sftp_client() as sftp:
            # List remote files
            try:
                files = await sftp.listdir(sandbox.results_dir)

                for filename in files:
                    remote_path = f"{sandbox.results_dir}/{filename}"
                    local_path = local_dir / filename

                    await sftp.get(remote_path, str(local_path))
                    logger.debug(f"Retrieved: {filename}")

                logger.info(f"Retrieved {len(files)} files from VPS")

            except Exception as e:
                logger.error(f"Failed to retrieve results: {e}")

        return local_dir

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """
        Destroy VPS sandbox and cleanup.

        Args:
            sandbox_id: Sandbox identifier
        """
        if sandbox_id not in self._sandboxes:
            return

        sandbox = self._sandboxes[sandbox_id]

        # Cleanup remote directory
        await self._run_command(f"rm -rf {sandbox.working_dir}", timeout=30)

        del self._sandboxes[sandbox_id]
        logger.info("Destroyed VPS sandbox", sandbox_id=sandbox_id)

    async def run_scan(
        self,
        target: str,
        scan_type: str = "full",
        tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run a complete scan on target using VPS.

        Args:
            target: Target URL or IP
            scan_type: Type of scan (quick, standard, full)
            tools: Specific tools to use

        Returns:
            Dict with scan results
        """
        sandbox = await self.create_sandbox()
        results = {
            "target": target,
            "scan_type": scan_type,
            "sandbox_id": sandbox.sandbox_id,
            "started_at": datetime.now().isoformat(),
            "findings": [],
            "tool_outputs": {},
        }

        try:
            # Determine tools to run based on scan type
            if tools:
                tools_to_run = tools
            elif scan_type == "quick":
                tools_to_run = ["nmap", "httpx", "nuclei"]
            elif scan_type == "standard":
                tools_to_run = ["nmap", "httpx", "nuclei", "ffuf", "nikto", "sslscan"]
            else:  # full
                tools_to_run = [
                    "subfinder", "httpx", "nmap", "nuclei", "nikto",
                    "ffuf", "sslscan", "whatweb", "wafw00f"
                ]

            # Run each tool
            for tool in tools_to_run:
                logger.info(f"Running {tool} on {target}")

                cmd = self._get_tool_command(tool, target, sandbox.results_dir)
                if cmd:
                    stdout, stderr, code = await self.execute(
                        sandbox.sandbox_id,
                        cmd,
                        timeout=600
                    )

                    results["tool_outputs"][tool] = {
                        "stdout": stdout,
                        "stderr": stderr,
                        "exit_code": code,
                    }

            # Retrieve results
            local_results = await self.retrieve_results(sandbox.sandbox_id)
            results["local_results_path"] = str(local_results)
            results["completed_at"] = datetime.now().isoformat()

        finally:
            await self.destroy_sandbox(sandbox.sandbox_id)

        return results

    def _get_tool_command(self, tool: str, target: str, output_dir: str) -> Optional[str]:
        """Get command for running a specific tool."""
        commands = {
            "nmap": f"nmap -sV -sC -oA {output_dir}/nmap_{target.replace('.', '_')} {target}",
            "subfinder": f"subfinder -d {target} -o {output_dir}/subfinder.txt",
            "httpx": f"echo {target} | httpx -json -o {output_dir}/httpx.json",
            "nuclei": f"nuclei -u {target} -json -o {output_dir}/nuclei.json",
            "nikto": f"nikto -h {target} -o {output_dir}/nikto.txt",
            "ffuf": f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {output_dir}/ffuf.json -of json",
            "sslscan": f"sslscan {target} > {output_dir}/sslscan.txt",
            "whatweb": f"whatweb {target} --log-json={output_dir}/whatweb.json",
            "wafw00f": f"wafw00f {target} -o {output_dir}/wafw00f.txt",
            "gobuster": f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_dir}/gobuster.txt",
            "dirsearch": f"dirsearch -u {target} --json-report={output_dir}/dirsearch.json",
        }

        return commands.get(tool)

    async def cleanup_all(self) -> int:
        """Cleanup all sandboxes and disconnect."""
        count = len(self._sandboxes)

        for sandbox_id in list(self._sandboxes.keys()):
            await self.destroy_sandbox(sandbox_id)

        await self.disconnect()

        return count


# =============================================================================
# VPS Setup Script Generator
# =============================================================================

def generate_vps_setup_script(
    categories: Optional[List[str]] = None,
    include_wordlists: bool = True,
) -> str:
    """
    Generate a bash script for setting up a VPS with security tools.

    Args:
        categories: Tool categories to include (default: all)
        include_wordlists: Include common wordlists

    Returns:
        Bash script as string
    """
    script = '''#!/bin/bash
# =============================================================================
# AIPTX VPS Setup Script
# =============================================================================
# This script installs security tools for penetration testing.
# Run as root or with sudo.
#
# Usage: curl -sL https://raw.githubusercontent.com/aiptx/aipt_v2/main/scripts/setup-vps.sh | sudo bash
# =============================================================================

set -e
export DEBIAN_FRONTEND=noninteractive

echo "[*] AIPTX VPS Setup Starting..."
echo "[*] This may take 10-30 minutes depending on your VPS."

# =============================================================================
# Base Dependencies
# =============================================================================
echo "[+] Installing base dependencies..."
apt-get update -qq
apt-get install -y -qq \\
    git curl wget unzip \\
    python3 python3-pip python3-venv \\
    golang-go ruby-full gem \\
    build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev \\
    nmap nikto sqlmap hydra john hashcat masscan \\
    jq tmux screen htop

# =============================================================================
# Go Setup
# =============================================================================
echo "[+] Setting up Go environment..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
mkdir -p $GOPATH/bin

cat >> ~/.bashrc << 'EOF'
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
EOF

# =============================================================================
# Security Tools
# =============================================================================
'''

    cats = categories or list(VPS_TOOLS.keys())

    for category in cats:
        if category not in VPS_TOOLS:
            continue

        script += f'\necho "[+] Installing {category.upper()} tools..."\n'

        for tool_name, tool_info in VPS_TOOLS[category].items():
            install_cmd = tool_info["install"]
            # Escape single quotes for bash
            install_cmd = install_cmd.replace("'", "'\\''")
            script += f"echo '    - Installing {tool_name}...'\n"
            script += f"{install_cmd} || echo '    [!] Failed to install {tool_name}'\n"

    if include_wordlists:
        script += '''
# =============================================================================
# Wordlists
# =============================================================================
echo "[+] Setting up wordlists..."
mkdir -p /usr/share/wordlists

# SecLists
if [ ! -d "/usr/share/wordlists/SecLists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
fi

# Common wordlists links
ln -sf /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt /usr/share/wordlists/common.txt
ln -sf /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt /usr/share/wordlists/medium.txt
ln -sf /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt /usr/share/wordlists/passwords.txt
'''

    script += '''
# =============================================================================
# AIPTX Results Directory
# =============================================================================
echo "[+] Creating AIPTX directories..."
mkdir -p /var/tmp/aiptx_results
chmod 700 /var/tmp/aiptx_results

# =============================================================================
# Complete
# =============================================================================
echo ""
echo "=============================================="
echo "[*] AIPTX VPS Setup Complete!"
echo "=============================================="
echo ""
echo "Installed tools can be verified with:"
echo "  which nmap nuclei subfinder httpx ffuf"
echo ""
echo "Ready for AIPTX connection."
echo "=============================================="
'''

    return script


# =============================================================================
# Convenience Functions
# =============================================================================

_default_vps_runtime: Optional[VPSRuntime] = None


async def get_vps_runtime() -> VPSRuntime:
    """Get or create the default VPS runtime instance."""
    global _default_vps_runtime
    if _default_vps_runtime is None:
        _default_vps_runtime = VPSRuntime()
        await _default_vps_runtime.connect()
    return _default_vps_runtime


async def run_on_vps(command: str, timeout: int = 300) -> Tuple[str, str, int]:
    """
    Convenience function to run a command on VPS.

    Args:
        command: Shell command to execute
        timeout: Command timeout

    Returns:
        Tuple of (stdout, stderr, exit_code)
    """
    runtime = await get_vps_runtime()
    sandbox = await runtime.create_sandbox()

    try:
        return await runtime.execute(sandbox.sandbox_id, command, timeout)
    finally:
        await runtime.destroy_sandbox(sandbox.sandbox_id)
