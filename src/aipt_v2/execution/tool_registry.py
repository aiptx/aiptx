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

    # Active Directory capabilities (v5.0)
    AD_RECON = "ad_recon"  # Domain discovery, user enumeration
    AD_LDAP_ENUM = "ad_ldap_enum"  # LDAP-based enumeration
    AD_KERBEROS = "ad_kerberos"  # Kerberos attacks (Kerberoast, AS-REP)
    AD_USER_ENUM = "ad_user_enum"  # User enumeration
    AD_ACL_ABUSE = "ad_acl_abuse"  # ACL-based privilege escalation
    AD_DELEGATION = "ad_delegation"  # Delegation abuse (RBCD, constrained)
    AD_CREDENTIAL = "ad_credential"  # Credential extraction (DCSync, LSASS)
    AD_ADCS = "ad_adcs"  # Certificate Services attacks
    AD_RELAY = "ad_relay"  # NTLM relay attacks
    AD_COERCE = "ad_coerce"  # Authentication coercion (PetitPotam, PrinterBug)
    AD_EXEC = "ad_exec"  # Remote execution (psexec, wmi, dcom)
    AD_BLOODHOUND = "ad_bloodhound"  # Attack path mapping


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

    "sublist3r": ToolConfig(
        name="sublist3r",
        binary="sublist3r",
        description="Subdomain enumeration using search engines",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.SUBDOMAIN_ENUM},
        default_timeout=300,
        max_parallel=1,
        output_file_flag="-o",
        install_cmd="pip3 install sublist3r",
        docs_url="https://github.com/aboul3la/Sublist3r",
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

    # ========== ACTIVE DIRECTORY TOOLS (v5.0) ==========

    # --- AD Recon Tools ---
    "bloodhound-python": ToolConfig(
        name="bloodhound-python",
        binary="bloodhound-python",
        description="BloodHound data collector for AD attack path mapping",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.AD_BLOODHOUND, ToolCapability.AD_RECON, ToolCapability.AD_LDAP_ENUM},
        default_timeout=600,
        max_parallel=1,
        safe_for_local=False,
        default_args=["-c", "All"],
        install_cmd="pip install bloodhound",
        docs_url="https://github.com/fox-it/BloodHound.py",
    ),

    "kerbrute": ToolConfig(
        name="kerbrute",
        binary="kerbrute",
        description="Kerberos user enumeration and password spraying",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.AD_USER_ENUM, ToolCapability.AD_KERBEROS, ToolCapability.CRED_SPRAY},
        default_timeout=300,
        max_parallel=2,
        safe_for_local=False,
        default_args=["userenum", "--safe"],
        install_cmd="go install github.com/ropnop/kerbrute@latest",
        docs_url="https://github.com/ropnop/kerbrute",
    ),

    "ldapsearch": ToolConfig(
        name="ldapsearch",
        binary="ldapsearch",
        description="LDAP client for AD enumeration",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.AD_LDAP_ENUM, ToolCapability.AD_RECON},
        default_timeout=120,
        max_parallel=3,
        default_args=["-x", "-H"],
    ),

    "windapsearch": ToolConfig(
        name="windapsearch",
        binary="windapsearch",
        description="LDAP enumeration tool for AD",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.AD_LDAP_ENUM, ToolCapability.AD_USER_ENUM},
        default_timeout=300,
        max_parallel=2,
        default_args=["--full"],
        install_cmd="go install github.com/ropnop/go-windapsearch@latest",
        docs_url="https://github.com/ropnop/go-windapsearch",
    ),

    "enum4linux-ng": ToolConfig(
        name="enum4linux-ng",
        binary="enum4linux-ng",
        description="SMB and LDAP enumeration tool",
        phase=ToolPhase.RECON,
        capabilities={ToolCapability.AD_RECON, ToolCapability.AD_USER_ENUM},
        default_timeout=300,
        max_parallel=1,
        json_output_flag="-oJ",
        default_args=["-A"],
        install_cmd="pip install enum4linux-ng",
        docs_url="https://github.com/cddmp/enum4linux-ng",
    ),

    # --- AD Scan Tools ---
    "certipy": ToolConfig(
        name="certipy",
        binary="certipy",
        description="AD Certificate Services enumeration and exploitation",
        phase=ToolPhase.SCAN,
        capabilities={ToolCapability.AD_ADCS, ToolCapability.VULN_SCAN},
        default_timeout=300,
        max_parallel=1,
        safe_for_local=False,
        default_args=["find", "-vulnerable"],
        install_cmd="pip install certipy-ad",
        docs_url="https://github.com/ly4k/Certipy",
    ),

    # --- AD Exploitation Tools (Impacket Suite) ---
    "secretsdump.py": ToolConfig(
        name="secretsdump.py",
        binary="secretsdump.py",
        description="DCSync and credential extraction (Impacket)",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_CREDENTIAL, ToolCapability.DATA_EXFIL},
        default_timeout=600,
        max_parallel=1,
        safe_for_local=False,
        default_args=["-just-dc-ntlm"],
        install_cmd="pip install impacket",
        docs_url="https://github.com/fortra/impacket",
    ),

    "GetUserSPNs.py": ToolConfig(
        name="GetUserSPNs.py",
        binary="GetUserSPNs.py",
        description="Kerberoasting - extract TGS tickets (Impacket)",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_KERBEROS, ToolCapability.AD_CREDENTIAL},
        default_timeout=300,
        max_parallel=2,
        safe_for_local=False,
        default_args=["-request"],
        install_cmd="pip install impacket",
    ),

    "GetNPUsers.py": ToolConfig(
        name="GetNPUsers.py",
        binary="GetNPUsers.py",
        description="AS-REP roasting - extract AS-REP hashes (Impacket)",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_KERBEROS, ToolCapability.AD_CREDENTIAL},
        default_timeout=300,
        max_parallel=2,
        safe_for_local=False,
        default_args=["-format", "hashcat"],
        install_cmd="pip install impacket",
    ),

    "getST.py": ToolConfig(
        name="getST.py",
        binary="getST.py",
        description="Request service tickets for delegation attacks (Impacket)",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_DELEGATION, ToolCapability.AD_KERBEROS},
        default_timeout=120,
        max_parallel=2,
        safe_for_local=False,
        install_cmd="pip install impacket",
    ),

    "rbcd.py": ToolConfig(
        name="rbcd.py",
        binary="rbcd.py",
        description="Resource-Based Constrained Delegation attack (Impacket)",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_DELEGATION, ToolCapability.AD_ACL_ABUSE},
        default_timeout=120,
        max_parallel=1,
        safe_for_local=False,
        install_cmd="pip install impacket",
    ),

    "ntlmrelayx.py": ToolConfig(
        name="ntlmrelayx.py",
        binary="ntlmrelayx.py",
        description="NTLM relay attacks (Impacket)",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_RELAY, ToolCapability.AD_CREDENTIAL},
        default_timeout=3600,  # Long-running relay server
        max_parallel=1,
        requires_root=True,
        safe_for_local=False,
        default_args=["--no-smb-server"],
        install_cmd="pip install impacket",
    ),

    "PetitPotam.py": ToolConfig(
        name="PetitPotam.py",
        binary="PetitPotam.py",
        description="Authentication coercion via MS-EFSRPC",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_COERCE, ToolCapability.AD_RELAY},
        default_timeout=60,
        max_parallel=1,
        safe_for_local=False,
        install_cmd="git clone https://github.com/topotam/PetitPotam",
        docs_url="https://github.com/topotam/PetitPotam",
    ),

    "lsassy": ToolConfig(
        name="lsassy",
        binary="lsassy",
        description="Remote LSASS credential extraction",
        phase=ToolPhase.EXPLOIT,
        capabilities={ToolCapability.AD_CREDENTIAL, ToolCapability.LATERAL_MOVE},
        default_timeout=300,
        max_parallel=2,
        safe_for_local=False,
        json_output_flag="--format json",
        default_args=["-m", "comsvcs"],
        install_cmd="pip install lsassy",
        docs_url="https://github.com/Hackndo/lsassy",
    ),

    # --- AD Lateral Movement Tools (Impacket Suite) ---
    "psexec.py": ToolConfig(
        name="psexec.py",
        binary="psexec.py",
        description="Remote command execution via SMB (Impacket)",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.AD_EXEC, ToolCapability.LATERAL_MOVE},
        default_timeout=300,
        max_parallel=3,
        safe_for_local=False,
        install_cmd="pip install impacket",
    ),

    "wmiexec.py": ToolConfig(
        name="wmiexec.py",
        binary="wmiexec.py",
        description="Remote command execution via WMI (Impacket)",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.AD_EXEC, ToolCapability.LATERAL_MOVE},
        default_timeout=300,
        max_parallel=3,
        safe_for_local=False,
        install_cmd="pip install impacket",
    ),

    "smbexec.py": ToolConfig(
        name="smbexec.py",
        binary="smbexec.py",
        description="Remote command execution via SMB service (Impacket)",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.AD_EXEC, ToolCapability.LATERAL_MOVE},
        default_timeout=300,
        max_parallel=3,
        safe_for_local=False,
        install_cmd="pip install impacket",
    ),

    "atexec.py": ToolConfig(
        name="atexec.py",
        binary="atexec.py",
        description="Remote command execution via Task Scheduler (Impacket)",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.AD_EXEC, ToolCapability.LATERAL_MOVE},
        default_timeout=300,
        max_parallel=3,
        safe_for_local=False,
        install_cmd="pip install impacket",
    ),

    "dcomexec.py": ToolConfig(
        name="dcomexec.py",
        binary="dcomexec.py",
        description="Remote command execution via DCOM (Impacket)",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.AD_EXEC, ToolCapability.LATERAL_MOVE},
        default_timeout=300,
        max_parallel=3,
        safe_for_local=False,
        install_cmd="pip install impacket",
    ),

    "evil-winrm": ToolConfig(
        name="evil-winrm",
        binary="evil-winrm",
        description="WinRM shell with PTH and file transfer",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={ToolCapability.AD_EXEC, ToolCapability.LATERAL_MOVE, ToolCapability.DATA_EXFIL},
        default_timeout=3600,  # Interactive shell
        max_parallel=3,
        safe_for_local=False,
        install_cmd="gem install evil-winrm",
        docs_url="https://github.com/Hackplayers/evil-winrm",
    ),

    "netexec": ToolConfig(
        name="netexec",
        binary="netexec",
        description="Network execution tool (CrackMapExec successor)",
        phase=ToolPhase.POST_EXPLOIT,
        capabilities={
            ToolCapability.LATERAL_MOVE,
            ToolCapability.AD_EXEC,
            ToolCapability.AD_CREDENTIAL,
            ToolCapability.CRED_SPRAY
        },
        default_timeout=600,
        max_parallel=1,
        safe_for_local=False,
        default_args=["smb"],
        install_cmd="pip install netexec",
        docs_url="https://github.com/Pennyw0rth/NetExec",
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
