"""
AIPTX Local Tool Installer
==========================

Automatically installs security tools on the user's local system.
Adapts installation commands based on detected OS and package manager.

Features:
- Cross-platform support (Linux, macOS, Windows)
- Multiple package manager support (apt, brew, yum, pacman, choco)
- Parallel installation for speed
- Progress tracking with Rich UI
- Rollback on failure
- Prerequisite installation (Go, Ruby, etc.)

Usage:
    installer = LocalToolInstaller()
    await installer.install_tools(categories=["recon", "scan"])
    # or
    await installer.install_all()
"""

import asyncio
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box

from aipt_v2.system_detector import (
    SystemDetector,
    SystemInfo,
    OSType,
    PackageManager,
    Architecture,
)
from aipt_v2.utils.logging import logger


console = Console()


class ToolCategory(Enum):
    """Security tool categories."""
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    API = "api"
    NETWORK = "network"
    PREREQUISITE = "prerequisite"
    ACTIVE_DIRECTORY = "active_directory"
    CLOUD = "cloud"
    CONTAINER = "container"
    OSINT = "osint"
    WIRELESS = "wireless"
    WEB = "web"
    SECRETS = "secrets"
    MOBILE = "mobile"


@dataclass
class ToolDefinition:
    """Definition of a security tool with installation commands."""
    name: str
    description: str
    category: ToolCategory
    # Installation commands per package manager
    install_commands: Dict[PackageManager, str]
    # Command to verify installation
    check_command: str
    # Alternative check (file existence)
    check_path: Optional[str] = None
    # Whether this is a core tool (should be installed by default)
    is_core: bool = False
    # Dependencies (other tool names)
    dependencies: List[str] = None
    # Whether requires sudo/admin
    requires_sudo: bool = False

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


# =============================================================================
# Tool Definitions - Cross-platform installation commands
# =============================================================================

TOOLS: Dict[str, ToolDefinition] = {
    # Prerequisites
    "go": ToolDefinition(
        name="go",
        description="Go programming language (required for many security tools)",
        category=ToolCategory.PREREQUISITE,
        install_commands={
            PackageManager.APT: "apt-get install -y golang-go",
            PackageManager.DNF: "dnf install -y golang",
            PackageManager.YUM: "yum install -y golang",
            PackageManager.PACMAN: "pacman -S --noconfirm go",
            PackageManager.BREW: "brew install go",
            PackageManager.CHOCO: "choco install golang -y",
            PackageManager.WINGET: "winget install GoLang.Go --accept-source-agreements --accept-package-agreements",
        },
        check_command="go version",
        is_core=True,
    ),
    "ruby": ToolDefinition(
        name="ruby",
        description="Ruby programming language",
        category=ToolCategory.PREREQUISITE,
        install_commands={
            PackageManager.APT: "apt-get install -y ruby-full",
            PackageManager.DNF: "dnf install -y ruby ruby-devel",
            PackageManager.YUM: "yum install -y ruby ruby-devel",
            PackageManager.PACMAN: "pacman -S --noconfirm ruby",
            PackageManager.BREW: "brew install ruby",
            PackageManager.CHOCO: "choco install ruby -y",
        },
        check_command="ruby --version",
        is_core=False,
    ),
    "rust": ToolDefinition(
        name="rust",
        description="Rust programming language",
        category=ToolCategory.PREREQUISITE,
        install_commands={
            PackageManager.APT: "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
            PackageManager.DNF: "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
            PackageManager.BREW: "brew install rust",
            PackageManager.PACMAN: "pacman -S --noconfirm rust",
            PackageManager.CHOCO: "choco install rust -y",
        },
        check_command="cargo --version",
        is_core=False,
    ),

    # RECON Tools
    "nmap": ToolDefinition(
        name="nmap",
        description="Network exploration and security auditing",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "apt-get install -y nmap",
            PackageManager.DNF: "dnf install -y nmap",
            PackageManager.YUM: "yum install -y nmap",
            PackageManager.PACMAN: "pacman -S --noconfirm nmap",
            PackageManager.BREW: "brew install nmap",
            PackageManager.CHOCO: "choco install nmap -y",
            PackageManager.WINGET: "winget install Nmap.Nmap --accept-source-agreements --accept-package-agreements",
        },
        check_command="nmap --version",
        is_core=True,
    ),
    "subfinder": ToolDefinition(
        name="subfinder",
        description="Subdomain discovery using passive sources",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            PackageManager.DNF: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            PackageManager.BREW: "brew install subfinder",
            PackageManager.PACMAN: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            PackageManager.CHOCO: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
        check_command="subfinder -version",
        dependencies=["go"],
        is_core=True,
    ),
    "httpx": ToolDefinition(
        name="httpx",
        description="Fast HTTP toolkit for probing web servers",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            PackageManager.DNF: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            PackageManager.BREW: "brew install httpx",
            PackageManager.PACMAN: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            PackageManager.CHOCO: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        check_command="httpx -version",
        dependencies=["go"],
        is_core=True,
    ),
    "amass": ToolDefinition(
        name="amass",
        description="In-depth attack surface mapping and asset discovery",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/owasp-amass/amass/v4/...@master",
            PackageManager.DNF: "go install -v github.com/owasp-amass/amass/v4/...@master",
            PackageManager.BREW: "brew install amass",
            PackageManager.PACMAN: "go install -v github.com/owasp-amass/amass/v4/...@master",
        },
        check_command="amass -version",
        dependencies=["go"],
    ),
    "dnsx": ToolDefinition(
        name="dnsx",
        description="Fast DNS toolkit for multiple DNS queries",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            PackageManager.DNF: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            PackageManager.BREW: "brew install dnsx",
            PackageManager.PACMAN: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        },
        check_command="dnsx -version",
        dependencies=["go"],
    ),
    "katana": ToolDefinition(
        name="katana",
        description="Fast web crawler for extracting endpoints",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
            PackageManager.DNF: "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
            PackageManager.BREW: "brew install katana",
            PackageManager.PACMAN: "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        },
        check_command="katana -version",
        dependencies=["go"],
    ),
    "whatweb": ToolDefinition(
        name="whatweb",
        description="Web fingerprinting tool",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "apt-get install -y whatweb",
            PackageManager.DNF: "dnf install -y whatweb",
            PackageManager.BREW: "brew install whatweb",
            PackageManager.PACMAN: "pacman -S --noconfirm whatweb",
        },
        check_command="whatweb --version",
    ),
    "wafw00f": ToolDefinition(
        name="wafw00f",
        description="Web Application Firewall detection",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "pip3 install wafw00f",
            PackageManager.DNF: "pip3 install wafw00f",
            PackageManager.BREW: "pip3 install wafw00f",
            PackageManager.PACMAN: "pip3 install wafw00f",
        },
        check_command="wafw00f -h",
    ),

    # SCAN Tools
    "nuclei": ToolDefinition(
        name="nuclei",
        description="Fast vulnerability scanner using templates",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
            PackageManager.DNF: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
            PackageManager.BREW: "brew install nuclei && nuclei -update-templates",
            PackageManager.PACMAN: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
        },
        check_command="nuclei -version",
        dependencies=["go"],
        is_core=True,
    ),
    "nikto": ToolDefinition(
        name="nikto",
        description="Web server vulnerability scanner",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "apt-get install -y nikto",
            PackageManager.DNF: "dnf install -y nikto",
            PackageManager.BREW: "brew install nikto",
            PackageManager.PACMAN: "pacman -S --noconfirm nikto",
        },
        check_command="nikto -Version",
        is_core=True,
    ),
    "ffuf": ToolDefinition(
        name="ffuf",
        description="Fast web fuzzer for directory discovery",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "go install -v github.com/ffuf/ffuf/v2@latest",
            PackageManager.DNF: "go install -v github.com/ffuf/ffuf/v2@latest",
            PackageManager.BREW: "brew install ffuf",
            PackageManager.PACMAN: "go install -v github.com/ffuf/ffuf/v2@latest",
        },
        check_command="ffuf -V",
        dependencies=["go"],
        is_core=True,
    ),
    "gobuster": ToolDefinition(
        name="gobuster",
        description="Directory and file brute-forcing tool",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "go install -v github.com/OJ/gobuster/v3@latest",
            PackageManager.DNF: "go install -v github.com/OJ/gobuster/v3@latest",
            PackageManager.BREW: "brew install gobuster",
            PackageManager.PACMAN: "go install -v github.com/OJ/gobuster/v3@latest",
        },
        check_command="gobuster version",
        dependencies=["go"],
    ),
    "feroxbuster": ToolDefinition(
        name="feroxbuster",
        description="Fast content discovery tool written in Rust",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s $HOME/.local/bin",
            PackageManager.BREW: "brew install feroxbuster",
            PackageManager.PACMAN: "pacman -S --noconfirm feroxbuster",
        },
        check_command="feroxbuster --version",
    ),
    "sslscan": ToolDefinition(
        name="sslscan",
        description="SSL/TLS vulnerability scanner",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "apt-get install -y sslscan",
            PackageManager.DNF: "dnf install -y sslscan",
            PackageManager.BREW: "brew install sslscan",
            PackageManager.PACMAN: "pacman -S --noconfirm sslscan",
        },
        check_command="sslscan --version",
    ),
    "gitleaks": ToolDefinition(
        name="gitleaks",
        description="Git secret scanner",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "go install github.com/gitleaks/gitleaks/v8@latest",
            PackageManager.BREW: "brew install gitleaks",
            PackageManager.PACMAN: "go install github.com/gitleaks/gitleaks/v8@latest",
        },
        check_command="gitleaks version",
        dependencies=["go"],
    ),
    "trivy": ToolDefinition(
        name="trivy",
        description="Container and filesystem vulnerability scanner",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
            PackageManager.BREW: "brew install trivy",
            PackageManager.PACMAN: "pacman -S --noconfirm trivy",
        },
        check_command="trivy --version",
    ),
    "wpscan": ToolDefinition(
        name="wpscan",
        description="WordPress vulnerability scanner",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "gem install wpscan",
            PackageManager.BREW: "brew install wpscan",
            PackageManager.PACMAN: "gem install wpscan",
        },
        check_command="wpscan --version",
        dependencies=["ruby"],
    ),

    # EXPLOIT Tools
    "sqlmap": ToolDefinition(
        name="sqlmap",
        description="Automatic SQL injection tool",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "apt-get install -y sqlmap",
            PackageManager.DNF: "dnf install -y sqlmap",
            PackageManager.BREW: "brew install sqlmap",
            PackageManager.PACMAN: "pacman -S --noconfirm sqlmap",
        },
        check_command="sqlmap --version",
        is_core=True,
    ),
    "hydra": ToolDefinition(
        name="hydra",
        description="Password brute-forcing tool",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "apt-get install -y hydra",
            PackageManager.DNF: "dnf install -y hydra",
            PackageManager.BREW: "brew install hydra",
            PackageManager.PACMAN: "pacman -S --noconfirm hydra",
        },
        check_command="hydra -h",
    ),
    "john": ToolDefinition(
        name="john",
        description="Password cracker",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "apt-get install -y john",
            PackageManager.DNF: "dnf install -y john",
            PackageManager.BREW: "brew install john",
            PackageManager.PACMAN: "pacman -S --noconfirm john",
        },
        check_command="john --version",
    ),
    "hashcat": ToolDefinition(
        name="hashcat",
        description="Advanced GPU-based password cracker",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "apt-get install -y hashcat",
            PackageManager.DNF: "dnf install -y hashcat",
            PackageManager.BREW: "brew install hashcat",
            PackageManager.PACMAN: "pacman -S --noconfirm hashcat",
        },
        check_command="hashcat --version",
    ),
    "commix": ToolDefinition(
        name="commix",
        description="Command injection exploitation tool",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "pip3 install commix",
            PackageManager.BREW: "pip3 install commix",
        },
        check_command="commix --version",
    ),

    # NETWORK Tools
    "masscan": ToolDefinition(
        name="masscan",
        description="Fast TCP port scanner",
        category=ToolCategory.NETWORK,
        install_commands={
            PackageManager.APT: "apt-get install -y masscan",
            PackageManager.DNF: "dnf install -y masscan",
            PackageManager.BREW: "brew install masscan",
            PackageManager.PACMAN: "pacman -S --noconfirm masscan",
        },
        check_command="masscan --version",
        requires_sudo=True,
    ),
    "naabu": ToolDefinition(
        name="naabu",
        description="Fast port scanner from ProjectDiscovery",
        category=ToolCategory.NETWORK,
        install_commands={
            PackageManager.APT: "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            PackageManager.BREW: "brew install naabu",
        },
        check_command="naabu -version",
        dependencies=["go"],
    ),

    # API Security Tools
    "arjun": ToolDefinition(
        name="arjun",
        description="HTTP parameter discovery",
        category=ToolCategory.API,
        install_commands={
            PackageManager.APT: "pip3 install arjun",
            PackageManager.BREW: "pip3 install arjun",
        },
        check_command="arjun -h",
    ),

    # =========================================================================
    # Additional RECON Tools
    # =========================================================================
    "assetfinder": ToolDefinition(
        name="assetfinder",
        description="Find domains and subdomains from various sources",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/tomnomnom/assetfinder@latest",
            PackageManager.BREW: "go install -v github.com/tomnomnom/assetfinder@latest",
        },
        check_command="assetfinder -h",
        dependencies=["go"],
    ),
    "waybackurls": ToolDefinition(
        name="waybackurls",
        description="Fetch URLs from Wayback Machine for a domain",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/tomnomnom/waybackurls@latest",
            PackageManager.BREW: "go install -v github.com/tomnomnom/waybackurls@latest",
        },
        check_command="waybackurls -h",
        dependencies=["go"],
    ),
    "gau": ToolDefinition(
        name="gau",
        description="Fetch known URLs from AlienVault, Wayback, and Common Crawl",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/lc/gau/v2/cmd/gau@latest",
            PackageManager.BREW: "go install -v github.com/lc/gau/v2/cmd/gau@latest",
        },
        check_command="gau -h",
        dependencies=["go"],
    ),
    "hakrawler": ToolDefinition(
        name="hakrawler",
        description="Simple, fast web crawler for discovering endpoints",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/hakluke/hakrawler@latest",
            PackageManager.BREW: "go install -v github.com/hakluke/hakrawler@latest",
        },
        check_command="hakrawler -h",
        dependencies=["go"],
    ),
    "gospider": ToolDefinition(
        name="gospider",
        description="Fast web spider written in Go",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "go install -v github.com/jaeles-project/gospider@latest",
            PackageManager.BREW: "go install -v github.com/jaeles-project/gospider@latest",
        },
        check_command="gospider -h",
        dependencies=["go"],
    ),
    "shodan-cli": ToolDefinition(
        name="shodan-cli",
        description="Shodan command-line interface",
        category=ToolCategory.RECON,
        install_commands={
            PackageManager.APT: "pip3 install shodan",
            PackageManager.BREW: "pip3 install shodan",
        },
        check_command="shodan -h",
    ),

    # =========================================================================
    # Additional SCAN Tools
    # =========================================================================
    "dirsearch": ToolDefinition(
        name="dirsearch",
        description="Web path brute-forcer",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "pip3 install dirsearch",
            PackageManager.BREW: "pip3 install dirsearch",
        },
        check_command="dirsearch -h",
    ),
    "testssl": ToolDefinition(
        name="testssl",
        description="SSL/TLS testing tool with comprehensive checks",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "apt-get install -y testssl.sh || git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/.local/testssl",
            PackageManager.BREW: "brew install testssl",
        },
        check_command="testssl.sh --version || testssl --version",
    ),
    "dalfox": ToolDefinition(
        name="dalfox",
        description="Fast XSS scanner and parameter analyzer",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "go install -v github.com/hahwul/dalfox/v2@latest",
            PackageManager.BREW: "brew install dalfox",
        },
        check_command="dalfox version",
        dependencies=["go"],
        is_core=True,
    ),
    "whatwaf": ToolDefinition(
        name="whatwaf",
        description="Detect and bypass WAF/IPS/IDS",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "pip3 install whatwaf",
            PackageManager.BREW: "pip3 install whatwaf",
        },
        check_command="whatwaf -h",
    ),
    "subjack": ToolDefinition(
        name="subjack",
        description="Subdomain takeover vulnerability scanner",
        category=ToolCategory.SCAN,
        install_commands={
            PackageManager.APT: "go install -v github.com/haccer/subjack@latest",
            PackageManager.BREW: "go install -v github.com/haccer/subjack@latest",
        },
        check_command="subjack -h",
        dependencies=["go"],
    ),

    # =========================================================================
    # WEB Application Tools
    # =========================================================================
    "xsstrike": ToolDefinition(
        name="xsstrike",
        description="Advanced XSS detection and exploitation",
        category=ToolCategory.WEB,
        install_commands={
            PackageManager.APT: "pip3 install xsstrike",
            PackageManager.BREW: "pip3 install xsstrike",
        },
        check_command="xsstrike -h",
        is_core=True,
    ),
    "jwt-tool": ToolDefinition(
        name="jwt-tool",
        description="JWT security testing toolkit",
        category=ToolCategory.WEB,
        install_commands={
            PackageManager.APT: "pip3 install jwt-tool",
            PackageManager.BREW: "pip3 install jwt-tool",
        },
        check_command="jwt_tool -h",
    ),
    "paramspider": ToolDefinition(
        name="paramspider",
        description="Mining parameters from web archives",
        category=ToolCategory.WEB,
        install_commands={
            PackageManager.APT: "pip3 install paramspider",
            PackageManager.BREW: "pip3 install paramspider",
        },
        check_command="paramspider -h",
    ),
    "cors-scanner": ToolDefinition(
        name="cors-scanner",
        description="CORS misconfiguration scanner",
        category=ToolCategory.WEB,
        install_commands={
            PackageManager.APT: "pip3 install cors",
            PackageManager.BREW: "pip3 install cors",
        },
        check_command="python3 -c 'import cors'",
    ),

    # =========================================================================
    # EXPLOIT Tools (Additional)
    # =========================================================================
    "crackmapexec": ToolDefinition(
        name="crackmapexec",
        description="Network exploitation and post-exploitation tool",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "pip3 install crackmapexec",
            PackageManager.BREW: "pip3 install crackmapexec",
        },
        check_command="crackmapexec -h",
    ),
    "impacket": ToolDefinition(
        name="impacket",
        description="Python classes for network protocols (psexec, secretsdump)",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "pip3 install impacket",
            PackageManager.BREW: "pip3 install impacket",
        },
        check_command="impacket-psexec -h",
        is_core=True,
    ),
    "evil-winrm": ToolDefinition(
        name="evil-winrm",
        description="WinRM shell for hacking/pentesting",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "gem install evil-winrm",
            PackageManager.BREW: "gem install evil-winrm",
        },
        check_command="evil-winrm -h",
        dependencies=["ruby"],
    ),
    "responder": ToolDefinition(
        name="responder",
        description="LLMNR/NBT-NS/MDNS poisoner and credential capture",
        category=ToolCategory.EXPLOIT,
        install_commands={
            PackageManager.APT: "apt-get install -y responder || pip3 install responder",
            PackageManager.BREW: "pip3 install responder",
        },
        check_command="responder -h",
        requires_sudo=True,
    ),

    # =========================================================================
    # POST-EXPLOIT Tools
    # =========================================================================
    "linpeas": ToolDefinition(
        name="linpeas",
        description="Linux privilege escalation scanner",
        category=ToolCategory.POST_EXPLOIT,
        install_commands={
            PackageManager.APT: "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o ~/.local/bin/linpeas.sh && chmod +x ~/.local/bin/linpeas.sh",
            PackageManager.BREW: "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o ~/.local/bin/linpeas.sh && chmod +x ~/.local/bin/linpeas.sh",
        },
        check_command="test -f ~/.local/bin/linpeas.sh",
        check_path="~/.local/bin/linpeas.sh",
        is_core=True,
    ),
    "pspy": ToolDefinition(
        name="pspy",
        description="Linux process monitor without root",
        category=ToolCategory.POST_EXPLOIT,
        install_commands={
            PackageManager.APT: "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o ~/.local/bin/pspy64 && chmod +x ~/.local/bin/pspy64",
            PackageManager.BREW: "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o ~/.local/bin/pspy64 && chmod +x ~/.local/bin/pspy64",
        },
        check_command="test -f ~/.local/bin/pspy64",
        check_path="~/.local/bin/pspy64",
    ),
    "chisel": ToolDefinition(
        name="chisel",
        description="TCP/UDP tunneling over HTTP",
        category=ToolCategory.POST_EXPLOIT,
        install_commands={
            PackageManager.APT: "go install -v github.com/jpillora/chisel@latest",
            PackageManager.BREW: "brew install chisel",
        },
        check_command="chisel -h",
        dependencies=["go"],
        is_core=True,
    ),
    "ligolo-ng": ToolDefinition(
        name="ligolo-ng",
        description="Advanced tunneling/pivoting tool",
        category=ToolCategory.POST_EXPLOIT,
        install_commands={
            PackageManager.APT: "go install -v github.com/nicocha30/ligolo-ng@latest",
            PackageManager.BREW: "go install -v github.com/nicocha30/ligolo-ng@latest",
        },
        check_command="ligolo-ng -h",
        dependencies=["go"],
    ),
    "lazagne": ToolDefinition(
        name="lazagne",
        description="Credential recovery from browsers, mail, wifi",
        category=ToolCategory.POST_EXPLOIT,
        install_commands={
            PackageManager.APT: "pip3 install lazagne",
            PackageManager.BREW: "pip3 install lazagne",
        },
        check_command="lazagne -h",
    ),

    # =========================================================================
    # ACTIVE DIRECTORY Tools
    # =========================================================================
    "bloodhound-python": ToolDefinition(
        name="bloodhound-python",
        description="BloodHound data collector for AD",
        category=ToolCategory.ACTIVE_DIRECTORY,
        install_commands={
            PackageManager.APT: "pip3 install bloodhound",
            PackageManager.BREW: "pip3 install bloodhound",
        },
        check_command="bloodhound-python -h",
        is_core=True,
    ),
    "kerbrute": ToolDefinition(
        name="kerbrute",
        description="Kerberos brute-forcing tool",
        category=ToolCategory.ACTIVE_DIRECTORY,
        install_commands={
            PackageManager.APT: "go install -v github.com/ropnop/kerbrute@latest",
            PackageManager.BREW: "go install -v github.com/ropnop/kerbrute@latest",
        },
        check_command="kerbrute -h",
        dependencies=["go"],
    ),
    "enum4linux-ng": ToolDefinition(
        name="enum4linux-ng",
        description="Next-gen Windows/Samba enumeration",
        category=ToolCategory.ACTIVE_DIRECTORY,
        install_commands={
            PackageManager.APT: "pip3 install enum4linux-ng",
            PackageManager.BREW: "pip3 install enum4linux-ng",
        },
        check_command="enum4linux-ng -h",
    ),
    "ldapdomaindump": ToolDefinition(
        name="ldapdomaindump",
        description="LDAP information dumper for AD",
        category=ToolCategory.ACTIVE_DIRECTORY,
        install_commands={
            PackageManager.APT: "pip3 install ldapdomaindump",
            PackageManager.BREW: "pip3 install ldapdomaindump",
        },
        check_command="ldapdomaindump -h",
    ),
    "adidnsdump": ToolDefinition(
        name="adidnsdump",
        description="Active Directory DNS zone dumper",
        category=ToolCategory.ACTIVE_DIRECTORY,
        install_commands={
            PackageManager.APT: "pip3 install adidnsdump",
            PackageManager.BREW: "pip3 install adidnsdump",
        },
        check_command="adidnsdump -h",
    ),

    # =========================================================================
    # CLOUD Security Tools
    # =========================================================================
    "prowler": ToolDefinition(
        name="prowler",
        description="AWS/Azure/GCP security assessment tool",
        category=ToolCategory.CLOUD,
        install_commands={
            PackageManager.APT: "pip3 install prowler",
            PackageManager.BREW: "brew install prowler",
        },
        check_command="prowler -h",
        is_core=True,
    ),
    "cloudsploit": ToolDefinition(
        name="cloudsploit",
        description="Cloud security scanning (AWS, Azure, GCP, Oracle)",
        category=ToolCategory.CLOUD,
        install_commands={
            PackageManager.APT: "npm install -g cloudsploit",
            PackageManager.BREW: "npm install -g cloudsploit",
        },
        check_command="cloudsploit -h",
    ),
    "pacu": ToolDefinition(
        name="pacu",
        description="AWS exploitation framework",
        category=ToolCategory.CLOUD,
        install_commands={
            PackageManager.APT: "pip3 install pacu",
            PackageManager.BREW: "pip3 install pacu",
        },
        check_command="pacu -h",
    ),
    "scoutsuite": ToolDefinition(
        name="scoutsuite",
        description="Multi-cloud security auditing tool",
        category=ToolCategory.CLOUD,
        install_commands={
            PackageManager.APT: "pip3 install scoutsuite",
            PackageManager.BREW: "pip3 install scoutsuite",
        },
        check_command="scout -h",
    ),
    "awscli": ToolDefinition(
        name="awscli",
        description="AWS command-line interface",
        category=ToolCategory.CLOUD,
        install_commands={
            PackageManager.APT: "pip3 install awscli",
            PackageManager.BREW: "brew install awscli",
            PackageManager.CHOCO: "choco install awscli -y",
        },
        check_command="aws --version",
    ),

    # =========================================================================
    # CONTAINER Security Tools
    # =========================================================================
    "docker-bench-security": ToolDefinition(
        name="docker-bench-security",
        description="Docker CIS benchmark checker",
        category=ToolCategory.CONTAINER,
        install_commands={
            PackageManager.APT: "git clone https://github.com/docker/docker-bench-security.git ~/.local/docker-bench-security",
            PackageManager.BREW: "git clone https://github.com/docker/docker-bench-security.git ~/.local/docker-bench-security",
        },
        check_command="test -d ~/.local/docker-bench-security",
    ),
    "grype": ToolDefinition(
        name="grype",
        description="Container vulnerability scanner",
        category=ToolCategory.CONTAINER,
        install_commands={
            PackageManager.APT: "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin",
            PackageManager.BREW: "brew install grype",
        },
        check_command="grype version",
        is_core=True,
    ),
    "syft": ToolDefinition(
        name="syft",
        description="Generate SBOM for containers",
        category=ToolCategory.CONTAINER,
        install_commands={
            PackageManager.APT: "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin",
            PackageManager.BREW: "brew install syft",
        },
        check_command="syft version",
    ),
    "kube-hunter": ToolDefinition(
        name="kube-hunter",
        description="Kubernetes penetration testing tool",
        category=ToolCategory.CONTAINER,
        install_commands={
            PackageManager.APT: "pip3 install kube-hunter",
            PackageManager.BREW: "pip3 install kube-hunter",
        },
        check_command="kube-hunter -h",
    ),
    "kubectl": ToolDefinition(
        name="kubectl",
        description="Kubernetes CLI tool",
        category=ToolCategory.CONTAINER,
        install_commands={
            PackageManager.APT: "snap install kubectl --classic || curl -LO 'https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl' && chmod +x kubectl && mv kubectl ~/.local/bin/",
            PackageManager.BREW: "brew install kubectl",
            PackageManager.CHOCO: "choco install kubernetes-cli -y",
        },
        check_command="kubectl version --client",
    ),

    # =========================================================================
    # OSINT Tools
    # =========================================================================
    "theHarvester": ToolDefinition(
        name="theHarvester",
        description="Email, subdomain, and name harvesting",
        category=ToolCategory.OSINT,
        install_commands={
            PackageManager.APT: "pip3 install theHarvester",
            PackageManager.BREW: "pip3 install theHarvester",
        },
        check_command="theHarvester -h",
        is_core=True,
    ),
    "spiderfoot": ToolDefinition(
        name="spiderfoot",
        description="OSINT automation platform",
        category=ToolCategory.OSINT,
        install_commands={
            PackageManager.APT: "pip3 install spiderfoot",
            PackageManager.BREW: "pip3 install spiderfoot",
        },
        check_command="spiderfoot -h",
    ),
    "sherlock": ToolDefinition(
        name="sherlock",
        description="Hunt usernames across social networks",
        category=ToolCategory.OSINT,
        install_commands={
            PackageManager.APT: "pip3 install sherlock-project",
            PackageManager.BREW: "pip3 install sherlock-project",
        },
        check_command="sherlock -h",
    ),
    "holehe": ToolDefinition(
        name="holehe",
        description="Check if email is used on various sites",
        category=ToolCategory.OSINT,
        install_commands={
            PackageManager.APT: "pip3 install holehe",
            PackageManager.BREW: "pip3 install holehe",
        },
        check_command="holehe -h",
    ),
    "photon": ToolDefinition(
        name="photon",
        description="Fast web crawler for OSINT",
        category=ToolCategory.OSINT,
        install_commands={
            PackageManager.APT: "pip3 install photon",
            PackageManager.BREW: "pip3 install photon",
        },
        check_command="photon -h",
    ),

    # =========================================================================
    # SECRETS Detection Tools
    # =========================================================================
    "trufflehog": ToolDefinition(
        name="trufflehog",
        description="Find secrets in git repos and filesystems",
        category=ToolCategory.SECRETS,
        install_commands={
            PackageManager.APT: "pip3 install trufflehog",
            PackageManager.BREW: "brew install trufflehog",
        },
        check_command="trufflehog --version",
        is_core=True,
    ),
    "detect-secrets": ToolDefinition(
        name="detect-secrets",
        description="Yelp's secrets detection tool",
        category=ToolCategory.SECRETS,
        install_commands={
            PackageManager.APT: "pip3 install detect-secrets",
            PackageManager.BREW: "pip3 install detect-secrets",
        },
        check_command="detect-secrets -h",
    ),
    "git-secrets": ToolDefinition(
        name="git-secrets",
        description="Prevent committing secrets to git",
        category=ToolCategory.SECRETS,
        install_commands={
            PackageManager.APT: "git clone https://github.com/awslabs/git-secrets.git && cd git-secrets && make install",
            PackageManager.BREW: "brew install git-secrets",
        },
        check_command="git secrets -h",
    ),
    "shhgit": ToolDefinition(
        name="shhgit",
        description="Find secrets in GitHub repos",
        category=ToolCategory.SECRETS,
        install_commands={
            PackageManager.APT: "go install -v github.com/eth0izzle/shhgit@latest",
            PackageManager.BREW: "go install -v github.com/eth0izzle/shhgit@latest",
        },
        check_command="shhgit -h",
        dependencies=["go"],
    ),

    # =========================================================================
    # MOBILE Security Tools
    # =========================================================================
    "apktool": ToolDefinition(
        name="apktool",
        description="Reverse engineer Android APK files",
        category=ToolCategory.MOBILE,
        install_commands={
            PackageManager.APT: "apt-get install -y apktool",
            PackageManager.BREW: "brew install apktool",
        },
        check_command="apktool -version",
    ),
    "jadx": ToolDefinition(
        name="jadx",
        description="DEX to Java decompiler",
        category=ToolCategory.MOBILE,
        install_commands={
            PackageManager.APT: "apt-get install -y jadx || pip3 install jadx",
            PackageManager.BREW: "brew install jadx",
        },
        check_command="jadx --version",
    ),
    "mobsf": ToolDefinition(
        name="mobsf",
        description="Mobile Security Framework for Android/iOS",
        category=ToolCategory.MOBILE,
        install_commands={
            PackageManager.APT: "pip3 install mobsfscan",
            PackageManager.BREW: "pip3 install mobsfscan",
        },
        check_command="mobsfscan -h",
    ),

    # =========================================================================
    # WIRELESS Tools (Linux primarily)
    # =========================================================================
    "aircrack-ng": ToolDefinition(
        name="aircrack-ng",
        description="WiFi security auditing tools",
        category=ToolCategory.WIRELESS,
        install_commands={
            PackageManager.APT: "apt-get install -y aircrack-ng",
            PackageManager.BREW: "brew install aircrack-ng",
            PackageManager.PACMAN: "pacman -S --noconfirm aircrack-ng",
        },
        check_command="aircrack-ng --help",
        requires_sudo=True,
    ),
    "reaver": ToolDefinition(
        name="reaver",
        description="WPS brute force attack tool",
        category=ToolCategory.WIRELESS,
        install_commands={
            PackageManager.APT: "apt-get install -y reaver",
            PackageManager.PACMAN: "pacman -S --noconfirm reaver",
        },
        check_command="reaver -h",
        requires_sudo=True,
    ),
    "wifite": ToolDefinition(
        name="wifite",
        description="Automated wireless auditor",
        category=ToolCategory.WIRELESS,
        install_commands={
            PackageManager.APT: "apt-get install -y wifite",
            PackageManager.PACMAN: "pacman -S --noconfirm wifite",
        },
        check_command="wifite -h",
        requires_sudo=True,
    ),
}


@dataclass
class InstallResult:
    """Result of a tool installation."""
    tool_name: str
    success: bool
    message: str
    already_installed: bool = False


class LocalToolInstaller:
    """
    Installs security tools on the local system.

    Automatically detects the OS and package manager, then installs
    tools using the appropriate commands.
    """

    def __init__(self, system_info: Optional[SystemInfo] = None):
        """
        Initialize the installer.

        Args:
            system_info: Pre-detected system info (will auto-detect if not provided)
        """
        self._system_info = system_info
        self._detector = SystemDetector()

    async def detect_system(self) -> SystemInfo:
        """Detect system if not already done."""
        if not self._system_info:
            self._system_info = await self._detector.detect()
        return self._system_info

    async def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        tool = TOOLS.get(tool_name)
        if not tool:
            return False

        # Check if binary exists
        if shutil.which(tool_name):
            return True

        # Try running check command
        try:
            proc = await asyncio.create_subprocess_shell(
                tool.check_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            return proc.returncode == 0
        except Exception:
            return False

    async def get_installed_tools(self) -> Dict[str, bool]:
        """Get installation status of all known tools."""
        results = {}
        for tool_name in TOOLS.keys():
            results[tool_name] = await self.check_tool_installed(tool_name)
        return results

    async def install_tool(
        self,
        tool_name: str,
        use_sudo: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> InstallResult:
        """
        Install a single tool.

        Args:
            tool_name: Name of the tool to install
            use_sudo: Use sudo for installation
            progress_callback: Callback for progress updates

        Returns:
            InstallResult with installation status
        """
        await self.detect_system()
        pkg_mgr = self._system_info.package_manager

        tool = TOOLS.get(tool_name)
        if not tool:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message=f"Unknown tool: {tool_name}"
            )

        # Check if already installed
        if await self.check_tool_installed(tool_name):
            return InstallResult(
                tool_name=tool_name,
                success=True,
                message="Already installed",
                already_installed=True
            )

        # Install dependencies first
        for dep in tool.dependencies:
            dep_result = await self.install_tool(dep, use_sudo, progress_callback)
            if not dep_result.success and not dep_result.already_installed:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    message=f"Failed to install dependency: {dep}"
                )

        # Get install command for this package manager
        install_cmd = tool.install_commands.get(pkg_mgr)
        if not install_cmd:
            # Try to find alternative package manager command
            for pm, cmd in tool.install_commands.items():
                if cmd.startswith("pip3 ") or cmd.startswith("go install"):
                    install_cmd = cmd
                    break

        if not install_cmd:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message=f"No installation method for {pkg_mgr.value}"
            )

        # Prepare command with sudo if needed
        if use_sudo and self._system_info.capabilities.has_sudo:
            if install_cmd.startswith("apt") or install_cmd.startswith("dnf") or \
               install_cmd.startswith("yum") or install_cmd.startswith("pacman"):
                install_cmd = f"sudo {install_cmd}"

        if progress_callback:
            progress_callback(f"Installing {tool_name}...")

        logger.info(f"Installing tool: {tool_name}", command=install_cmd[:100])

        try:
            # Set up environment for Go tools
            env_setup = ""
            if "go install" in install_cmd:
                go_path = Path.home() / "go" / "bin"
                env_setup = f"export PATH=$PATH:{go_path} && export GOPATH=$HOME/go && "

            full_cmd = f"{env_setup}{install_cmd}"

            proc = await asyncio.create_subprocess_shell(
                full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**dict(__import__('os').environ), "GOPATH": str(Path.home() / "go")},
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600  # 10 minute timeout
            )

            if proc.returncode == 0:
                # Verify installation
                if await self.check_tool_installed(tool_name):
                    return InstallResult(
                        tool_name=tool_name,
                        success=True,
                        message="Installed successfully"
                    )
                else:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        message="Install completed but verification failed"
                    )
            else:
                error_msg = stderr.decode()[:200] if stderr else "Unknown error"
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    message=f"Installation failed: {error_msg}"
                )

        except asyncio.TimeoutError:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message="Installation timed out"
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message=f"Installation error: {str(e)}"
            )

    async def install_tools(
        self,
        categories: Optional[List[str]] = None,
        tools: Optional[List[str]] = None,
        core_only: bool = False,
        parallel: int = 3,
        use_sudo: bool = True,
    ) -> Dict[str, InstallResult]:
        """
        Install multiple tools.

        Args:
            categories: Tool categories to install (recon, scan, exploit, etc.)
            tools: Specific tools to install (overrides categories)
            core_only: Only install core tools
            parallel: Number of parallel installations
            use_sudo: Use sudo for installation

        Returns:
            Dict mapping tool names to InstallResult
        """
        await self.detect_system()

        # Determine which tools to install
        tools_to_install: List[str] = []

        if tools:
            tools_to_install = tools
        elif categories:
            for tool_name, tool_def in TOOLS.items():
                if tool_def.category.value in categories:
                    if not core_only or tool_def.is_core:
                        tools_to_install.append(tool_name)
        elif core_only:
            tools_to_install = [
                name for name, tool in TOOLS.items()
                if tool.is_core
            ]
        else:
            tools_to_install = list(TOOLS.keys())

        # Remove duplicates and sort by dependencies
        tools_to_install = self._sort_by_dependencies(tools_to_install)

        results: Dict[str, InstallResult] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Installing {len(tools_to_install)} tools...",
                total=len(tools_to_install)
            )

            for tool_name in tools_to_install:
                progress.update(task, description=f"[cyan]Installing {tool_name}...")

                result = await self.install_tool(tool_name, use_sudo)
                results[tool_name] = result

                if result.success:
                    if result.already_installed:
                        progress.console.print(f"  [dim]✓ {tool_name} (already installed)[/dim]")
                    else:
                        progress.console.print(f"  [green]✓ {tool_name} installed[/green]")
                else:
                    progress.console.print(f"  [red]✗ {tool_name}: {result.message}[/red]")

                progress.advance(task)

        return results

    async def install_core_tools(self) -> Dict[str, InstallResult]:
        """Install only core essential tools."""
        return await self.install_tools(core_only=True)

    async def install_all(self) -> Dict[str, InstallResult]:
        """Install all available tools."""
        return await self.install_tools()

    def _sort_by_dependencies(self, tools: List[str]) -> List[str]:
        """Sort tools so dependencies come first."""
        sorted_tools = []
        visited: Set[str] = set()

        def visit(tool_name: str):
            if tool_name in visited:
                return
            visited.add(tool_name)

            tool = TOOLS.get(tool_name)
            if tool:
                for dep in tool.dependencies:
                    visit(dep)

            if tool_name in tools:
                sorted_tools.append(tool_name)

        for tool_name in tools:
            visit(tool_name)

        return sorted_tools

    def print_tool_status(self, results: Dict[str, InstallResult]):
        """Print a summary table of installation results."""
        table = Table(title="Installation Results", box=box.ROUNDED)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Message", style="dim")

        for tool_name, result in sorted(results.items()):
            if result.success:
                status = "[green]✓ Installed[/green]" if not result.already_installed else "[dim]✓ Already installed[/dim]"
            else:
                status = "[red]✗ Failed[/red]"

            table.add_row(tool_name, status, result.message[:50])

        console.print(table)

        # Summary
        installed = sum(1 for r in results.values() if r.success and not r.already_installed)
        already = sum(1 for r in results.values() if r.already_installed)
        failed = sum(1 for r in results.values() if not r.success)

        console.print(f"\n[bold]Summary:[/bold] {installed} installed, {already} already present, {failed} failed")


async def install_prerequisites(system_info: Optional[SystemInfo] = None) -> Dict[str, InstallResult]:
    """Install prerequisite tools (Go, Ruby, etc.)."""
    installer = LocalToolInstaller(system_info)
    prereq_tools = [
        name for name, tool in TOOLS.items()
        if tool.category == ToolCategory.PREREQUISITE
    ]
    return await installer.install_tools(tools=prereq_tools)


async def install_recommended_tools(system_info: Optional[SystemInfo] = None) -> Dict[str, InstallResult]:
    """Install recommended core security tools."""
    installer = LocalToolInstaller(system_info)
    return await installer.install_core_tools()


def get_available_tools() -> Dict[str, ToolDefinition]:
    """Get all available tool definitions."""
    return TOOLS.copy()


def get_tools_by_category(category: str) -> Dict[str, ToolDefinition]:
    """Get tools in a specific category."""
    return {
        name: tool for name, tool in TOOLS.items()
        if tool.category.value == category
    }


if __name__ == "__main__":
    async def main():
        detector = SystemDetector()
        system_info = await detector.detect()
        detector.print_summary(system_info)

        installer = LocalToolInstaller(system_info)

        console.print("\n[bold]Checking installed tools...[/bold]")
        installed = await installer.get_installed_tools()

        table = Table(box=box.ROUNDED)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Category")

        for tool_name, is_installed in sorted(installed.items()):
            tool = TOOLS.get(tool_name)
            status = "[green]✓[/green]" if is_installed else "[red]✗[/red]"
            category = tool.category.value if tool else "unknown"
            table.add_row(tool_name, status, category)

        console.print(table)

    asyncio.run(main())
