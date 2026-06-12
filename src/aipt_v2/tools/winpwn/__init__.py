"""
WinPwn Integration Module for AIPTX

Provides automated orchestration of WinPwn PowerShell framework
for Windows and Active Directory penetration testing.

WinPwn is a Windows/AD penetration testing automation framework
by @S3cur3Th1sSh1t that consolidates many security tools and
techniques into a single PowerShell script.

This module provides:
- Configuration management for WinPwn execution
- PowerShell execution engine (local and remote)
- Output parsing to structured findings
- Attack orchestration and automation

NOTE: This module orchestrates existing WinPwn functionality.
It does not implement new attack techniques or enhance
offensive capabilities.

Usage:
    from aipt_v2.tools.winpwn import (
        WinPwnConfig,
        WinPwnAttacks,
        get_winpwn_config,
        run_winpwn_assessment,
    )

    # Configure
    config = get_winpwn_config(
        script_path="/path/to/WinPwn.ps1",
        domain="corp.local",
        dc_ip="10.0.0.1"
    )

    # Run assessment
    attacks = WinPwnAttacks(config)
    result = await attacks.run_full_assessment()

    # Get report
    print(attacks.get_findings_report())

Quick Usage:
    from aipt_v2.tools.winpwn import run_winpwn_assessment

    result = await run_winpwn_assessment(
        script_path="/path/to/WinPwn.ps1",
        modules=["localrecon", "privesc"]
    )
"""

# PowerShell Execution
from aipt_v2.tools.winpwn.powershell_executor import (
    PowerShellExecutor,
    PowerShellResult,
    WinRMExecutor,
)

# Attack Orchestration
from aipt_v2.tools.winpwn.winpwn_attacks import (
    ModuleResult,
    WinPwnAttacks,
    WinPwnResult,
    quick_local_recon,
    run_winpwn_assessment,
)

# Configuration
from aipt_v2.tools.winpwn.winpwn_config import (
    WinPwnConfig,
    WinPwnCredentials,
    WinPwnExecutionMode,
    WinPwnModule,
    get_winpwn_config,
    validate_winpwn_config,
)

# Output Parsing
from aipt_v2.tools.winpwn.winpwn_parsers import (
    ExtractedCredential,
    FindingCategory,
    FindingSeverity,
    WinPwnFinding,
    WinPwnParser,
)

# Available WinPwn modules for reference
AVAILABLE_MODULES = {
    # Reconnaissance
    "localrecon": "Local system reconnaissance",
    "domainrecon": "Domain enumeration",
    # Credentials
    "kittielocal": "Local credential extraction",
    "lsassdump": "LSASS memory dump",
    "samfile": "SAM database extraction",
    "sessiongopher": "Session credential extraction",
    "wificreds": "WiFi password extraction",
    "browserpwn": "Browser credential extraction",
    # Privilege Escalation
    "privesc": "Privilege escalation checks",
    "kernelexploits": "Kernel exploit checks",
    "uacbypass": "UAC bypass techniques",
    "tokenmanipulation": "Token manipulation",
    # Domain Attacks
    "kerberoasting": "Kerberoasting attack",
    "sharphound": "BloodHound data collection",
    "inveigh": "LLMNR/NBT-NS poisoning",
    "domainpassspray": "Domain password spraying",
    # Lateral Movement
    "latmov": "Lateral movement techniques",
    "shareenum": "Share enumeration",
    # Full Automation
    "winpwn": "Full WinPwn automation",
}


def get_available_modules() -> dict:
    """Get dictionary of available WinPwn modules."""
    return AVAILABLE_MODULES.copy()


def get_module_info(module_name: str) -> str:
    """Get description of a specific module."""
    return AVAILABLE_MODULES.get(module_name, f"Unknown module: {module_name}")


__all__ = [
    # Configuration
    "WinPwnConfig",
    "WinPwnCredentials",
    "WinPwnModule",
    "WinPwnExecutionMode",
    "get_winpwn_config",
    "validate_winpwn_config",
    # Execution
    "PowerShellExecutor",
    "PowerShellResult",
    "WinRMExecutor",
    # Parsing
    "WinPwnParser",
    "WinPwnFinding",
    "ExtractedCredential",
    "FindingSeverity",
    "FindingCategory",
    # Attacks
    "WinPwnAttacks",
    "WinPwnResult",
    "ModuleResult",
    "run_winpwn_assessment",
    "quick_local_recon",
    # Utilities
    "get_available_modules",
    "get_module_info",
    "AVAILABLE_MODULES",
]
