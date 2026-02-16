"""
PowerShell Arsenal Integration for AIPTX

This module provides integration with offensive PowerShell scripts
and payloads for penetration testing and red teaming, enabling
automated execution of 87 PowerShell scripts.

Features:
- Local script execution from cloned repository
- Remote IEX loading from GitHub
- WinRM remote execution to Windows targets
- AMSI bypass integration
- Structured output parsing
- BaseScanner integration for AIPTX pipeline

Usage:
    # Quick credential gathering
    from aipt_v2.tools.ps_arsenal import PSArsenalAttacks, PSArsenalConfig

    config = PSArsenalConfig(scripts_path="/tmp/ps_arsenal")
    attacks = PSArsenalAttacks(config)
    result = await attacks.gather_all_credentials()

    # Direct script execution
    from aipt_v2.tools.ps_arsenal import PSArsenalExecutor

    executor = PSArsenalExecutor(scripts_path="/tmp/ps_arsenal")
    result = await executor.execute_by_name("Get-Information")

    # Scanner integration
    from aipt_v2.tools.ps_arsenal import PSArsenalScanner, PSScanConfig

    scanner = PSArsenalScanner(PSScanConfig(scripts_path="/tmp/ps_arsenal"))
    scan_result = await scanner.scan("localhost")

Script Categories:
- Gather (18): Credential extraction, keylogging, system info
- Shells (15): TCP, UDP, HTTP, ICMP, WMI shells
- Utility (15): Encoding, persistence, exfiltration helpers
- Backdoors (10): HTTP, DNS, registry persistence
- Client (10): Document-based attacks (Word, Excel, HTA)
- Escalation (3): UAC bypass, token manipulation
- Execution (5): Download-execute, MSSQL command execution
- Scan (2): Port scanning, brute forcing
- Pivot (3): Lateral movement helpers
- MITM (1): HTTP proxy interception
- ActiveDirectory (2): Constrained delegation, DCShadow
- Bypass (1): AMSI bypass

Author: AIPTX Integration
License: MIT
"""

# Lazy imports to avoid loading heavy dependencies until needed
_LAZY_IMPORTS = {
    # Configuration
    "PSArsenalConfig": ".ps_config",
    "PSCredentials": ".ps_config",
    "PSLoadMode": ".ps_config",
    "PSCategory": ".ps_config",
    "PSScanConfig": ".ps_config",
    "RequiredPrivilege": ".ps_config",
    "get_ps_config": ".ps_config",
    "validate_ps_config": ".ps_config",

    # Metadata
    "ScriptMetadata": ".ps_metadata",
    "ScriptCategory": ".ps_metadata",
    "OutputType": ".ps_metadata",
    "SCRIPT_METADATA": ".ps_metadata",
    "get_script_metadata": ".ps_metadata",
    "get_scripts_by_category": ".ps_metadata",
    "get_credential_scripts": ".ps_metadata",
    "get_shell_scripts": ".ps_metadata",
    "get_admin_scripts": ".ps_metadata",
    "get_all_script_names": ".ps_metadata",
    "get_category_counts": ".ps_metadata",

    # Executor
    "PSArsenalExecutor": ".ps_executor",
    "PSExecutionError": ".ps_executor",
    "ScriptNotFoundError": ".ps_executor",
    "AMSIBlockedError": ".ps_executor",
    "PrivilegeError": ".ps_executor",
    "AMSI_BYPASS_TECHNIQUES": ".ps_executor",
    "create_executor_from_config": ".ps_executor",

    # Parsers
    "PSArsenalParser": ".ps_parsers",
    "PSFinding": ".ps_parsers",
    "PSCredential": ".ps_parsers",
    "PSFindingCategory": ".ps_parsers",
    "PSFindingSeverity": ".ps_parsers",

    # Attacks
    "PSArsenalAttacks": ".ps_attacks",
    "AttackResult": ".ps_attacks",

    # Scanner
    "PSArsenalScanner": ".ps_scanner",
    "ScanResult": ".ps_scanner",
    "ScanFinding": ".ps_scanner",
    "create_ps_scanner": ".ps_scanner",
}


def __getattr__(name: str):
    """Lazy import handler."""
    if name in _LAZY_IMPORTS:
        module_path = _LAZY_IMPORTS[name]
        import importlib
        module = importlib.import_module(module_path, package=__name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    """List available exports."""
    return list(_LAZY_IMPORTS.keys())


# Version info
__version__ = "1.0.0"
__author__ = "AIPTX"

# Script count for quick reference
TOTAL_SCRIPTS = 86
SCRIPT_CATEGORIES = [
    "Gather", "Shells", "Utility", "Backdoors", "Client",
    "Escalation", "Execution", "Scan", "Pivot", "MITM",
    "ActiveDirectory", "Bypass", "Misc", "Prasadhak"
]


# Convenience functions that don't require lazy loading
def list_scripts() -> dict:
    """
    List all available PowerShell scripts by category.

    Returns:
        Dict mapping category names to script lists
    """
    from .ps_metadata import (
        SCRIPT_METADATA,
        ScriptCategory
    )

    result = {}
    for category in ScriptCategory:
        scripts = [
            s.name for s in SCRIPT_METADATA.values()
            if s.category == category
        ]
        if scripts:
            result[category.value] = sorted(scripts)
    return result


def get_script_info(script_name: str) -> dict:
    """
    Get information about a specific script.

    Args:
        script_name: Name of the script

    Returns:
        Dict with script metadata or empty dict if not found
    """
    from .ps_metadata import get_script_metadata

    metadata = get_script_metadata(script_name)
    if not metadata:
        return {}

    return {
        "name": metadata.name,
        "category": metadata.category.value,
        "function_name": metadata.function_name,
        "description": metadata.description,
        "required_privilege": metadata.required_privilege.value,
        "parameters": metadata.parameters,
        "required_params": metadata.required_params,
        "mitre_techniques": metadata.mitre_techniques,
        "output_type": metadata.output_type.value,
        "is_destructive": metadata.is_destructive,
        "requires_interaction": metadata.requires_interaction,
    }


__all__ = [
    # Version
    "__version__",
    "TOTAL_SCRIPTS",
    "SCRIPT_CATEGORIES",

    # Configuration
    "PSArsenalConfig",
    "PSCredentials",
    "PSLoadMode",
    "PSCategory",
    "PSScanConfig",
    "RequiredPrivilege",
    "get_ps_config",
    "validate_ps_config",

    # Metadata
    "ScriptMetadata",
    "ScriptCategory",
    "OutputType",
    "SCRIPT_METADATA",
    "get_script_metadata",
    "get_scripts_by_category",
    "get_credential_scripts",
    "get_shell_scripts",
    "get_admin_scripts",
    "get_all_script_names",
    "get_category_counts",

    # Executor
    "PSArsenalExecutor",
    "PSExecutionError",
    "ScriptNotFoundError",
    "AMSIBlockedError",
    "PrivilegeError",
    "AMSI_BYPASS_TECHNIQUES",
    "create_executor_from_config",

    # Parsers
    "PSArsenalParser",
    "PSFinding",
    "PSCredential",
    "PSFindingCategory",
    "PSFindingSeverity",

    # Attacks
    "PSArsenalAttacks",
    "AttackResult",

    # Scanner
    "PSArsenalScanner",
    "ScanResult",
    "ScanFinding",
    "create_ps_scanner",

    # Convenience
    "list_scripts",
    "get_script_info",
]
