"""
PowerShell Arsenal Scanner Integration

Integrates PowerShell scripts with AIPTX's BaseScanner framework
for use in automated scanning pipelines.

Usage:
    from aipt_v2.tools.ps_arsenal import PSArsenalScanner, PSScanConfig

    config = PSScanConfig(scripts_path="/tmp/ps_arsenal")
    scanner = PSArsenalScanner(config)
    result = await scanner.scan("target-host")
"""

import logging
import platform
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from aipt_v2.tools.ps_arsenal.ps_config import (
    PSArsenalConfig,
    PSScanConfig,
    PSLoadMode
)
from aipt_v2.tools.ps_arsenal.ps_executor import PSArsenalExecutor
from aipt_v2.tools.ps_arsenal.ps_parsers import (
    PSArsenalParser,
    PSFinding,
    PSCredential,
    PSFindingSeverity
)
from aipt_v2.tools.ps_arsenal.ps_metadata import (
    SCRIPT_METADATA,
    get_script_metadata,
    ScriptCategory
)

logger = logging.getLogger(__name__)


# =============================================================================
# SCAN RESULT MODELS
# =============================================================================

class ScanSeverity:
    """Severity levels for scan findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanFinding:
    """Standard scan finding compatible with AIPTX pipeline."""
    title: str
    severity: str
    description: str
    host: str = ""
    port: int = 0
    url: str = ""
    evidence: str = ""
    scanner: str = "ps_arsenal"
    template: str = ""
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "evidence": self.evidence,
            "scanner": self.scanner,
            "template": self.template,
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "tags": self.tags,
            "metadata": self.metadata,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    """Complete scan result."""
    scanner: str
    target: str
    status: str = "pending"  # pending, running, completed, failed
    findings: List[ScanFinding] = field(default_factory=list)
    credentials: List[PSCredential] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)

    def add_finding(self, finding: ScanFinding) -> None:
        """Add a finding to results."""
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scanner": self.scanner,
            "target": self.target,
            "status": self.status,
            "findings_count": len(self.findings),
            "credentials_count": len(self.credentials),
            "findings": [f.to_dict() for f in self.findings],
            "credentials": [c.to_dict() for c in self.credentials],
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors
        }


# =============================================================================
# POWERSHELL ARSENAL SCANNER
# =============================================================================

class PSArsenalScanner:
    """
    PowerShell Arsenal Scanner for AIPTX pipeline integration.

    Provides automated execution of PowerShell scripts as part of
    the scanning framework with standardized output.
    """

    def __init__(self, config: Optional[PSScanConfig] = None):
        """
        Initialize scanner.

        Args:
            config: PSScanConfig instance
        """
        self.config = config or PSScanConfig()
        self.executor = PSArsenalExecutor(
            scripts_path=self.config.scripts_path,
            base_url=self.config.base_url,
            load_mode=self.config.load_mode,
            bypass_amsi=self.config.bypass_amsi
        )
        self.parser = PSArsenalParser()

    def is_available(self) -> bool:
        """
        Check if PowerShell Arsenal scanning is available.

        Returns:
            True if PowerShell is available
        """
        # Check for PowerShell
        if platform.system() == "Windows":
            return True

        # Check for pwsh on non-Windows
        return shutil.which("pwsh") is not None

    def _convert_severity(self, severity: PSFindingSeverity) -> str:
        """Convert PS severity to standard severity."""
        mapping = {
            PSFindingSeverity.CRITICAL: ScanSeverity.CRITICAL,
            PSFindingSeverity.HIGH: ScanSeverity.HIGH,
            PSFindingSeverity.MEDIUM: ScanSeverity.MEDIUM,
            PSFindingSeverity.LOW: ScanSeverity.LOW,
            PSFindingSeverity.INFO: ScanSeverity.INFO,
        }
        return mapping.get(severity, ScanSeverity.INFO)

    def _convert_finding(
        self,
        finding: PSFinding,
        target: str
    ) -> ScanFinding:
        """Convert PSFinding to ScanFinding."""
        return ScanFinding(
            title=finding.title,
            severity=self._convert_severity(finding.severity),
            description=finding.description,
            host=target,
            scanner="ps_arsenal",
            template=finding.source_script,
            evidence=finding.raw_data[:500] if finding.raw_data else "",
            tags=finding.mitre_attack,
            metadata=finding.metadata
        )

    async def scan(
        self,
        target: str,
        scripts: Optional[List[str]] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run PowerShell Arsenal scan against target.

        Args:
            target: Target host (for labeling - scripts run locally or via WinRM)
            scripts: Specific scripts to run (default: from config)
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="ps_arsenal", target=target)
        result.status = "running"
        result.start_time = datetime.now(timezone.utc)

        scripts_to_run = scripts or self.config.scripts_to_run

        for script_name in scripts_to_run:
            if script_name not in SCRIPT_METADATA:
                result.errors.append(f"Unknown script: {script_name}")
                continue

            metadata = get_script_metadata(script_name)
            if not metadata:
                continue

            try:
                # Execute script
                ps_result = await self.executor.execute_script(
                    category=metadata.category.value,
                    script_name=script_name,
                    function_name=metadata.function_name,
                    parameters=kwargs.get("params", {}),
                    timeout=self.config.timeout
                )

                result.raw_output += f"\n=== {script_name} ===\n{ps_result.output}"

                if ps_result.success:
                    # Parse output
                    findings, credentials = self.parser.parse_all(
                        ps_result.output,
                        script_name
                    )

                    # Convert and add findings
                    for f in findings:
                        result.add_finding(self._convert_finding(f, target))

                    # Add credentials
                    result.credentials.extend(credentials)
                else:
                    if ps_result.metadata.get("amsi_blocked"):
                        result.errors.append(f"{script_name}: Blocked by AMSI")
                    elif ps_result.metadata.get("privilege_error"):
                        result.errors.append(f"{script_name}: Insufficient privileges")
                    else:
                        result.errors.append(f"{script_name}: {ps_result.stderr[:100]}")

            except Exception as e:
                logger.exception(f"Error running {script_name}")
                result.errors.append(f"{script_name}: {str(e)}")

        result.status = "completed"
        result.end_time = datetime.now(timezone.utc)
        result.duration_seconds = (
            result.end_time - result.start_time
        ).total_seconds()

        return result

    async def quick_scan(self, target: str) -> ScanResult:
        """
        Quick reconnaissance scan.

        Args:
            target: Target host

        Returns:
            ScanResult with basic system info
        """
        return await self.scan(
            target,
            scripts=["Get-Information", "Check-VM"]
        )

    async def credential_scan(self, target: str) -> ScanResult:
        """
        Credential-focused scan.

        Args:
            target: Target host

        Returns:
            ScanResult with credential findings
        """
        return await self.scan(
            target,
            scripts=[
                "Invoke-Mimikatz",
                "Get-PassHashes",
                "Get-WLAN-Keys",
                "Get-WebCredentials",
            ]
        )

    def parse_output(self, output: str) -> List[ScanFinding]:
        """
        Parse raw output into findings.

        Args:
            output: Raw PowerShell output

        Returns:
            List of ScanFinding objects
        """
        findings, _ = self.parser.parse_all(output, "unknown")
        return [
            ScanFinding(
                title=f.title,
                severity=self._convert_severity(f.severity),
                description=f.description,
                scanner="ps_arsenal",
                template=f.source_script
            )
            for f in findings
        ]


def create_ps_scanner(
    scripts_path: Optional[str] = None,
    scripts_to_run: Optional[List[str]] = None
) -> PSArsenalScanner:
    """
    Factory function to create PSArsenalScanner.

    Args:
        scripts_path: Path to PowerShell scripts
        scripts_to_run: List of scripts to run

    Returns:
        Configured PSArsenalScanner
    """
    config = PSScanConfig(
        scripts_path=scripts_path or "/tmp/ps_arsenal",
        scripts_to_run=scripts_to_run or ["Get-Information", "Check-VM"]
    )
    return PSArsenalScanner(config)


__all__ = [
    "PSArsenalScanner",
    "ScanResult",
    "ScanFinding",
    "ScanSeverity",
    "create_ps_scanner",
]
