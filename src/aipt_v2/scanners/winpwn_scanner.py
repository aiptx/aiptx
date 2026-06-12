"""
WinPwn Scanner Integration

Integrates WinPwn PowerShell framework into AIPTX scanning pipeline.
Provides automated Windows and Active Directory security assessment.

WinPwn by @S3cur3Th1sSh1t consolidates Windows/AD penetration testing
tools into a single framework for comprehensive assessments.

Usage:
    from aipt_v2.scanners import WinPwnScanner, WinPwnScanConfig

    config = WinPwnScanConfig(
        domain="corp.local",
        dc_ip="10.0.0.1",
        username="admin",
        password="secret",
        script_path="/path/to/WinPwn.ps1"
    )

    scanner = WinPwnScanner(config)
    result = await scanner.scan()
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aipt_v2.scanners.base import (
    BaseScanner,
    ScanFinding,
    ScanSeverity,
)
from aipt_v2.tools.winpwn import (
    FindingSeverity,
    WinPwnAttacks,
    WinPwnConfig,
    WinPwnFinding,
    WinPwnModule,
    WinPwnResult,
    get_winpwn_config,
)

logger = logging.getLogger(__name__)


@dataclass
class WinPwnScanConfig:
    """Configuration for WinPwn scanner."""

    # Target
    domain: str = ""
    dc_ip: str = ""
    target_host: str = ""

    # Credentials
    username: str = ""
    password: str = ""
    ntlm_hash: str = ""

    # WinPwn location
    script_path: str = ""
    repo_url: str = ""

    # Modules to run
    modules: List[str] = field(
        default_factory=lambda: [
            "localrecon",
            "privesc",
        ]
    )

    # Options
    run_domain_recon: bool = True
    run_credential_extraction: bool = True
    run_kerberoasting: bool = True
    run_bloodhound: bool = False

    # Execution
    bypass_amsi: bool = True
    noninteractive: bool = True
    timeout: int = 600

    # Output
    output_dir: str = "./winpwn_results"


@dataclass
class WinPwnScanResult:
    """Result from WinPwn scan."""

    scanner: str = "winpwn"
    target: str = ""
    domain: str = ""
    status: str = "pending"

    # Results
    findings: List[ScanFinding] = field(default_factory=list)
    credentials_found: int = 0
    modules_run: List[str] = field(default_factory=list)

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Raw data
    raw_result: Optional[WinPwnResult] = None
    errors: List[str] = field(default_factory=list)

    def severity_counts(self) -> Dict[str, int]:
        """Get finding counts by severity."""
        counts = {s.value: 0 for s in ScanSeverity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scanner": self.scanner,
            "target": self.target,
            "domain": self.domain,
            "status": self.status,
            "findings_count": len(self.findings),
            "credentials_found": self.credentials_found,
            "modules_run": self.modules_run,
            "severity_counts": self.severity_counts(),
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }


class WinPwnScanner(BaseScanner):
    """
    WinPwn Scanner Integration.

    Automates Windows and Active Directory security assessments
    using the WinPwn PowerShell framework.

    Provides:
    - Local reconnaissance and privilege escalation checks
    - Domain enumeration and attack path discovery
    - Credential extraction and Kerberos attacks
    - Integration with BloodHound for AD analysis
    """

    def __init__(self, config: WinPwnScanConfig):
        """
        Initialize WinPwn scanner.

        Args:
            config: WinPwn scan configuration
        """
        self.config = config
        self._attacks: Optional[WinPwnAttacks] = None

    @staticmethod
    def is_available() -> bool:
        """
        Check if WinPwn can be executed.

        Returns:
            True if PowerShell is available
        """
        # Check for PowerShell
        if platform.system() == "Windows":
            return True

        # Check for pwsh on non-Windows
        import shutil

        return shutil.which("pwsh") is not None

    def _get_winpwn_config(self) -> WinPwnConfig:
        """Build WinPwnConfig from scan config."""
        # Determine modules to enable
        modules = []

        # Map string module names to enums
        module_map = {
            "localrecon": WinPwnModule.LOCAL_RECON,
            "domainrecon": WinPwnModule.DOMAIN_RECON,
            "privesc": WinPwnModule.PRIVESC,
            "kittielocal": WinPwnModule.KITTIE_LOCAL,
            "lsassdump": WinPwnModule.LSASS_DUMP,
            "samfile": WinPwnModule.SAM_FILE,
            "kerberoasting": WinPwnModule.KERBEROASTING,
            "sharphound": WinPwnModule.BLOODHOUND,
            "sessiongopher": WinPwnModule.SESSIONGOPHER,
            "browserpwn": WinPwnModule.BROWSER_PWN,
            "wificreds": WinPwnModule.WIFI_CREDS,
            "tokenmanipulation": WinPwnModule.TOKEN_MANIPULATION,
            "latmov": WinPwnModule.LATERAL_MOVEMENT,
            "shareenum": WinPwnModule.SHARE_ENUM,
        }

        for mod_name in self.config.modules:
            if mod_name.lower() in module_map:
                modules.append(module_map[mod_name.lower()])

        # Add conditional modules
        if self.config.run_domain_recon and self.config.domain:
            if WinPwnModule.DOMAIN_RECON not in modules:
                modules.append(WinPwnModule.DOMAIN_RECON)

        if self.config.run_kerberoasting and self.config.domain:
            if WinPwnModule.KERBEROASTING not in modules:
                modules.append(WinPwnModule.KERBEROASTING)

        if self.config.run_bloodhound and self.config.domain:
            if WinPwnModule.BLOODHOUND not in modules:
                modules.append(WinPwnModule.BLOODHOUND)

        if self.config.run_credential_extraction:
            if WinPwnModule.KITTIE_LOCAL not in modules:
                modules.append(WinPwnModule.KITTIE_LOCAL)

        return get_winpwn_config(
            script_path=self.config.script_path,
            target_host=self.config.target_host,
            domain=self.config.domain,
            dc_ip=self.config.dc_ip,
            username=self.config.username,
            password=self.config.password,
            ntlm_hash=self.config.ntlm_hash,
            repo_url=self.config.repo_url,
            enabled_modules=modules,
            bypass_amsi=self.config.bypass_amsi,
            noninteractive=self.config.noninteractive,
            output_dir=self.config.output_dir,
            timeout=self.config.timeout,
        )

    def _convert_severity(self, severity: FindingSeverity) -> ScanSeverity:
        """Convert WinPwn severity to AIPTX severity."""
        mapping = {
            FindingSeverity.CRITICAL: ScanSeverity.CRITICAL,
            FindingSeverity.HIGH: ScanSeverity.HIGH,
            FindingSeverity.MEDIUM: ScanSeverity.MEDIUM,
            FindingSeverity.LOW: ScanSeverity.LOW,
            FindingSeverity.INFO: ScanSeverity.INFO,
        }
        return mapping.get(severity, ScanSeverity.INFO)

    def _convert_finding(self, wp_finding: WinPwnFinding) -> ScanFinding:
        """Convert WinPwn finding to AIPTX ScanFinding."""
        return ScanFinding(
            title=wp_finding.title,
            severity=self._convert_severity(wp_finding.severity),
            description=wp_finding.description,
            host=self.config.target_host or self.config.dc_ip,
            evidence=wp_finding.raw_data[:500] if wp_finding.raw_data else "",
            scanner="winpwn",
            template=wp_finding.source_module,
            tags=[wp_finding.category.value, wp_finding.source_module],
        )

    async def scan(self, target: str = None) -> WinPwnScanResult:
        """
        Run WinPwn security assessment.

        Args:
            target: Optional target override (uses config if not provided)

        Returns:
            WinPwnScanResult with findings
        """
        result = WinPwnScanResult(
            target=target or self.config.target_host or self.config.dc_ip,
            domain=self.config.domain,
            start_time=datetime.now(timezone.utc),
        )

        # Check availability
        if not self.is_available():
            result.status = "failed"
            result.errors.append("PowerShell not available on this system")
            result.end_time = datetime.now(timezone.utc)
            return result

        try:
            # Build config and create attacks instance
            wp_config = self._get_winpwn_config()
            self._attacks = WinPwnAttacks(wp_config)

            logger.info(f"Starting WinPwn scan against {result.target}")
            result.status = "running"

            # Run all configured modules
            wp_result = await self._attacks.run_all_modules()

            # Convert findings
            for wp_finding in wp_result.all_findings:
                scan_finding = self._convert_finding(wp_finding)
                result.findings.append(scan_finding)

            # Track credentials
            result.credentials_found = len(wp_result.all_credentials)

            # Track modules
            result.modules_run = wp_result.modules_run

            # Store raw result
            result.raw_result = wp_result

            result.status = "completed"
            logger.info(
                f"WinPwn scan completed: {len(result.findings)} findings, "
                f"{result.credentials_found} credentials"
            )

        except Exception as e:
            logger.exception(f"WinPwn scan failed: {e}")
            result.status = "failed"
            result.errors.append(str(e))

        finally:
            result.end_time = datetime.now(timezone.utc)
            if result.start_time and result.end_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

            # Cleanup
            if self._attacks:
                await self._attacks.cleanup()

        return result

    async def run_quick_recon(self) -> WinPwnScanResult:
        """
        Run quick local reconnaissance only.

        Returns:
            WinPwnScanResult with local findings
        """
        # Temporarily override modules
        original_modules = self.config.modules
        self.config.modules = ["localrecon", "privesc"]
        self.config.run_domain_recon = False
        self.config.run_credential_extraction = False
        self.config.run_kerberoasting = False

        try:
            return await self.scan()
        finally:
            self.config.modules = original_modules

    async def run_domain_assessment(self) -> WinPwnScanResult:
        """
        Run full domain security assessment.

        Requires domain credentials.

        Returns:
            WinPwnScanResult with domain findings
        """
        if not self.config.domain or not self.config.username:
            result = WinPwnScanResult(target=self.config.dc_ip, status="failed")
            result.errors.append("Domain credentials required for domain assessment")
            return result

        # Enable all domain modules
        self.config.modules = [
            "localrecon",
            "domainrecon",
            "privesc",
            "kerberoasting",
        ]
        self.config.run_domain_recon = True
        self.config.run_kerberoasting = True

        return await self.scan()

    def parse_output(self, output: str) -> List[ScanFinding]:
        """
        Parse raw WinPwn output.

        Args:
            output: Raw output string

        Returns:
            List of ScanFindings
        """
        from aipt_v2.tools.winpwn import WinPwnParser

        parser = WinPwnParser()
        findings, credentials = parser.parse_all(output, module="winpwn")

        return [self._convert_finding(f) for f in findings]

    def get_report(self) -> str:
        """
        Get formatted report from last scan.

        Returns:
            Text report of findings
        """
        if self._attacks:
            return self._attacks.get_findings_report()
        return "No scan results available"


# Convenience functions for CLI integration
async def scan_windows(
    target: str,
    domain: str = "",
    dc_ip: str = "",
    username: str = "",
    password: str = "",
    script_path: str = "",
    modules: List[str] = None,
    **kwargs,
) -> WinPwnScanResult:
    """
    Quick Windows security scan.

    Args:
        target: Target host
        domain: AD domain name
        dc_ip: Domain Controller IP
        username: Username for authentication
        password: Password
        script_path: Path to WinPwn.ps1
        modules: Modules to run
        **kwargs: Additional config options

    Returns:
        WinPwnScanResult with findings
    """
    config = WinPwnScanConfig(
        target_host=target,
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        script_path=script_path,
        modules=modules or ["localrecon", "privesc"],
        **kwargs,
    )

    scanner = WinPwnScanner(config)
    return await scanner.scan()


async def scan_ad_with_winpwn(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    script_path: str = "",
    full_assessment: bool = False,
    **kwargs,
) -> WinPwnScanResult:
    """
    Active Directory security assessment using WinPwn.

    Args:
        domain: AD domain name
        dc_ip: Domain Controller IP
        username: Username
        password: Password
        script_path: Path to WinPwn.ps1
        full_assessment: Run comprehensive assessment
        **kwargs: Additional options

    Returns:
        WinPwnScanResult with AD findings
    """
    modules = ["localrecon", "domainrecon", "privesc", "kerberoasting"]
    if full_assessment:
        modules.extend(["sharphound", "kittielocal"])

    config = WinPwnScanConfig(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        script_path=script_path,
        modules=modules,
        run_domain_recon=True,
        run_kerberoasting=True,
        run_bloodhound=full_assessment,
        run_credential_extraction=full_assessment,
        **kwargs,
    )

    scanner = WinPwnScanner(config)
    return await scanner.scan()


__all__ = [
    "WinPwnScanner",
    "WinPwnScanConfig",
    "WinPwnScanResult",
    "scan_windows",
    "scan_ad_with_winpwn",
]
