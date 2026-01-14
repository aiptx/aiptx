"""
ScoutSuite Integration - Multi-Cloud Security Auditing

ScoutSuite is an open-source multi-cloud security auditing tool
that assesses the security posture of cloud environments.

Supports:
- AWS (Amazon Web Services)
- Azure (Microsoft Azure)
- GCP (Google Cloud Platform)
- Alibaba Cloud
- Oracle Cloud Infrastructure

Usage:
    from aipt_v2.tools.cloud import run_scoutsuite

    findings = await run_scoutsuite("aws", profile="production")
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aipt_v2.tools.cloud.cloud_config import CloudConfig, get_cloud_config


@dataclass
class ScoutSuiteConfig:
    """ScoutSuite configuration."""
    provider: str = "aws"  # aws, azure, gcp, aliyun, oci

    # AWS options
    aws_profile: str = "default"
    aws_regions: List[str] = field(default_factory=list)  # Empty = all

    # Azure options
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""

    # GCP options
    gcp_project_id: str = ""
    gcp_service_account: str = ""

    # Scanning options
    services: List[str] = field(default_factory=list)  # Empty = all
    skip_services: List[str] = field(default_factory=list)
    max_workers: int = 25
    no_browser: bool = True

    # Output options
    output_dir: str = "./scoutsuite_results"
    report_name: str = ""
    timestamp: bool = True


@dataclass
class ScoutSuiteResult:
    """Result of a ScoutSuite scan."""
    provider: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    findings_count: int
    flagged_items: int
    report_path: str
    summary: Dict[str, int]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ScoutSuiteTool:
    """
    ScoutSuite wrapper for multi-cloud security auditing.

    Provides a Python interface to the ScoutSuite CLI tool
    for automated cloud security assessments.
    """

    def __init__(self, config: Optional[ScoutSuiteConfig] = None):
        """
        Initialize ScoutSuite tool.

        Args:
            config: ScoutSuite configuration
        """
        self.config = config or ScoutSuiteConfig()
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._installed = None

    async def check_installed(self) -> bool:
        """Check if ScoutSuite is installed."""
        if self._installed is not None:
            return self._installed

        try:
            process = await asyncio.create_subprocess_shell(
                "scout --version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            self._installed = process.returncode == 0
        except Exception:
            self._installed = False

        return self._installed

    def _build_command(self) -> str:
        """Build ScoutSuite command from configuration."""
        cmd_parts = ["scout", self.config.provider]

        # Add provider-specific options
        if self.config.provider == "aws":
            if self.config.aws_profile:
                cmd_parts.extend(["--profile", self.config.aws_profile])
            if self.config.aws_regions:
                cmd_parts.extend(["--regions", ",".join(self.config.aws_regions)])

        elif self.config.provider == "azure":
            if self.config.azure_subscription_id:
                cmd_parts.extend(["--subscription-id", self.config.azure_subscription_id])
            if self.config.azure_tenant_id:
                cmd_parts.extend(["--tenant-id", self.config.azure_tenant_id])

        elif self.config.provider == "gcp":
            if self.config.gcp_project_id:
                cmd_parts.extend(["--project-id", self.config.gcp_project_id])
            if self.config.gcp_service_account:
                cmd_parts.extend(["--service-account", self.config.gcp_service_account])

        # Add service filtering
        if self.config.services:
            cmd_parts.extend(["--services", ",".join(self.config.services)])
        if self.config.skip_services:
            cmd_parts.extend(["--skip", ",".join(self.config.skip_services)])

        # Add general options
        cmd_parts.extend(["--max-workers", str(self.config.max_workers)])
        cmd_parts.extend(["--report-dir", str(self.output_dir)])

        if self.config.report_name:
            cmd_parts.extend(["--report-name", self.config.report_name])

        if self.config.no_browser:
            cmd_parts.append("--no-browser")

        if self.config.timestamp:
            cmd_parts.append("--timestamp")

        return " ".join(cmd_parts)

    async def scan(self, timeout: int = 3600) -> ScoutSuiteResult:
        """
        Run ScoutSuite scan.

        Args:
            timeout: Scan timeout in seconds

        Returns:
            ScoutSuiteResult with findings summary
        """
        if not await self.check_installed():
            raise RuntimeError("ScoutSuite is not installed. Install with: pip install scoutsuite")

        started_at = datetime.now(timezone.utc).isoformat()
        start_time = asyncio.get_event_loop().time()

        cmd = self._build_command()
        print(f"[*] Running: {cmd}")

        # Set up environment
        env = os.environ.copy()

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(f"ScoutSuite scan timed out after {timeout}s")

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = asyncio.get_event_loop().time() - start_time

        # Parse results
        report_path = self._find_latest_report()
        findings_count = 0
        flagged_items = 0
        summary = {"danger": 0, "warning": 0, "info": 0}

        if report_path and report_path.exists():
            results = self._parse_results(report_path)
            findings_count = results.get("findings_count", 0)
            flagged_items = results.get("flagged_items", 0)
            summary = results.get("summary", summary)

        status = "completed" if process.returncode == 0 else "failed"

        return ScoutSuiteResult(
            provider=self.config.provider,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            findings_count=findings_count,
            flagged_items=flagged_items,
            report_path=str(report_path) if report_path else "",
            summary=summary,
            metadata={
                "command": cmd,
                "return_code": process.returncode,
                "stderr": stderr.decode() if process.returncode != 0 else ""
            }
        )

    def _find_latest_report(self) -> Optional[Path]:
        """Find the latest ScoutSuite results file."""
        results_dir = self.output_dir / "scoutsuite-results"
        if results_dir.exists():
            js_files = list(results_dir.glob("scoutsuite_results*.js"))
            if js_files:
                return max(js_files, key=lambda f: f.stat().st_mtime)

        # Try alternative location
        js_files = list(self.output_dir.glob("**/scoutsuite_results*.js"))
        if js_files:
            return max(js_files, key=lambda f: f.stat().st_mtime)

        return None

    def _parse_results(self, results_file: Path) -> Dict[str, Any]:
        """Parse ScoutSuite results JavaScript file."""
        try:
            content = results_file.read_text()

            # Remove JS variable assignment
            if "scoutsuite_results =" in content:
                content = content.split("scoutsuite_results =", 1)[1].strip()
                if content.endswith(";"):
                    content = content[:-1]

            data = json.loads(content)

            # Count findings
            findings_count = 0
            flagged_items = 0
            summary = {"danger": 0, "warning": 0, "info": 0}

            services = data.get("services", {})
            for service_data in services.values():
                service_findings = service_data.get("findings", {})
                for finding in service_findings.values():
                    findings_count += 1
                    flagged = finding.get("flagged_items", 0)
                    flagged_items += flagged

                    if flagged > 0:
                        level = finding.get("level", "warning")
                        if level in summary:
                            summary[level] += flagged

            return {
                "findings_count": findings_count,
                "flagged_items": flagged_items,
                "summary": summary,
                "account_id": data.get("account_id", ""),
                "last_run": data.get("last_run", {})
            }

        except Exception as e:
            print(f"[!] Error parsing ScoutSuite results: {e}")
            return {"findings_count": 0, "flagged_items": 0, "summary": {}}

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get parsed findings from the latest scan."""
        report_path = self._find_latest_report()
        if not report_path:
            return []

        try:
            content = report_path.read_text()
            if "scoutsuite_results =" in content:
                content = content.split("scoutsuite_results =", 1)[1].strip()
                if content.endswith(";"):
                    content = content[:-1]

            data = json.loads(content)
            findings = []

            services = data.get("services", {})
            for service_name, service_data in services.items():
                for finding_id, finding_data in service_data.get("findings", {}).items():
                    if finding_data.get("flagged_items", 0) > 0:
                        findings.append({
                            "provider": self.config.provider,
                            "service": service_name,
                            "id": finding_id,
                            "level": finding_data.get("level", "warning"),
                            "description": finding_data.get("description", ""),
                            "rationale": finding_data.get("rationale", ""),
                            "remediation": finding_data.get("remediation", ""),
                            "flagged_items": finding_data.get("flagged_items", 0),
                            "items": finding_data.get("items", []),
                            "compliance": finding_data.get("compliance", [])
                        })

            return findings

        except Exception as e:
            print(f"[!] Error getting findings: {e}")
            return []


# Convenience function
async def run_scoutsuite(
    provider: str = "aws",
    profile: Optional[str] = None,
    regions: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    output_dir: str = "./scoutsuite_results",
    timeout: int = 3600
) -> ScoutSuiteResult:
    """
    Run ScoutSuite scan.

    Args:
        provider: Cloud provider (aws, azure, gcp)
        profile: AWS profile name (for AWS)
        regions: Specific regions to scan
        services: Specific services to scan
        output_dir: Output directory for reports
        timeout: Scan timeout in seconds

    Returns:
        ScoutSuiteResult
    """
    config = ScoutSuiteConfig(
        provider=provider,
        aws_profile=profile or "default",
        aws_regions=regions or [],
        services=services or [],
        output_dir=output_dir
    )

    tool = ScoutSuiteTool(config)
    return await tool.scan(timeout=timeout)
