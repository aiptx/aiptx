"""
Prowler Integration - AWS Security Best Practices Auditing

Prowler is an open-source security tool to perform AWS, GCP, and Azure
security best practices assessments, audits, incident response,
continuous monitoring, hardening and forensics readiness.

Supports:
- CIS AWS Foundations Benchmark
- PCI-DSS
- HIPAA
- GDPR
- AWS Well-Architected Framework
- 300+ security checks

Usage:
    from aipt_v2.tools.cloud import run_prowler

    findings = await run_prowler(profile="production", compliance=["cis", "pci"])
"""

import asyncio
import json
import csv
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aipt_v2.tools.cloud.cloud_config import CloudConfig, get_cloud_config


@dataclass
class ProwlerConfig:
    """Prowler configuration."""
    provider: str = "aws"  # aws, azure, gcp

    # AWS options
    aws_profile: str = "default"
    aws_regions: List[str] = field(default_factory=list)  # Empty = all

    # Compliance frameworks
    compliance: List[str] = field(default_factory=list)  # cis, pci, hipaa, gdpr

    # Scanning options
    checks: List[str] = field(default_factory=list)  # Specific checks to run
    services: List[str] = field(default_factory=list)  # Specific services
    severity: List[str] = field(default_factory=lambda: ["critical", "high", "medium", "low"])

    # Output options
    output_dir: str = "./prowler_results"
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])

    # Performance
    parallel: bool = True
    shodan_api_key: str = ""  # Optional Shodan integration


@dataclass
class ProwlerFinding:
    """Individual Prowler finding."""
    check_id: str
    check_title: str
    service: str
    severity: str
    status: str  # PASS, FAIL, INFO, WARNING
    region: str
    resource_id: str
    resource_arn: str
    description: str
    risk: str
    remediation: str
    compliance: List[str] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class ProwlerResult:
    """Result of a Prowler scan."""
    provider: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    total_checks: int
    passed: int
    failed: int
    warnings: int
    findings: List[ProwlerFinding]
    report_path: str
    summary: Dict[str, int]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ProwlerTool:
    """
    Prowler wrapper for AWS/Azure/GCP security auditing.

    Provides a Python interface to the Prowler CLI tool
    for automated cloud security assessments against
    compliance frameworks.
    """

    def __init__(self, config: Optional[ProwlerConfig] = None):
        """
        Initialize Prowler tool.

        Args:
            config: Prowler configuration
        """
        self.config = config or ProwlerConfig()
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._installed = None
        self._version = None

    async def check_installed(self) -> bool:
        """Check if Prowler is installed."""
        if self._installed is not None:
            return self._installed

        try:
            process = await asyncio.create_subprocess_shell(
                "prowler --version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            self._installed = process.returncode == 0
            if self._installed:
                self._version = stdout.decode().strip()
        except Exception:
            self._installed = False

        return self._installed

    async def get_version(self) -> str:
        """Get Prowler version."""
        if not await self.check_installed():
            return "Not installed"
        return self._version or "Unknown"

    def _build_command(self) -> str:
        """Build Prowler command from configuration."""
        cmd_parts = ["prowler", self.config.provider]

        # Add provider-specific options
        if self.config.provider == "aws":
            if self.config.aws_profile:
                cmd_parts.extend(["--profile", self.config.aws_profile])
            if self.config.aws_regions:
                cmd_parts.extend(["--filter-region", ",".join(self.config.aws_regions)])

        # Add compliance frameworks
        if self.config.compliance:
            for framework in self.config.compliance:
                cmd_parts.extend(["--compliance", framework])

        # Add specific checks
        if self.config.checks:
            cmd_parts.extend(["--checks", ",".join(self.config.checks)])

        # Add service filtering
        if self.config.services:
            cmd_parts.extend(["--services", ",".join(self.config.services)])

        # Add severity filtering
        if self.config.severity:
            cmd_parts.extend(["--severity", ",".join(self.config.severity)])

        # Add output options
        cmd_parts.extend(["--output-directory", str(self.output_dir)])

        if self.config.output_formats:
            cmd_parts.extend(["--output-formats", ",".join(self.config.output_formats)])

        # Add Shodan integration if configured
        if self.config.shodan_api_key:
            cmd_parts.extend(["--shodan", self.config.shodan_api_key])

        # Quiet mode for cleaner output
        cmd_parts.append("--no-banner")

        return " ".join(cmd_parts)

    async def scan(self, timeout: int = 3600) -> ProwlerResult:
        """
        Run Prowler scan.

        Args:
            timeout: Scan timeout in seconds

        Returns:
            ProwlerResult with findings summary
        """
        if not await self.check_installed():
            raise RuntimeError("Prowler is not installed. Install with: pip install prowler")

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
            raise TimeoutError(f"Prowler scan timed out after {timeout}s")

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = asyncio.get_event_loop().time() - start_time

        # Parse results
        findings = self._parse_findings()
        report_path = self._find_latest_report()

        # Calculate summary
        total_checks = len(findings)
        passed = sum(1 for f in findings if f.status == "PASS")
        failed = sum(1 for f in findings if f.status == "FAIL")
        warnings = sum(1 for f in findings if f.status in ["WARNING", "INFO"])

        summary = {
            "critical": sum(1 for f in findings if f.severity == "critical" and f.status == "FAIL"),
            "high": sum(1 for f in findings if f.severity == "high" and f.status == "FAIL"),
            "medium": sum(1 for f in findings if f.severity == "medium" and f.status == "FAIL"),
            "low": sum(1 for f in findings if f.severity == "low" and f.status == "FAIL"),
        }

        status = "completed" if process.returncode == 0 else "failed"

        return ProwlerResult(
            provider=self.config.provider,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            total_checks=total_checks,
            passed=passed,
            failed=failed,
            warnings=warnings,
            findings=findings,
            report_path=str(report_path) if report_path else "",
            summary=summary,
            metadata={
                "command": cmd,
                "return_code": process.returncode,
                "version": self._version,
                "stderr": stderr.decode() if process.returncode != 0 else ""
            }
        )

    def _find_latest_report(self) -> Optional[Path]:
        """Find the latest Prowler output file."""
        # Prowler creates timestamped directories
        if not self.output_dir.exists():
            return None

        # Look for JSON output files
        json_files = list(self.output_dir.glob("**/prowler-output*.json"))
        if json_files:
            return max(json_files, key=lambda f: f.stat().st_mtime)

        # Try CSV files
        csv_files = list(self.output_dir.glob("**/prowler-output*.csv"))
        if csv_files:
            return max(csv_files, key=lambda f: f.stat().st_mtime)

        # Try HTML files
        html_files = list(self.output_dir.glob("**/prowler-output*.html"))
        if html_files:
            return max(html_files, key=lambda f: f.stat().st_mtime)

        return None

    def _parse_findings(self) -> List[ProwlerFinding]:
        """Parse findings from Prowler output."""
        findings = []

        # Try JSON first (preferred)
        json_files = list(self.output_dir.glob("**/prowler-output*.json"))
        if json_files:
            latest_json = max(json_files, key=lambda f: f.stat().st_mtime)
            findings.extend(self._parse_json_findings(latest_json))

        # Fall back to CSV if no JSON
        if not findings:
            csv_files = list(self.output_dir.glob("**/prowler-output*.csv"))
            if csv_files:
                latest_csv = max(csv_files, key=lambda f: f.stat().st_mtime)
                findings.extend(self._parse_csv_findings(latest_csv))

        return findings

    def _parse_json_findings(self, json_file: Path) -> List[ProwlerFinding]:
        """Parse findings from JSON output."""
        findings = []

        try:
            with open(json_file, 'r') as f:
                # Prowler JSON can be JSONL (one JSON per line) or array
                content = f.read().strip()

                if content.startswith('['):
                    # JSON array
                    data = json.loads(content)
                else:
                    # JSONL format
                    data = []
                    for line in content.split('\n'):
                        if line.strip():
                            data.append(json.loads(line))

                for item in data:
                    finding = ProwlerFinding(
                        check_id=item.get("CheckID", item.get("check_id", "")),
                        check_title=item.get("CheckTitle", item.get("check_title", "")),
                        service=item.get("ServiceName", item.get("service", "")),
                        severity=item.get("Severity", item.get("severity", "")).lower(),
                        status=item.get("Status", item.get("status", "")).upper(),
                        region=item.get("Region", item.get("region", "")),
                        resource_id=item.get("ResourceId", item.get("resource_id", "")),
                        resource_arn=item.get("ResourceArn", item.get("resource_arn", "")),
                        description=item.get("StatusExtended", item.get("description", "")),
                        risk=item.get("Risk", item.get("risk", "")),
                        remediation=item.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                        compliance=item.get("Compliance", []),
                        timestamp=item.get("Timestamp", item.get("timestamp", ""))
                    )
                    findings.append(finding)

        except Exception as e:
            print(f"[!] Error parsing Prowler JSON: {e}")

        return findings

    def _parse_csv_findings(self, csv_file: Path) -> List[ProwlerFinding]:
        """Parse findings from CSV output."""
        findings = []

        try:
            with open(csv_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    finding = ProwlerFinding(
                        check_id=row.get("CHECK_ID", row.get("check_id", "")),
                        check_title=row.get("CHECK_TITLE", row.get("check_title", "")),
                        service=row.get("SERVICE_NAME", row.get("service", "")),
                        severity=row.get("SEVERITY", row.get("severity", "")).lower(),
                        status=row.get("STATUS", row.get("status", "")).upper(),
                        region=row.get("REGION", row.get("region", "")),
                        resource_id=row.get("RESOURCE_ID", row.get("resource_id", "")),
                        resource_arn=row.get("RESOURCE_ARN", row.get("resource_arn", "")),
                        description=row.get("STATUS_EXTENDED", row.get("description", "")),
                        risk=row.get("RISK", row.get("risk", "")),
                        remediation=row.get("REMEDIATION", row.get("remediation", "")),
                        compliance=[],
                        timestamp=row.get("TIMESTAMP", row.get("timestamp", ""))
                    )
                    findings.append(finding)

        except Exception as e:
            print(f"[!] Error parsing Prowler CSV: {e}")

        return findings

    def get_failed_findings(self) -> List[ProwlerFinding]:
        """Get only failed findings from the latest scan."""
        all_findings = self._parse_findings()
        return [f for f in all_findings if f.status == "FAIL"]

    def get_findings_by_severity(self, severity: str) -> List[ProwlerFinding]:
        """Get findings filtered by severity."""
        all_findings = self._parse_findings()
        return [f for f in all_findings if f.severity.lower() == severity.lower()]

    def get_findings_by_service(self, service: str) -> List[ProwlerFinding]:
        """Get findings filtered by AWS service."""
        all_findings = self._parse_findings()
        return [f for f in all_findings if service.lower() in f.service.lower()]

    def get_compliance_summary(self) -> Dict[str, Dict[str, int]]:
        """Get compliance framework summary."""
        findings = self._parse_findings()
        compliance_summary = {}

        for finding in findings:
            for framework in finding.compliance:
                if framework not in compliance_summary:
                    compliance_summary[framework] = {"passed": 0, "failed": 0}

                if finding.status == "PASS":
                    compliance_summary[framework]["passed"] += 1
                elif finding.status == "FAIL":
                    compliance_summary[framework]["failed"] += 1

        return compliance_summary


async def list_available_checks(provider: str = "aws") -> List[Dict[str, str]]:
    """
    List all available Prowler checks for a provider.

    Args:
        provider: Cloud provider (aws, azure, gcp)

    Returns:
        List of check definitions
    """
    try:
        process = await asyncio.create_subprocess_shell(
            f"prowler {provider} --list-checks --no-banner",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()

        checks = []
        for line in stdout.decode().split('\n'):
            if line.strip() and not line.startswith(('-', '=')):
                parts = line.split(' - ', 1)
                if len(parts) == 2:
                    checks.append({
                        "id": parts[0].strip(),
                        "title": parts[1].strip()
                    })

        return checks
    except Exception as e:
        print(f"[!] Error listing checks: {e}")
        return []


async def list_compliance_frameworks(provider: str = "aws") -> List[str]:
    """
    List available compliance frameworks.

    Args:
        provider: Cloud provider

    Returns:
        List of framework names
    """
    try:
        process = await asyncio.create_subprocess_shell(
            f"prowler {provider} --list-compliance --no-banner",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()

        frameworks = []
        for line in stdout.decode().split('\n'):
            line = line.strip()
            if line and not line.startswith(('-', '=', 'Available')):
                frameworks.append(line)

        return frameworks
    except Exception:
        # Return default frameworks if listing fails
        return [
            "cis_1.4_aws",
            "cis_1.5_aws",
            "cis_2.0_aws",
            "pci_3.2.1_aws",
            "hipaa_aws",
            "gdpr_aws",
            "aws_well_architected_framework",
            "nist_800_53_revision_5_aws"
        ]


# Convenience function
async def run_prowler(
    profile: Optional[str] = None,
    regions: Optional[List[str]] = None,
    compliance: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    output_dir: str = "./prowler_results",
    timeout: int = 3600
) -> ProwlerResult:
    """
    Run Prowler AWS security scan.

    Args:
        profile: AWS profile name
        regions: Specific regions to scan
        compliance: Compliance frameworks to check (cis, pci, hipaa, gdpr)
        services: Specific AWS services to scan
        severity: Severity levels to include
        output_dir: Output directory for reports
        timeout: Scan timeout in seconds

    Returns:
        ProwlerResult
    """
    config = ProwlerConfig(
        provider="aws",
        aws_profile=profile or "default",
        aws_regions=regions or [],
        compliance=compliance or [],
        services=services or [],
        severity=severity or ["critical", "high", "medium", "low"],
        output_dir=output_dir
    )

    tool = ProwlerTool(config)
    return await tool.scan(timeout=timeout)


# Quick check functions
async def quick_iam_check(profile: str = "default") -> ProwlerResult:
    """Quick IAM security check."""
    config = ProwlerConfig(
        aws_profile=profile,
        services=["iam"],
        severity=["critical", "high"]
    )
    tool = ProwlerTool(config)
    return await tool.scan(timeout=600)


async def quick_s3_check(profile: str = "default") -> ProwlerResult:
    """Quick S3 security check."""
    config = ProwlerConfig(
        aws_profile=profile,
        services=["s3"],
        severity=["critical", "high"]
    )
    tool = ProwlerTool(config)
    return await tool.scan(timeout=600)


async def quick_network_check(profile: str = "default") -> ProwlerResult:
    """Quick network/VPC security check."""
    config = ProwlerConfig(
        aws_profile=profile,
        services=["ec2", "vpc"],
        severity=["critical", "high"]
    )
    tool = ProwlerTool(config)
    return await tool.scan(timeout=900)


async def compliance_scan(
    profile: str = "default",
    framework: str = "cis_2.0_aws"
) -> ProwlerResult:
    """Run compliance-focused scan."""
    config = ProwlerConfig(
        aws_profile=profile,
        compliance=[framework]
    )
    tool = ProwlerTool(config)
    return await tool.scan(timeout=3600)
