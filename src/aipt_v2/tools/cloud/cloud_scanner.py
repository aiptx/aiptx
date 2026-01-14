"""
Unified Cloud Security Scanner

Provides a unified interface for scanning AWS, Azure, and GCP
cloud infrastructure for security misconfigurations.
"""

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from aipt_v2.tools.cloud.cloud_config import CloudConfig, get_cloud_config

logger = logging.getLogger(__name__)


class CloudSeverity(Enum):
    """Cloud finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


@dataclass
class CloudFinding:
    """A security finding from cloud scanning."""
    provider: str
    service: str
    resource_id: str
    resource_name: str
    title: str
    description: str
    severity: str
    recommendation: str
    region: str = ""
    account_id: str = ""
    compliance: List[str] = field(default_factory=list)  # e.g., ["CIS 1.1", "PCI 2.1"]
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_aipt_finding(self) -> Dict[str, Any]:
        """Convert to AIPT Finding format."""
        return {
            "type": f"cloud_{self.service}",
            "value": self.resource_id,
            "description": f"[{self.provider.upper()}] {self.title}: {self.description}",
            "severity": self.severity,
            "phase": "scan",
            "tool": f"cloud_scanner_{self.provider}",
            "target": self.resource_name,
            "evidence": json.dumps(self.metadata),
            "remediation": self.recommendation,
            "metadata": {
                "provider": self.provider,
                "service": self.service,
                "region": self.region,
                "account_id": self.account_id,
                "compliance": self.compliance,
                "resource_id": self.resource_id
            },
            "timestamp": self.timestamp
        }


@dataclass
class CloudScanResult:
    """Result of a cloud security scan."""
    provider: str
    status: str  # completed, failed, partial
    started_at: str
    finished_at: str
    duration: float
    findings: List[CloudFinding]
    summary: Dict[str, int]  # Severity counts
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class CloudScanner:
    """
    Unified cloud security scanner.

    Orchestrates scanning across multiple cloud providers using
    ScoutSuite, Prowler, and custom checks.
    """

    def __init__(self, config: Optional[CloudConfig] = None):
        """
        Initialize cloud scanner.

        Args:
            config: Cloud configuration (auto-detected if not provided)
        """
        self.config = config or get_cloud_config()
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[CloudFinding] = []
        self.on_finding: Optional[Callable[[CloudFinding], None]] = None

    def _log(self, message: str, level: str = "info"):
        """Log with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"info": "[*]", "success": "[+]", "error": "[-]", "warning": "[!]"}
        print(f"{timestamp} {prefix.get(level, '[*]')} {message}")
        if level == "error":
            logger.error(message)
        else:
            logger.info(message)

    async def scan(self, providers: Optional[List[str]] = None) -> List[CloudScanResult]:
        """
        Run cloud security scan across specified providers.

        Args:
            providers: List of providers to scan (uses config if not specified)

        Returns:
            List of CloudScanResult for each provider
        """
        providers = providers or self.config.get_configured_providers()

        if not providers:
            self._log("No cloud providers configured. Set credentials first.", "error")
            return []

        self._log(f"Starting cloud security scan for: {', '.join(providers)}")
        results = []

        for provider in providers:
            try:
                result = await self._scan_provider(provider)
                results.append(result)
                self.findings.extend(result.findings)
            except Exception as e:
                self._log(f"Error scanning {provider}: {str(e)}", "error")
                results.append(CloudScanResult(
                    provider=provider,
                    status="failed",
                    started_at=datetime.now(timezone.utc).isoformat(),
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    duration=0,
                    findings=[],
                    summary={},
                    errors=[str(e)]
                ))

        return results

    async def _scan_provider(self, provider: str) -> CloudScanResult:
        """Scan a specific cloud provider."""
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = asyncio.get_event_loop().time()

        self._log(f"Scanning {provider.upper()}...")

        findings = []
        errors = []

        if provider == "aws":
            findings, errors = await self._scan_aws()
        elif provider == "azure":
            findings, errors = await self._scan_azure()
        elif provider == "gcp":
            findings, errors = await self._scan_gcp()
        else:
            errors.append(f"Unknown provider: {provider}")

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = asyncio.get_event_loop().time() - start_time

        # Calculate summary
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.severity.lower()
            if sev in summary:
                summary[sev] += 1

        self._log(f"{provider.upper()} scan complete: {len(findings)} findings", "success")

        return CloudScanResult(
            provider=provider,
            status="completed" if not errors else "partial",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            findings=findings,
            summary=summary,
            errors=errors
        )

    async def _scan_aws(self) -> tuple:
        """Scan AWS infrastructure."""
        findings = []
        errors = []

        aws_config = self.config.aws
        env = {**os.environ, **aws_config.to_env_dict()}

        # Run ScoutSuite for AWS
        try:
            scoutsuite_findings = await self._run_scoutsuite("aws", env)
            findings.extend(scoutsuite_findings)
        except Exception as e:
            errors.append(f"ScoutSuite AWS: {str(e)}")
            self._log(f"ScoutSuite failed: {e}", "warning")

        # Run Prowler for AWS
        try:
            prowler_findings = await self._run_prowler(env)
            findings.extend(prowler_findings)
        except Exception as e:
            errors.append(f"Prowler: {str(e)}")
            self._log(f"Prowler failed: {e}", "warning")

        # Run custom AWS checks
        try:
            custom_findings = await self._run_aws_custom_checks(env)
            findings.extend(custom_findings)
        except Exception as e:
            errors.append(f"Custom AWS checks: {str(e)}")

        return findings, errors

    async def _scan_azure(self) -> tuple:
        """Scan Azure infrastructure."""
        findings = []
        errors = []

        azure_config = self.config.azure
        env = {**os.environ, **azure_config.to_env_dict()}

        # Run ScoutSuite for Azure
        try:
            scoutsuite_findings = await self._run_scoutsuite("azure", env)
            findings.extend(scoutsuite_findings)
        except Exception as e:
            errors.append(f"ScoutSuite Azure: {str(e)}")

        return findings, errors

    async def _scan_gcp(self) -> tuple:
        """Scan GCP infrastructure."""
        findings = []
        errors = []

        gcp_config = self.config.gcp
        env = {**os.environ, **gcp_config.to_env_dict()}

        # Run ScoutSuite for GCP
        try:
            scoutsuite_findings = await self._run_scoutsuite("gcp", env)
            findings.extend(scoutsuite_findings)
        except Exception as e:
            errors.append(f"ScoutSuite GCP: {str(e)}")

        return findings, errors

    async def _run_scoutsuite(self, provider: str, env: Dict[str, str]) -> List[CloudFinding]:
        """Run ScoutSuite for a provider."""
        findings = []
        output_dir = self.output_dir / f"scoutsuite_{provider}"
        output_dir.mkdir(exist_ok=True)

        cmd = f"scout {provider} --report-dir {output_dir} --no-browser"

        self._log(f"Running ScoutSuite for {provider}...")

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=self.config.timeout
        )

        if process.returncode == 0:
            # Parse ScoutSuite results
            results_file = output_dir / "scoutsuite-results" / "scoutsuite_results.js"
            if results_file.exists():
                findings = self._parse_scoutsuite_results(results_file, provider)
        else:
            raise Exception(f"ScoutSuite failed: {stderr.decode()}")

        return findings

    async def _run_prowler(self, env: Dict[str, str]) -> List[CloudFinding]:
        """Run Prowler for AWS."""
        findings = []
        output_file = self.output_dir / "prowler_results.json"

        cmd = f"prowler aws --output-formats json --output-filename {output_file}"

        self._log("Running Prowler for AWS...")

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=self.config.timeout
        )

        if process.returncode == 0 and output_file.exists():
            findings = self._parse_prowler_results(output_file)
        else:
            # Prowler might not be installed
            self._log("Prowler not available or failed", "warning")

        return findings

    async def _run_aws_custom_checks(self, env: Dict[str, str]) -> List[CloudFinding]:
        """Run custom AWS security checks using boto3."""
        findings = []

        try:
            import boto3
            from botocore.exceptions import ClientError

            # Create session
            session = boto3.Session(
                profile_name=self.config.aws.profile,
                region_name=self.config.aws.region
            )

            # Check S3 public buckets
            s3_findings = await self._check_s3_public_access(session)
            findings.extend(s3_findings)

            # Check security groups
            sg_findings = await self._check_security_groups(session)
            findings.extend(sg_findings)

            # Check IAM
            iam_findings = await self._check_iam_issues(session)
            findings.extend(iam_findings)

        except ImportError:
            self._log("boto3 not installed, skipping custom AWS checks", "warning")
        except Exception as e:
            self._log(f"Custom AWS check error: {e}", "warning")

        return findings

    async def _check_s3_public_access(self, session) -> List[CloudFinding]:
        """Check for public S3 buckets."""
        findings = []
        s3 = session.client('s3')

        try:
            buckets = s3.list_buckets().get('Buckets', [])
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    # Check bucket ACL
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI', '').endswith('AllUsers'):
                            findings.append(CloudFinding(
                                provider="aws",
                                service="s3",
                                resource_id=bucket_name,
                                resource_name=bucket_name,
                                title="Public S3 Bucket",
                                description=f"S3 bucket {bucket_name} is publicly accessible",
                                severity="critical",
                                recommendation="Remove public access from the bucket ACL",
                                compliance=["CIS 2.1.1", "PCI 2.1"],
                                metadata={"acl_grant": str(grant)}
                            ))
                except Exception:
                    continue
        except Exception as e:
            self._log(f"S3 check error: {e}", "warning")

        return findings

    async def _check_security_groups(self, session) -> List[CloudFinding]:
        """Check for overly permissive security groups."""
        findings = []
        ec2 = session.client('ec2')

        try:
            sgs = ec2.describe_security_groups().get('SecurityGroups', [])
            for sg in sgs:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']

                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            port = rule.get('FromPort', 'All')
                            if port in [22, 3389, 'All']:
                                findings.append(CloudFinding(
                                    provider="aws",
                                    service="ec2",
                                    resource_id=sg_id,
                                    resource_name=sg_name,
                                    title="Security Group Open to Internet",
                                    description=f"Security group {sg_name} allows inbound traffic from 0.0.0.0/0 on port {port}",
                                    severity="high" if port in [22, 3389] else "medium",
                                    recommendation="Restrict inbound access to specific IP ranges",
                                    compliance=["CIS 4.1", "CIS 4.2"],
                                    metadata={"port": port, "cidr": cidr}
                                ))
        except Exception as e:
            self._log(f"Security groups check error: {e}", "warning")

        return findings

    async def _check_iam_issues(self, session) -> List[CloudFinding]:
        """Check for IAM security issues."""
        findings = []
        iam = session.client('iam')

        try:
            # Check for root account access keys
            try:
                summary = iam.get_account_summary()
                if summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0) > 0:
                    findings.append(CloudFinding(
                        provider="aws",
                        service="iam",
                        resource_id="root",
                        resource_name="Root Account",
                        title="Root Account Has Access Keys",
                        description="The root account has active access keys which is a security risk",
                        severity="critical",
                        recommendation="Delete root account access keys and use IAM users instead",
                        compliance=["CIS 1.4"]
                    ))
            except Exception:
                pass

            # Check for users without MFA
            users = iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                try:
                    mfa = iam.list_mfa_devices(UserName=username)
                    if not mfa.get('MFADevices', []):
                        findings.append(CloudFinding(
                            provider="aws",
                            service="iam",
                            resource_id=username,
                            resource_name=username,
                            title="IAM User Without MFA",
                            description=f"IAM user {username} does not have MFA enabled",
                            severity="medium",
                            recommendation="Enable MFA for all IAM users",
                            compliance=["CIS 1.2"]
                        ))
                except Exception:
                    continue

        except Exception as e:
            self._log(f"IAM check error: {e}", "warning")

        return findings

    def _parse_scoutsuite_results(self, results_file: Path, provider: str) -> List[CloudFinding]:
        """Parse ScoutSuite results file."""
        findings = []

        try:
            content = results_file.read_text()
            # Remove JS wrapper
            if content.startswith("scoutsuite_results ="):
                content = content.replace("scoutsuite_results =", "").strip()

            data = json.loads(content)
            services = data.get('services', {})

            for service_name, service_data in services.items():
                service_findings = service_data.get('findings', {})
                for finding_id, finding_data in service_findings.items():
                    if finding_data.get('flagged_items', 0) > 0:
                        severity = self._map_scoutsuite_severity(finding_data.get('level', 'warning'))
                        for item in finding_data.get('items', []):
                            findings.append(CloudFinding(
                                provider=provider,
                                service=service_name,
                                resource_id=item,
                                resource_name=item,
                                title=finding_data.get('description', finding_id),
                                description=finding_data.get('rationale', ''),
                                severity=severity,
                                recommendation=finding_data.get('remediation', ''),
                                compliance=finding_data.get('compliance', [])
                            ))
        except Exception as e:
            self._log(f"Error parsing ScoutSuite results: {e}", "warning")

        return findings

    def _parse_prowler_results(self, results_file: Path) -> List[CloudFinding]:
        """Parse Prowler JSON results."""
        findings = []

        try:
            with open(results_file) as f:
                for line in f:
                    if line.strip():
                        check = json.loads(line)
                        if check.get('StatusExtended', '').upper() == 'FAIL':
                            findings.append(CloudFinding(
                                provider="aws",
                                service=check.get('ServiceName', 'unknown'),
                                resource_id=check.get('ResourceId', ''),
                                resource_name=check.get('ResourceName', ''),
                                title=check.get('CheckTitle', ''),
                                description=check.get('StatusExtended', ''),
                                severity=check.get('Severity', 'medium').lower(),
                                recommendation=check.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                                region=check.get('Region', ''),
                                account_id=check.get('AccountId', ''),
                                compliance=check.get('Compliance', [])
                            ))
        except Exception as e:
            self._log(f"Error parsing Prowler results: {e}", "warning")

        return findings

    def _map_scoutsuite_severity(self, level: str) -> str:
        """Map ScoutSuite severity to standard levels."""
        mapping = {
            "danger": "critical",
            "warning": "high",
            "info": "medium"
        }
        return mapping.get(level.lower(), "medium")

    def get_findings_by_severity(self, severity: str) -> List[CloudFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def get_findings_by_provider(self, provider: str) -> List[CloudFinding]:
        """Get findings filtered by provider."""
        return [f for f in self.findings if f.provider.lower() == provider.lower()]

    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary."""
        summary = {
            "total_findings": len(self.findings),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_provider": {},
            "by_service": {}
        }

        for finding in self.findings:
            # Count by severity
            sev = finding.severity.lower()
            if sev in summary["by_severity"]:
                summary["by_severity"][sev] += 1

            # Count by provider
            provider = finding.provider
            if provider not in summary["by_provider"]:
                summary["by_provider"][provider] = 0
            summary["by_provider"][provider] += 1

            # Count by service
            service = f"{finding.provider}:{finding.service}"
            if service not in summary["by_service"]:
                summary["by_service"][service] = 0
            summary["by_service"][service] += 1

        return summary


# Convenience functions
def get_cloud_scanner(
    providers: Optional[List[str]] = None,
    aws_profile: Optional[str] = None,
    azure_subscription: Optional[str] = None,
    gcp_project: Optional[str] = None,
    **kwargs
) -> CloudScanner:
    """
    Get a configured cloud scanner instance.

    Args:
        providers: Cloud providers to scan
        aws_profile: AWS CLI profile name
        azure_subscription: Azure subscription ID
        gcp_project: GCP project ID

    Returns:
        CloudScanner instance
    """
    config = get_cloud_config(
        providers=providers,
        aws_profile=aws_profile,
        azure_subscription=azure_subscription,
        gcp_project=gcp_project,
        **kwargs
    )
    return CloudScanner(config)


async def scan_cloud(
    providers: Optional[List[str]] = None,
    **kwargs
) -> List[CloudScanResult]:
    """
    Run cloud security scan.

    Args:
        providers: Cloud providers to scan
        **kwargs: Additional configuration

    Returns:
        List of CloudScanResult
    """
    scanner = get_cloud_scanner(providers=providers, **kwargs)
    return await scanner.scan()
