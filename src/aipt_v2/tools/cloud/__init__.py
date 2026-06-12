"""
AIPT Cloud Security Module - Multi-Cloud Vulnerability Scanning

Provides comprehensive cloud security assessment for:
- AWS (Amazon Web Services)
- Azure (Microsoft Azure)
- GCP (Google Cloud Platform)

Tools integrated:
- ScoutSuite: Multi-cloud security auditing
- Prowler: AWS security best practices
- Custom checks: IAM, S3, Security Groups, etc.

Usage:
    from aipt_v2.tools.cloud import CloudScanner, get_cloud_scanner

    scanner = get_cloud_scanner(provider="aws", profile="default")
    findings = await scanner.scan()
"""

from aipt_v2.tools.cloud.cloud_config import (
    AWSConfig,
    AzureConfig,
    CloudConfig,
    GCPConfig,
    get_cloud_config,
)
from aipt_v2.tools.cloud.cloud_scanner import (
    CloudFinding,
    CloudScanner,
    CloudSeverity,
    get_cloud_scanner,
    scan_cloud,
)
from aipt_v2.tools.cloud.prowler_tool import (
    ProwlerConfig,
    ProwlerTool,
    run_prowler,
)
from aipt_v2.tools.cloud.scoutsuite_tool import (
    ScoutSuiteConfig,
    ScoutSuiteTool,
    run_scoutsuite,
)

__all__ = [
    # Configuration
    "CloudConfig",
    "AWSConfig",
    "AzureConfig",
    "GCPConfig",
    "get_cloud_config",
    # Scanner
    "CloudScanner",
    "CloudFinding",
    "CloudSeverity",
    "get_cloud_scanner",
    "scan_cloud",
    # ScoutSuite
    "ScoutSuiteTool",
    "ScoutSuiteConfig",
    "run_scoutsuite",
    # Prowler
    "ProwlerTool",
    "ProwlerConfig",
    "run_prowler",
]
