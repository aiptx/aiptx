"""
Cloud Configuration Management

Handles credentials and configuration for multi-cloud security scanning.
Supports AWS profiles, Azure subscriptions, and GCP projects.
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class AWSConfig:
    """AWS-specific configuration."""
    profile: str = "default"
    region: str = "us-east-1"
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None

    # Scanning options
    services: List[str] = field(default_factory=lambda: [
        "iam", "s3", "ec2", "rds", "lambda", "cloudtrail",
        "cloudwatch", "kms", "sns", "sqs", "vpc", "elb"
    ])
    skip_services: List[str] = field(default_factory=list)

    def __post_init__(self):
        # Load from environment if not provided
        if not self.access_key_id:
            self.access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        if not self.secret_access_key:
            self.secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        if not self.session_token:
            self.session_token = os.getenv("AWS_SESSION_TOKEN")
        if self.region == "us-east-1":
            self.region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    def is_configured(self) -> bool:
        """Check if AWS credentials are available."""
        # Either profile-based or key-based auth
        if self.profile:
            # Check if credentials file exists
            creds_file = Path.home() / ".aws" / "credentials"
            return creds_file.exists()
        return bool(self.access_key_id and self.secret_access_key)

    def to_env_dict(self) -> Dict[str, str]:
        """Convert to environment variables dict."""
        env = {"AWS_DEFAULT_REGION": self.region}
        if self.profile:
            env["AWS_PROFILE"] = self.profile
        if self.access_key_id:
            env["AWS_ACCESS_KEY_ID"] = self.access_key_id
        if self.secret_access_key:
            env["AWS_SECRET_ACCESS_KEY"] = self.secret_access_key
        if self.session_token:
            env["AWS_SESSION_TOKEN"] = self.session_token
        return env


@dataclass
class AzureConfig:
    """Azure-specific configuration."""
    subscription_id: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    # Use Azure CLI auth by default
    use_cli_auth: bool = True

    # Scanning options
    resource_groups: List[str] = field(default_factory=list)  # Empty = all

    def __post_init__(self):
        # Load from environment if not provided
        if not self.subscription_id:
            self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        if not self.tenant_id:
            self.tenant_id = os.getenv("AZURE_TENANT_ID")
        if not self.client_id:
            self.client_id = os.getenv("AZURE_CLIENT_ID")
        if not self.client_secret:
            self.client_secret = os.getenv("AZURE_CLIENT_SECRET")

    def is_configured(self) -> bool:
        """Check if Azure credentials are available."""
        if self.use_cli_auth:
            # Check for Azure CLI
            return Path.home().joinpath(".azure").exists()
        return bool(self.subscription_id and self.tenant_id and
                    self.client_id and self.client_secret)

    def to_env_dict(self) -> Dict[str, str]:
        """Convert to environment variables dict."""
        env = {}
        if self.subscription_id:
            env["AZURE_SUBSCRIPTION_ID"] = self.subscription_id
        if self.tenant_id:
            env["AZURE_TENANT_ID"] = self.tenant_id
        if self.client_id:
            env["AZURE_CLIENT_ID"] = self.client_id
        if self.client_secret:
            env["AZURE_CLIENT_SECRET"] = self.client_secret
        return env


@dataclass
class GCPConfig:
    """GCP-specific configuration."""
    project_id: Optional[str] = None
    credentials_file: Optional[str] = None

    # Use application default credentials
    use_adc: bool = True

    # Scanning options
    regions: List[str] = field(default_factory=list)  # Empty = all

    def __post_init__(self):
        # Load from environment if not provided
        if not self.project_id:
            self.project_id = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
        if not self.credentials_file:
            self.credentials_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

    def is_configured(self) -> bool:
        """Check if GCP credentials are available."""
        if self.use_adc:
            # Check for application default credentials
            adc_path = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
            return adc_path.exists() or bool(self.credentials_file)
        return bool(self.project_id and self.credentials_file)

    def to_env_dict(self) -> Dict[str, str]:
        """Convert to environment variables dict."""
        env = {}
        if self.project_id:
            env["GOOGLE_CLOUD_PROJECT"] = self.project_id
        if self.credentials_file:
            env["GOOGLE_APPLICATION_CREDENTIALS"] = self.credentials_file
        return env


@dataclass
class CloudConfig:
    """Unified cloud configuration."""

    # Provider configs
    aws: AWSConfig = field(default_factory=AWSConfig)
    azure: AzureConfig = field(default_factory=AzureConfig)
    gcp: GCPConfig = field(default_factory=GCPConfig)

    # General settings
    providers: List[str] = field(default_factory=lambda: ["aws"])
    output_dir: str = "./cloud_scan_results"
    severity_threshold: str = "low"  # low, medium, high, critical

    # Scanning options
    parallel_scans: bool = True
    max_workers: int = 5
    timeout: int = 3600  # 1 hour default

    def get_configured_providers(self) -> List[str]:
        """Get list of providers with valid credentials."""
        configured = []
        if "aws" in self.providers and self.aws.is_configured():
            configured.append("aws")
        if "azure" in self.providers and self.azure.is_configured():
            configured.append("azure")
        if "gcp" in self.providers and self.gcp.is_configured():
            configured.append("gcp")
        return configured

    def get_provider_config(self, provider: str) -> Any:
        """Get configuration for a specific provider."""
        provider_map = {
            "aws": self.aws,
            "azure": self.azure,
            "gcp": self.gcp
        }
        return provider_map.get(provider.lower())


def get_cloud_config(
    providers: Optional[List[str]] = None,
    aws_profile: Optional[str] = None,
    azure_subscription: Optional[str] = None,
    gcp_project: Optional[str] = None,
    **kwargs
) -> CloudConfig:
    """
    Create CloudConfig from parameters and environment.

    Args:
        providers: List of cloud providers to scan ("aws", "azure", "gcp")
        aws_profile: AWS CLI profile name
        azure_subscription: Azure subscription ID
        gcp_project: GCP project ID
        **kwargs: Additional configuration options

    Returns:
        CloudConfig instance
    """
    # Build AWS config
    aws_config = AWSConfig(
        profile=aws_profile or os.getenv("AWS_PROFILE", "default"),
        region=kwargs.get("aws_region", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    )

    # Build Azure config
    azure_config = AzureConfig(
        subscription_id=azure_subscription or os.getenv("AZURE_SUBSCRIPTION_ID")
    )

    # Build GCP config
    gcp_config = GCPConfig(
        project_id=gcp_project or os.getenv("GOOGLE_CLOUD_PROJECT")
    )

    # Determine providers
    if providers is None:
        providers = ["aws"]  # Default to AWS only

    return CloudConfig(
        aws=aws_config,
        azure=azure_config,
        gcp=gcp_config,
        providers=providers,
        output_dir=kwargs.get("output_dir", "./cloud_scan_results"),
        severity_threshold=kwargs.get("severity_threshold", "low"),
        timeout=kwargs.get("timeout", 3600)
    )


def validate_cloud_credentials() -> Dict[str, Dict[str, Any]]:
    """
    Validate credentials for all cloud providers.

    Returns:
        Dict with validation results per provider
    """
    results = {}

    # Check AWS
    aws_config = AWSConfig()
    results["aws"] = {
        "configured": aws_config.is_configured(),
        "profile": aws_config.profile,
        "region": aws_config.region,
        "has_keys": bool(aws_config.access_key_id)
    }

    # Check Azure
    azure_config = AzureConfig()
    results["azure"] = {
        "configured": azure_config.is_configured(),
        "subscription": azure_config.subscription_id,
        "use_cli": azure_config.use_cli_auth
    }

    # Check GCP
    gcp_config = GCPConfig()
    results["gcp"] = {
        "configured": gcp_config.is_configured(),
        "project": gcp_config.project_id,
        "use_adc": gcp_config.use_adc
    }

    return results
