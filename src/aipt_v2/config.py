"""
AIPT v2 Configuration Management
================================

Centralized configuration with validation using Pydantic.
Loads from environment variables with sensible defaults.
"""

import os
from typing import List, Optional
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings

from .utils.logging import logger


class LLMSettings(BaseModel):
    """LLM provider configuration."""

    provider: str = Field(default="anthropic", description="LLM provider name")
    model: str = Field(default="claude-sonnet-4-20250514", description="Model identifier")
    api_key: Optional[str] = Field(default=None, description="API key")
    api_base: Optional[str] = Field(default=None, description="Custom API base URL")
    timeout: int = Field(default=120, ge=10, le=600, description="Request timeout in seconds")
    max_tokens: int = Field(default=4096, ge=100, le=128000, description="Max response tokens")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Sampling temperature")
    enable_caching: bool = Field(default=True, description="Enable prompt caching")

    @field_validator("api_key", mode="before")
    @classmethod
    def get_api_key_from_env(cls, v):
        if v:
            return v
        # Try common environment variables
        for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY"]:
            if os.getenv(key):
                return os.getenv(key)
        return None


class ScannerSettings(BaseModel):
    """Enterprise scanner configuration."""

    # Acunetix
    acunetix_url: Optional[str] = Field(default=None, description="Acunetix API URL")
    acunetix_api_key: Optional[str] = Field(default=None, description="Acunetix API key")

    # Burp Suite
    burp_url: Optional[str] = Field(default=None, description="Burp Suite API URL")
    burp_api_key: Optional[str] = Field(default=None, description="Burp Suite API key")

    # Nessus
    nessus_url: Optional[str] = Field(default=None, description="Nessus API URL")
    nessus_access_key: Optional[str] = Field(default=None, description="Nessus access key")
    nessus_secret_key: Optional[str] = Field(default=None, description="Nessus secret key")

    # OWASP ZAP
    zap_url: Optional[str] = Field(default=None, description="ZAP API URL")
    zap_api_key: Optional[str] = Field(default=None, description="ZAP API key")

    @field_validator("acunetix_url", "burp_url", "nessus_url", "zap_url", mode="before")
    @classmethod
    def validate_url(cls, v):
        if v and not v.startswith(("http://", "https://")):
            raise ValueError(f"Invalid URL format: {v}")
        return v


class VPSSettings(BaseModel):
    """VPS execution configuration."""

    host: Optional[str] = Field(default=None, description="VPS hostname or IP")
    user: str = Field(default="ubuntu", description="SSH username")
    key_path: Optional[str] = Field(default=None, description="Path to SSH private key")
    port: int = Field(default=22, ge=1, le=65535, description="SSH port")
    # Security: Use /var/tmp for longer-lived temp files (survives reboots)
    # The directory should be created with restricted permissions (700) on the VPS
    results_dir: str = Field(
        default="/var/tmp/aipt_results",
        description="Remote results directory (should be created with mode 700)"
    )
    timeout: int = Field(default=300, ge=30, le=3600, description="Command timeout in seconds")

    @field_validator("key_path", mode="before")
    @classmethod
    def expand_key_path(cls, v):
        if v:
            return str(Path(v).expanduser().resolve())
        return v


class APISettings(BaseModel):
    """REST API configuration."""

    # Security: Default to localhost to avoid accidental exposure (CWE-605)
    # Use AIPT_API__HOST=0.0.0.0 for production deployments behind a reverse proxy
    host: str = Field(default="127.0.0.1", description="API host (use 0.0.0.0 for network access)")
    port: int = Field(default=8000, ge=1, le=65535, description="API port")
    cors_origins: List[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins"
    )
    rate_limit: str = Field(default="100/minute", description="Rate limit per client")
    enable_docs: bool = Field(default=True, description="Enable Swagger/OpenAPI docs")


class DatabaseSettings(BaseModel):
    """Database configuration."""

    url: str = Field(default="sqlite:///./aipt.db", description="Database connection URL")
    echo: bool = Field(default=False, description="Echo SQL queries")
    pool_size: int = Field(default=5, ge=1, le=100, description="Connection pool size")


class LoggingSettings(BaseModel):
    """Logging configuration."""

    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="console", description="Log format (console or json)")
    redact_secrets: bool = Field(default=True, description="Redact sensitive values in logs")


class AIPTConfig(BaseSettings):
    """
    Main AIPT v2 configuration.

    Loads from environment variables with AIPT_ prefix.
    """

    # Sub-configurations
    llm: LLMSettings = Field(default_factory=LLMSettings)
    scanners: ScannerSettings = Field(default_factory=ScannerSettings)
    vps: VPSSettings = Field(default_factory=VPSSettings)
    api: APISettings = Field(default_factory=APISettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    # General settings
    sandbox_mode: bool = Field(default=False, description="Run tools in sandbox")
    output_dir: Path = Field(default=Path("./results"), description="Output directory")
    reports_dir: Path = Field(default=Path("./reports"), description="Reports directory")

    model_config = {
        "env_prefix": "AIPT_",
        "env_nested_delimiter": "__",
        "case_sensitive": False,
    }

    @model_validator(mode="after")
    def create_directories(self):
        """Ensure output directories exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        return self


@lru_cache(maxsize=1)
def get_config() -> AIPTConfig:
    """
    Get the global configuration instance.

    Returns:
        AIPTConfig instance loaded from environment
    """
    # Load from environment
    config = AIPTConfig(
        llm=LLMSettings(
            provider=os.getenv("AIPT_LLM_PROVIDER", "anthropic"),
            model=os.getenv("AIPT_LLM_MODEL", "claude-sonnet-4-20250514"),
            api_key=os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY"),
            timeout=int(os.getenv("AIPT_LLM_TIMEOUT", "120")),
        ),
        scanners=ScannerSettings(
            acunetix_url=os.getenv("ACUNETIX_URL"),
            acunetix_api_key=os.getenv("ACUNETIX_API_KEY"),
            burp_url=os.getenv("BURP_URL"),
            burp_api_key=os.getenv("BURP_API_KEY"),
            nessus_url=os.getenv("NESSUS_URL"),
            nessus_access_key=os.getenv("NESSUS_ACCESS_KEY"),
            nessus_secret_key=os.getenv("NESSUS_SECRET_KEY"),
            zap_url=os.getenv("ZAP_URL"),
            zap_api_key=os.getenv("ZAP_API_KEY"),
        ),
        vps=VPSSettings(
            host=os.getenv("VPS_HOST"),
            user=os.getenv("VPS_USER", "ubuntu"),
            key_path=os.getenv("VPS_KEY"),
        ),
        api=APISettings(
            cors_origins=os.getenv("AIPT_CORS_ORIGINS", "http://localhost:3000").split(","),
            rate_limit=os.getenv("AIPT_RATE_LIMIT", "100/minute"),
        ),
        database=DatabaseSettings(
            url=os.getenv("DATABASE_URL", "sqlite:///./aipt.db"),
        ),
        logging=LoggingSettings(
            level=os.getenv("AIPT_LOG_LEVEL", "INFO"),
            format=os.getenv("AIPT_LOG_FORMAT", "console"),
        ),
        sandbox_mode=os.getenv("AIPT_SANDBOX_MODE", "false").lower() == "true",
    )

    # Log configuration (without secrets)
    logger.info(
        "Configuration loaded",
        llm_provider=config.llm.provider,
        llm_model=config.llm.model,
        has_llm_key=bool(config.llm.api_key),
        has_acunetix=bool(config.scanners.acunetix_url),
        has_burp=bool(config.scanners.burp_url),
        has_nessus=bool(config.scanners.nessus_url),
        has_vps=bool(config.vps.host),
        sandbox_mode=config.sandbox_mode,
    )

    return config


def validate_config_for_features(features: List[str]) -> List[str]:
    """
    Validate that required configuration is present for requested features.

    Args:
        features: List of feature names to validate

    Returns:
        List of error messages (empty if all valid)
    """
    config = get_config()
    errors = []

    if "llm" in features and not config.llm.api_key:
        errors.append(
            "LLM API key required. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable."
        )

    if "acunetix" in features:
        if not config.scanners.acunetix_url:
            errors.append("Acunetix URL required. Set ACUNETIX_URL environment variable.")
        if not config.scanners.acunetix_api_key:
            errors.append("Acunetix API key required. Set ACUNETIX_API_KEY environment variable.")

    if "burp" in features:
        if not config.scanners.burp_url:
            errors.append("Burp Suite URL required. Set BURP_URL environment variable.")
        if not config.scanners.burp_api_key:
            errors.append("Burp Suite API key required. Set BURP_API_KEY environment variable.")

    if "nessus" in features:
        if not config.scanners.nessus_url:
            errors.append("Nessus URL required. Set NESSUS_URL environment variable.")
        if not config.scanners.nessus_access_key:
            errors.append("Nessus access key required. Set NESSUS_ACCESS_KEY environment variable.")
        if not config.scanners.nessus_secret_key:
            errors.append("Nessus secret key required. Set NESSUS_SECRET_KEY environment variable.")

    if "vps" in features:
        if not config.vps.host:
            errors.append("VPS host required. Set VPS_HOST environment variable.")
        if not config.vps.key_path:
            errors.append("VPS SSH key path required. Set VPS_KEY environment variable.")
        elif not Path(config.vps.key_path).exists():
            errors.append(f"VPS SSH key not found: {config.vps.key_path}")

    return errors


# Convenience function
def require_config(*features: str) -> AIPTConfig:
    """
    Get config and raise if required features are not configured.

    Args:
        *features: Feature names to validate

    Returns:
        AIPTConfig instance

    Raises:
        ValueError: If required configuration is missing
    """
    errors = validate_config_for_features(list(features))
    if errors:
        raise ValueError("Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))
    return get_config()
