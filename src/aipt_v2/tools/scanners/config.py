"""
AIPT Scanner Configuration - Centralized Scanner Settings

This file contains all configuration for external security scanners.
Modify these settings to connect to different scanner instances.
"""

import os
from dataclasses import dataclass
from typing import Optional


# ==================== Server Configuration ====================

# Remote Scanner Server - MUST be configured via environment variable
# No default IP - users must explicitly configure their scanner server
SCANNER_SERVER_IP = os.getenv("AIPT_SCANNER_IP", "localhost")

# Port Configuration
ACUNETIX_PORT = int(os.getenv("AIPT_ACUNETIX_PORT", "3443"))
BURP_PORT = int(os.getenv("AIPT_BURP_PORT", "1337"))

# Full URLs - default to localhost (safe default)
ACUNETIX_URL = os.getenv("AIPT_ACUNETIX_URL", f"https://{SCANNER_SERVER_IP}:{ACUNETIX_PORT}")
BURP_URL = os.getenv("AIPT_BURP_URL", f"http://{SCANNER_SERVER_IP}:{BURP_PORT}/v0.1")


# ==================== Acunetix Configuration ====================

@dataclass
class AcunetixSettings:
    """Acunetix scanner settings."""
    base_url: str = ACUNETIX_URL
    # API key MUST be provided via environment variable - no default for security
    api_key: str = os.getenv("AIPT_ACUNETIX_API_KEY", "")
    verify_ssl: bool = False
    timeout: int = 120  # Increased from 30 to handle slow responses during polling

    # Default scan settings
    default_profile: str = "full"  # full, high_risk, xss, sqli, crawl, malware
    default_criticality: int = 10  # 0-30 (10=normal, 30=critical)

    # Rate limiting
    max_concurrent_scans: int = 5
    poll_interval: int = 30  # seconds


# ==================== Burp Suite Configuration ====================

@dataclass
class BurpSettings:
    """Burp Suite scanner settings."""
    base_url: str = BURP_URL
    # API key MUST be provided via environment variable - no default for security
    api_key: str = os.getenv("AIPT_BURP_API_KEY", "")
    verify_ssl: bool = False
    timeout: int = 120  # Increased from 30 to handle slow responses during polling

    # Default scan settings
    default_config: Optional[str] = None  # Scan configuration ID

    # Rate limiting
    max_concurrent_scans: int = 3
    poll_interval: int = 30  # seconds


# ==================== Global Settings ====================

@dataclass
class ScannerSettings:
    """Global scanner settings."""
    # Timeouts
    scan_timeout: int = 3600  # 1 hour max per scan
    connection_timeout: int = 30

    # Output
    save_reports: bool = True
    report_dir: str = "reports/scanners"
    report_format: str = "html"  # html, pdf, xml

    # Finding thresholds
    min_severity: str = "info"  # info, low, medium, high, critical
    deduplicate_findings: bool = True

    # Retry settings
    max_retries: int = 3
    retry_delay: int = 5  # seconds


# ==================== Default Instances ====================

ACUNETIX = AcunetixSettings()
BURP = BurpSettings()
SCANNER = ScannerSettings()


# ==================== Configuration Helpers ====================

def get_acunetix_config() -> dict:
    """Get Acunetix configuration as dict for tool initialization."""
    return {
        "base_url": ACUNETIX.base_url,
        "api_key": ACUNETIX.api_key,
        "verify_ssl": ACUNETIX.verify_ssl,
        "timeout": ACUNETIX.timeout
    }


def get_burp_config() -> dict:
    """Get Burp Suite configuration as dict for tool initialization."""
    return {
        "base_url": BURP.base_url,
        "api_key": BURP.api_key,
        "verify_ssl": BURP.verify_ssl,
        "timeout": BURP.timeout
    }


def print_config():
    """Print current scanner configuration."""
    print("=" * 60)
    print("AIPT Scanner Configuration")
    print("=" * 60)
    print(f"\nServer IP: {SCANNER_SERVER_IP}")
    print(f"\nAcunetix:")
    print(f"  URL:     {ACUNETIX.base_url}")
    print(f"  API Key: {ACUNETIX.api_key[:20]}..." if ACUNETIX.api_key else "  API Key: Not set")
    print(f"  SSL:     {ACUNETIX.verify_ssl}")
    print(f"\nBurp Suite:")
    print(f"  URL:     {BURP.base_url}")
    print(f"  API Key: {BURP.api_key[:20]}..." if BURP.api_key else "  API Key: Not set")
    print(f"  SSL:     {BURP.verify_ssl}")
    print("=" * 60)


# ==================== Environment Variable Reference ====================
"""
Environment variables for configuration (REQUIRED for scanner functionality):

    AIPT_SCANNER_IP         - Scanner server IP (default: localhost)
    AIPT_ACUNETIX_PORT      - Acunetix port (default: 3443)
    AIPT_BURP_PORT          - Burp port (default: 1337)
    AIPT_ACUNETIX_URL       - Full Acunetix URL (overrides IP+port)
    AIPT_BURP_URL           - Full Burp URL (overrides IP+port)
    AIPT_ACUNETIX_API_KEY   - Acunetix API key (REQUIRED - no default)
    AIPT_BURP_API_KEY       - Burp Suite API key (REQUIRED - no default)

Example:
    export AIPT_SCANNER_IP="your-scanner-server.local"
    export AIPT_ACUNETIX_API_KEY="your-acunetix-api-key"
    export AIPT_BURP_API_KEY="your-burp-api-key"

SECURITY NOTE: Never commit API keys to source control. Always use environment
variables or a secure secrets manager.
"""


if __name__ == "__main__":
    print_config()
