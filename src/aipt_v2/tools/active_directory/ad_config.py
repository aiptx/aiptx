"""
Active Directory Configuration

Handles credentials and configuration for AD penetration testing.
Supports multiple authentication methods:
- Password authentication
- NTLM hash authentication (pass-the-hash)
- Kerberos ticket authentication

Usage:
    from aipt_v2.tools.active_directory import ADConfig, get_ad_config

    config = get_ad_config(
        domain="corp.local",
        dc_ip="10.0.0.1",
        username="admin",
        password="secret"
    )
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class ADCredentials:
    """Active Directory credentials."""
    username: str = ""
    password: str = ""
    domain: str = ""

    # Alternative auth methods
    ntlm_hash: str = ""  # Format: LMHASH:NTHASH or just NTHASH
    aes_key: str = ""    # Kerberos AES key
    ccache_file: str = ""  # Kerberos ticket cache

    # Kerberos options
    use_kerberos: bool = False
    kdcHost: str = ""

    def __post_init__(self):
        """Load from environment if not provided."""
        if not self.username:
            self.username = os.getenv("AD_USERNAME", "")
        if not self.password:
            self.password = os.getenv("AD_PASSWORD", "")
        if not self.domain:
            self.domain = os.getenv("AD_DOMAIN", "")
        if not self.ntlm_hash:
            self.ntlm_hash = os.getenv("AD_NTLM_HASH", "")
        if not self.ccache_file:
            self.ccache_file = os.getenv("KRB5CCNAME", "")

    def get_auth_string(self) -> str:
        """Get authentication string for tools."""
        if self.domain and self.username:
            return f"{self.domain}\\{self.username}"
        return self.username

    def has_credentials(self) -> bool:
        """Check if valid credentials are available."""
        return bool(
            (self.username and self.password) or
            (self.username and self.ntlm_hash) or
            self.ccache_file
        )

    def is_hash_auth(self) -> bool:
        """Check if using hash-based authentication."""
        return bool(self.ntlm_hash and not self.password)

    def get_password_or_hash(self) -> str:
        """Get password or hash for authentication."""
        return self.password if self.password else self.ntlm_hash


@dataclass
class ADConfig:
    """Active Directory scanning configuration."""
    # Domain settings
    domain: str = ""
    dc_ip: str = ""
    dc_hostname: str = ""

    # Credentials
    credentials: ADCredentials = field(default_factory=ADCredentials)

    # Target settings
    target_users: List[str] = field(default_factory=list)
    target_groups: List[str] = field(default_factory=list)
    target_computers: List[str] = field(default_factory=list)

    # Scanning options
    enum_users: bool = True
    enum_groups: bool = True
    enum_computers: bool = True
    enum_gpos: bool = True
    enum_trusts: bool = True

    # Attack options
    run_kerberoast: bool = False
    run_asreproast: bool = False
    run_bloodhound: bool = False

    # Output
    output_dir: str = "./ad_results"

    # LDAP settings
    ldap_port: int = 389
    ldaps_port: int = 636
    use_ssl: bool = False
    use_gc: bool = False  # Global Catalog (port 3268/3269)

    # Timeouts
    timeout: int = 30

    def __post_init__(self):
        """Initialize from environment."""
        if not self.domain:
            self.domain = os.getenv("AD_DOMAIN", "")
        if not self.dc_ip:
            self.dc_ip = os.getenv("AD_DC_IP", os.getenv("DC_IP", ""))

        # Ensure credentials have domain
        if self.domain and not self.credentials.domain:
            self.credentials.domain = self.domain

    def get_ldap_uri(self) -> str:
        """Get LDAP connection URI."""
        protocol = "ldaps" if self.use_ssl else "ldap"
        port = self.ldaps_port if self.use_ssl else self.ldap_port

        if self.use_gc:
            port = 3269 if self.use_ssl else 3268

        host = self.dc_ip or self.dc_hostname
        return f"{protocol}://{host}:{port}"

    def get_base_dn(self) -> str:
        """Get LDAP base DN from domain."""
        if not self.domain:
            return ""
        parts = self.domain.split(".")
        return ",".join([f"DC={part}" for part in parts])

    def is_configured(self) -> bool:
        """Check if AD is properly configured."""
        return bool(
            self.domain and
            (self.dc_ip or self.dc_hostname) and
            self.credentials.has_credentials()
        )


def get_ad_config(
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    **kwargs
) -> ADConfig:
    """
    Create ADConfig from parameters and environment.

    Args:
        domain: AD domain name (e.g., "corp.local")
        dc_ip: Domain Controller IP address
        username: AD username
        password: AD password
        ntlm_hash: NTLM hash for pass-the-hash
        **kwargs: Additional configuration options

    Returns:
        ADConfig instance
    """
    credentials = ADCredentials(
        username=username or os.getenv("AD_USERNAME", ""),
        password=password or os.getenv("AD_PASSWORD", ""),
        domain=domain or os.getenv("AD_DOMAIN", ""),
        ntlm_hash=ntlm_hash or os.getenv("AD_NTLM_HASH", "")
    )

    return ADConfig(
        domain=domain or os.getenv("AD_DOMAIN", ""),
        dc_ip=dc_ip or os.getenv("AD_DC_IP", ""),
        credentials=credentials,
        output_dir=kwargs.get("output_dir", "./ad_results"),
        use_ssl=kwargs.get("use_ssl", False),
        timeout=kwargs.get("timeout", 30),
        run_kerberoast=kwargs.get("run_kerberoast", False),
        run_asreproast=kwargs.get("run_asreproast", False),
        run_bloodhound=kwargs.get("run_bloodhound", False)
    )


def validate_ad_config(config: ADConfig) -> dict:
    """
    Validate AD configuration.

    Args:
        config: ADConfig to validate

    Returns:
        Dict with validation results
    """
    results = {
        "valid": False,
        "errors": [],
        "warnings": []
    }

    # Check required fields
    if not config.domain:
        results["errors"].append("Domain not specified")

    if not config.dc_ip and not config.dc_hostname:
        results["errors"].append("Domain Controller not specified")

    if not config.credentials.has_credentials():
        results["errors"].append("No valid credentials provided")

    # Check credential format
    if config.credentials.ntlm_hash:
        hash_parts = config.credentials.ntlm_hash.split(":")
        if len(hash_parts) == 2:
            if len(hash_parts[0]) != 32 or len(hash_parts[1]) != 32:
                results["warnings"].append("NTLM hash format may be incorrect")
        elif len(hash_parts) == 1:
            if len(hash_parts[0]) != 32:
                results["warnings"].append("NT hash length should be 32 characters")

    # All good
    if not results["errors"]:
        results["valid"] = True

    return results
