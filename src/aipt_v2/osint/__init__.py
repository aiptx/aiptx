"""
AIPTX OSINT Module - Open Source Intelligence Gathering.

Comprehensive OSINT automation for penetration testing:
- Email harvesting from multiple sources
- Domain reconnaissance and enumeration
- Subdomain discovery via certificate transparency
- Technology fingerprinting
- IP geolocation and intelligence

Added in AIPTX v5.2.

Example usage:
    from aipt_v2.osint import EmailHarvester, DomainRecon

    # Harvest emails
    async with EmailHarvester() as harvester:
        emails = await harvester.harvest("example.com")

    # Domain reconnaissance
    async with DomainRecon() as recon:
        info = await recon.full_recon("example.com")
        print(f"Subdomains: {info.subdomains}")
        print(f"Technologies: {info.technologies}")

    # Convenience functions
    from aipt_v2.osint import harvest_emails, enumerate_subdomains
    emails = await harvest_emails("example.com")
    subs = await enumerate_subdomains("example.com")
"""

from aipt_v2.osint.domain_recon import (
    DomainInfo,
    DomainRecon,
    IPInfo,
    enumerate_subdomains,
    get_ip_info,
    recon_domain,
)
from aipt_v2.osint.email_harvester import (
    EmailHarvester,
    EmailProfile,
    EmailResult,
    harvest_emails,
    validate_email,
)

__all__ = [
    # Email Harvester
    "EmailHarvester",
    "EmailResult",
    "EmailProfile",
    "harvest_emails",
    "validate_email",
    # Domain Recon
    "DomainRecon",
    "DomainInfo",
    "IPInfo",
    "recon_domain",
    "enumerate_subdomains",
    "get_ip_info",
]
