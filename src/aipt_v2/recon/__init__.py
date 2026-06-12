"""
AIPT Recon Module

Reconnaissance and information gathering:
- Subdomain enumeration
- Port scanning
- Technology detection
- DNS analysis
- Whois lookups
- Active Directory discovery
"""

from .ad_discovery import (
    ADDiscovery,
    ADDiscoveryConfig,
    ADDiscoveryResult,
    ADServiceType,
    DomainController,
    DomainTrust,
    ForestInfo,
    discover_domain,
    find_domain_controllers,
)
from .ad_users import (
    ADUser,
    ADUserEnumConfig,
    ADUserEnumerator,
    ADUserEnumResult,
    EnumMethod,
    enumerate_users,
    find_asrep_roastable_users,
    find_kerberoastable_users,
)
from .dns import (
    DNSAnalyzer,
    DNSRecord,
    DNSResult,
)
from .osint import (
    OSINTCollector,
    OSINTResult,
)
from .subdomain import (
    SubdomainConfig,
    SubdomainEnumerator,
    SubdomainResult,
)
from .tech_detect import (
    TechDetector,
    Technology,
    TechStack,
)

__all__ = [
    "SubdomainEnumerator",
    "SubdomainConfig",
    "SubdomainResult",
    "TechDetector",
    "Technology",
    "TechStack",
    "DNSAnalyzer",
    "DNSRecord",
    "DNSResult",
    "OSINTCollector",
    "OSINTResult",
    # AD Discovery
    "ADDiscovery",
    "ADDiscoveryConfig",
    "ADDiscoveryResult",
    "DomainController",
    "DomainTrust",
    "ForestInfo",
    "ADServiceType",
    "discover_domain",
    "find_domain_controllers",
    # AD User Enumeration
    "ADUserEnumerator",
    "ADUserEnumConfig",
    "ADUserEnumResult",
    "ADUser",
    "EnumMethod",
    "enumerate_users",
    "find_kerberoastable_users",
    "find_asrep_roastable_users",
]
