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

from .subdomain import (
    SubdomainEnumerator,
    SubdomainConfig,
    SubdomainResult,
)
from .tech_detect import (
    TechDetector,
    Technology,
    TechStack,
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
from .ad_discovery import (
    ADDiscovery,
    ADDiscoveryConfig,
    ADDiscoveryResult,
    DomainController,
    DomainTrust,
    ForestInfo,
    ADServiceType,
    discover_domain,
    find_domain_controllers,
)
from .ad_users import (
    ADUserEnumerator,
    ADUserEnumConfig,
    ADUserEnumResult,
    ADUser,
    EnumMethod,
    enumerate_users,
    find_kerberoastable_users,
    find_asrep_roastable_users,
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
