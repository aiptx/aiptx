"""
AIPT Scanners Module

Integrations with popular security scanning tools:
- Nuclei - Template-based vulnerability scanner
- Nmap - Network scanner
- Nikto - Web server scanner
- SQLMap - SQL injection scanner
- Gobuster - Directory/DNS brute-forcing
- Ffuf - Fast web fuzzer
- Dalfox - XSS scanner
- Httpx - HTTP probing
- Dnsx - DNS toolkit
- Katana - Web crawler
- Hydra - Login cracker
- WPScan - WordPress scanner
- Trivy - Container/filesystem CVE scanner
- Subfinder - Subdomain discovery
- Amass - Attack surface mapping
- TestSSL - SSL/TLS testing
- PAT - PayloadsAllTheThings vulnerability scanner
"""

# PowerShell Arsenal Scanner
from aipt_v2.tools.ps_arsenal import (
    PSArsenalScanner,
    PSScanConfig,
)
from aipt_v2.tools.ps_arsenal import ScanFinding as PSArsenalScanFinding
from aipt_v2.tools.ps_arsenal import ScanResult as PSArsenalScanResult
from aipt_v2.tools.ps_arsenal import (
    create_ps_scanner,
)

from .ad_adcs_scanner import (
    ADCSConfig,
    ADCSResult,
    ADCSScanner,
    CertificateAuthority,
    CertificateTemplate,
    ESCType,
    scan_adcs,
)

# AD Scanners
from .ad_privesc_scanner import (
    ADFindingType,
    ADPrivescConfig,
    ADPrivescResult,
    ADPrivescScanner,
    ADPrivilegedAccount,
    scan_ad_privesc,
)
from .base import BaseScanner, ScanFinding, ScanResult, ScanSeverity
from .dalfox import DalfoxConfig, DalfoxScanner

# Exploit scanners
from .exploit import HydraConfig, HydraScanner, SqlmapConfig, SqlmapScanner
from .ffuf import FfufConfig, FfufScanner
from .gobuster import GobusterConfig, GobusterScanner
from .nikto import NiktoScanner
from .nmap import NmapConfig, NmapScanner
from .nuclei import NucleiConfig, NucleiScanner

# PAT - PayloadsAllTheThings Scanner
from .pat import (
    DetectionMethod,
    InjectionPoint,
    PATScanConfig,
    PATScanner,
    PATScanResult,
    PayloadDatabase,
    PayloadTechnique,
    VulnerabilityType,
)
from .pat import scan_url as pat_scan_url
from .pat import update_payloads as pat_update_payloads

# Recon scanners
from .recon import (
    AmassConfig,
    AmassScanner,
    DnsxConfig,
    DnsxScanner,
    HttpxConfig,
    HttpxScanner,
    KatanaConfig,
    KatanaScanner,
    SubfinderConfig,
    SubfinderScanner,
)
from .testssl import TestSSLConfig, TestSSLScanner
from .trivy import TrivyConfig, TrivyScanner
from .web import WebScanConfig, WebScanner

# WinPwn Windows/AD Scanner
from .winpwn_scanner import (
    WinPwnScanConfig,
    WinPwnScanner,
    WinPwnScanResult,
    scan_ad_with_winpwn,
    scan_windows,
)
from .wpscan import WPScanConfig, WPScanScanner

__all__ = [
    # Base
    "BaseScanner",
    "ScanResult",
    "ScanFinding",
    "ScanSeverity",
    # Core scanners
    "NucleiScanner",
    "NucleiConfig",
    "NmapScanner",
    "NmapConfig",
    "NiktoScanner",
    "WebScanner",
    "WebScanConfig",
    # Web fuzzers & scanners
    "FfufScanner",
    "FfufConfig",
    "DalfoxScanner",
    "DalfoxConfig",
    "GobusterScanner",
    "GobusterConfig",
    "WPScanScanner",
    "WPScanConfig",
    "TrivyScanner",
    "TrivyConfig",
    "TestSSLScanner",
    "TestSSLConfig",
    # Recon scanners
    "HttpxScanner",
    "HttpxConfig",
    "DnsxScanner",
    "DnsxConfig",
    "KatanaScanner",
    "KatanaConfig",
    "SubfinderScanner",
    "SubfinderConfig",
    "AmassScanner",
    "AmassConfig",
    # Exploit scanners
    "SqlmapScanner",
    "SqlmapConfig",
    "HydraScanner",
    "HydraConfig",
    # AD Scanners
    "ADPrivescScanner",
    "ADPrivescConfig",
    "ADPrivescResult",
    "ADPrivilegedAccount",
    "ADFindingType",
    "scan_ad_privesc",
    # ADCS Scanner
    "ADCSScanner",
    "ADCSConfig",
    "ADCSResult",
    "CertificateAuthority",
    "CertificateTemplate",
    "ESCType",
    "scan_adcs",
    # WinPwn Scanner
    "WinPwnScanner",
    "WinPwnScanConfig",
    "WinPwnScanResult",
    "scan_windows",
    "scan_ad_with_winpwn",
    # PAT Scanner
    "PATScanner",
    "PATScanConfig",
    "PATScanResult",
    "VulnerabilityType",
    "InjectionPoint",
    "PayloadTechnique",
    "DetectionMethod",
    "PayloadDatabase",
    "pat_scan_url",
    "pat_update_payloads",
    # PowerShell Arsenal Scanner
    "PSArsenalScanner",
    "PSScanConfig",
    "PSArsenalScanResult",
    "PSArsenalScanFinding",
    "create_ps_scanner",
]
