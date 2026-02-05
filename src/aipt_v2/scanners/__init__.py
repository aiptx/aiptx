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

from .base import BaseScanner, ScanResult, ScanFinding, ScanSeverity
from .nuclei import NucleiScanner, NucleiConfig
from .nmap import NmapScanner, NmapConfig
from .nikto import NiktoScanner
from .web import WebScanner, WebScanConfig
from .ffuf import FfufScanner, FfufConfig
from .dalfox import DalfoxScanner, DalfoxConfig
from .wpscan import WPScanScanner, WPScanConfig
from .trivy import TrivyScanner, TrivyConfig
from .gobuster import GobusterScanner, GobusterConfig
from .testssl import TestSSLScanner, TestSSLConfig

# Recon scanners
from .recon import HttpxScanner, HttpxConfig
from .recon import DnsxScanner, DnsxConfig
from .recon import KatanaScanner, KatanaConfig
from .recon import SubfinderScanner, SubfinderConfig
from .recon import AmassScanner, AmassConfig

# Exploit scanners
from .exploit import SqlmapScanner, SqlmapConfig
from .exploit import HydraScanner, HydraConfig

# AD Scanners
from .ad_privesc_scanner import (
    ADPrivescScanner,
    ADPrivescConfig,
    ADPrivescResult,
    ADPrivilegedAccount,
    ADFindingType,
    scan_ad_privesc,
)
from .ad_adcs_scanner import (
    ADCSScanner,
    ADCSConfig,
    ADCSResult,
    CertificateAuthority,
    CertificateTemplate,
    ESCType,
    scan_adcs,
)

# WinPwn Windows/AD Scanner
from .winpwn_scanner import (
    WinPwnScanner,
    WinPwnScanConfig,
    WinPwnScanResult,
    scan_windows,
    scan_ad_with_winpwn,
)

# PAT - PayloadsAllTheThings Scanner
from .pat import (
    PATScanner,
    PATScanConfig,
    PATScanResult,
    VulnerabilityType,
    InjectionPoint,
    PayloadTechnique,
    DetectionMethod,
    PayloadDatabase,
    scan_url as pat_scan_url,
    update_payloads as pat_update_payloads,
)

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
]
