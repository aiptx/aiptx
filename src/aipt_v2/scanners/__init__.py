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
]
