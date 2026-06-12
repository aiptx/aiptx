"""
AIPT Scanner Tools - External Scanner Integrations

Provides plug-and-play integrations with enterprise security scanners:
- Acunetix Web Vulnerability Scanner
- Burp Suite Pro/Enterprise
- Nessus Professional/Expert (Network Vulnerability Scanner)
- OWASP ZAP (Dynamic Application Security Testing)

Configuration via environment variables (see config.py):
    AIPT_SCANNER_IP       - Your scanner server IP/hostname
    AIPT_ACUNETIX_API_KEY - Acunetix API key (required)
    AIPT_BURP_API_KEY     - Burp Suite API key (required)
    AIPT_ACUNETIX_URL     - Full Acunetix URL (optional, overrides IP+port)
    AIPT_BURP_URL         - Full Burp URL (optional, overrides IP+port)
"""

# Acunetix Integration
from aipt_v2.tools.scanners.acunetix_tool import (
    AcunetixConfig,
    AcunetixTool,
    ScanProfile,
)
from aipt_v2.tools.scanners.acunetix_tool import ScanResult as AcunetixScanResult
from aipt_v2.tools.scanners.acunetix_tool import ScanStatus as AcunetixScanStatus
from aipt_v2.tools.scanners.acunetix_tool import Severity as AcunetixSeverity
from aipt_v2.tools.scanners.acunetix_tool import Vulnerability as AcunetixVulnerability
from aipt_v2.tools.scanners.acunetix_tool import (
    acunetix_scan,
    acunetix_status,
    acunetix_summary,
    acunetix_vulns,
    get_acunetix,
)

# Burp Suite Integration
from aipt_v2.tools.scanners.burp_tool import (
    BurpConfig,
    BurpTool,
)
from aipt_v2.tools.scanners.burp_tool import Issue as BurpIssue
from aipt_v2.tools.scanners.burp_tool import (
    IssueConfidence,
    IssueSeverity,
)
from aipt_v2.tools.scanners.burp_tool import ScanResult as BurpScanResult
from aipt_v2.tools.scanners.burp_tool import ScanStatus as BurpScanStatus
from aipt_v2.tools.scanners.burp_tool import (
    burp_issues,
    burp_scan,
    burp_status,
    burp_summary,
    get_burp,
)

# Configuration
from aipt_v2.tools.scanners.config import (
    ACUNETIX,
    ACUNETIX_PORT,
    ACUNETIX_URL,
    BURP,
    BURP_PORT,
    BURP_URL,
    SCANNER,
    SCANNER_SERVER_IP,
    AcunetixSettings,
    BurpSettings,
    ScannerSettings,
    get_acunetix_config,
    get_burp_config,
    print_config,
)

# Nessus Integration
from aipt_v2.tools.scanners.nessus_tool import (
    NessusConfig,
    NessusTool,
)
from aipt_v2.tools.scanners.nessus_tool import ScanResult as NessusScanResult
from aipt_v2.tools.scanners.nessus_tool import Vulnerability as NessusVulnerability
from aipt_v2.tools.scanners.nessus_tool import (
    get_nessus,
    nessus_scan,
    nessus_summary,
    nessus_vulns,
)

# OWASP ZAP Integration
from aipt_v2.tools.scanners.zap_tool import Alert as ZAPAlert
from aipt_v2.tools.scanners.zap_tool import ScanResult as ZAPScanResult
from aipt_v2.tools.scanners.zap_tool import (
    ZAPConfig,
    ZAPTool,
    get_zap,
    zap_alerts,
    zap_scan,
    zap_summary,
)

__all__ = [
    # Configuration
    "SCANNER_SERVER_IP",
    "ACUNETIX_PORT",
    "BURP_PORT",
    "ACUNETIX_URL",
    "BURP_URL",
    "ACUNETIX",
    "BURP",
    "SCANNER",
    "AcunetixSettings",
    "BurpSettings",
    "ScannerSettings",
    "get_acunetix_config",
    "get_burp_config",
    "print_config",
    # Acunetix
    "AcunetixTool",
    "AcunetixConfig",
    "ScanProfile",
    "AcunetixScanStatus",
    "AcunetixScanResult",
    "AcunetixVulnerability",
    "AcunetixSeverity",
    "get_acunetix",
    "acunetix_scan",
    "acunetix_status",
    "acunetix_vulns",
    "acunetix_summary",
    # Burp Suite
    "BurpTool",
    "BurpConfig",
    "BurpScanStatus",
    "BurpScanResult",
    "BurpIssue",
    "IssueSeverity",
    "IssueConfidence",
    "get_burp",
    "burp_scan",
    "burp_status",
    "burp_issues",
    "burp_summary",
    # Nessus
    "NessusTool",
    "NessusConfig",
    "NessusScanResult",
    "NessusVulnerability",
    "get_nessus",
    "nessus_scan",
    "nessus_vulns",
    "nessus_summary",
    # OWASP ZAP
    "ZAPTool",
    "ZAPConfig",
    "ZAPScanResult",
    "ZAPAlert",
    "get_zap",
    "zap_scan",
    "zap_alerts",
    "zap_summary",
    # Unified Interface
    "ScannerType",
    "get_scanner",
    "scan_target",
    "get_findings",
    "get_all_findings",
    "test_all_connections",
]


# ==================== Unified Scanner Interface ====================


class ScannerType:
    """Scanner type constants."""

    ACUNETIX = "acunetix"
    BURP = "burp"
    NESSUS = "nessus"
    ZAP = "zap"


def get_scanner(scanner_type: str, config: dict = None):
    """
    Get a scanner instance by type.

    Args:
        scanner_type: 'acunetix', 'burp', 'nessus', or 'zap'
        config: Optional configuration dict

    Returns:
        Scanner tool instance
    """
    if scanner_type == ScannerType.ACUNETIX:
        cfg = AcunetixConfig(**config) if config else None
        return get_acunetix(cfg)
    elif scanner_type == ScannerType.BURP:
        cfg = BurpConfig(**config) if config else None
        return get_burp(cfg)
    elif scanner_type == ScannerType.NESSUS:
        cfg = NessusConfig(**config) if config else None
        return get_nessus(cfg)
    elif scanner_type == ScannerType.ZAP:
        cfg = ZAPConfig(**config) if config else None
        return get_zap(cfg)
    else:
        raise ValueError(f"Unknown scanner type: {scanner_type}")


def scan_target(url: str, scanner_type: str = "acunetix", **kwargs):
    """
    Unified scan function - works with any scanner.

    Args:
        url: Target URL to scan
        scanner_type: 'acunetix', 'burp', 'nessus', or 'zap'
        **kwargs: Scanner-specific options

    Returns:
        ScanResult from the chosen scanner
    """
    if scanner_type == ScannerType.ACUNETIX:
        profile = kwargs.get("profile", "full")
        return acunetix_scan(url, profile)
    elif scanner_type == ScannerType.BURP:
        config_id = kwargs.get("config_id")
        return burp_scan(url, config_id)
    elif scanner_type == ScannerType.NESSUS:
        policy = kwargs.get("policy", "basic")
        return nessus_scan(url, policy)
    elif scanner_type == ScannerType.ZAP:
        return zap_scan(url)
    else:
        raise ValueError(f"Unknown scanner type: {scanner_type}")


def get_findings(scanner_type: str, scan_id: str = None, severity: str = None):
    """
    Get findings from any scanner in unified AIPT format.

    Args:
        scanner_type: 'acunetix', 'burp', 'nessus', or 'zap'
        scan_id: Optional scan ID filter
        severity: Optional severity filter

    Returns:
        List of findings in AIPT format
    """
    if scanner_type == ScannerType.ACUNETIX:
        return acunetix_vulns(scan_id, severity)
    elif scanner_type == ScannerType.BURP:
        return burp_issues(scan_id, severity)
    elif scanner_type == ScannerType.NESSUS:
        return nessus_vulns(scan_id, severity)
    elif scanner_type == ScannerType.ZAP:
        return zap_alerts(scan_id, severity)
    else:
        raise ValueError(f"Unknown scanner type: {scanner_type}")


def get_all_findings(scan_ids: dict = None) -> list:
    """
    Aggregate findings from all scanners.

    Args:
        scan_ids: Dict mapping scanner_type to scan_id

    Returns:
        Combined list of findings from all scanners
    """
    findings = []
    scan_ids = scan_ids or {}

    try:
        acunetix_findings = acunetix_vulns(scan_ids.get("acunetix"))
        findings.extend(acunetix_findings)
    except Exception:
        pass  # Scanner not available

    try:
        burp_findings = burp_issues(scan_ids.get("burp"))
        findings.extend(burp_findings)
    except Exception:
        pass  # Scanner not available

    try:
        nessus_findings = nessus_vulns(scan_ids.get("nessus"))
        findings.extend(nessus_findings)
    except Exception:
        pass  # Scanner not available

    try:
        zap_findings = zap_alerts(scan_ids.get("zap"))
        findings.extend(zap_findings)
    except Exception:
        pass  # Scanner not available

    return findings


def test_all_connections() -> dict:
    """
    Test connections to all configured scanners.

    Returns:
        Dict with connection status for each scanner
    """
    results = {}

    # Test Acunetix
    try:
        acunetix = AcunetixTool()
        results["acunetix"] = {
            "connected": acunetix.connect(),
            "url": acunetix.config.base_url,
            "info": acunetix.get_info() if acunetix.is_connected() else None,
        }
    except Exception as e:
        results["acunetix"] = {"connected": False, "error": str(e)}

    # Test Burp
    try:
        burp = BurpTool()
        results["burp"] = {
            "connected": burp.connect(),
            "url": burp.config.base_url,
            "info": burp.get_info() if burp.is_connected() else None,
        }
    except Exception as e:
        results["burp"] = {"connected": False, "error": str(e)}

    # Test Nessus
    try:
        nessus = NessusTool()
        results["nessus"] = {
            "connected": nessus.connect(),
            "url": nessus.config.base_url,
            "info": nessus.get_info() if nessus.is_connected() else None,
        }
    except Exception as e:
        results["nessus"] = {"connected": False, "error": str(e)}

    # Test OWASP ZAP
    try:
        zap = ZAPTool()
        results["zap"] = {
            "connected": zap.connect(),
            "url": zap.config.base_url,
            "info": zap.get_info() if zap.is_connected() else None,
        }
    except Exception as e:
        results["zap"] = {"connected": False, "error": str(e)}

    return results
