"""AIPT Data Models"""

from .finding_v2 import (
    FindingCategory,
    FindingV2,
    ScannerType,
    SeverityV2,
    VerificationStatusV2,
    categorize_vuln_type,
    determine_scanner_type,
    merge_findings_v2,
    normalize_url,
)
from .findings import Finding, Severity, VerificationStatus, VulnerabilityType
from .phase_result import Phase, PhaseResult
from .scan_config import ScanConfig, ScanMode

__all__ = [
    # Legacy Finding
    "Finding",
    "Severity",
    "VulnerabilityType",
    "VerificationStatus",
    # FindingV2 (canonical)
    "FindingV2",
    "FindingCategory",
    "VerificationStatusV2",
    "ScannerType",
    "SeverityV2",
    "normalize_url",
    "categorize_vuln_type",
    "determine_scanner_type",
    "merge_findings_v2",
    # Config
    "ScanConfig",
    "ScanMode",
    "PhaseResult",
    "Phase",
]
