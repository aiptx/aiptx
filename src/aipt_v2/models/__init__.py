"""AIPT Data Models"""

from .findings import Finding, Severity, VulnerabilityType, VerificationStatus
from .scan_config import ScanConfig, ScanMode
from .phase_result import PhaseResult, Phase
from .finding_v2 import (
    FindingV2,
    FindingCategory,
    VerificationStatusV2,
    ScannerType,
    SeverityV2,
    normalize_url,
    categorize_vuln_type,
    determine_scanner_type,
    merge_findings_v2,
)

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
