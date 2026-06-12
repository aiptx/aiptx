"""
AIPT Compliance Framework Module

Maps security findings to compliance frameworks:
- OWASP Top 10 2021 (A01-A10)
- SANS Top 25 CWEs
- PCI-DSS 4.0 Requirements
- NIST 800-53 Controls
- CIS Controls v8

Usage:
    from aipt_v2.compliance import ComplianceMapper, generate_compliance_report

    mapper = ComplianceMapper()
    report = mapper.map_findings(findings, frameworks=["owasp", "pci"])
"""

from aipt_v2.compliance.compliance_report import (
    ComplianceReport,
    ComplianceReportGenerator,
    generate_compliance_report,
)
from aipt_v2.compliance.framework_mapper import (
    ComplianceMapper,
    ComplianceMapping,
    FrameworkCategory,
    map_to_frameworks,
)
from aipt_v2.compliance.nist_mapping import (
    NIST_CONTROLS,
    NISTMapper,
    get_nist_control,
)
from aipt_v2.compliance.owasp_mapping import (
    OWASP_TOP_10,
    OWASPMapper,
    get_owasp_category,
)
from aipt_v2.compliance.pci_mapping import (
    PCI_DSS_REQUIREMENTS,
    PCIMapper,
    get_pci_requirement,
)

__all__ = [
    # Mapper
    "ComplianceMapper",
    "ComplianceMapping",
    "FrameworkCategory",
    "map_to_frameworks",
    # OWASP
    "OWASPMapper",
    "OWASP_TOP_10",
    "get_owasp_category",
    # PCI
    "PCIMapper",
    "PCI_DSS_REQUIREMENTS",
    "get_pci_requirement",
    # NIST
    "NISTMapper",
    "NIST_CONTROLS",
    "get_nist_control",
    # Reports
    "ComplianceReport",
    "generate_compliance_report",
    "ComplianceReportGenerator",
]
