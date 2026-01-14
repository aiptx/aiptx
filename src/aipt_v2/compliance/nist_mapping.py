"""
NIST 800-53 Mapping

NIST Special Publication 800-53 Security Controls mapping.
Maps CWEs to NIST control families.

Usage:
    from aipt_v2.compliance import NISTMapper, get_nist_control

    control = get_nist_control("CWE-89")  # Returns "SI-10"
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class NISTControl:
    """NIST 800-53 control definition."""
    id: str
    family: str
    name: str
    description: str
    cwes: List[str]
    related_controls: List[str]
    priority: str  # P1, P2, P3


# NIST 800-53 Rev 5 Controls (security-relevant subset)
NIST_CONTROLS = {
    # Access Control (AC) Family
    "AC-2": NISTControl(
        id="AC-2",
        family="Access Control",
        name="Account Management",
        description="Manage system accounts, including establishing, activating, "
                   "modifying, disabling, and removing accounts.",
        cwes=["CWE-287", "CWE-306"],
        related_controls=["AC-3", "AC-5", "AC-6", "IA-2"],
        priority="P1"
    ),

    "AC-3": NISTControl(
        id="AC-3",
        family="Access Control",
        name="Access Enforcement",
        description="Enforce approved authorizations for logical access to information "
                   "and system resources.",
        cwes=["CWE-284", "CWE-862", "CWE-639", "CWE-285"],
        related_controls=["AC-2", "AC-5", "AC-6", "AC-17", "AC-21"],
        priority="P1"
    ),

    "AC-6": NISTControl(
        id="AC-6",
        family="Access Control",
        name="Least Privilege",
        description="Employ the principle of least privilege, allowing only authorized "
                   "accesses for users which are necessary to accomplish assigned tasks.",
        cwes=["CWE-863", "CWE-269", "CWE-250"],
        related_controls=["AC-2", "AC-3", "AC-5", "CM-11", "PL-2"],
        priority="P1"
    ),

    "AC-17": NISTControl(
        id="AC-17",
        family="Access Control",
        name="Remote Access",
        description="Establish usage restrictions, configuration requirements, and "
                   "implementation guidance for each type of remote access allowed.",
        cwes=["CWE-287", "CWE-294", "CWE-300"],
        related_controls=["AC-2", "AC-3", "AC-4", "AC-18", "IA-2"],
        priority="P1"
    ),

    # Audit and Accountability (AU) Family
    "AU-2": NISTControl(
        id="AU-2",
        family="Audit and Accountability",
        name="Audit Events",
        description="Determine that the system is capable of auditing defined events "
                   "and coordinate the audit function with other entities.",
        cwes=["CWE-778", "CWE-779"],
        related_controls=["AU-3", "AU-6", "AU-12", "SI-4"],
        priority="P1"
    ),

    "AU-3": NISTControl(
        id="AU-3",
        family="Audit and Accountability",
        name="Content of Audit Records",
        description="Ensure that audit records contain information that establishes "
                   "what type of event occurred, when and where it occurred, and source.",
        cwes=["CWE-223", "CWE-779"],
        related_controls=["AU-2", "AU-8", "AU-12", "SI-11"],
        priority="P1"
    ),

    "AU-9": NISTControl(
        id="AU-9",
        family="Audit and Accountability",
        name="Protection of Audit Information",
        description="Protect audit information and audit tools from unauthorized access, "
                   "modification, and deletion.",
        cwes=["CWE-117", "CWE-532"],
        related_controls=["AC-3", "AU-4", "AU-11", "SC-28"],
        priority="P1"
    ),

    # Configuration Management (CM) Family
    "CM-6": NISTControl(
        id="CM-6",
        family="Configuration Management",
        name="Configuration Settings",
        description="Establish and document mandatory configuration settings for system "
                   "components using security configuration checklists.",
        cwes=["CWE-16", "CWE-260", "CWE-611", "CWE-756", "CWE-1188"],
        related_controls=["AC-19", "CM-2", "CM-3", "CM-7", "SI-4"],
        priority="P1"
    ),

    "CM-7": NISTControl(
        id="CM-7",
        family="Configuration Management",
        name="Least Functionality",
        description="Configure the system to provide only essential capabilities and "
                   "prohibit or restrict the use of functions, ports, protocols, and services.",
        cwes=["CWE-1188", "CWE-489"],
        related_controls=["AC-6", "CM-2", "CM-6", "SA-5"],
        priority="P1"
    ),

    # Identification and Authentication (IA) Family
    "IA-2": NISTControl(
        id="IA-2",
        family="Identification and Authentication",
        name="Identification and Authentication (Organizational Users)",
        description="Uniquely identify and authenticate organizational users and "
                   "associate that unique identification with processes acting on behalf.",
        cwes=["CWE-287", "CWE-306", "CWE-290"],
        related_controls=["AC-2", "AC-3", "AC-14", "IA-4", "IA-5"],
        priority="P1"
    ),

    "IA-5": NISTControl(
        id="IA-5",
        family="Identification and Authentication",
        name="Authenticator Management",
        description="Manage system authenticators by verifying identity before "
                   "establishing new authenticators and establishing procedures for "
                   "lost or compromised authenticators.",
        cwes=["CWE-521", "CWE-798", "CWE-259", "CWE-307", "CWE-620"],
        related_controls=["AC-20", "IA-2", "IA-4", "IA-8"],
        priority="P1"
    ),

    "IA-8": NISTControl(
        id="IA-8",
        family="Identification and Authentication",
        name="Identification and Authentication (Non-Organizational Users)",
        description="Uniquely identify and authenticate non-organizational users.",
        cwes=["CWE-287", "CWE-384"],
        related_controls=["AC-14", "IA-2", "IA-4", "IA-5"],
        priority="P1"
    ),

    # Risk Assessment (RA) Family
    "RA-5": NISTControl(
        id="RA-5",
        family="Risk Assessment",
        name="Vulnerability Scanning",
        description="Scan for vulnerabilities in the system and hosted applications "
                   "and when new vulnerabilities are identified and reported.",
        cwes=["CWE-937", "CWE-1104", "CWE-1035"],
        related_controls=["CA-2", "CA-7", "PM-15", "RA-3", "SI-2"],
        priority="P1"
    ),

    # System and Communications Protection (SC) Family
    "SC-8": NISTControl(
        id="SC-8",
        family="System and Communications Protection",
        name="Transmission Confidentiality and Integrity",
        description="Protect the confidentiality and integrity of transmitted information.",
        cwes=["CWE-319", "CWE-523"],
        related_controls=["AC-17", "PE-4", "SC-12", "SC-13", "SC-23"],
        priority="P1"
    ),

    "SC-12": NISTControl(
        id="SC-12",
        family="System and Communications Protection",
        name="Cryptographic Key Establishment and Management",
        description="Establish and manage cryptographic keys when cryptography is "
                   "employed within the system.",
        cwes=["CWE-320", "CWE-321", "CWE-326"],
        related_controls=["SC-13", "SC-17"],
        priority="P1"
    ),

    "SC-13": NISTControl(
        id="SC-13",
        family="System and Communications Protection",
        name="Cryptographic Protection",
        description="Implement cryptographic mechanisms in accordance with applicable "
                   "laws, policies, and standards.",
        cwes=["CWE-327", "CWE-328", "CWE-330", "CWE-338"],
        related_controls=["SC-8", "SC-12", "SC-28"],
        priority="P1"
    ),

    "SC-28": NISTControl(
        id="SC-28",
        family="System and Communications Protection",
        name="Protection of Information at Rest",
        description="Protect the confidentiality and integrity of information at rest.",
        cwes=["CWE-311", "CWE-312", "CWE-313"],
        related_controls=["AC-3", "SC-8", "SC-12", "SC-13"],
        priority="P1"
    ),

    # System and Information Integrity (SI) Family
    "SI-2": NISTControl(
        id="SI-2",
        family="System and Information Integrity",
        name="Flaw Remediation",
        description="Identify, report, and correct system flaws; test software and "
                   "firmware updates related to flaw remediation.",
        cwes=["CWE-937", "CWE-1104"],
        related_controls=["CA-5", "CM-3", "CM-6", "RA-5", "SI-11"],
        priority="P1"
    ),

    "SI-10": NISTControl(
        id="SI-10",
        family="System and Information Integrity",
        name="Information Input Validation",
        description="Check the validity of information inputs.",
        cwes=["CWE-20", "CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-918",
              "CWE-22", "CWE-434", "CWE-77", "CWE-74"],
        related_controls=["SI-15"],
        priority="P1"
    ),

    "SI-11": NISTControl(
        id="SI-11",
        family="System and Information Integrity",
        name="Error Handling",
        description="Generate error messages that provide information necessary for "
                   "corrective actions without revealing information that could be exploited.",
        cwes=["CWE-209", "CWE-200"],
        related_controls=["AU-3", "AU-9", "SC-31", "SI-2"],
        priority="P2"
    )
}


class NISTMapper:
    """NIST 800-53 specific mapper."""

    def __init__(self):
        self.controls = NIST_CONTROLS

    def get_control(self, cwe_id: str) -> Optional[NISTControl]:
        """Get NIST control for a CWE."""
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        for control in self.controls.values():
            if cwe_id in control.cwes:
                return control

        return None

    def get_control_by_id(self, control_id: str) -> Optional[NISTControl]:
        """Get NIST control by ID."""
        return self.controls.get(control_id.upper())

    def get_controls_by_family(self, family: str) -> List[NISTControl]:
        """Get all controls in a family."""
        return [c for c in self.controls.values()
                if family.lower() in c.family.lower()]

    def get_all_controls_for_cwe(self, cwe_id: str) -> List[NISTControl]:
        """Get all NIST controls mapped to a CWE."""
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        controls = []
        for control in self.controls.values():
            if cwe_id in control.cwes:
                controls.append(control)

        return controls

    def get_compliance_status(self, findings: List[Dict]) -> Dict[str, Dict]:
        """
        Calculate NIST compliance status based on findings.

        Args:
            findings: List of findings with CWE IDs

        Returns:
            Dict with compliance status per control
        """
        status = {}

        for control_id, control in self.controls.items():
            affected_cwes = []
            for finding in findings:
                cwe = finding.get("cwe", finding.get("cwe_id", ""))
                cwe_normalized = cwe.upper()
                if not cwe_normalized.startswith("CWE-"):
                    cwe_normalized = f"CWE-{cwe_normalized}"

                if cwe_normalized in control.cwes:
                    affected_cwes.append(cwe)

            status[control_id] = {
                "control_name": control.name,
                "family": control.family,
                "compliant": len(affected_cwes) == 0,
                "findings_count": len(affected_cwes),
                "affected_cwes": affected_cwes,
                "priority": control.priority
            }

        return status


def get_nist_control(cwe_id: str) -> Optional[str]:
    """
    Get NIST control ID for a CWE.

    Args:
        cwe_id: CWE identifier

    Returns:
        NIST control ID or None
    """
    mapper = NISTMapper()
    control = mapper.get_control(cwe_id)
    return control.id if control else None
