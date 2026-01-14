"""
PCI-DSS 4.0 Mapping

Payment Card Industry Data Security Standard mapping.
Maps CWEs to PCI-DSS 4.0 requirements.

Usage:
    from aipt_v2.compliance import PCIMapper, get_pci_requirement

    req = get_pci_requirement("CWE-89")  # Returns "6.2"
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class PCIRequirement:
    """PCI-DSS requirement definition."""
    id: str
    name: str
    description: str
    sub_requirements: List[str]
    cwes: List[str]
    testing_procedures: List[str]


# PCI-DSS 4.0 Requirements (security-relevant subset)
PCI_DSS_REQUIREMENTS = {
    "2.2": PCIRequirement(
        id="2.2",
        name="System Components are Configured and Managed Securely",
        description="Configuration standards are developed, implemented, and maintained "
                   "for system components that are consistent with industry-accepted "
                   "system hardening standards.",
        sub_requirements=[
            "2.2.1 - Configuration standards are implemented",
            "2.2.2 - Vendor default accounts are managed",
            "2.2.3 - Primary functions are separated on different servers",
            "2.2.4 - Only necessary services and protocols are enabled",
            "2.2.5 - Insecure services and protocols are addressed",
            "2.2.6 - System security parameters are configured",
            "2.2.7 - Non-console administrative access is encrypted"
        ],
        cwes=["CWE-16", "CWE-260", "CWE-611", "CWE-756", "CWE-942"],
        testing_procedures=[
            "Examine configuration standards",
            "Examine system configurations",
            "Interview system administrators"
        ]
    ),

    "3.4": PCIRequirement(
        id="3.4",
        name="PAN is Rendered Unreadable Anywhere it is Stored",
        description="Primary Account Numbers (PAN) is rendered unreadable anywhere "
                   "it is stored using strong cryptography.",
        sub_requirements=[
            "3.4.1 - PAN rendered unreadable via cryptography or truncation",
            "3.4.2 - Technical controls prevent PAN copy/relocation"
        ],
        cwes=["CWE-311", "CWE-312", "CWE-313", "CWE-316"],
        testing_procedures=[
            "Examine data repositories to verify PAN is unreadable",
            "Examine cryptographic key management procedures"
        ]
    ),

    "3.5": PCIRequirement(
        id="3.5",
        name="Cryptographic Keys are Protected",
        description="Cryptographic keys used to protect stored account data "
                   "are secured.",
        sub_requirements=[
            "3.5.1 - Key access restricted to fewest custodians",
            "3.5.1.1 - Service providers: key per customer",
            "3.5.1.2 - Key storage in secure cryptographic device",
            "3.5.1.3 - Key stored in fewest locations"
        ],
        cwes=["CWE-320", "CWE-321", "CWE-326", "CWE-327"],
        testing_procedures=[
            "Examine documented procedures",
            "Interview personnel",
            "Observe key management processes"
        ]
    ),

    "4.1": PCIRequirement(
        id="4.1",
        name="Strong Cryptography Protects Data During Transmission",
        description="Processes and mechanisms are defined to protect account data "
                   "with strong cryptography during transmission over open networks.",
        sub_requirements=[
            "4.1.1 - Security policies and procedures documented",
            "4.1.2 - Roles and responsibilities assigned"
        ],
        cwes=["CWE-319", "CWE-326", "CWE-327", "CWE-523"],
        testing_procedures=[
            "Examine policies and configuration standards",
            "Interview responsible personnel"
        ]
    ),

    "6.2": PCIRequirement(
        id="6.2",
        name="Bespoke and Custom Software is Developed Securely",
        description="Bespoke and custom software is developed securely, and "
                   "software development follows secure software development guidance.",
        sub_requirements=[
            "6.2.1 - Software developed based on industry standards",
            "6.2.2 - Personnel trained in secure development",
            "6.2.3 - Code reviewed for vulnerabilities",
            "6.2.4 - Common software attacks addressed"
        ],
        cwes=["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-918", "CWE-22",
              "CWE-434", "CWE-352", "CWE-601", "CWE-20"],
        testing_procedures=[
            "Examine secure development procedures",
            "Interview developers",
            "Review code review processes"
        ]
    ),

    "6.3": PCIRequirement(
        id="6.3",
        name="Security Vulnerabilities are Identified and Addressed",
        description="Security vulnerabilities are identified and addressed.",
        sub_requirements=[
            "6.3.1 - Vulnerabilities identified via reputable sources",
            "6.3.2 - Inventory of bespoke software maintained",
            "6.3.3 - Vulnerabilities addressed via patching"
        ],
        cwes=["CWE-937", "CWE-1035", "CWE-1104"],
        testing_procedures=[
            "Examine processes for identifying vulnerabilities",
            "Interview responsible personnel"
        ]
    ),

    "7.1": PCIRequirement(
        id="7.1",
        name="Access to System Components is Defined and Assigned",
        description="Processes and mechanisms for restricting access to system "
                   "components and cardholder data are defined and understood.",
        sub_requirements=[
            "7.1.1 - Security policies defined and known",
            "7.1.2 - Access control model defined"
        ],
        cwes=["CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-639"],
        testing_procedures=[
            "Examine documented policies",
            "Interview personnel"
        ]
    ),

    "8.3": PCIRequirement(
        id="8.3",
        name="Strong Authentication for Users and Administrators",
        description="Strong authentication for users and administrators is established "
                   "and managed.",
        sub_requirements=[
            "8.3.1 - All access authenticated",
            "8.3.2 - Strong cryptography for authentication",
            "8.3.4 - MFA for remote network access",
            "8.3.5 - MFA for all access to CDE",
            "8.3.6 - MFA systems cannot be bypassed",
            "8.3.9 - Passwords have minimum complexity",
            "8.3.10 - Failed login attempts limited"
        ],
        cwes=["CWE-287", "CWE-521", "CWE-798", "CWE-307", "CWE-384", "CWE-306"],
        testing_procedures=[
            "Examine system configuration standards",
            "Observe authentication processes"
        ]
    ),

    "10.2": PCIRequirement(
        id="10.2",
        name="Audit Logs are Implemented",
        description="Audit logs are implemented to support the detection of "
                   "anomalies and suspicious activity.",
        sub_requirements=[
            "10.2.1 - Audit logs enabled and active",
            "10.2.1.1 - User access to CHD logged",
            "10.2.1.2 - Admin actions logged",
            "10.2.1.3 - Access to audit logs logged",
            "10.2.1.4 - Invalid access attempts logged",
            "10.2.1.5 - Changes to auth credentials logged",
            "10.2.1.6 - System/log events logged",
            "10.2.1.7 - Security events logged"
        ],
        cwes=["CWE-778", "CWE-223", "CWE-117", "CWE-532"],
        testing_procedures=[
            "Examine audit log configurations",
            "Interview personnel",
            "Review log samples"
        ]
    ),

    "11.3": PCIRequirement(
        id="11.3",
        name="External and Internal Vulnerabilities Regularly Identified",
        description="External and internal vulnerabilities are regularly identified, "
                   "prioritized, and addressed.",
        sub_requirements=[
            "11.3.1 - Internal vulnerability scans quarterly",
            "11.3.2 - External vulnerability scans quarterly",
            "11.3.3 - Vulnerability scans after significant changes",
            "11.3.4 - Internal penetration testing"
        ],
        cwes=["CWE-937", "CWE-1104"],
        testing_procedures=[
            "Examine scan reports",
            "Interview responsible personnel",
            "Examine remediation processes"
        ]
    )
}


class PCIMapper:
    """PCI-DSS specific mapper."""

    def __init__(self):
        self.requirements = PCI_DSS_REQUIREMENTS

    def get_requirement(self, cwe_id: str) -> Optional[PCIRequirement]:
        """Get PCI requirement for a CWE."""
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        for req_id, requirement in self.requirements.items():
            if cwe_id in requirement.cwes:
                return requirement

        return None

    def get_requirement_by_id(self, req_id: str) -> Optional[PCIRequirement]:
        """Get PCI requirement by ID."""
        return self.requirements.get(req_id)

    def get_all_requirements_for_cwe(self, cwe_id: str) -> List[PCIRequirement]:
        """Get all PCI requirements mapped to a CWE."""
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        requirements = []
        for requirement in self.requirements.values():
            if cwe_id in requirement.cwes:
                requirements.append(requirement)

        return requirements

    def get_compliance_status(self, findings: List[Dict]) -> Dict[str, Dict]:
        """
        Calculate PCI-DSS compliance status based on findings.

        Args:
            findings: List of findings with CWE IDs

        Returns:
            Dict with compliance status per requirement
        """
        status = {}

        for req_id, requirement in self.requirements.items():
            affected_cwes = []
            for finding in findings:
                cwe = finding.get("cwe", finding.get("cwe_id", ""))
                if cwe.upper() in requirement.cwes or f"CWE-{cwe}" in requirement.cwes:
                    affected_cwes.append(cwe)

            status[req_id] = {
                "requirement_name": requirement.name,
                "compliant": len(affected_cwes) == 0,
                "findings_count": len(affected_cwes),
                "affected_cwes": affected_cwes
            }

        return status


def get_pci_requirement(cwe_id: str) -> Optional[str]:
    """
    Get PCI-DSS requirement ID for a CWE.

    Args:
        cwe_id: CWE identifier

    Returns:
        PCI requirement ID or None
    """
    mapper = PCIMapper()
    requirement = mapper.get_requirement(cwe_id)
    return requirement.id if requirement else None
