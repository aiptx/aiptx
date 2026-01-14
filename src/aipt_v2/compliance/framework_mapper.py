"""
Compliance Framework Mapper

Central mapping engine that converts security findings to compliance frameworks.
Maps CWE IDs to OWASP, PCI-DSS, NIST, and SANS categories.

Usage:
    from aipt_v2.compliance import ComplianceMapper

    mapper = ComplianceMapper()
    mappings = mapper.map_finding(finding)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class Framework(Enum):
    """Supported compliance frameworks."""
    OWASP = "owasp"
    PCI_DSS = "pci_dss"
    NIST = "nist_800_53"
    SANS = "sans_top_25"
    CIS = "cis_controls"


@dataclass
class FrameworkCategory:
    """A category within a compliance framework."""
    framework: str
    category_id: str
    category_name: str
    description: str
    requirements: List[str] = field(default_factory=list)


@dataclass
class ComplianceMapping:
    """Mapping of a finding to compliance frameworks."""
    finding_id: str
    cwe_id: str
    cwe_name: str
    severity: str
    frameworks: Dict[str, FrameworkCategory]
    risk_score: float = 0.0
    remediation_priority: str = ""


# CWE to Framework mapping tables
CWE_TO_OWASP = {
    # A01:2021 - Broken Access Control
    "CWE-22": "A01", "CWE-23": "A01", "CWE-35": "A01", "CWE-59": "A01",
    "CWE-200": "A01", "CWE-201": "A01", "CWE-219": "A01", "CWE-264": "A01",
    "CWE-275": "A01", "CWE-276": "A01", "CWE-284": "A01", "CWE-285": "A01",
    "CWE-352": "A01", "CWE-359": "A01", "CWE-377": "A01", "CWE-402": "A01",
    "CWE-425": "A01", "CWE-441": "A01", "CWE-497": "A01", "CWE-538": "A01",
    "CWE-540": "A01", "CWE-548": "A01", "CWE-552": "A01", "CWE-566": "A01",
    "CWE-601": "A01", "CWE-639": "A01", "CWE-651": "A01", "CWE-668": "A01",
    "CWE-706": "A01", "CWE-862": "A01", "CWE-863": "A01", "CWE-913": "A01",
    "CWE-922": "A01", "CWE-1275": "A01",

    # A02:2021 - Cryptographic Failures
    "CWE-261": "A02", "CWE-296": "A02", "CWE-310": "A02", "CWE-319": "A02",
    "CWE-320": "A02", "CWE-321": "A02", "CWE-322": "A02", "CWE-323": "A02",
    "CWE-324": "A02", "CWE-325": "A02", "CWE-326": "A02", "CWE-327": "A02",
    "CWE-328": "A02", "CWE-329": "A02", "CWE-330": "A02", "CWE-331": "A02",
    "CWE-335": "A02", "CWE-336": "A02", "CWE-337": "A02", "CWE-338": "A02",
    "CWE-340": "A02", "CWE-347": "A02", "CWE-523": "A02", "CWE-720": "A02",
    "CWE-757": "A02", "CWE-759": "A02", "CWE-760": "A02", "CWE-780": "A02",
    "CWE-818": "A02", "CWE-916": "A02",

    # A03:2021 - Injection
    "CWE-20": "A03", "CWE-74": "A03", "CWE-75": "A03", "CWE-77": "A03",
    "CWE-78": "A03", "CWE-79": "A03", "CWE-80": "A03", "CWE-83": "A03",
    "CWE-87": "A03", "CWE-88": "A03", "CWE-89": "A03", "CWE-90": "A03",
    "CWE-91": "A03", "CWE-93": "A03", "CWE-94": "A03", "CWE-95": "A03",
    "CWE-96": "A03", "CWE-97": "A03", "CWE-98": "A03", "CWE-99": "A03",
    "CWE-113": "A03", "CWE-116": "A03", "CWE-138": "A03", "CWE-184": "A03",
    "CWE-470": "A03", "CWE-471": "A03", "CWE-564": "A03", "CWE-610": "A03",
    "CWE-643": "A03", "CWE-644": "A03", "CWE-652": "A03", "CWE-917": "A03",

    # A04:2021 - Insecure Design
    "CWE-73": "A04", "CWE-183": "A04", "CWE-209": "A04", "CWE-213": "A04",
    "CWE-235": "A04", "CWE-256": "A04", "CWE-257": "A04", "CWE-266": "A04",
    "CWE-269": "A04", "CWE-280": "A04", "CWE-311": "A04", "CWE-312": "A04",
    "CWE-313": "A04", "CWE-316": "A04", "CWE-419": "A04", "CWE-430": "A04",
    "CWE-434": "A04", "CWE-444": "A04", "CWE-451": "A04", "CWE-472": "A04",
    "CWE-501": "A04", "CWE-522": "A04", "CWE-525": "A04", "CWE-539": "A04",
    "CWE-579": "A04", "CWE-598": "A04", "CWE-602": "A04", "CWE-642": "A04",
    "CWE-646": "A04", "CWE-650": "A04", "CWE-653": "A04", "CWE-656": "A04",
    "CWE-657": "A04", "CWE-799": "A04", "CWE-807": "A04", "CWE-840": "A04",
    "CWE-841": "A04", "CWE-927": "A04", "CWE-1021": "A04", "CWE-1173": "A04",

    # A05:2021 - Security Misconfiguration
    "CWE-2": "A05", "CWE-11": "A05", "CWE-13": "A05", "CWE-15": "A05",
    "CWE-16": "A05", "CWE-260": "A05", "CWE-315": "A05", "CWE-520": "A05",
    "CWE-526": "A05", "CWE-537": "A05", "CWE-541": "A05", "CWE-547": "A05",
    "CWE-611": "A05", "CWE-614": "A05", "CWE-756": "A05", "CWE-776": "A05",
    "CWE-942": "A05", "CWE-1004": "A05", "CWE-1032": "A05", "CWE-1174": "A05",

    # A06:2021 - Vulnerable and Outdated Components
    "CWE-937": "A06", "CWE-1035": "A06", "CWE-1104": "A06",

    # A07:2021 - Identification and Authentication Failures
    "CWE-255": "A07", "CWE-259": "A07", "CWE-287": "A07", "CWE-288": "A07",
    "CWE-290": "A07", "CWE-294": "A07", "CWE-295": "A07", "CWE-297": "A07",
    "CWE-300": "A07", "CWE-302": "A07", "CWE-304": "A07", "CWE-306": "A07",
    "CWE-307": "A07", "CWE-346": "A07", "CWE-384": "A07", "CWE-521": "A07",
    "CWE-613": "A07", "CWE-620": "A07", "CWE-640": "A07", "CWE-798": "A07",
    "CWE-940": "A07", "CWE-1216": "A07",

    # A08:2021 - Software and Data Integrity Failures
    "CWE-345": "A08", "CWE-353": "A08", "CWE-426": "A08", "CWE-494": "A08",
    "CWE-502": "A08", "CWE-565": "A08", "CWE-784": "A08", "CWE-829": "A08",
    "CWE-830": "A08", "CWE-915": "A08",

    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09", "CWE-778": "A09",

    # A10:2021 - Server-Side Request Forgery (SSRF)
    "CWE-918": "A10"
}

# CWE to PCI-DSS 4.0 mapping
CWE_TO_PCI = {
    # Req 6: Develop and maintain secure systems
    "CWE-79": "6.2", "CWE-89": "6.2", "CWE-78": "6.2", "CWE-94": "6.2",
    "CWE-502": "6.2", "CWE-918": "6.2", "CWE-22": "6.2", "CWE-434": "6.2",

    # Req 2: Apply secure configurations
    "CWE-16": "2.2", "CWE-260": "2.2", "CWE-611": "2.2",

    # Req 3: Protect stored account data
    "CWE-312": "3.4", "CWE-311": "3.4", "CWE-327": "3.5",

    # Req 4: Protect cardholder data with strong cryptography
    "CWE-319": "4.1", "CWE-326": "4.1", "CWE-327": "4.1",

    # Req 7: Restrict access by need to know
    "CWE-284": "7.1", "CWE-285": "7.1", "CWE-862": "7.1", "CWE-863": "7.1",

    # Req 8: Identify users and authenticate access
    "CWE-287": "8.3", "CWE-521": "8.3", "CWE-798": "8.3", "CWE-307": "8.3",

    # Req 10: Log and monitor all access
    "CWE-778": "10.2", "CWE-223": "10.2", "CWE-117": "10.2",

    # Req 11: Test security regularly
    "CWE-937": "11.3", "CWE-1104": "11.3"
}

# CWE to NIST 800-53 mapping
CWE_TO_NIST = {
    # Access Control (AC)
    "CWE-284": "AC-3", "CWE-285": "AC-6", "CWE-862": "AC-3", "CWE-863": "AC-6",
    "CWE-639": "AC-3",

    # Audit and Accountability (AU)
    "CWE-778": "AU-2", "CWE-223": "AU-3", "CWE-117": "AU-9",

    # Identification and Authentication (IA)
    "CWE-287": "IA-2", "CWE-521": "IA-5", "CWE-798": "IA-5", "CWE-307": "IA-5",
    "CWE-384": "IA-8",

    # System and Communications Protection (SC)
    "CWE-319": "SC-8", "CWE-327": "SC-13", "CWE-326": "SC-12",
    "CWE-311": "SC-28",

    # System and Information Integrity (SI)
    "CWE-79": "SI-10", "CWE-89": "SI-10", "CWE-78": "SI-10",
    "CWE-502": "SI-10", "CWE-94": "SI-10", "CWE-20": "SI-10",

    # Configuration Management (CM)
    "CWE-16": "CM-6", "CWE-260": "CM-6", "CWE-611": "CM-6",

    # Risk Assessment (RA)
    "CWE-937": "RA-5", "CWE-1104": "RA-5"
}


class ComplianceMapper:
    """
    Maps security findings to compliance frameworks.

    Supports OWASP Top 10, PCI-DSS, NIST 800-53, and SANS Top 25.
    """

    def __init__(self):
        """Initialize mapper with CWE mappings."""
        self.cwe_to_owasp = CWE_TO_OWASP
        self.cwe_to_pci = CWE_TO_PCI
        self.cwe_to_nist = CWE_TO_NIST

    def map_finding(
        self,
        cwe_id: str,
        finding_id: str = "",
        severity: str = "medium",
        frameworks: List[str] = None
    ) -> ComplianceMapping:
        """
        Map a single finding to compliance frameworks.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79" or "79")
            finding_id: Unique finding identifier
            severity: Finding severity
            frameworks: List of frameworks to map to

        Returns:
            ComplianceMapping
        """
        # Normalize CWE ID
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        cwe_id = cwe_id.upper()

        frameworks = frameworks or ["owasp", "pci", "nist"]
        framework_mappings = {}

        # Map to OWASP
        if "owasp" in frameworks and cwe_id in self.cwe_to_owasp:
            owasp_cat = self.cwe_to_owasp[cwe_id]
            framework_mappings["owasp"] = FrameworkCategory(
                framework="OWASP Top 10 2021",
                category_id=owasp_cat,
                category_name=self._get_owasp_name(owasp_cat),
                description=self._get_owasp_description(owasp_cat)
            )

        # Map to PCI-DSS
        if "pci" in frameworks and cwe_id in self.cwe_to_pci:
            pci_req = self.cwe_to_pci[cwe_id]
            framework_mappings["pci_dss"] = FrameworkCategory(
                framework="PCI-DSS 4.0",
                category_id=pci_req,
                category_name=f"Requirement {pci_req}",
                description=self._get_pci_description(pci_req)
            )

        # Map to NIST
        if "nist" in frameworks and cwe_id in self.cwe_to_nist:
            nist_control = self.cwe_to_nist[cwe_id]
            framework_mappings["nist"] = FrameworkCategory(
                framework="NIST 800-53",
                category_id=nist_control,
                category_name=nist_control,
                description=self._get_nist_description(nist_control)
            )

        # Calculate risk score
        risk_score = self._calculate_risk_score(severity, len(framework_mappings))

        # Determine remediation priority
        priority = "critical" if risk_score >= 8 else \
                   "high" if risk_score >= 6 else \
                   "medium" if risk_score >= 4 else "low"

        return ComplianceMapping(
            finding_id=finding_id,
            cwe_id=cwe_id,
            cwe_name=self._get_cwe_name(cwe_id),
            severity=severity,
            frameworks=framework_mappings,
            risk_score=risk_score,
            remediation_priority=priority
        )

    def map_findings(
        self,
        findings: List[Dict],
        frameworks: List[str] = None
    ) -> List[ComplianceMapping]:
        """
        Map multiple findings to compliance frameworks.

        Args:
            findings: List of finding dicts with 'cwe' and 'severity' keys
            frameworks: Frameworks to map to

        Returns:
            List of ComplianceMapping
        """
        mappings = []

        for finding in findings:
            cwe = finding.get("cwe", finding.get("cwe_id", ""))
            if cwe:
                mapping = self.map_finding(
                    cwe_id=cwe,
                    finding_id=finding.get("id", ""),
                    severity=finding.get("severity", "medium"),
                    frameworks=frameworks
                )
                mappings.append(mapping)

        return mappings

    def _calculate_risk_score(self, severity: str, framework_count: int) -> float:
        """Calculate risk score based on severity and compliance impact."""
        severity_scores = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1
        }

        base_score = severity_scores.get(severity.lower(), 5)

        # Increase score based on compliance framework impact
        compliance_multiplier = 1 + (framework_count * 0.1)

        return min(10, base_score * compliance_multiplier)

    def _get_owasp_name(self, category: str) -> str:
        """Get OWASP category name."""
        names = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery"
        }
        return names.get(category, "Unknown")

    def _get_owasp_description(self, category: str) -> str:
        """Get OWASP category description."""
        descriptions = {
            "A01": "Access control enforces policy such that users cannot act outside their intended permissions.",
            "A02": "Failures related to cryptography which often leads to sensitive data exposure.",
            "A03": "User-supplied data is not validated, filtered, or sanitized by the application.",
            "A04": "Missing or ineffective control design.",
            "A05": "Missing appropriate security hardening or improperly configured permissions.",
            "A06": "Using components with known vulnerabilities.",
            "A07": "Confirmation of the user's identity, authentication, and session management.",
            "A08": "Code and infrastructure that does not protect against integrity violations.",
            "A09": "Insufficient logging, detection, monitoring, and active response.",
            "A10": "Fetching a remote resource without validating the user-supplied URL."
        }
        return descriptions.get(category, "")

    def _get_pci_description(self, requirement: str) -> str:
        """Get PCI-DSS requirement description."""
        descriptions = {
            "2.2": "Apply secure configurations to all system components",
            "3.4": "Protect stored cardholder data",
            "3.5": "Protect cryptographic keys",
            "4.1": "Protect cardholder data with strong cryptography during transmission",
            "6.2": "Develop secure software",
            "7.1": "Restrict access to system components",
            "8.3": "Strong authentication for users and administrators",
            "10.2": "Implement automated audit trails",
            "11.3": "External and internal vulnerabilities are identified"
        }
        return descriptions.get(requirement, "")

    def _get_nist_description(self, control: str) -> str:
        """Get NIST control description."""
        descriptions = {
            "AC-3": "Access Enforcement",
            "AC-6": "Least Privilege",
            "AU-2": "Audit Events",
            "AU-3": "Content of Audit Records",
            "AU-9": "Protection of Audit Information",
            "IA-2": "Identification and Authentication",
            "IA-5": "Authenticator Management",
            "IA-8": "Identification and Authentication (Non-Organizational Users)",
            "SC-8": "Transmission Confidentiality and Integrity",
            "SC-12": "Cryptographic Key Establishment and Management",
            "SC-13": "Cryptographic Protection",
            "SC-28": "Protection of Information at Rest",
            "SI-10": "Information Input Validation",
            "CM-6": "Configuration Settings",
            "RA-5": "Vulnerability Scanning"
        }
        return descriptions.get(control, "")

    def _get_cwe_name(self, cwe_id: str) -> str:
        """Get CWE name."""
        # Common CWE names
        names = {
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-78": "OS Command Injection",
            "CWE-94": "Code Injection",
            "CWE-22": "Path Traversal",
            "CWE-287": "Improper Authentication",
            "CWE-284": "Improper Access Control",
            "CWE-327": "Use of Broken Crypto Algorithm",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-918": "Server-Side Request Forgery",
            "CWE-434": "Unrestricted File Upload",
            "CWE-798": "Use of Hardcoded Credentials",
            "CWE-862": "Missing Authorization",
            "CWE-863": "Incorrect Authorization",
            "CWE-307": "Improper Restriction of Auth Attempts"
        }
        return names.get(cwe_id, cwe_id)


# Convenience function
def map_to_frameworks(
    findings: List[Dict],
    frameworks: List[str] = None
) -> List[ComplianceMapping]:
    """
    Quick mapping of findings to frameworks.

    Args:
        findings: List of findings
        frameworks: Target frameworks

    Returns:
        List of mappings
    """
    mapper = ComplianceMapper()
    return mapper.map_findings(findings, frameworks)
