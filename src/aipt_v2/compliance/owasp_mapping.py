"""
OWASP Top 10 2021 Mapping

Provides detailed OWASP Top 10 2021 category definitions
and CWE-to-OWASP mapping.

Usage:
    from aipt_v2.compliance import OWASPMapper, get_owasp_category

    category = get_owasp_category("CWE-79")  # Returns A03
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class OWASPCategory:
    """OWASP Top 10 category definition."""
    id: str
    name: str
    description: str
    cwes: List[str]
    risk_factors: Dict[str, str]
    prevention: List[str]


# OWASP Top 10 2021 definitions
OWASP_TOP_10 = {
    "A01": OWASPCategory(
        id="A01:2021",
        name="Broken Access Control",
        description="Access control enforces policy such that users cannot act outside "
                   "of their intended permissions. Failures typically lead to unauthorized "
                   "information disclosure, modification, or destruction of all data or "
                   "performing a business function outside the user's limits.",
        cwes=["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219",
              "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359",
              "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540",
              "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668",
              "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"],
        risk_factors={
            "threat_agents": "Anyone with network access",
            "exploitability": "Average",
            "prevalence": "Widespread",
            "detectability": "Average",
            "impact": "Severe"
        },
        prevention=[
            "Except for public resources, deny by default",
            "Implement access control mechanisms once and re-use them",
            "Enforce record ownership, rather than accepting that the user can create, read, update, or delete any record",
            "Disable web server directory listing and ensure file metadata and backup files are not present",
            "Log access control failures, alert admins when appropriate",
            "Rate limit API and controller access to minimize harm from automated attack tooling",
            "Invalidate JWT tokens on the server after logout"
        ]
    ),

    "A02": OWASPCategory(
        id="A02:2021",
        name="Cryptographic Failures",
        description="Failures related to cryptography (or lack thereof) which often lead "
                   "to exposure of sensitive data. This includes exposure of sensitive data "
                   "that requires protection, such as passwords, credit card numbers, health "
                   "records, personal information.",
        cwes=["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-320", "CWE-321", "CWE-322",
              "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329",
              "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340",
              "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780",
              "CWE-818", "CWE-916"],
        risk_factors={
            "threat_agents": "Attackers with access to data in transit/at rest",
            "exploitability": "Average",
            "prevalence": "Widespread",
            "detectability": "Average",
            "impact": "Severe"
        },
        prevention=[
            "Classify data processed, stored, or transmitted by an application",
            "Don't store sensitive data unnecessarily. Discard it as soon as possible",
            "Make sure to encrypt all sensitive data at rest",
            "Ensure up-to-date and strong standard algorithms, protocols, and keys are in place",
            "Encrypt all data in transit with secure protocols such as TLS",
            "Disable caching for responses that contain sensitive data",
            "Do not use legacy protocols such as FTP and SMTP for transporting sensitive data"
        ]
    ),

    "A03": OWASPCategory(
        id="A03:2021",
        name="Injection",
        description="User-supplied data is not validated, filtered, or sanitized by the "
                   "application. Dynamic queries or non-parameterized calls without "
                   "context-aware escaping are used directly in the interpreter.",
        cwes=["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80",
              "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93",
              "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-113",
              "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610",
              "CWE-643", "CWE-644", "CWE-652", "CWE-917"],
        risk_factors={
            "threat_agents": "Anyone who can send untrusted data",
            "exploitability": "Easy",
            "prevalence": "Common",
            "detectability": "Easy",
            "impact": "Severe"
        },
        prevention=[
            "Use a safe API which avoids using the interpreter entirely",
            "Use positive server-side input validation",
            "Use LIMIT and other SQL controls to prevent mass disclosure",
            "Use parameterized queries and stored procedures",
            "Escape special characters using the specific escape syntax"
        ]
    ),

    "A04": OWASPCategory(
        id="A04:2021",
        name="Insecure Design",
        description="Insecure design is a broad category representing different weaknesses, "
                   "expressed as 'missing or ineffective control design.' This category "
                   "focuses on risks related to design and architectural flaws.",
        cwes=["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257",
              "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316",
              "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501",
              "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642",
              "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807",
              "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"],
        risk_factors={
            "threat_agents": "Varies based on design flaw",
            "exploitability": "Average",
            "prevalence": "Common",
            "detectability": "Difficult",
            "impact": "Moderate to Severe"
        },
        prevention=[
            "Establish and use a secure development lifecycle",
            "Use threat modeling for critical authentication and access control",
            "Integrate security language and controls into user stories",
            "Write unit and integration tests to validate security controls",
            "Tier application and network layers for critical applications"
        ]
    ),

    "A05": OWASPCategory(
        id="A05:2021",
        name="Security Misconfiguration",
        description="The application might be vulnerable if missing appropriate security "
                   "hardening or having improperly configured permissions on cloud services. "
                   "Default configurations, incomplete or ad hoc configurations.",
        cwes=["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315",
              "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614",
              "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"],
        risk_factors={
            "threat_agents": "Attackers with system access",
            "exploitability": "Easy",
            "prevalence": "Widespread",
            "detectability": "Easy",
            "impact": "Moderate"
        },
        prevention=[
            "A repeatable hardening process for fast and easy deployment",
            "A minimal platform without unnecessary features and components",
            "A task to review and update configurations as part of patch management",
            "A segmented application architecture with effective separation",
            "Sending security directives to clients, e.g., Security Headers"
        ]
    ),

    "A06": OWASPCategory(
        id="A06:2021",
        name="Vulnerable and Outdated Components",
        description="Components run with the same privileges as the application. "
                   "If a vulnerable component is exploited, such an attack can "
                   "facilitate serious data loss or server takeover.",
        cwes=["CWE-937", "CWE-1035", "CWE-1104"],
        risk_factors={
            "threat_agents": "Attackers with vulnerability knowledge",
            "exploitability": "Average",
            "prevalence": "Widespread",
            "detectability": "Difficult",
            "impact": "Moderate to Severe"
        },
        prevention=[
            "Remove unused dependencies, unnecessary features, components",
            "Continuously inventory component versions (client and server-side)",
            "Monitor sources like CVE and NVD for vulnerabilities",
            "Only obtain components from official sources over secure links",
            "Monitor for libraries and components that are unmaintained"
        ]
    ),

    "A07": OWASPCategory(
        id="A07:2021",
        name="Identification and Authentication Failures",
        description="Confirmation of the user's identity, authentication, and session "
                   "management is critical to protect against authentication-related attacks.",
        cwes=["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295",
              "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346",
              "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940",
              "CWE-1216"],
        risk_factors={
            "threat_agents": "Anyone attempting to impersonate users",
            "exploitability": "Average",
            "prevalence": "Common",
            "detectability": "Average",
            "impact": "Severe"
        },
        prevention=[
            "Implement multi-factor authentication",
            "Do not ship or deploy with any default credentials",
            "Implement weak-password checks against top 10,000 worst passwords",
            "Use a server-side session manager that generates random session IDs",
            "Limit or increasingly delay failed login attempts"
        ]
    ),

    "A08": OWASPCategory(
        id="A08:2021",
        name="Software and Data Integrity Failures",
        description="Code and infrastructure that does not protect against integrity "
                   "violations. This includes using plugins, libraries, or modules from "
                   "untrusted sources, repositories, and CDNs.",
        cwes=["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784",
              "CWE-829", "CWE-830", "CWE-915"],
        risk_factors={
            "threat_agents": "Supply chain or CI/CD attackers",
            "exploitability": "Average",
            "prevalence": "Common",
            "detectability": "Difficult",
            "impact": "Severe"
        },
        prevention=[
            "Use digital signatures to verify software or data is from expected source",
            "Ensure libraries and dependencies are consuming trusted repositories",
            "Use a software supply chain security tool like OWASP Dependency-Check",
            "Ensure your CI/CD pipeline has proper segregation and access control",
            "Do not send unsigned or unencrypted serialized data to untrusted clients"
        ]
    ),

    "A09": OWASPCategory(
        id="A09:2021",
        name="Security Logging and Monitoring Failures",
        description="This category helps detect, escalate, and respond to active breaches. "
                   "Without logging and monitoring, breaches cannot be detected.",
        cwes=["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        risk_factors={
            "threat_agents": "Attackers relying on lack of monitoring",
            "exploitability": "Average",
            "prevalence": "Widespread",
            "detectability": "Difficult",
            "impact": "Moderate"
        },
        prevention=[
            "Ensure all login, access control, and server-side input validation failures are logged",
            "Ensure logs are generated in a format easily consumed by log management solutions",
            "Ensure log data is encoded correctly to prevent injections",
            "Establish effective monitoring and alerting",
            "Establish an incident response and recovery plan"
        ]
    ),

    "A10": OWASPCategory(
        id="A10:2021",
        name="Server-Side Request Forgery",
        description="SSRF flaws occur whenever a web application is fetching a remote "
                   "resource without validating the user-supplied URL. It allows an "
                   "attacker to coerce the application to send a crafted request to "
                   "an unexpected destination.",
        cwes=["CWE-918"],
        risk_factors={
            "threat_agents": "Attackers with access to URL input",
            "exploitability": "Average",
            "prevalence": "Common",
            "detectability": "Average",
            "impact": "Moderate to Severe"
        },
        prevention=[
            "Sanitize and validate all client-supplied input data",
            "Enforce the URL schema, port, and destination with a positive allow list",
            "Do not send raw responses to clients",
            "Disable HTTP redirections",
            "Use network-level firewall policies to block all but essential traffic"
        ]
    )
}


class OWASPMapper:
    """OWASP Top 10 specific mapper."""

    def __init__(self):
        self.categories = OWASP_TOP_10

    def get_category(self, cwe_id: str) -> Optional[OWASPCategory]:
        """Get OWASP category for a CWE."""
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        for cat_id, category in self.categories.items():
            if cwe_id in category.cwes:
                return category

        return None

    def get_category_by_id(self, category_id: str) -> Optional[OWASPCategory]:
        """Get OWASP category by ID (A01-A10)."""
        return self.categories.get(category_id.upper())

    def get_all_cwes_for_category(self, category_id: str) -> List[str]:
        """Get all CWEs mapped to a category."""
        category = self.categories.get(category_id.upper())
        return category.cwes if category else []


def get_owasp_category(cwe_id: str) -> Optional[str]:
    """
    Get OWASP category ID for a CWE.

    Args:
        cwe_id: CWE identifier

    Returns:
        OWASP category ID (A01-A10) or None
    """
    mapper = OWASPMapper()
    category = mapper.get_category(cwe_id)
    return category.id if category else None
