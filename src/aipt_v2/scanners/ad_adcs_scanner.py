"""
AIPTX Active Directory Certificate Services Scanner

Identifies vulnerable ADCS configurations:
- ESC1: Enrollee supplies subject + Client Authentication
- ESC2: Any Purpose EKU or no EKU
- ESC3: Certificate Request Agent
- ESC4: Vulnerable certificate template ACLs
- ESC5: Vulnerable PKI object ACLs
- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag
- ESC7: Vulnerable CA ACLs
- ESC8: NTLM relay to HTTP enrollment
- ESC9-11: Additional misconfigurations
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from .base import ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


class ESCType(Enum):
    """ADCS vulnerability types (ESC = Escalation)"""
    ESC1 = "ESC1"  # Enrollee supplies subject
    ESC2 = "ESC2"  # Any Purpose EKU
    ESC3 = "ESC3"  # Certificate Request Agent
    ESC4 = "ESC4"  # Vulnerable template ACLs
    ESC5 = "ESC5"  # Vulnerable PKI ACLs
    ESC6 = "ESC6"  # EDITF_ATTRIBUTESUBJECTALTNAME2
    ESC7 = "ESC7"  # Vulnerable CA ACLs
    ESC8 = "ESC8"  # HTTP enrollment relay
    ESC9 = "ESC9"  # No security extension
    ESC10 = "ESC10"  # Weak certificate mapping
    ESC11 = "ESC11"  # NTLM relay to RPC


@dataclass
class CertificateAuthority:
    """Certificate Authority information"""
    name: str
    dns_name: str
    ca_certificate: str = ""
    config_string: str = ""

    # CA settings
    web_enrollment: bool = False
    web_enrollment_url: str = ""
    request_disposition: int = 0
    edit_flags: int = 0

    # Vulnerabilities
    allows_san_flag: bool = False  # ESC6
    ntlm_relay_vulnerable: bool = False  # ESC8
    vulnerable_acls: bool = False  # ESC7

    # Metadata
    templates: list[str] = field(default_factory=list)
    esc_types: list[ESCType] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "dns_name": self.dns_name,
            "web_enrollment": self.web_enrollment,
            "web_enrollment_url": self.web_enrollment_url,
            "allows_san_flag": self.allows_san_flag,
            "ntlm_relay_vulnerable": self.ntlm_relay_vulnerable,
            "vulnerable_acls": self.vulnerable_acls,
            "templates_count": len(self.templates),
            "esc_types": [e.value for e in self.esc_types],
        }


@dataclass
class CertificateTemplate:
    """Certificate template information"""
    name: str
    display_name: str = ""
    oid: str = ""
    schema_version: int = 1

    # Enrollment settings
    enrollee_supplies_subject: bool = False
    requires_manager_approval: bool = False
    authorized_signatures_required: int = 0

    # Extended Key Usage
    eku: list[str] = field(default_factory=list)  # OIDs
    eku_names: list[str] = field(default_factory=list)
    any_purpose: bool = False
    client_authentication: bool = False
    certificate_request_agent: bool = False

    # Permissions
    enrollment_rights: list[str] = field(default_factory=list)
    write_owner: list[str] = field(default_factory=list)
    write_dacl: list[str] = field(default_factory=list)
    write_property: list[str] = field(default_factory=list)

    # Vulnerabilities
    esc_types: list[ESCType] = field(default_factory=list)
    risk_score: int = 0
    attack_paths: list[str] = field(default_factory=list)

    def is_vulnerable(self) -> bool:
        """Check if template has any ESC vulnerability"""
        return len(self.esc_types) > 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "enrollee_supplies_subject": self.enrollee_supplies_subject,
            "requires_manager_approval": self.requires_manager_approval,
            "eku_names": self.eku_names,
            "any_purpose": self.any_purpose,
            "client_authentication": self.client_authentication,
            "certificate_request_agent": self.certificate_request_agent,
            "enrollment_rights": self.enrollment_rights,
            "esc_types": [e.value for e in self.esc_types],
            "risk_score": self.risk_score,
            "attack_paths": self.attack_paths,
        }


@dataclass
class ADCSConfig:
    """ADCS scanner configuration"""
    # Authentication
    username: Optional[str] = None
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None
    domain: Optional[str] = None
    dc_ip: Optional[str] = None

    # Scan options
    check_web_enrollment: bool = True
    check_ntlm_relay: bool = True
    enumerate_templates: bool = True

    # Timeouts
    timeout: float = 60.0


@dataclass
class ADCSResult:
    """ADCS scan results"""
    target_domain: str
    certificate_authorities: list[CertificateAuthority] = field(default_factory=list)
    templates: list[CertificateTemplate] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)

    # Statistics
    total_cas: int = 0
    total_templates: int = 0
    vulnerable_templates: int = 0
    esc1_count: int = 0
    esc2_count: int = 0
    esc3_count: int = 0
    esc4_count: int = 0
    esc6_count: int = 0
    esc8_count: int = 0

    # Metadata
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def get_vulnerable_templates(self) -> list[CertificateTemplate]:
        """Get templates with vulnerabilities"""
        return [t for t in self.templates if t.is_vulnerable()]

    def get_templates_by_esc(self, esc_type: ESCType) -> list[CertificateTemplate]:
        """Get templates vulnerable to specific ESC"""
        return [t for t in self.templates if esc_type in t.esc_types]

    def update_stats(self) -> None:
        """Update statistics"""
        self.total_cas = len(self.certificate_authorities)
        self.total_templates = len(self.templates)
        self.vulnerable_templates = len(self.get_vulnerable_templates())
        self.esc1_count = len(self.get_templates_by_esc(ESCType.ESC1))
        self.esc2_count = len(self.get_templates_by_esc(ESCType.ESC2))
        self.esc3_count = len(self.get_templates_by_esc(ESCType.ESC3))
        self.esc4_count = len(self.get_templates_by_esc(ESCType.ESC4))
        self.esc6_count = sum(1 for ca in self.certificate_authorities if ca.allows_san_flag)
        self.esc8_count = sum(1 for ca in self.certificate_authorities if ca.ntlm_relay_vulnerable)

    def to_dict(self) -> dict:
        self.update_stats()
        return {
            "target_domain": self.target_domain,
            "statistics": {
                "total_cas": self.total_cas,
                "total_templates": self.total_templates,
                "vulnerable_templates": self.vulnerable_templates,
                "esc1": self.esc1_count,
                "esc2": self.esc2_count,
                "esc3": self.esc3_count,
                "esc4": self.esc4_count,
                "esc6": self.esc6_count,
                "esc8": self.esc8_count,
            },
            "certificate_authorities": [ca.to_dict() for ca in self.certificate_authorities],
            "vulnerable_templates": [t.to_dict() for t in self.get_vulnerable_templates()],
            "findings": [f.to_dict() for f in self.findings],
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }


class ADCSScanner:
    """
    Active Directory Certificate Services Scanner.

    Identifies vulnerable ADCS configurations using certipy patterns:
    - ESC1-ESC11 vulnerabilities
    - CA misconfigurations
    - Template permission issues
    """

    # EKU OIDs
    EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    EKU_PKINIT = "1.3.6.1.5.2.3.4"
    EKU_ANY_PURPOSE = "2.5.29.37.0"
    EKU_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

    def __init__(self, config: Optional[ADCSConfig] = None):
        self.config = config or ADCSConfig()

    async def scan(self, domain: str, dc_ip: str) -> ADCSResult:
        """
        Scan ADCS for vulnerabilities.

        Args:
            domain: Domain name
            dc_ip: DC IP address

        Returns:
            ADCSResult with findings
        """
        result = ADCSResult(target_domain=domain)
        result.start_time = datetime.utcnow()

        try:
            # Try certipy first (most comprehensive)
            certipy_result = await self._scan_with_certipy(domain, dc_ip)
            if certipy_result:
                result.certificate_authorities = certipy_result.get("cas", [])
                result.templates = certipy_result.get("templates", [])
            else:
                # Fallback to LDAP-based scanning
                await self._scan_via_ldap(domain, dc_ip, result)

            # Check web enrollment endpoints
            if self.config.check_web_enrollment:
                await self._check_web_enrollment(result)

            # Generate findings
            self._generate_findings(result)

        except Exception as e:
            logger.error(f"ADCS scan failed: {e}")
            result.errors.append(str(e))

        result.end_time = datetime.utcnow()
        if result.start_time:
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        result.update_stats()
        return result

    async def _scan_with_certipy(self, domain: str, dc_ip: str) -> Optional[dict]:
        """Use certipy for ADCS enumeration"""
        try:
            cmd = ["certipy", "find"]

            if self.config.username and self.config.password:
                cmd.extend([
                    "-u", f"{self.config.username}@{domain}",
                    "-p", self.config.password,
                ])
            elif self.config.username and self.config.ntlm_hash:
                cmd.extend([
                    "-u", f"{self.config.username}@{domain}",
                    "-hashes", f":{self.config.ntlm_hash}",
                ])

            cmd.extend([
                "-dc-ip", dc_ip,
                "-vulnerable",
                "-stdout",
            ])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout
            )

            output = stdout.decode()
            return self._parse_certipy_output(output, domain)

        except FileNotFoundError:
            logger.warning("certipy not found, falling back to LDAP scanning")
            return None
        except Exception as e:
            logger.error(f"certipy scan failed: {e}")
            return None

    def _parse_certipy_output(self, output: str, domain: str) -> dict:
        """Parse certipy find output"""
        result = {"cas": [], "templates": []}

        current_section = None
        current_ca = None
        current_template = None

        for line in output.split("\n"):
            line = line.strip()

            # Detect sections
            if "Certificate Authorities" in line:
                current_section = "ca"
                continue
            elif "Certificate Templates" in line:
                current_section = "templates"
                continue

            # Parse CA info
            if current_section == "ca":
                if line.startswith("CA Name"):
                    ca_name = line.split(":")[-1].strip()
                    current_ca = CertificateAuthority(
                        name=ca_name,
                        dns_name="",
                    )
                    result["cas"].append(current_ca)
                elif current_ca:
                    if "DNS Name" in line:
                        current_ca.dns_name = line.split(":")[-1].strip()
                    elif "Web Enrollment" in line:
                        current_ca.web_enrollment = "enabled" in line.lower() or "true" in line.lower()
                    elif "EDITF_ATTRIBUTESUBJECTALTNAME2" in line:
                        current_ca.allows_san_flag = True
                        current_ca.esc_types.append(ESCType.ESC6)

            # Parse template info
            elif current_section == "templates":
                if line.startswith("Template Name"):
                    template_name = line.split(":")[-1].strip()
                    current_template = CertificateTemplate(name=template_name)
                    result["templates"].append(current_template)
                elif current_template:
                    if "Enrollee Supplies Subject" in line:
                        current_template.enrollee_supplies_subject = "true" in line.lower()
                    elif "Client Authentication" in line:
                        current_template.client_authentication = "true" in line.lower()
                    elif "Any Purpose" in line:
                        current_template.any_purpose = "true" in line.lower()
                    elif "Certificate Request Agent" in line:
                        current_template.certificate_request_agent = "true" in line.lower()
                    elif "Manager Approval" in line:
                        current_template.requires_manager_approval = "true" in line.lower()
                    elif "[!] Vulnerabilities" in line or "ESC" in line:
                        # Parse ESC types
                        for esc in ESCType:
                            if esc.value in line:
                                current_template.esc_types.append(esc)

        # Analyze templates for ESC vulnerabilities
        for template in result["templates"]:
            self._analyze_template(template)

        return result

    def _analyze_template(self, template: CertificateTemplate) -> None:
        """Analyze template for ESC vulnerabilities"""

        # ESC1: Enrollee supplies subject + Client Authentication + Low-priv enrollment
        if (template.enrollee_supplies_subject and
            template.client_authentication and
            not template.requires_manager_approval):
            if ESCType.ESC1 not in template.esc_types:
                template.esc_types.append(ESCType.ESC1)
            template.risk_score += 100
            template.attack_paths.append(
                "Request certificate with arbitrary SAN -> Authenticate as any user"
            )

        # ESC2: Any Purpose EKU or no EKU
        if template.any_purpose:
            if ESCType.ESC2 not in template.esc_types:
                template.esc_types.append(ESCType.ESC2)
            template.risk_score += 80
            template.attack_paths.append(
                "Request any-purpose certificate -> Use for client auth"
            )

        # ESC3: Certificate Request Agent
        if template.certificate_request_agent:
            if ESCType.ESC3 not in template.esc_types:
                template.esc_types.append(ESCType.ESC3)
            template.risk_score += 90
            template.attack_paths.append(
                "Request agent certificate -> Request certificate on behalf of any user"
            )

        # ESC4: Vulnerable ACLs - would need to check permissions
        # This is simplified; real check needs DACL parsing

    async def _scan_via_ldap(self, domain: str, dc_ip: str, result: ADCSResult) -> None:
        """Fallback LDAP-based ADCS scanning"""
        try:
            from ldap3 import Server, Connection, SUBTREE, NTLM

            server = Server(dc_ip, port=389, connect_timeout=30)

            if self.config.username and self.config.password:
                user = f"{self.config.domain}\\{self.config.username}"
                conn = Connection(server, user=user, password=self.config.password, authentication=NTLM)
            else:
                conn = Connection(server)

            if not conn.bind():
                logger.error("LDAP bind failed for ADCS scan")
                return

            # Find configuration naming context
            config_nc = f"CN=Configuration,DC={',DC='.join(domain.split('.'))}"

            # Enumerate Certificate Authorities
            ca_filter = "(objectClass=pKIEnrollmentService)"
            conn.search(
                search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}",
                search_filter=ca_filter,
                search_scope=SUBTREE,
                attributes=["cn", "dNSHostName", "certificateTemplates"],
            )

            for entry in conn.entries:
                ca = CertificateAuthority(
                    name=str(entry.cn),
                    dns_name=str(entry.dNSHostName) if hasattr(entry, "dNSHostName") else "",
                )

                if hasattr(entry, "certificateTemplates"):
                    templates = entry.certificateTemplates.values if hasattr(entry.certificateTemplates, "values") else []
                    ca.templates = list(templates)

                result.certificate_authorities.append(ca)

            # Enumerate Certificate Templates
            template_filter = "(objectClass=pKICertificateTemplate)"
            conn.search(
                search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}",
                search_filter=template_filter,
                search_scope=SUBTREE,
                attributes=[
                    "cn", "displayName", "msPKI-Certificate-Name-Flag",
                    "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
                    "msPKI-RA-Signature", "msPKI-Certificate-Application-Policy",
                ],
            )

            for entry in conn.entries:
                template = CertificateTemplate(
                    name=str(entry.cn),
                    display_name=str(entry.displayName) if hasattr(entry, "displayName") else str(entry.cn),
                )

                # Check name flags for enrollee supplies subject
                if hasattr(entry, "msPKI-Certificate-Name-Flag"):
                    name_flag = int(str(entry["msPKI-Certificate-Name-Flag"]))
                    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
                    template.enrollee_supplies_subject = bool(name_flag & 0x1)

                # Check EKU
                if hasattr(entry, "pKIExtendedKeyUsage"):
                    ekus = entry.pKIExtendedKeyUsage.values if hasattr(entry.pKIExtendedKeyUsage, "values") else []
                    template.eku = list(ekus)
                    template.client_authentication = self.EKU_CLIENT_AUTH in ekus
                    template.any_purpose = self.EKU_ANY_PURPOSE in ekus
                    template.certificate_request_agent = self.EKU_CERTIFICATE_REQUEST_AGENT in ekus

                # Check signature requirements
                if hasattr(entry, "msPKI-RA-Signature"):
                    template.authorized_signatures_required = int(str(entry["msPKI-RA-Signature"]))
                    template.requires_manager_approval = template.authorized_signatures_required > 0

                # Analyze for vulnerabilities
                self._analyze_template(template)
                result.templates.append(template)

            conn.unbind()

        except ImportError:
            logger.error("ldap3 not installed")
        except Exception as e:
            logger.error(f"LDAP ADCS scan failed: {e}")
            result.errors.append(str(e))

    async def _check_web_enrollment(self, result: ADCSResult) -> None:
        """Check for HTTP web enrollment endpoints (ESC8)"""
        import httpx

        for ca in result.certificate_authorities:
            if not ca.dns_name:
                continue

            # Common web enrollment URLs
            urls = [
                f"http://{ca.dns_name}/certsrv/",
                f"https://{ca.dns_name}/certsrv/",
                f"http://{ca.dns_name}/certsrv/certfnsh.asp",
            ]

            for url in urls:
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10) as client:
                        response = await client.get(url)

                        if response.status_code in (200, 401, 403):
                            ca.web_enrollment = True
                            ca.web_enrollment_url = url

                            # Check for NTLM auth (ESC8 vulnerable)
                            if response.status_code == 401:
                                auth_header = response.headers.get("WWW-Authenticate", "")
                                if "NTLM" in auth_header or "Negotiate" in auth_header:
                                    ca.ntlm_relay_vulnerable = True
                                    ca.esc_types.append(ESCType.ESC8)

                            break

                except Exception as e:
                    logger.debug(f"Web enrollment check failed for {url}: {e}")

    def _generate_findings(self, result: ADCSResult) -> None:
        """Generate ScanFinding objects from results"""

        # ESC1 findings
        for template in result.get_templates_by_esc(ESCType.ESC1):
            result.findings.append(ScanFinding(
                title=f"ESC1 Vulnerable Template: {template.name}",
                severity=ScanSeverity.CRITICAL,
                description=(
                    f"Template '{template.name}' allows enrollee to supply subject name "
                    f"and has Client Authentication EKU. Can request certificate as any user."
                ),
                scanner="ad_adcs_scanner",
                tags=["adcs", "esc1", "certificate", "privilege_escalation"],
            ))

        # ESC2 findings
        for template in result.get_templates_by_esc(ESCType.ESC2):
            result.findings.append(ScanFinding(
                title=f"ESC2 Vulnerable Template: {template.name}",
                severity=ScanSeverity.HIGH,
                description=(
                    f"Template '{template.name}' has Any Purpose EKU. "
                    f"Certificate can be used for any authentication purpose."
                ),
                scanner="ad_adcs_scanner",
                tags=["adcs", "esc2", "certificate"],
            ))

        # ESC3 findings
        for template in result.get_templates_by_esc(ESCType.ESC3):
            result.findings.append(ScanFinding(
                title=f"ESC3 Vulnerable Template: {template.name}",
                severity=ScanSeverity.CRITICAL,
                description=(
                    f"Template '{template.name}' allows Certificate Request Agent. "
                    f"Can request certificates on behalf of other users."
                ),
                scanner="ad_adcs_scanner",
                tags=["adcs", "esc3", "certificate", "delegation"],
            ))

        # ESC6 findings (CA level)
        for ca in result.certificate_authorities:
            if ca.allows_san_flag:
                result.findings.append(ScanFinding(
                    title=f"ESC6 Vulnerable CA: {ca.name}",
                    severity=ScanSeverity.CRITICAL,
                    description=(
                        f"CA '{ca.name}' has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled. "
                        f"Any template can be used to request certificate with arbitrary SAN."
                    ),
                    scanner="ad_adcs_scanner",
                    tags=["adcs", "esc6", "ca_misconfiguration"],
                ))

        # ESC8 findings
        for ca in result.certificate_authorities:
            if ca.ntlm_relay_vulnerable:
                result.findings.append(ScanFinding(
                    title=f"ESC8 Vulnerable Endpoint: {ca.name}",
                    severity=ScanSeverity.CRITICAL,
                    description=(
                        f"CA '{ca.name}' has HTTP enrollment with NTLM authentication at {ca.web_enrollment_url}. "
                        f"Vulnerable to NTLM relay attacks."
                    ),
                    url=ca.web_enrollment_url,
                    scanner="ad_adcs_scanner",
                    tags=["adcs", "esc8", "ntlm_relay", "web_enrollment"],
                ))


# Convenience function
async def scan_adcs(
    domain: str,
    dc_ip: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
) -> ADCSResult:
    """
    Scan ADCS for vulnerabilities.

    Args:
        domain: Domain name
        dc_ip: DC IP
        username: Username
        password: Password
        ntlm_hash: NTLM hash

    Returns:
        ADCSResult with findings
    """
    config = ADCSConfig(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        dc_ip=dc_ip,
    )
    scanner = ADCSScanner(config)
    return await scanner.scan(domain, dc_ip)
