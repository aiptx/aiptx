"""
AIPT Active Directory Privilege Escalation Scanner

Identifies privileged accounts, dangerous configurations, and
potential privilege escalation paths in Active Directory.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from .base import ScanFinding, ScanResult, ScanSeverity

logger = logging.getLogger(__name__)


class ADFindingType(Enum):
    """Types of AD security findings"""
    # Privileged Groups
    DOMAIN_ADMIN = "domain_admin"
    ENTERPRISE_ADMIN = "enterprise_admin"
    SCHEMA_ADMIN = "schema_admin"
    BACKUP_OPERATOR = "backup_operator"
    ACCOUNT_OPERATOR = "account_operator"
    SERVER_OPERATOR = "server_operator"
    PRINT_OPERATOR = "print_operator"
    DNSADMIN = "dnsadmin"

    # Dangerous Configurations
    ASREP_ROASTABLE = "asrep_roastable"
    KERBEROASTABLE = "kerberoastable"
    UNCONSTRAINED_DELEGATION = "unconstrained_delegation"
    CONSTRAINED_DELEGATION = "constrained_delegation"
    RBCD_TARGET = "rbcd_target"
    PASSWORD_NEVER_EXPIRES = "password_never_expires"
    PASSWORD_NOT_REQUIRED = "password_not_required"
    REVERSIBLE_ENCRYPTION = "reversible_encryption"
    DES_ONLY = "des_only_encryption"
    NO_PREAUTH = "no_preauth"
    TRUSTED_FOR_DELEGATION = "trusted_for_delegation"

    # Service Accounts
    GMSA = "gmsa"
    MSA = "msa"
    LAPS_READER = "laps_reader"

    # ACL Abuse
    GENERICALL_USER = "genericall_on_user"
    GENERICALL_GROUP = "genericall_on_group"
    GENERICALL_COMPUTER = "genericall_on_computer"
    WRITEDACL = "writedacl"
    WRITEOWNER = "writeowner"
    FORCECHANGEPASSWORD = "forcechangepassword"
    ADDMEMBER = "addmember"
    WRITESPN = "writespn"

    # Misconfiguration
    ADMINCOUNT_ORPHAN = "admincount_orphan"
    SID_HISTORY = "sid_history"
    SHADOW_CREDENTIALS = "shadow_credentials_target"


@dataclass
class ADPrivilegedAccount:
    """Privileged AD account or group"""
    name: str
    sam_account_name: str
    object_type: str  # user, group, computer
    dn: str = ""
    sid: str = ""

    # Privileges
    finding_types: list[ADFindingType] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)

    # Risk assessment
    risk_score: int = 0
    attack_paths: list[str] = field(default_factory=list)

    # Additional attributes
    spn: list[str] = field(default_factory=list)
    delegation_targets: list[str] = field(default_factory=list)
    acl_rights: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "sam_account_name": self.sam_account_name,
            "object_type": self.object_type,
            "dn": self.dn,
            "sid": self.sid,
            "finding_types": [f.value for f in self.finding_types],
            "groups": self.groups,
            "risk_score": self.risk_score,
            "attack_paths": self.attack_paths,
            "spn": self.spn,
            "delegation_targets": self.delegation_targets,
        }


@dataclass
class ADPrivescConfig:
    """AD privilege escalation scanner configuration"""
    # What to scan for
    scan_privileged_groups: bool = True
    scan_dangerous_flags: bool = True
    scan_delegation: bool = True
    scan_acls: bool = True
    scan_service_accounts: bool = True
    scan_gpos: bool = True
    scan_laps: bool = True

    # LDAP settings
    ldap_timeout: float = 30.0
    page_size: int = 1000

    # Credentials
    username: Optional[str] = None
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None
    domain: Optional[str] = None

    # DC connection
    dc_ip: Optional[str] = None


@dataclass
class ADPrivescResult:
    """AD privilege escalation scan results"""
    target_domain: str
    dc_ip: str

    # Discovered items
    privileged_accounts: list[ADPrivilegedAccount] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)

    # Statistics
    domain_admins_count: int = 0
    enterprise_admins_count: int = 0
    kerberoastable_count: int = 0
    asrep_roastable_count: int = 0
    unconstrained_delegation_count: int = 0
    constrained_delegation_count: int = 0
    acl_abuse_count: int = 0

    # Risk summary
    critical_findings: int = 0
    high_findings: int = 0
    total_risk_score: int = 0

    # Metadata
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def get_by_type(self, finding_type: ADFindingType) -> list[ADPrivilegedAccount]:
        """Get accounts by finding type"""
        return [a for a in self.privileged_accounts if finding_type in a.finding_types]

    def update_stats(self) -> None:
        """Update statistics from findings"""
        self.domain_admins_count = len(self.get_by_type(ADFindingType.DOMAIN_ADMIN))
        self.enterprise_admins_count = len(self.get_by_type(ADFindingType.ENTERPRISE_ADMIN))
        self.kerberoastable_count = len(self.get_by_type(ADFindingType.KERBEROASTABLE))
        self.asrep_roastable_count = len(self.get_by_type(ADFindingType.ASREP_ROASTABLE))
        self.unconstrained_delegation_count = len(self.get_by_type(ADFindingType.UNCONSTRAINED_DELEGATION))
        self.constrained_delegation_count = len(self.get_by_type(ADFindingType.CONSTRAINED_DELEGATION))

        self.critical_findings = sum(1 for f in self.findings if f.severity == ScanSeverity.CRITICAL)
        self.high_findings = sum(1 for f in self.findings if f.severity == ScanSeverity.HIGH)
        self.total_risk_score = sum(a.risk_score for a in self.privileged_accounts)

    def to_dict(self) -> dict:
        self.update_stats()
        return {
            "target_domain": self.target_domain,
            "dc_ip": self.dc_ip,
            "statistics": {
                "domain_admins": self.domain_admins_count,
                "enterprise_admins": self.enterprise_admins_count,
                "kerberoastable": self.kerberoastable_count,
                "asrep_roastable": self.asrep_roastable_count,
                "unconstrained_delegation": self.unconstrained_delegation_count,
                "constrained_delegation": self.constrained_delegation_count,
                "critical_findings": self.critical_findings,
                "high_findings": self.high_findings,
                "total_risk_score": self.total_risk_score,
            },
            "privileged_accounts": [a.to_dict() for a in self.privileged_accounts],
            "findings": [f.to_dict() for f in self.findings],
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }


class ADPrivescScanner:
    """
    Active Directory Privilege Escalation Scanner.

    Identifies:
    - Members of privileged groups (Domain Admins, Enterprise Admins, etc.)
    - Accounts with dangerous configurations (AS-REP roastable, Kerberoastable)
    - Delegation misconfigurations (unconstrained, constrained, RBCD)
    - ACL abuse opportunities (GenericAll, WriteDACL, etc.)
    - Service account vulnerabilities (gMSA, LAPS readers)
    """

    # Privileged group SIDs
    PRIVILEGED_GROUPS = {
        "S-1-5-32-544": ("Administrators", ADFindingType.DOMAIN_ADMIN),
        "S-1-5-21-*-512": ("Domain Admins", ADFindingType.DOMAIN_ADMIN),
        "S-1-5-21-*-519": ("Enterprise Admins", ADFindingType.ENTERPRISE_ADMIN),
        "S-1-5-21-*-518": ("Schema Admins", ADFindingType.SCHEMA_ADMIN),
        "S-1-5-32-551": ("Backup Operators", ADFindingType.BACKUP_OPERATOR),
        "S-1-5-32-548": ("Account Operators", ADFindingType.ACCOUNT_OPERATOR),
        "S-1-5-32-549": ("Server Operators", ADFindingType.SERVER_OPERATOR),
        "S-1-5-32-550": ("Print Operators", ADFindingType.PRINT_OPERATOR),
    }

    # User Account Control flags
    UAC_FLAGS = {
        0x0002: ("ACCOUNTDISABLE", None),
        0x0020: ("PASSWD_NOTREQD", ADFindingType.PASSWORD_NOT_REQUIRED),
        0x0080: ("ENCRYPTED_TEXT_PWD_ALLOWED", ADFindingType.REVERSIBLE_ENCRYPTION),
        0x10000: ("DONT_EXPIRE_PASSWORD", ADFindingType.PASSWORD_NEVER_EXPIRES),
        0x80000: ("TRUSTED_FOR_DELEGATION", ADFindingType.UNCONSTRAINED_DELEGATION),
        0x100000: ("NOT_DELEGATED", None),  # Actually a protection
        0x200000: ("USE_DES_KEY_ONLY", ADFindingType.DES_ONLY),
        0x400000: ("DONT_REQ_PREAUTH", ADFindingType.ASREP_ROASTABLE),
        0x1000000: ("TRUSTED_TO_AUTH_FOR_DELEGATION", ADFindingType.CONSTRAINED_DELEGATION),
    }

    def __init__(self, config: Optional[ADPrivescConfig] = None):
        self.config = config or ADPrivescConfig()
        self._conn = None

    async def scan(self, domain: str, dc_ip: str) -> ADPrivescResult:
        """
        Perform AD privilege escalation scan.

        Args:
            domain: Target domain name
            dc_ip: Domain controller IP

        Returns:
            ADPrivescResult with findings
        """
        result = ADPrivescResult(target_domain=domain, dc_ip=dc_ip)
        result.start_time = datetime.utcnow()

        try:
            # Connect to LDAP
            conn = await self._connect_ldap(domain, dc_ip)
            if not conn:
                result.errors.append("Failed to connect to LDAP")
                return result

            base_dn = ",".join(f"DC={part}" for part in domain.split("."))

            # Phase 1: Enumerate privileged groups
            if self.config.scan_privileged_groups:
                logger.info("Scanning privileged groups")
                await self._scan_privileged_groups(conn, base_dn, result)

            # Phase 2: Find dangerous user configurations
            if self.config.scan_dangerous_flags:
                logger.info("Scanning dangerous configurations")
                await self._scan_dangerous_flags(conn, base_dn, result)

            # Phase 3: Scan delegation configurations
            if self.config.scan_delegation:
                logger.info("Scanning delegation configurations")
                await self._scan_delegation(conn, base_dn, result)

            # Phase 4: Scan for Kerberoastable accounts
            logger.info("Scanning for Kerberoastable accounts")
            await self._scan_kerberoastable(conn, base_dn, result)

            # Phase 5: Scan ACLs for abuse opportunities
            if self.config.scan_acls:
                logger.info("Scanning ACLs for abuse opportunities")
                await self._scan_acl_abuse(conn, base_dn, result)

            # Phase 6: Scan for LAPS
            if self.config.scan_laps:
                logger.info("Scanning LAPS configuration")
                await self._scan_laps(conn, base_dn, result)

            # Phase 7: Scan service accounts
            if self.config.scan_service_accounts:
                logger.info("Scanning service accounts")
                await self._scan_service_accounts(conn, base_dn, result)

            conn.unbind()

        except Exception as e:
            logger.error(f"AD privilege scan failed: {e}")
            result.errors.append(str(e))

        result.end_time = datetime.utcnow()
        if result.start_time:
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        result.update_stats()
        return result

    async def _connect_ldap(self, domain: str, dc_ip: str):
        """Connect to LDAP server"""
        try:
            from ldap3 import Server, Connection, ALL, SIMPLE, NTLM

            server = Server(dc_ip, port=389, get_info=ALL, connect_timeout=self.config.ldap_timeout)

            if self.config.username and self.config.password:
                user = f"{self.config.domain}\\{self.config.username}" if self.config.domain else self.config.username
                conn = Connection(server, user=user, password=self.config.password, authentication=NTLM)
            elif self.config.username and self.config.ntlm_hash:
                # NTLM hash auth requires special handling
                user = f"{self.config.domain}\\{self.config.username}" if self.config.domain else self.config.username
                conn = Connection(server, user=user, password=self.config.ntlm_hash, authentication=NTLM)
            else:
                # Anonymous bind
                conn = Connection(server)

            if conn.bind():
                logger.info(f"Connected to LDAP on {dc_ip}")
                return conn
            else:
                logger.error(f"LDAP bind failed: {conn.last_error}")
                return None

        except ImportError:
            logger.error("ldap3 not installed")
            return None
        except Exception as e:
            logger.error(f"LDAP connection failed: {e}")
            return None

    async def _scan_privileged_groups(self, conn, base_dn: str, result: ADPrivescResult) -> None:
        """Enumerate members of privileged groups"""
        from ldap3 import SUBTREE

        privileged_groups = [
            ("Domain Admins", ADFindingType.DOMAIN_ADMIN),
            ("Enterprise Admins", ADFindingType.ENTERPRISE_ADMIN),
            ("Schema Admins", ADFindingType.SCHEMA_ADMIN),
            ("Administrators", ADFindingType.DOMAIN_ADMIN),
            ("Backup Operators", ADFindingType.BACKUP_OPERATOR),
            ("Account Operators", ADFindingType.ACCOUNT_OPERATOR),
            ("Server Operators", ADFindingType.SERVER_OPERATOR),
            ("Print Operators", ADFindingType.PRINT_OPERATOR),
            ("DnsAdmins", ADFindingType.DNSADMIN),
        ]

        for group_name, finding_type in privileged_groups:
            search_filter = f"(&(objectClass=group)(cn={group_name}))"

            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["member", "distinguishedName"],
            )

            for entry in conn.entries:
                if hasattr(entry, "member"):
                    members = entry.member.values if hasattr(entry.member, "values") else [str(entry.member)]

                    for member_dn in members:
                        if not member_dn:
                            continue

                        # Get member details
                        conn.search(
                            search_base=str(member_dn),
                            search_filter="(objectClass=*)",
                            search_scope="BASE",
                            attributes=["sAMAccountName", "objectClass", "objectSid", "userAccountControl"],
                        )

                        if conn.entries:
                            member_entry = conn.entries[0]
                            sam_name = str(member_entry.sAMAccountName) if hasattr(member_entry, "sAMAccountName") else ""

                            # Determine object type
                            obj_class = member_entry.objectClass.values if hasattr(member_entry.objectClass, "values") else []
                            if "user" in obj_class:
                                obj_type = "user"
                            elif "group" in obj_class:
                                obj_type = "group"
                            elif "computer" in obj_class:
                                obj_type = "computer"
                            else:
                                obj_type = "unknown"

                            # Create or update account record
                            existing = next((a for a in result.privileged_accounts if a.dn == str(member_dn)), None)

                            if existing:
                                if finding_type not in existing.finding_types:
                                    existing.finding_types.append(finding_type)
                                existing.groups.append(group_name)
                            else:
                                account = ADPrivilegedAccount(
                                    name=sam_name or str(member_dn).split(",")[0].replace("CN=", ""),
                                    sam_account_name=sam_name,
                                    object_type=obj_type,
                                    dn=str(member_dn),
                                    sid=str(member_entry.objectSid) if hasattr(member_entry, "objectSid") else "",
                                    finding_types=[finding_type],
                                    groups=[group_name],
                                    risk_score=self._calculate_risk_score([finding_type]),
                                )
                                result.privileged_accounts.append(account)

                            # Create finding
                            severity = self._get_finding_severity(finding_type)
                            result.findings.append(ScanFinding(
                                title=f"Member of {group_name}: {sam_name}",
                                severity=severity,
                                description=f"User/Group '{sam_name}' is a member of the privileged group '{group_name}'",
                                host=result.dc_ip,
                                scanner="ad_privesc_scanner",
                                tags=[finding_type.value, "privileged_group"],
                            ))

    async def _scan_dangerous_flags(self, conn, base_dn: str, result: ADPrivescResult) -> None:
        """Find users with dangerous UAC flags"""
        from ldap3 import SUBTREE

        # Find AS-REP roastable users (DONT_REQ_PREAUTH)
        search_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "objectSid", "userAccountControl"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)

            existing = next((a for a in result.privileged_accounts if a.sam_account_name == sam_name), None)

            if existing:
                if ADFindingType.ASREP_ROASTABLE not in existing.finding_types:
                    existing.finding_types.append(ADFindingType.ASREP_ROASTABLE)
                    existing.risk_score += 30
            else:
                account = ADPrivilegedAccount(
                    name=sam_name,
                    sam_account_name=sam_name,
                    object_type="user",
                    dn=str(entry.distinguishedName),
                    sid=str(entry.objectSid) if hasattr(entry, "objectSid") else "",
                    finding_types=[ADFindingType.ASREP_ROASTABLE],
                    risk_score=30,
                    attack_paths=["AS-REP Roast -> Crack Hash -> Credential Access"],
                )
                result.privileged_accounts.append(account)

            result.findings.append(ScanFinding(
                title=f"AS-REP Roastable User: {sam_name}",
                severity=ScanSeverity.HIGH,
                description=f"User '{sam_name}' has DONT_REQ_PREAUTH flag set. Can request AS-REP without pre-authentication and crack offline.",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["asrep_roastable", "kerberos", "credential_access"],
            ))

        # Find users with password not required
        search_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)

            result.findings.append(ScanFinding(
                title=f"Password Not Required: {sam_name}",
                severity=ScanSeverity.HIGH,
                description=f"User '{sam_name}' has PASSWD_NOTREQD flag. Account may have blank password.",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["password_not_required", "misconfiguration"],
            ))

        # Find users with password never expires
        search_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)

            result.findings.append(ScanFinding(
                title=f"Password Never Expires: {sam_name}",
                severity=ScanSeverity.LOW,
                description=f"User '{sam_name}' has password set to never expire.",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["password_never_expires", "policy"],
            ))

    async def _scan_kerberoastable(self, conn, base_dn: str, result: ADPrivescResult) -> None:
        """Find Kerberoastable users (users with SPNs)"""
        from ldap3 import SUBTREE

        # Users with SPNs (excluding computer accounts)
        search_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "objectSid", "servicePrincipalName", "adminCount"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)
            spns = entry.servicePrincipalName.values if hasattr(entry.servicePrincipalName, "values") else []

            existing = next((a for a in result.privileged_accounts if a.sam_account_name == sam_name), None)

            admin_count = False
            if hasattr(entry, "adminCount"):
                try:
                    admin_count = int(str(entry.adminCount)) == 1
                except (ValueError, TypeError):
                    pass

            if existing:
                if ADFindingType.KERBEROASTABLE not in existing.finding_types:
                    existing.finding_types.append(ADFindingType.KERBEROASTABLE)
                    existing.risk_score += 25
                existing.spn = list(spns)
            else:
                account = ADPrivilegedAccount(
                    name=sam_name,
                    sam_account_name=sam_name,
                    object_type="user",
                    dn=str(entry.distinguishedName),
                    sid=str(entry.objectSid) if hasattr(entry, "objectSid") else "",
                    finding_types=[ADFindingType.KERBEROASTABLE],
                    spn=list(spns),
                    risk_score=25 + (20 if admin_count else 0),
                    attack_paths=["Kerberoast -> Request TGS -> Crack Hash -> Credential Access"],
                )
                result.privileged_accounts.append(account)

            severity = ScanSeverity.HIGH if admin_count else ScanSeverity.MEDIUM
            result.findings.append(ScanFinding(
                title=f"Kerberoastable User: {sam_name}",
                severity=severity,
                description=f"User '{sam_name}' has SPNs: {', '.join(spns[:3])}{'...' if len(spns) > 3 else ''}. Can request TGS and crack offline.",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["kerberoastable", "kerberos", "credential_access"] + (["admincount"] if admin_count else []),
            ))

    async def _scan_delegation(self, conn, base_dn: str, result: ADPrivescResult) -> None:
        """Find delegation misconfigurations"""
        from ldap3 import SUBTREE

        # Unconstrained delegation (computers)
        search_filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "dNSHostName"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)
            dns_name = str(entry.dNSHostName) if hasattr(entry, "dNSHostName") else sam_name

            account = ADPrivilegedAccount(
                name=dns_name,
                sam_account_name=sam_name,
                object_type="computer",
                dn=str(entry.distinguishedName),
                finding_types=[ADFindingType.UNCONSTRAINED_DELEGATION],
                risk_score=40,
                attack_paths=[
                    "Compromise Computer -> Capture TGTs -> Impersonate Any User",
                    "PrinterBug/PetitPotam -> Capture DC TGT -> DCSync",
                ],
            )
            result.privileged_accounts.append(account)

            result.findings.append(ScanFinding(
                title=f"Unconstrained Delegation: {dns_name}",
                severity=ScanSeverity.CRITICAL,
                description=f"Computer '{dns_name}' has unconstrained delegation. Can capture TGTs of connecting users.",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["unconstrained_delegation", "kerberos", "lateral_movement"],
            ))

        # Constrained delegation (msDS-AllowedToDelegateTo)
        search_filter = "(msDS-AllowedToDelegateTo=*)"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "objectClass", "msDS-AllowedToDelegateTo"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)
            obj_class = entry.objectClass.values if hasattr(entry.objectClass, "values") else []
            obj_type = "computer" if "computer" in obj_class else "user"

            delegation_targets = []
            if hasattr(entry, "msDS-AllowedToDelegateTo"):
                targets = entry["msDS-AllowedToDelegateTo"]
                delegation_targets = targets.values if hasattr(targets, "values") else [str(targets)]

            existing = next((a for a in result.privileged_accounts if a.sam_account_name == sam_name), None)

            if existing:
                if ADFindingType.CONSTRAINED_DELEGATION not in existing.finding_types:
                    existing.finding_types.append(ADFindingType.CONSTRAINED_DELEGATION)
                    existing.risk_score += 30
                existing.delegation_targets = list(delegation_targets)
            else:
                account = ADPrivilegedAccount(
                    name=sam_name,
                    sam_account_name=sam_name,
                    object_type=obj_type,
                    dn=str(entry.distinguishedName),
                    finding_types=[ADFindingType.CONSTRAINED_DELEGATION],
                    delegation_targets=list(delegation_targets),
                    risk_score=30,
                    attack_paths=["S4U2Self -> S4U2Proxy -> Access Target Service as Any User"],
                )
                result.privileged_accounts.append(account)

            result.findings.append(ScanFinding(
                title=f"Constrained Delegation: {sam_name}",
                severity=ScanSeverity.HIGH,
                description=f"{obj_type.title()} '{sam_name}' has constrained delegation to: {', '.join(delegation_targets[:3])}",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["constrained_delegation", "kerberos", "lateral_movement"],
            ))

        # Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
        search_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "objectClass"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)

            result.findings.append(ScanFinding(
                title=f"RBCD Configured: {sam_name}",
                severity=ScanSeverity.MEDIUM,
                description=f"Object '{sam_name}' has RBCD configured. May be attack target or indicator of compromise.",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["rbcd", "kerberos", "lateral_movement"],
            ))

    async def _scan_acl_abuse(self, conn, base_dn: str, result: ADPrivescResult) -> None:
        """Scan for ACL abuse opportunities"""
        # This is complex and typically requires BloodHound for comprehensive analysis
        # Here we do basic checks for common dangerous permissions

        logger.info("ACL scanning requires BloodHound for comprehensive analysis")

        # Check if current user has interesting permissions
        # This would require parsing nTSecurityDescriptor which is complex
        # Recommend using BloodHound instead

        result.findings.append(ScanFinding(
            title="ACL Analysis Recommended",
            severity=ScanSeverity.INFO,
            description="For comprehensive ACL abuse path analysis, run BloodHound collector and analyze in BloodHound GUI.",
            host=result.dc_ip,
            scanner="ad_privesc_scanner",
            tags=["acl", "recommendation"],
        ))

    async def _scan_laps(self, conn, base_dn: str, result: ADPrivescResult) -> None:
        """Scan for LAPS configuration and readers"""
        from ldap3 import SUBTREE

        # Check if LAPS is deployed (ms-Mcs-AdmPwd attribute exists)
        search_filter = "(ms-Mcs-AdmPwd=*)"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "ms-Mcs-AdmPwd"],
        )

        if conn.entries:
            # We can read LAPS passwords!
            for entry in conn.entries:
                sam_name = str(entry.sAMAccountName)
                # Don't log the actual password
                result.findings.append(ScanFinding(
                    title=f"LAPS Password Readable: {sam_name}",
                    severity=ScanSeverity.CRITICAL,
                    description=f"Current user can read LAPS password for computer '{sam_name}'",
                    host=result.dc_ip,
                    scanner="ad_privesc_scanner",
                    tags=["laps", "credential_access", "local_admin"],
                ))
        else:
            # Check if LAPS is deployed at all
            search_filter = "(objectClass=computer)"
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["ms-Mcs-AdmPwdExpirationTime"],
                size_limit=1,
            )

            if not conn.entries:
                result.findings.append(ScanFinding(
                    title="LAPS Not Deployed",
                    severity=ScanSeverity.MEDIUM,
                    description="LAPS does not appear to be deployed in this domain.",
                    host=result.dc_ip,
                    scanner="ad_privesc_scanner",
                    tags=["laps", "missing_control"],
                ))

    async def _scan_service_accounts(self, conn, base_dn: str, result: ADPrivescResult) -> None:
        """Scan for gMSA and other service accounts"""
        from ldap3 import SUBTREE

        # Find Group Managed Service Accounts
        search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "msDS-GroupMSAMembership"],
        )

        for entry in conn.entries:
            sam_name = str(entry.sAMAccountName)

            account = ADPrivilegedAccount(
                name=sam_name,
                sam_account_name=sam_name,
                object_type="gmsa",
                dn=str(entry.distinguishedName),
                finding_types=[ADFindingType.GMSA],
                risk_score=10,
            )
            result.privileged_accounts.append(account)

            result.findings.append(ScanFinding(
                title=f"Group Managed Service Account: {sam_name}",
                severity=ScanSeverity.INFO,
                description=f"gMSA '{sam_name}' found. Check who can retrieve the password.",
                host=result.dc_ip,
                scanner="ad_privesc_scanner",
                tags=["gmsa", "service_account"],
            ))

    def _calculate_risk_score(self, finding_types: list[ADFindingType]) -> int:
        """Calculate risk score based on finding types"""
        scores = {
            ADFindingType.DOMAIN_ADMIN: 100,
            ADFindingType.ENTERPRISE_ADMIN: 100,
            ADFindingType.SCHEMA_ADMIN: 90,
            ADFindingType.UNCONSTRAINED_DELEGATION: 80,
            ADFindingType.DNSADMIN: 70,
            ADFindingType.BACKUP_OPERATOR: 60,
            ADFindingType.CONSTRAINED_DELEGATION: 50,
            ADFindingType.ASREP_ROASTABLE: 40,
            ADFindingType.KERBEROASTABLE: 35,
            ADFindingType.ACCOUNT_OPERATOR: 50,
            ADFindingType.SERVER_OPERATOR: 40,
            ADFindingType.PASSWORD_NOT_REQUIRED: 30,
            ADFindingType.GENERICALL_USER: 60,
            ADFindingType.GENERICALL_GROUP: 70,
            ADFindingType.WRITEDACL: 60,
        }

        total = 0
        for ft in finding_types:
            total += scores.get(ft, 10)

        return min(total, 100)  # Cap at 100

    def _get_finding_severity(self, finding_type: ADFindingType) -> ScanSeverity:
        """Get severity for finding type"""
        critical = {
            ADFindingType.DOMAIN_ADMIN,
            ADFindingType.ENTERPRISE_ADMIN,
            ADFindingType.UNCONSTRAINED_DELEGATION,
            ADFindingType.LAPS_READER,
        }

        high = {
            ADFindingType.SCHEMA_ADMIN,
            ADFindingType.BACKUP_OPERATOR,
            ADFindingType.DNSADMIN,
            ADFindingType.CONSTRAINED_DELEGATION,
            ADFindingType.ASREP_ROASTABLE,
            ADFindingType.KERBEROASTABLE,
            ADFindingType.GENERICALL_USER,
            ADFindingType.GENERICALL_GROUP,
            ADFindingType.WRITEDACL,
            ADFindingType.PASSWORD_NOT_REQUIRED,
        }

        medium = {
            ADFindingType.ACCOUNT_OPERATOR,
            ADFindingType.SERVER_OPERATOR,
            ADFindingType.RBCD_TARGET,
        }

        if finding_type in critical:
            return ScanSeverity.CRITICAL
        elif finding_type in high:
            return ScanSeverity.HIGH
        elif finding_type in medium:
            return ScanSeverity.MEDIUM
        else:
            return ScanSeverity.LOW


# Convenience function
async def scan_ad_privesc(
    domain: str,
    dc_ip: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
) -> ADPrivescResult:
    """
    Scan Active Directory for privilege escalation paths.

    Args:
        domain: Target domain
        dc_ip: Domain controller IP
        username: Optional credentials
        password: Optional credentials
        ntlm_hash: Optional NTLM hash for pass-the-hash

    Returns:
        ADPrivescResult with findings
    """
    config = ADPrivescConfig(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        dc_ip=dc_ip,
    )
    scanner = ADPrivescScanner(config)
    return await scanner.scan(domain, dc_ip)
