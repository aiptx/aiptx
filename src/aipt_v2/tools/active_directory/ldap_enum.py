"""
LDAP Enumeration for Active Directory

Comprehensive LDAP enumeration including:
- User enumeration
- Group enumeration
- Computer enumeration
- GPO enumeration
- Domain trust enumeration
- Service account detection
- Privileged account identification

Usage:
    from aipt_v2.tools.active_directory import LDAPEnum

    enum = LDAPEnum(config)
    users = await enum.enumerate_users()
    groups = await enum.enumerate_groups()
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from aipt_v2.core.event_loop_manager import current_time
from aipt_v2.tools.active_directory.ad_config import ADConfig, get_ad_config

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, KERBEROS, SASL
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


@dataclass
class LDAPFinding:
    """LDAP enumeration finding."""
    category: str  # user, group, computer, gpo, trust, misc
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    object_dn: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class LDAPEnumResult:
    """Result of LDAP enumeration."""
    domain: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    users: List[Dict]
    groups: List[Dict]
    computers: List[Dict]
    gpos: List[Dict]
    trusts: List[Dict]
    findings: List[LDAPFinding]
    metadata: Dict[str, Any] = field(default_factory=dict)


class LDAPEnum:
    """
    LDAP Enumeration Tool.

    Enumerates Active Directory objects via LDAP
    and identifies security issues.
    """

    # Privileged groups to flag
    PRIVILEGED_GROUPS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",
        "Domain Controllers",
        "Group Policy Creator Owners"
    ]

    # Dangerous user attributes
    DANGEROUS_FLAGS = {
        0x00010000: "PASSWORD_NEVER_EXPIRES",
        0x00020000: "MNS_LOGON_ACCOUNT",
        0x00000002: "ACCOUNT_DISABLED",
        0x00000010: "LOCKOUT",
        0x00000020: "PASSWORD_NOT_REQUIRED",
        0x00000040: "PASSWORD_CANT_CHANGE",
        0x00000080: "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
        0x00200000: "TRUSTED_FOR_DELEGATION",
        0x00400000: "NOT_DELEGATED",
        0x00800000: "USE_DES_KEY_ONLY",
        0x01000000: "DONT_REQ_PREAUTH",
        0x04000000: "TRUSTED_TO_AUTH_FOR_DELEGATION"
    }

    def __init__(self, config: Optional[ADConfig] = None):
        """
        Initialize LDAP enumerator.

        Args:
            config: AD configuration
        """
        if not HAS_LDAP3:
            raise ImportError("ldap3 is required. Install with: pip install ldap3")

        self.config = config or ADConfig()
        self.connection: Optional[Connection] = None
        self.findings: List[LDAPFinding] = []

    def _connect(self) -> bool:
        """Establish LDAP connection."""
        try:
            server = Server(
                self.config.dc_ip,
                port=self.config.ldaps_port if self.config.use_ssl else self.config.ldap_port,
                use_ssl=self.config.use_ssl,
                get_info=ALL
            )

            # Determine authentication method
            if self.config.credentials.use_kerberos:
                self.connection = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS
                )
            else:
                # NTLM authentication
                user = self.config.credentials.get_auth_string()
                password = self.config.credentials.get_password_or_hash()

                self.connection = Connection(
                    server,
                    user=user,
                    password=password,
                    authentication=NTLM
                )

            return self.connection.bind()

        except Exception as e:
            print(f"[!] LDAP connection failed: {e}")
            return False

    def _search(
        self,
        search_filter: str,
        attributes: List[str] = None,
        search_base: str = None
    ) -> List[Dict]:
        """Execute LDAP search."""
        if not self.connection:
            return []

        base = search_base or self.config.get_base_dn()
        attrs = attributes or ["*"]

        try:
            self.connection.search(
                search_base=base,
                search_filter=search_filter,
                attributes=attrs
            )

            results = []
            for entry in self.connection.entries:
                entry_dict = {
                    "dn": entry.entry_dn,
                    "attributes": dict(entry.entry_attributes_as_dict)
                }
                results.append(entry_dict)

            return results

        except Exception as e:
            print(f"[!] LDAP search failed: {e}")
            return []

    def enumerate_users(self) -> List[Dict]:
        """Enumerate domain users."""
        users = self._search(
            "(objectClass=user)",
            attributes=[
                "sAMAccountName", "userPrincipalName", "displayName",
                "description", "memberOf", "userAccountControl",
                "pwdLastSet", "lastLogonTimestamp", "adminCount",
                "servicePrincipalName", "msDS-AllowedToDelegateTo"
            ]
        )

        # Analyze users for security issues
        for user in users:
            attrs = user.get("attributes", {})
            sam = attrs.get("sAMAccountName", [""])[0]
            uac = attrs.get("userAccountControl", [0])[0]

            # Check for dangerous flags
            if isinstance(uac, int):
                for flag_value, flag_name in self.DANGEROUS_FLAGS.items():
                    if uac & flag_value:
                        severity = "high" if flag_name in [
                            "DONT_REQ_PREAUTH", "TRUSTED_FOR_DELEGATION",
                            "PASSWORD_NOT_REQUIRED"
                        ] else "medium"

                        self.findings.append(LDAPFinding(
                            category="user",
                            severity=severity,
                            title=f"User has {flag_name} flag",
                            description=f"User {sam} has {flag_name} UAC flag set",
                            object_dn=user.get("dn", ""),
                            attributes={"flag": flag_name, "uac": uac},
                            remediation=f"Review and remove {flag_name} flag if not required"
                        ))

            # Check for service accounts (Kerberoastable)
            spns = attrs.get("servicePrincipalName", [])
            if spns:
                self.findings.append(LDAPFinding(
                    category="user",
                    severity="high",
                    title="Kerberoastable Account",
                    description=f"User {sam} has SPNs and may be Kerberoastable",
                    object_dn=user.get("dn", ""),
                    attributes={"spns": spns},
                    remediation="Use strong passwords for service accounts"
                ))

            # Check for delegation
            delegation = attrs.get("msDS-AllowedToDelegateTo", [])
            if delegation:
                self.findings.append(LDAPFinding(
                    category="user",
                    severity="high",
                    title="Constrained Delegation",
                    description=f"User {sam} can delegate to specific services",
                    object_dn=user.get("dn", ""),
                    attributes={"delegation_targets": delegation},
                    remediation="Review delegation configuration"
                ))

            # Check admin count
            if attrs.get("adminCount", [0])[0] == 1:
                self.findings.append(LDAPFinding(
                    category="user",
                    severity="info",
                    title="Protected Admin Account",
                    description=f"User {sam} has adminCount=1 (was/is admin)",
                    object_dn=user.get("dn", ""),
                    attributes={},
                    remediation="Verify admin privileges are appropriate"
                ))

        return users

    def enumerate_groups(self) -> List[Dict]:
        """Enumerate domain groups."""
        groups = self._search(
            "(objectClass=group)",
            attributes=[
                "sAMAccountName", "description", "member",
                "memberOf", "adminCount", "groupType"
            ]
        )

        # Check for privileged groups
        for group in groups:
            attrs = group.get("attributes", {})
            name = attrs.get("sAMAccountName", [""])[0]
            members = attrs.get("member", [])

            if name in self.PRIVILEGED_GROUPS:
                self.findings.append(LDAPFinding(
                    category="group",
                    severity="info",
                    title=f"Privileged Group: {name}",
                    description=f"Group {name} has {len(members)} members",
                    object_dn=group.get("dn", ""),
                    attributes={"member_count": len(members)},
                    remediation="Review membership regularly"
                ))

        return groups

    def enumerate_computers(self) -> List[Dict]:
        """Enumerate domain computers."""
        computers = self._search(
            "(objectClass=computer)",
            attributes=[
                "sAMAccountName", "dNSHostName", "operatingSystem",
                "operatingSystemVersion", "userAccountControl",
                "lastLogonTimestamp", "servicePrincipalName",
                "msDS-AllowedToDelegateTo"
            ]
        )

        for computer in computers:
            attrs = computer.get("attributes", {})
            name = attrs.get("sAMAccountName", [""])[0]
            os_name = attrs.get("operatingSystem", [""])[0]

            # Check for legacy OS
            if os_name and any(legacy in os_name.lower() for legacy in [
                "2003", "2008", "xp", "vista", "windows 7"
            ]):
                self.findings.append(LDAPFinding(
                    category="computer",
                    severity="high",
                    title="Legacy Operating System",
                    description=f"Computer {name} runs {os_name}",
                    object_dn=computer.get("dn", ""),
                    attributes={"os": os_name},
                    remediation="Upgrade to supported operating system"
                ))

            # Check for unconstrained delegation
            uac = attrs.get("userAccountControl", [0])[0]
            if isinstance(uac, int) and (uac & 0x00080000):  # TRUSTED_FOR_DELEGATION
                self.findings.append(LDAPFinding(
                    category="computer",
                    severity="critical",
                    title="Unconstrained Delegation",
                    description=f"Computer {name} has unconstrained delegation",
                    object_dn=computer.get("dn", ""),
                    attributes={},
                    remediation="Remove unconstrained delegation or use constrained"
                ))

        return computers

    def enumerate_gpos(self) -> List[Dict]:
        """Enumerate Group Policy Objects."""
        gpos = self._search(
            "(objectClass=groupPolicyContainer)",
            attributes=[
                "displayName", "gPCFileSysPath", "versionNumber",
                "gPCFunctionalityVersion"
            ]
        )

        return gpos

    def enumerate_trusts(self) -> List[Dict]:
        """Enumerate domain trusts."""
        trusts = self._search(
            "(objectClass=trustedDomain)",
            attributes=[
                "name", "trustDirection", "trustType",
                "trustAttributes", "securityIdentifier"
            ]
        )

        for trust in trusts:
            attrs = trust.get("attributes", {})
            name = attrs.get("name", [""])[0]
            direction = attrs.get("trustDirection", [0])[0]

            direction_map = {
                0: "Disabled",
                1: "Inbound",
                2: "Outbound",
                3: "Bidirectional"
            }

            self.findings.append(LDAPFinding(
                category="trust",
                severity="info",
                title=f"Domain Trust: {name}",
                description=f"Trust direction: {direction_map.get(direction, 'Unknown')}",
                object_dn=trust.get("dn", ""),
                attributes={"direction": direction_map.get(direction)},
                remediation="Review trust relationships regularly"
            ))

        return trusts

    def enumerate_asreproastable(self) -> List[Dict]:
        """Find users vulnerable to AS-REP roasting."""
        # Users with DONT_REQ_PREAUTH flag
        users = self._search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            attributes=["sAMAccountName", "userPrincipalName", "description"]
        )

        for user in users:
            attrs = user.get("attributes", {})
            sam = attrs.get("sAMAccountName", [""])[0]

            self.findings.append(LDAPFinding(
                category="user",
                severity="high",
                title="AS-REP Roastable Account",
                description=f"User {sam} does not require Kerberos pre-authentication",
                object_dn=user.get("dn", ""),
                attributes={},
                remediation="Enable Kerberos pre-authentication"
            ))

        return users

    def enumerate_laps(self) -> List[Dict]:
        """Check for LAPS deployment."""
        # Check if LAPS schema is present
        computers = self._search(
            "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
            attributes=["sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"]
        )

        if computers:
            self.findings.append(LDAPFinding(
                category="misc",
                severity="info",
                title="LAPS Deployed",
                description=f"LAPS is deployed on {len(computers)} computers",
                object_dn="",
                attributes={"computer_count": len(computers)},
                remediation="Ensure LAPS passwords are retrieved securely"
            ))
        else:
            self.findings.append(LDAPFinding(
                category="misc",
                severity="medium",
                title="LAPS Not Detected",
                description="LAPS does not appear to be deployed",
                object_dn="",
                attributes={},
                remediation="Consider deploying LAPS for local admin password management"
            ))

        return computers

    async def enumerate_all(self) -> LDAPEnumResult:
        """Run full LDAP enumeration."""
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = current_time()

        if not self._connect():
            return LDAPEnumResult(
                domain=self.config.domain,
                status="failed",
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration=0,
                users=[],
                groups=[],
                computers=[],
                gpos=[],
                trusts=[],
                findings=[],
                metadata={"error": "LDAP connection failed"}
            )

        # Run enumeration
        users = self.enumerate_users()
        groups = self.enumerate_groups()
        computers = self.enumerate_computers()
        gpos = self.enumerate_gpos()
        trusts = self.enumerate_trusts()
        self.enumerate_asreproastable()
        self.enumerate_laps()

        # Close connection
        if self.connection:
            self.connection.unbind()

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = current_time() - start_time

        return LDAPEnumResult(
            domain=self.config.domain,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            users=users,
            groups=groups,
            computers=computers,
            gpos=gpos,
            trusts=trusts,
            findings=self.findings,
            metadata={
                "user_count": len(users),
                "group_count": len(groups),
                "computer_count": len(computers),
                "finding_count": len(self.findings)
            }
        )


# Convenience function
async def enumerate_ldap(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    **kwargs
) -> LDAPEnumResult:
    """
    Quick LDAP enumeration.

    Args:
        domain: AD domain
        dc_ip: Domain Controller IP
        username: Username
        password: Password
        **kwargs: Additional options

    Returns:
        LDAPEnumResult
    """
    config = get_ad_config(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        **kwargs
    )

    enum = LDAPEnum(config)
    return await enum.enumerate_all()
