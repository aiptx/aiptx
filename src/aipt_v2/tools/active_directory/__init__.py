"""
AIPT Active Directory Security Module

Comprehensive Active Directory penetration testing:
- BloodHound integration for attack path mapping
- Kerberos attacks (Kerberoasting, AS-REP roasting)
- LDAP enumeration (users, groups, computers, GPOs)
- SMB attacks (relay, pass-the-hash, PsExec)
- Domain trust enumeration and abuse

Usage:
    from aipt_v2.tools.active_directory import (
        ADScanner,
        BloodHoundWrapper,
        KerberosAttacks,
        LDAPEnum,
        SMBAttacks
    )

    # Run full AD assessment
    scanner = ADScanner(domain="corp.local", dc_ip="10.0.0.1")
    findings = await scanner.scan(username="user", password="pass")
"""

from aipt_v2.tools.active_directory.ad_config import (
    ADConfig,
    ADCredentials,
    get_ad_config,
)

from aipt_v2.tools.active_directory.ldap_enum import (
    LDAPEnum,
    LDAPFinding,
    enumerate_ldap,
)

from aipt_v2.tools.active_directory.kerberos_attacks import (
    KerberosAttacks,
    KerberosFinding,
    run_kerberoast,
    run_asreproast,
)

from aipt_v2.tools.active_directory.smb_attacks import (
    SMBAttacks,
    SMBFinding,
    enumerate_smb,
)

from aipt_v2.tools.active_directory.bloodhound_wrapper import (
    BloodHoundWrapper,
    BloodHoundResult,
    run_bloodhound,
)

__all__ = [
    # Config
    "ADConfig",
    "ADCredentials",
    "get_ad_config",
    # LDAP
    "LDAPEnum",
    "LDAPFinding",
    "enumerate_ldap",
    # Kerberos
    "KerberosAttacks",
    "KerberosFinding",
    "run_kerberoast",
    "run_asreproast",
    # SMB
    "SMBAttacks",
    "SMBFinding",
    "enumerate_smb",
    # BloodHound
    "BloodHoundWrapper",
    "BloodHoundResult",
    "run_bloodhound",
]
