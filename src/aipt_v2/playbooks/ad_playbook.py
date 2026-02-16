"""
Active Directory Penetration Testing Playbook.

Comprehensive methodology for testing Active Directory environments.
Leverages AIPTX's existing AD capabilities and attack chains.
"""

from .base_playbook import BasePlaybook, Phase, PlaybookMode


class ADPlaybook(BasePlaybook):
    """
    Active Directory penetration testing playbook.

    Covers the full AD attack lifecycle from reconnaissance
    to domain dominance. Integrates with AIPTX's AD tools.
    """

    name = "ad"
    description = "Active Directory Penetration Testing"
    mode = PlaybookMode.ADAPTIVE
    target_type = "ad"
    estimated_duration = 14400  # 4 hours

    phases = [
        # Phase 1: AD Reconnaissance
        Phase(
            name="AD Reconnaissance",
            objective="Enumerate domain structure and identify attack surface",
            techniques=[
                "Identify domain controllers via DNS/LDAP",
                "Enumerate domain trusts and forest structure",
                "Gather domain functional level information",
                "Enumerate domain users and groups",
                "Identify privileged accounts (Domain Admins, Enterprise Admins)",
                "Enumerate service accounts (SPNs)",
                "Discover computer accounts and their OS versions",
                "Map Group Policy Objects (GPOs)",
                "Identify LAPS deployment",
            ],
            required_tools=["ldapsearch", "bloodhound", "adidnsdump", "kerbrute"],
            mitre_techniques=["T1087.002", "T1069.002", "T1482"],
            timeout=1200,
            parallel_safe=True,
        ),
        # Phase 2: Initial Access
        Phase(
            name="Initial Access",
            objective="Obtain initial foothold via Kerberos or credential attacks",
            techniques=[
                "AS-REP Roasting for accounts without pre-auth",
                "Kerberoasting for service account hashes",
                "Password spraying against discovered users",
                "Check for null session access",
                "LDAP anonymous bind enumeration",
                "SMB null session enumeration",
                "Check for LLMNR/NBT-NS poisoning opportunities",
            ],
            required_tools=["impacket", "kerbrute", "crackmapexec", "responder"],
            mitre_techniques=["T1558.003", "T1558.004", "T1110.003"],
            timeout=1800,
            depends_on=["AD Reconnaissance"],
        ),
        # Phase 3: Credential Access
        Phase(
            name="Credential Access",
            objective="Extract and crack credentials from compromised systems",
            techniques=[
                "Dump LSASS memory for credentials",
                "Extract cached domain credentials",
                "Dump SAM database hashes",
                "Extract DPAPI secrets",
                "Harvest credentials from browsers/applications",
                "Crack obtained hashes (hashcat/john)",
                "Extract credentials from Group Policy Preferences",
                "Search for credentials in SYSVOL scripts",
            ],
            required_tools=["mimikatz", "secretsdump", "lsassy", "dpapi"],
            mitre_techniques=["T1003.001", "T1003.002", "T1003.003", "T1552.006"],
            timeout=1200,
            depends_on=["Initial Access"],
        ),
        # Phase 4: Privilege Escalation
        Phase(
            name="Privilege Escalation",
            objective="Escalate privileges within the domain",
            techniques=[
                "Exploit ACL misconfigurations (WriteDACL, GenericAll)",
                "Abuse constrained delegation",
                "Exploit resource-based constrained delegation (RBCD)",
                "Shadow Credentials attack",
                "Exploit GPO permissions",
                "Abuse certificate template vulnerabilities (ESC1-ESC8)",
                "Kerberos delegation abuse",
                "Token impersonation",
            ],
            required_tools=["bloodhound", "certipy", "impacket", "rubeus"],
            mitre_techniques=["T1134", "T1484", "T1558.001"],
            timeout=1800,
            depends_on=["Credential Access"],
        ),
        # Phase 5: Lateral Movement
        Phase(
            name="Lateral Movement",
            objective="Move laterally through the network to reach high-value targets",
            techniques=[
                "Pass-the-Hash (PtH) attacks",
                "Pass-the-Ticket (PtT) attacks",
                "Overpass-the-Hash",
                "Remote execution via PsExec",
                "Remote execution via WMI",
                "Remote execution via WinRM",
                "Remote execution via DCOM",
                "SMB lateral movement",
                "RDP hijacking",
            ],
            required_tools=["impacket", "crackmapexec", "evil-winrm"],
            mitre_techniques=["T1550.002", "T1550.003", "T1021.002", "T1021.003"],
            timeout=1200,
            depends_on=["Credential Access"],
        ),
        # Phase 6: Domain Dominance
        Phase(
            name="Domain Dominance",
            objective="Achieve and maintain domain-wide access",
            techniques=[
                "DCSync attack to extract all password hashes",
                "Create Golden Ticket for persistence",
                "Create Silver Tickets for service access",
                "Dump NTDS.dit from domain controller",
                "Skeleton Key attack",
                "DCShadow for stealthy persistence",
                "AdminSDHolder abuse",
                "Add backdoor domain admin account",
            ],
            required_tools=["impacket", "mimikatz", "secretsdump"],
            mitre_techniques=["T1003.006", "T1558.001", "T1207"],
            timeout=1200,
            depends_on=["Privilege Escalation"],
        ),
        # Phase 7: AD CS Attacks
        Phase(
            name="AD Certificate Services",
            objective="Exploit Active Directory Certificate Services",
            techniques=[
                "Enumerate certificate templates (ESC1-ESC8)",
                "Request certificates with overly permissive templates",
                "NTLM relay to AD CS (ESC8)",
                "Certificate theft from compromised machines",
                "Golden Certificate attack",
                "Shadow Credentials via certificate abuse",
                "CA private key extraction",
            ],
            required_tools=["certipy", "petitpotam", "ntlmrelayx"],
            mitre_techniques=["T1649", "T1558.004"],
            timeout=900,
            depends_on=["AD Reconnaissance"],
            parallel_safe=True,
        ),
        # Phase 8: Persistence
        Phase(
            name="AD Persistence",
            objective="Establish persistent access to the domain",
            techniques=[
                "Create backdoor domain admin",
                "Modify ACLs for persistent access",
                "Add DCSync rights to controlled user",
                "Deploy skeleton key on DC",
                "Create malicious GPO",
                "Golden Ticket creation",
                "Shadow Credentials for persistence",
                "SID History injection",
            ],
            required_tools=["impacket", "mimikatz", "bloodhound"],
            mitre_techniques=["T1098", "T1136.002", "T1484.001"],
            timeout=600,
            depends_on=["Domain Dominance"],
            skip_on_failure=True,  # Persistence is optional
        ),
    ]


class ADQuickPlaybook(BasePlaybook):
    """
    Quick AD assessment playbook for time-constrained engagements.

    Focuses on high-value attacks that can be completed quickly.
    """

    name = "ad_quick"
    description = "Quick Active Directory Assessment"
    mode = PlaybookMode.SEQUENTIAL
    target_type = "ad"
    estimated_duration = 3600  # 1 hour

    phases = [
        Phase(
            name="Quick Recon",
            objective="Fast enumeration of domain structure",
            techniques=[
                "Identify domain controllers",
                "Enumerate domain users via LDAP",
                "Find privileged users and groups",
                "Enumerate SPNs for Kerberoasting",
                "Check for AS-REP roastable accounts",
            ],
            required_tools=["ldapsearch", "kerbrute", "impacket"],
            mitre_techniques=["T1087.002"],
            timeout=600,
        ),
        Phase(
            name="Quick Wins",
            objective="Execute high-success-rate attacks",
            techniques=[
                "AS-REP Roasting",
                "Kerberoasting",
                "Password spraying with common passwords",
                "Check for null sessions",
            ],
            required_tools=["impacket", "kerbrute", "crackmapexec"],
            mitre_techniques=["T1558.003", "T1558.004"],
            timeout=900,
            depends_on=["Quick Recon"],
        ),
        Phase(
            name="Credential Cracking",
            objective="Crack obtained hashes",
            techniques=[
                "Crack AS-REP hashes",
                "Crack Kerberoast hashes",
                "Attempt common password patterns",
            ],
            required_tools=["hashcat", "john"],
            mitre_techniques=["T1110.002"],
            timeout=1200,
            depends_on=["Quick Wins"],
        ),
        Phase(
            name="Privilege Check",
            objective="Check for quick privilege escalation paths",
            techniques=[
                "Run BloodHound analysis",
                "Check for ACL misconfigurations",
                "Check for dangerous delegations",
                "Check for certificate template vulnerabilities",
            ],
            required_tools=["bloodhound", "certipy"],
            mitre_techniques=["T1069.002"],
            timeout=600,
            depends_on=["Quick Recon"],
            parallel_safe=True,
        ),
    ]
