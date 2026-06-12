"""
WinPwn Output Parsers

Parses output from WinPwn modules and converts to structured AIPTX findings.

Handles parsing of:
- Credential extraction output (Mimikatz-style, SAM dumps)
- Reconnaissance output (system info, privilege checks)
- Domain enumeration results
- Privilege escalation findings
- BloodHound/SharpHound data

Usage:
    from aipt_v2.tools.winpwn import WinPwnParser

    parser = WinPwnParser()
    findings = parser.parse_kittielocal_output(output)
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Tuple


class FindingSeverity(Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    """Finding category types."""

    CREDENTIAL = "credential"
    PRIVILEGE = "privilege"
    MISCONFIGURATION = "misconfiguration"
    VULNERABILITY = "vulnerability"
    INFORMATION = "information"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class WinPwnFinding:
    """Structured finding from WinPwn output."""

    title: str
    category: FindingCategory
    severity: FindingSeverity
    description: str
    source_module: str
    raw_data: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "source_module": self.source_module,
            "raw_data": self.raw_data,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class ExtractedCredential:
    """Extracted credential from output."""

    username: str
    domain: str = ""
    password: str = ""
    ntlm_hash: str = ""
    lm_hash: str = ""
    sha1_hash: str = ""
    source: str = ""
    credential_type: str = ""  # plaintext, hash, ticket
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "username": self.username,
            "domain": self.domain,
            "password": self.password if self.password else "[REDACTED]",
            "ntlm_hash": self.ntlm_hash,
            "lm_hash": self.lm_hash,
            "sha1_hash": self.sha1_hash,
            "source": self.source,
            "credential_type": self.credential_type,
            "metadata": self.metadata,
        }


class WinPwnParser:
    """
    Parser for WinPwn module outputs.

    Extracts structured findings and credentials from
    raw WinPwn output text.
    """

    def __init__(self):
        """Initialize parser with regex patterns."""
        self._init_patterns()

    def _init_patterns(self):
        """Initialize regex patterns for parsing."""
        # Mimikatz-style credential patterns
        self.patterns = {
            # Username from various formats
            "username": re.compile(
                r"(?:User(?:name)?|SAMAccountName|Account)\s*[:=]\s*([^\s\n\r]+)", re.IGNORECASE
            ),
            # Domain patterns
            "domain": re.compile(r"(?:Domain|Realm)\s*[:=]\s*([^\s\n\r]+)", re.IGNORECASE),
            # Password plaintext
            "password": re.compile(r"(?:Password|Cleartext)\s*[:=]\s*(.+?)(?:\n|$)", re.IGNORECASE),
            # NTLM hash
            "ntlm": re.compile(r"(?:NTLM|NT)\s*[:=]\s*([a-fA-F0-9]{32})", re.IGNORECASE),
            # LM hash
            "lm": re.compile(r"LM\s*[:=]\s*([a-fA-F0-9]{32})", re.IGNORECASE),
            # SHA1 hash
            "sha1": re.compile(r"SHA1\s*[:=]\s*([a-fA-F0-9]{40})", re.IGNORECASE),
            # Kerberos tickets
            "krb5tgs": re.compile(r"\$krb5tgs\$[^\s]+", re.MULTILINE),
            "krb5asrep": re.compile(r"\$krb5asrep\$[^\s]+", re.MULTILINE),
            # WiFi passwords
            "wifi_key": re.compile(r"Key Content\s*[:=]\s*(.+?)(?:\n|$)", re.IGNORECASE),
            # Browser credentials
            "browser_cred": re.compile(
                r"URL:\s*(.+?)\s*Username:\s*(.+?)\s*Password:\s*(.+?)(?:\n|$)",
                re.IGNORECASE | re.DOTALL,
            ),
            # Service account
            "service_account": re.compile(
                r"ServicePrincipalName.*?:\s*(.+?)(?:\n|$)", re.IGNORECASE
            ),
            # Privilege patterns
            "privilege_enabled": re.compile(r"(Se\w+Privilege)\s+.*?Enabled", re.IGNORECASE),
            # Autologon credentials
            "autologon": re.compile(r"DefaultPassword\s+REG_SZ\s+(.+?)(?:\n|$)", re.IGNORECASE),
            # Stored credentials
            "cmdkey": re.compile(
                r"Target:\s*(.+?)\s+Type:\s*(.+?)(?:\s+User:\s*(.+?))?(?:\n|$)", re.IGNORECASE
            ),
            # SAM dump format
            "sam_entry": re.compile(
                r"([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
            ),
            # Secretsdump format
            "secretsdump": re.compile(
                r"(\S+?)\\(\S+?):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
            ),
        }

    def parse_mimikatz_output(self, output: str) -> List[ExtractedCredential]:
        """
        Parse Mimikatz-style credential output.

        Args:
            output: Raw output from credential extraction

        Returns:
            List of extracted credentials
        """
        credentials = []

        # Split into credential blocks
        blocks = re.split(r"\n\s*\*\s*(?:Username|User)\s*:", output, flags=re.IGNORECASE)

        for block in blocks[1:]:  # Skip first empty block
            cred = ExtractedCredential(username="", source="mimikatz", credential_type="hash")

            # Extract username (first line of block)
            username_match = re.match(r"\s*([^\n\r]+)", block)
            if username_match:
                cred.username = username_match.group(1).strip()

            # Extract domain
            domain_match = self.patterns["domain"].search(block)
            if domain_match:
                cred.domain = domain_match.group(1).strip()

            # Extract password if plaintext
            pwd_match = self.patterns["password"].search(block)
            if pwd_match:
                pwd = pwd_match.group(1).strip()
                if pwd and pwd != "(null)" and pwd != "":
                    cred.password = pwd
                    cred.credential_type = "plaintext"

            # Extract NTLM hash
            ntlm_match = self.patterns["ntlm"].search(block)
            if ntlm_match:
                cred.ntlm_hash = ntlm_match.group(1).lower()

            # Extract LM hash
            lm_match = self.patterns["lm"].search(block)
            if lm_match:
                cred.lm_hash = lm_match.group(1).lower()

            # Extract SHA1
            sha1_match = self.patterns["sha1"].search(block)
            if sha1_match:
                cred.sha1_hash = sha1_match.group(1).lower()

            # Only add if we have username and some credential data
            if cred.username and (cred.password or cred.ntlm_hash):
                credentials.append(cred)

        return credentials

    def parse_sam_dump(self, output: str) -> List[ExtractedCredential]:
        """
        Parse SAM database dump output.

        Args:
            output: Raw SAM dump output

        Returns:
            List of extracted credentials
        """
        credentials = []

        # Standard SAM format: user:rid:lmhash:nthash:::
        for match in self.patterns["sam_entry"].finditer(output):
            cred = ExtractedCredential(
                username=match.group(1),
                domain="",
                lm_hash=match.group(3).lower(),
                ntlm_hash=match.group(4).lower(),
                source="sam_dump",
                credential_type="hash",
                metadata={"rid": match.group(2)},
            )
            credentials.append(cred)

        # Secretsdump format with domain: domain\user:rid:lm:nt:::
        for match in self.patterns["secretsdump"].finditer(output):
            cred = ExtractedCredential(
                username=match.group(2),
                domain=match.group(1),
                lm_hash=match.group(4).lower(),
                ntlm_hash=match.group(5).lower(),
                source="secretsdump",
                credential_type="hash",
                metadata={"rid": match.group(3)},
            )
            credentials.append(cred)

        return credentials

    def parse_kerberos_tickets(self, output: str) -> List[WinPwnFinding]:
        """
        Parse Kerberoasting/AS-REP roasting output.

        Args:
            output: Raw Kerberos attack output

        Returns:
            List of findings with ticket hashes
        """
        findings = []

        # TGS tickets (Kerberoasting)
        for match in self.patterns["krb5tgs"].finditer(output):
            ticket = match.group(0)

            # Extract username from ticket
            user_match = re.search(r"\$krb5tgs\$\d+\$\*([^$]+)\$", ticket)
            username = user_match.group(1) if user_match else "unknown"

            findings.append(
                WinPwnFinding(
                    title=f"Kerberoastable Account: {username}",
                    category=FindingCategory.CREDENTIAL,
                    severity=FindingSeverity.HIGH,
                    description=f"Extracted TGS ticket for service account {username}. "
                    "This hash can be cracked offline to reveal the service account password.",
                    source_module="kerberoasting",
                    raw_data=ticket[:200] + "..." if len(ticket) > 200 else ticket,
                    remediation="Use strong passwords (25+ chars) for service accounts. "
                    "Consider using Group Managed Service Accounts (gMSA).",
                    references=[
                        "https://attack.mitre.org/techniques/T1558/003/",
                        "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting",
                    ],
                    metadata={"username": username, "ticket_type": "TGS"},
                )
            )

        # AS-REP tickets
        for match in self.patterns["krb5asrep"].finditer(output):
            ticket = match.group(0)

            # Extract username from ticket
            user_match = re.search(r"\$krb5asrep\$\d+\$([^@]+)@", ticket)
            username = user_match.group(1) if user_match else "unknown"

            findings.append(
                WinPwnFinding(
                    title=f"AS-REP Roastable Account: {username}",
                    category=FindingCategory.CREDENTIAL,
                    severity=FindingSeverity.HIGH,
                    description=f"Account {username} does not require Kerberos pre-authentication. "
                    "AS-REP hash can be cracked offline.",
                    source_module="asreproast",
                    raw_data=ticket[:200] + "..." if len(ticket) > 200 else ticket,
                    remediation="Enable Kerberos pre-authentication for this account.",
                    references=[
                        "https://attack.mitre.org/techniques/T1558/004/",
                    ],
                    metadata={"username": username, "ticket_type": "AS-REP"},
                )
            )

        return findings

    def parse_privilege_check(self, output: str) -> List[WinPwnFinding]:
        """
        Parse privilege enumeration output.

        Args:
            output: Raw whoami /priv output

        Returns:
            List of privilege-related findings
        """
        findings = []

        # Map dangerous privileges to findings
        dangerous_privs = {
            "SeImpersonatePrivilege": {
                "severity": FindingSeverity.HIGH,
                "desc": "Can impersonate tokens - Potato attacks possible",
                "exploits": ["JuicyPotato", "PrintSpoofer", "GodPotato"],
            },
            "SeAssignPrimaryTokenPrivilege": {
                "severity": FindingSeverity.HIGH,
                "desc": "Can assign primary tokens - Token manipulation possible",
                "exploits": ["Token manipulation", "Potato attacks"],
            },
            "SeBackupPrivilege": {
                "severity": FindingSeverity.HIGH,
                "desc": "Can backup any file - Read SAM/SYSTEM hives",
                "exploits": ["SAM extraction", "Shadow copy extraction"],
            },
            "SeRestorePrivilege": {
                "severity": FindingSeverity.HIGH,
                "desc": "Can write to any location",
                "exploits": ["DLL hijacking", "Service binary replacement"],
            },
            "SeDebugPrivilege": {
                "severity": FindingSeverity.CRITICAL,
                "desc": "Full debug access - Can dump LSASS",
                "exploits": ["LSASS dump", "Process injection"],
            },
            "SeTakeOwnershipPrivilege": {
                "severity": FindingSeverity.MEDIUM,
                "desc": "Can take ownership of any object",
                "exploits": ["File ownership takeover"],
            },
            "SeLoadDriverPrivilege": {
                "severity": FindingSeverity.CRITICAL,
                "desc": "Can load kernel drivers",
                "exploits": ["Capcom.sys", "Malicious driver loading"],
            },
        }

        for priv, info in dangerous_privs.items():
            if priv in output and "Enabled" in output:
                findings.append(
                    WinPwnFinding(
                        title=f"Dangerous Privilege: {priv}",
                        category=FindingCategory.PRIVILEGE,
                        severity=info["severity"],
                        description=info["desc"],
                        source_module="privcheck",
                        remediation=f"Review if this privilege is required. "
                        f"Potential exploits: {', '.join(info['exploits'])}",
                        metadata={"privilege": priv, "exploits": info["exploits"]},
                    )
                )

        return findings

    def parse_local_recon(self, output: str) -> List[WinPwnFinding]:
        """
        Parse local reconnaissance output.

        Args:
            output: Raw local recon output

        Returns:
            List of recon findings
        """
        findings = []

        # Check for unquoted service paths
        if "Unquoted" in output or ("C:\\" in output and " " in output and '"' not in output):
            findings.append(
                WinPwnFinding(
                    title="Unquoted Service Path Found",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=FindingSeverity.MEDIUM,
                    description="Service with unquoted path containing spaces detected. "
                    "Can be exploited for privilege escalation via binary planting.",
                    source_module="localrecon",
                    remediation="Quote service binary paths or remove spaces from path.",
                )
            )

        # Check for AlwaysInstallElevated
        if "AlwaysInstallElevated" in output and ("0x1" in output or "1" in output):
            findings.append(
                WinPwnFinding(
                    title="AlwaysInstallElevated Enabled",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=FindingSeverity.HIGH,
                    description="AlwaysInstallElevated is enabled. "
                    "MSI packages can be installed with SYSTEM privileges.",
                    source_module="localrecon",
                    remediation="Disable AlwaysInstallElevated in both HKLM and HKCU.",
                )
            )

        # Check for stored credentials
        if "cmdkey" in output.lower() or "Target:" in output:
            findings.append(
                WinPwnFinding(
                    title="Stored Credentials Found",
                    category=FindingCategory.CREDENTIAL,
                    severity=FindingSeverity.MEDIUM,
                    description="Windows Credential Manager contains stored credentials.",
                    source_module="localrecon",
                    remediation="Review stored credentials and remove unnecessary entries.",
                )
            )

        # Check for autologon
        if "DefaultPassword" in output:
            findings.append(
                WinPwnFinding(
                    title="Autologon Credentials Found",
                    category=FindingCategory.CREDENTIAL,
                    severity=FindingSeverity.HIGH,
                    description="Autologon is configured with password stored in registry.",
                    source_module="localrecon",
                    remediation="Disable autologon or use LSA-protected autologon.",
                )
            )

        return findings

    def parse_domain_recon(self, output: str) -> List[WinPwnFinding]:
        """
        Parse domain reconnaissance output.

        Args:
            output: Raw domain recon output

        Returns:
            List of domain findings
        """
        findings = []

        # Check for unconstrained delegation
        if "Unconstrained" in output and "Delegation" in output:
            findings.append(
                WinPwnFinding(
                    title="Unconstrained Delegation Found",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=FindingSeverity.CRITICAL,
                    description="Computer with unconstrained delegation can capture TGTs "
                    "from any user authenticating to it.",
                    source_module="domainrecon",
                    remediation="Use constrained delegation or remove delegation entirely.",
                    references=["https://attack.mitre.org/techniques/T1558/"],
                )
            )

        # Check for RBCD targets
        if "Resource-Based" in output or "msDS-AllowedToActOnBehalfOfOtherIdentity" in output:
            findings.append(
                WinPwnFinding(
                    title="Resource-Based Constrained Delegation",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=FindingSeverity.HIGH,
                    description="RBCD configuration found. May be abusable for privilege escalation.",
                    source_module="domainrecon",
                    remediation="Review RBCD configurations and remove unnecessary entries.",
                )
            )

        # Check for ADCS vulnerabilities
        if "ESC" in output or "Certificate" in output:
            # Look for specific ESC numbers
            esc_matches = re.findall(r"ESC\d+", output)
            for esc in set(esc_matches):
                findings.append(
                    WinPwnFinding(
                        title=f"ADCS Vulnerability: {esc}",
                        category=FindingCategory.VULNERABILITY,
                        severity=FindingSeverity.HIGH,
                        description=f"Active Directory Certificate Services vulnerability {esc} detected.",
                        source_module="domainrecon",
                        remediation="Review and remediate ADCS template configurations.",
                        references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                    )
                )

        # Check for GPP passwords
        if "cpassword" in output.lower() or "Groups.xml" in output:
            findings.append(
                WinPwnFinding(
                    title="GPP Password Found",
                    category=FindingCategory.CREDENTIAL,
                    severity=FindingSeverity.HIGH,
                    description="Group Policy Preferences password found. Can be trivially decrypted.",
                    source_module="domainrecon",
                    remediation="Remove GPP XML files containing passwords from SYSVOL.",
                )
            )

        return findings

    def parse_all(
        self, output: str, module: str = "unknown"
    ) -> Tuple[List[WinPwnFinding], List[ExtractedCredential]]:
        """
        Parse output and extract all findings and credentials.

        Args:
            output: Raw output from any WinPwn module
            module: Source module name

        Returns:
            Tuple of (findings, credentials)
        """
        findings = []
        credentials = []

        # Try all parsers
        credentials.extend(self.parse_mimikatz_output(output))
        credentials.extend(self.parse_sam_dump(output))

        findings.extend(self.parse_kerberos_tickets(output))
        findings.extend(self.parse_privilege_check(output))
        findings.extend(self.parse_local_recon(output))
        findings.extend(self.parse_domain_recon(output))

        # Update source module
        for finding in findings:
            if finding.source_module == "unknown":
                finding.source_module = module

        for cred in credentials:
            if not cred.source:
                cred.source = module

        return findings, credentials


__all__ = [
    "WinPwnParser",
    "WinPwnFinding",
    "ExtractedCredential",
    "FindingSeverity",
    "FindingCategory",
]
