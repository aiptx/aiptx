"""
PowerShell Arsenal Output Parsers

Parse output from PowerShell scripts into structured findings.
Supports credential extraction, system info, and vulnerability detection.

Usage:
    from aipt_v2.tools.ps_arsenal import PSArsenalParser

    parser = PSArsenalParser()
    findings, credentials = parser.parse_all(output, "Invoke-Mimikatz")
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from enum import Enum


class PSFindingCategory(Enum):
    """Finding category types for PowerShell output."""
    CREDENTIAL = "credential"
    HASH = "hash"
    SYSTEM_INFO = "system_info"
    PERSISTENCE = "persistence"
    ESCALATION = "escalation"
    EXFILTRATION = "exfiltration"
    SHELL = "shell"
    NETWORK = "network"
    KEYLOG = "keylog"
    VM_DETECTION = "vm_detection"
    WLAN = "wlan"
    BROWSER = "browser"


class PSFindingSeverity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PSFinding:
    """Structured finding from PowerShell script output."""
    title: str
    category: PSFindingCategory
    severity: PSFindingSeverity
    description: str
    source_script: str
    raw_data: str = ""
    remediation: str = ""
    mitre_attack: List[str] = field(default_factory=list)
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
            "source_script": self.source_script,
            "raw_data": self.raw_data[:500] if self.raw_data else "",
            "remediation": self.remediation,
            "mitre_attack": self.mitre_attack,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class PSCredential:
    """Extracted credential from PowerShell output."""
    username: str
    domain: str = ""
    password: str = ""
    ntlm_hash: str = ""
    lm_hash: str = ""
    sha1_hash: str = ""
    source: str = ""
    credential_type: str = ""  # plaintext, hash, wlan, browser, ticket
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (password redacted)."""
        return {
            "username": self.username,
            "domain": self.domain,
            "password": "***REDACTED***" if self.password else "",
            "ntlm_hash": self.ntlm_hash[:8] + "..." if self.ntlm_hash else "",
            "lm_hash": self.lm_hash[:8] + "..." if self.lm_hash else "",
            "source": self.source,
            "credential_type": self.credential_type,
            "metadata": self.metadata,
        }

    @property
    def has_credential(self) -> bool:
        """Check if credential has usable data."""
        return bool(self.password or self.ntlm_hash or self.lm_hash)


class PSArsenalParser:
    """
    Parser for PowerShell script outputs.

    Parses output from scripts into structured findings
    and extracted credentials.
    """

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize regex patterns for parsing."""
        self.patterns = {
            # SAM/secretsdump format: user:rid:lmhash:nthash:::
            "passhash_entry": re.compile(
                r"^([^\s:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
                re.MULTILINE
            ),

            # WLAN profile patterns
            "wlan_profile": re.compile(
                r"(?:SSID\s+\d+\s*:\s*|Profile\s*:\s*)(.+?)(?:\n|$)",
                re.IGNORECASE
            ),
            "wlan_key": re.compile(
                r"Key Content\s*:\s*(.+?)(?:\n|$)",
                re.IGNORECASE
            ),

            # Get-Information patterns
            "os_name": re.compile(r"OS Name:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "os_version": re.compile(r"OS Version:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "computer_name": re.compile(r"Computer Name:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "domain_name": re.compile(r"Domain:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "current_user": re.compile(r"Current User:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "logon_server": re.compile(r"Logon Server:\s*(.+?)(?:\n|$)", re.IGNORECASE),

            # Mimikatz patterns
            "mimikatz_user": re.compile(
                r"\*\s*Username\s*:\s*(.+?)(?:\n|$)",
                re.IGNORECASE
            ),
            "mimikatz_domain": re.compile(
                r"\*\s*Domain\s*:\s*(.+?)(?:\n|$)",
                re.IGNORECASE
            ),
            "mimikatz_password": re.compile(
                r"\*\s*Password\s*:\s*(.+?)(?:\n|$)",
                re.IGNORECASE
            ),
            "mimikatz_ntlm": re.compile(
                r"\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})",
                re.IGNORECASE
            ),
            "mimikatz_sha1": re.compile(
                r"\*\s*SHA1\s*:\s*([a-fA-F0-9]{40})",
                re.IGNORECASE
            ),

            # Kerberos tickets
            "krb_tgs": re.compile(r"\$krb5tgs\$[^\s]+"),
            "krb_asrep": re.compile(r"\$krb5asrep\$[^\s]+"),

            # VM detection
            "vm_detected": re.compile(
                r"(VMware|VirtualBox|Hyper-V|QEMU|Xen|Virtual\s*PC|KVM)",
                re.IGNORECASE
            ),

            # Browser credentials
            "browser_url": re.compile(r"URL:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "browser_username": re.compile(r"Username:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "browser_password": re.compile(r"Password:\s*(.+?)(?:\n|$)", re.IGNORECASE),

            # LSA secrets
            "lsa_secret": re.compile(
                r"Secret\s*:\s*(.+?)(?:\n|$)",
                re.IGNORECASE
            ),

            # Session info
            "putty_session": re.compile(r"PuTTY Session:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "winscp_session": re.compile(r"WinSCP Session:\s*(.+?)(?:\n|$)", re.IGNORECASE),
            "rdp_session": re.compile(r"RDP Session:\s*(.+?)(?:\n|$)", re.IGNORECASE),

            # Keylogger
            "keylog_entry": re.compile(r"\[([^\]]+)\]\s*(.+?)(?:\n|$)"),

            # General credential patterns
            "generic_password": re.compile(
                r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^'\"\n\r]+)",
                re.IGNORECASE
            ),
            "generic_username": re.compile(
                r"(?:username|user|login)\s*[=:]\s*['\"]?([^'\"\n\r]+)",
                re.IGNORECASE
            ),
        }

    def parse_get_passhashes(
        self,
        output: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """Parse Get-PassHashes output."""
        findings = []
        credentials = []

        for match in self.patterns["passhash_entry"].finditer(output):
            username = match.group(1)
            rid = match.group(2)
            lm_hash = match.group(3).lower()
            nt_hash = match.group(4).lower()

            cred = PSCredential(
                username=username,
                lm_hash=lm_hash if lm_hash != "aad3b435b51404eeaad3b435b51404ee" else "",
                ntlm_hash=nt_hash,
                source="Get-PassHashes",
                credential_type="hash",
                metadata={"rid": rid}
            )
            credentials.append(cred)

            findings.append(PSFinding(
                title=f"Password Hash Extracted: {username}",
                category=PSFindingCategory.HASH,
                severity=PSFindingSeverity.CRITICAL,
                description=f"NTLM hash extracted for local user '{username}' (RID: {rid})",
                source_script="Get-PassHashes",
                raw_data=f"NT:{nt_hash[:8]}...",
                remediation="Change password for affected account. Review credential storage policies.",
                mitre_attack=["T1003.002"],
                metadata={"username": username, "rid": rid}
            ))

        return findings, credentials

    def parse_get_wlan_keys(
        self,
        output: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """Parse Get-WLAN-Keys output."""
        findings = []
        credentials = []

        # Find all SSID and key pairs
        ssid_matches = list(self.patterns["wlan_profile"].finditer(output))
        key_matches = list(self.patterns["wlan_key"].finditer(output))

        # Pair them up (they should appear in order)
        for i, ssid_match in enumerate(ssid_matches):
            ssid = ssid_match.group(1).strip()
            key = ""

            if i < len(key_matches):
                key = key_matches[i].group(1).strip()

            if ssid:
                cred = PSCredential(
                    username=ssid,
                    password=key,
                    source="Get-WLAN-Keys",
                    credential_type="wlan"
                )
                credentials.append(cred)

                severity = PSFindingSeverity.MEDIUM if key else PSFindingSeverity.LOW
                findings.append(PSFinding(
                    title=f"WiFi Network Found: {ssid}",
                    category=PSFindingCategory.WLAN,
                    severity=severity,
                    description=f"WiFi password {'extracted' if key else 'not available'} for network '{ssid}'",
                    source_script="Get-WLAN-Keys",
                    remediation="Review stored WiFi credentials. Use enterprise authentication.",
                    mitre_attack=["T1552.001"],
                    metadata={"ssid": ssid, "has_key": bool(key)}
                ))

        return findings, credentials

    def parse_invoke_mimikatz(
        self,
        output: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """Parse Invoke-Mimikatz output."""
        findings = []
        credentials = []

        # Split by credential blocks
        blocks = re.split(r"\n\s*\*\s*Username\s*:", output, flags=re.IGNORECASE)

        for block in blocks[1:]:  # Skip first split (before first Username)
            cred = PSCredential(
                username="",  # Will be extracted from block
                source="Invoke-Mimikatz",
                credential_type="hash"
            )

            # Extract username (first line of block)
            username_match = re.match(r"\s*([^\n\r]+)", block)
            if username_match:
                cred.username = username_match.group(1).strip()

            # Extract domain
            domain_match = self.patterns["mimikatz_domain"].search(block)
            if domain_match:
                cred.domain = domain_match.group(1).strip()

            # Extract password
            pwd_match = self.patterns["mimikatz_password"].search(block)
            if pwd_match:
                pwd = pwd_match.group(1).strip()
                if pwd and pwd.lower() != "(null)":
                    cred.password = pwd
                    cred.credential_type = "plaintext"

            # Extract NTLM hash
            ntlm_match = self.patterns["mimikatz_ntlm"].search(block)
            if ntlm_match:
                cred.ntlm_hash = ntlm_match.group(1).lower()

            # Extract SHA1
            sha1_match = self.patterns["mimikatz_sha1"].search(block)
            if sha1_match:
                cred.sha1_hash = sha1_match.group(1).lower()

            # Only add if we got something useful
            if cred.username and cred.has_credential:
                credentials.append(cred)

                severity = PSFindingSeverity.CRITICAL if cred.password else PSFindingSeverity.HIGH
                user_display = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username

                findings.append(PSFinding(
                    title=f"Credential Extracted: {user_display}",
                    category=PSFindingCategory.CREDENTIAL,
                    severity=severity,
                    description=f"{'Plaintext password' if cred.password else 'NTLM hash'} extracted from LSASS memory",
                    source_script="Invoke-Mimikatz",
                    remediation="Rotate affected credentials. Enable Credential Guard. Review LSASS protections.",
                    mitre_attack=["T1003.001"],
                    metadata={
                        "username": cred.username,
                        "domain": cred.domain,
                        "type": cred.credential_type
                    }
                ))

        return findings, credentials

    def parse_check_vm(self, output: str) -> List[PSFinding]:
        """Parse Check-VM output."""
        findings = []

        vm_match = self.patterns["vm_detected"].search(output)
        if vm_match:
            vm_type = vm_match.group(1)
            findings.append(PSFinding(
                title=f"Virtual Machine Detected: {vm_type}",
                category=PSFindingCategory.VM_DETECTION,
                severity=PSFindingSeverity.INFO,
                description=f"Target system appears to be running on {vm_type} virtualization platform",
                source_script="Check-VM",
                mitre_attack=["T1497.001"],
                metadata={"vm_type": vm_type}
            ))
        else:
            # Check for "not a VM" indicators
            if any(phrase in output.lower() for phrase in ["no vm", "physical", "not virtual"]):
                findings.append(PSFinding(
                    title="Physical Machine Detected",
                    category=PSFindingCategory.VM_DETECTION,
                    severity=PSFindingSeverity.INFO,
                    description="Target system appears to be a physical machine (no VM indicators found)",
                    source_script="Check-VM",
                    mitre_attack=["T1497.001"]
                ))

        return findings

    def parse_get_information(self, output: str) -> List[PSFinding]:
        """Parse Get-Information output."""
        findings = []
        info = {}

        # Extract various system information
        for field, pattern in [
            ("os_name", self.patterns["os_name"]),
            ("os_version", self.patterns["os_version"]),
            ("computer_name", self.patterns["computer_name"]),
            ("domain", self.patterns["domain_name"]),
            ("current_user", self.patterns["current_user"]),
            ("logon_server", self.patterns["logon_server"]),
        ]:
            match = pattern.search(output)
            if match:
                info[field] = match.group(1).strip()

        findings.append(PSFinding(
            title="System Information Gathered",
            category=PSFindingCategory.SYSTEM_INFO,
            severity=PSFindingSeverity.INFO,
            description=f"System recon completed: {info.get('computer_name', 'Unknown')} ({info.get('os_name', 'Unknown OS')})",
            source_script="Get-Information",
            raw_data=output[:1000],
            mitre_attack=["T1082", "T1016", "T1033"],
            metadata=info
        ))

        return findings

    def parse_keylogger(self, output: str) -> List[PSFinding]:
        """Parse Keylogger output."""
        findings = []

        keylog_entries = self.patterns["keylog_entry"].findall(output)
        if keylog_entries:
            findings.append(PSFinding(
                title="Keylogger Data Captured",
                category=PSFindingCategory.KEYLOG,
                severity=PSFindingSeverity.HIGH,
                description=f"Captured {len(keylog_entries)} keystroke entries",
                source_script="Keylogger",
                raw_data=output[:500],
                remediation="User awareness training. Endpoint detection and response.",
                mitre_attack=["T1056.001"],
                metadata={"entry_count": len(keylog_entries)}
            ))

        return findings

    def parse_session_gopher(
        self,
        output: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """Parse Invoke-SessionGopher output."""
        findings = []
        credentials = []

        # Check for PuTTY sessions
        putty_matches = self.patterns["putty_session"].findall(output)
        for session in putty_matches:
            findings.append(PSFinding(
                title=f"PuTTY Session Found: {session}",
                category=PSFindingCategory.SYSTEM_INFO,
                severity=PSFindingSeverity.MEDIUM,
                description=f"Saved PuTTY session configuration found",
                source_script="Invoke-SessionGopher",
                mitre_attack=["T1552.001"],
                metadata={"session_type": "putty", "session_name": session}
            ))

        # Check for WinSCP sessions
        winscp_matches = self.patterns["winscp_session"].findall(output)
        for session in winscp_matches:
            findings.append(PSFinding(
                title=f"WinSCP Session Found: {session}",
                category=PSFindingCategory.SYSTEM_INFO,
                severity=PSFindingSeverity.MEDIUM,
                description="Saved WinSCP session with potential credentials",
                source_script="Invoke-SessionGopher",
                mitre_attack=["T1552.001", "T1555"],
                metadata={"session_type": "winscp", "session_name": session}
            ))

        # Check for RDP sessions
        rdp_matches = self.patterns["rdp_session"].findall(output)
        for session in rdp_matches:
            findings.append(PSFinding(
                title=f"RDP Session Found: {session}",
                category=PSFindingCategory.SYSTEM_INFO,
                severity=PSFindingSeverity.LOW,
                description="Saved RDP connection history found",
                source_script="Invoke-SessionGopher",
                mitre_attack=["T1552.001"],
                metadata={"session_type": "rdp", "session_name": session}
            ))

        return findings, credentials

    def parse_web_credentials(
        self,
        output: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """Parse Get-WebCredentials output."""
        findings = []
        credentials = []

        # Simple pattern matching for browser credentials
        url_matches = self.patterns["browser_url"].findall(output)
        user_matches = self.patterns["browser_username"].findall(output)
        pass_matches = self.patterns["browser_password"].findall(output)

        for i, url in enumerate(url_matches):
            username = user_matches[i] if i < len(user_matches) else ""
            password = pass_matches[i] if i < len(pass_matches) else ""

            if username:
                cred = PSCredential(
                    username=username,
                    password=password,
                    source="Get-WebCredentials",
                    credential_type="browser",
                    metadata={"url": url}
                )
                credentials.append(cred)

                findings.append(PSFinding(
                    title=f"Browser Credential Found: {username}",
                    category=PSFindingCategory.BROWSER,
                    severity=PSFindingSeverity.HIGH if password else PSFindingSeverity.MEDIUM,
                    description=f"Web credential extracted from Windows Vault for {url}",
                    source_script="Get-WebCredentials",
                    remediation="Use a password manager. Clear browser saved passwords.",
                    mitre_attack=["T1555.003"],
                    metadata={"url": url, "username": username}
                ))

        return findings, credentials

    def parse_lsa_secret(
        self,
        output: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """Parse Get-LSASecret output."""
        findings = []
        credentials = []

        secret_matches = self.patterns["lsa_secret"].findall(output)
        for secret in secret_matches:
            findings.append(PSFinding(
                title=f"LSA Secret Found: {secret[:30]}...",
                category=PSFindingCategory.CREDENTIAL,
                severity=PSFindingSeverity.HIGH,
                description="LSA secret extracted from registry (may contain service account passwords)",
                source_script="Get-LSASecret",
                raw_data=secret[:100],
                remediation="Rotate affected service account credentials.",
                mitre_attack=["T1003.004"]
            ))

        return findings, credentials

    def parse_all(
        self,
        output: str,
        script_name: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """
        Parse output from any PowerShell script.

        Routes to appropriate parser based on script name.

        Args:
            output: Raw PowerShell output
            script_name: Name of the script that generated output

        Returns:
            Tuple of (findings, credentials)
        """
        findings = []
        credentials = []

        # Route to specific parsers
        parser_map = {
            "Get-PassHashes": self.parse_get_passhashes,
            "Get-WLAN-Keys": self.parse_get_wlan_keys,
            "Invoke-Mimikatz": self.parse_invoke_mimikatz,
            "Invoke-MimikatzWDigestDowngrade": self.parse_invoke_mimikatz,
            "Get-LSASecret": self.parse_lsa_secret,
            "Get-WebCredentials": self.parse_web_credentials,
            "Invoke-SessionGopher": self.parse_session_gopher,
            "Check-VM": lambda o: (self.parse_check_vm(o), []),
            "Get-Information": lambda o: (self.parse_get_information(o), []),
            "Keylogger": lambda o: (self.parse_keylogger(o), []),
        }

        if script_name in parser_map:
            result = parser_map[script_name](output)
            if isinstance(result, tuple):
                findings, credentials = result
            else:
                findings = result
        else:
            # Generic parsing - try common patterns
            f, c = self._generic_parse(output, script_name)
            findings.extend(f)
            credentials.extend(c)

        return findings, credentials

    def _generic_parse(
        self,
        output: str,
        script_name: str
    ) -> Tuple[List[PSFinding], List[PSCredential]]:
        """Generic parsing for unknown scripts."""
        findings = []
        credentials = []

        # Try Mimikatz-style parsing
        if "Username" in output and ("NTLM" in output or "Password" in output):
            f, c = self.parse_invoke_mimikatz(output)
            findings.extend(f)
            credentials.extend(c)

        # Try hash parsing
        if re.search(r":[a-fA-F0-9]{32}:", output):
            f, c = self.parse_get_passhashes(output)
            findings.extend(f)
            credentials.extend(c)

        # Try WLAN parsing
        if "SSID" in output or "Key Content" in output:
            f, c = self.parse_get_wlan_keys(output)
            findings.extend(f)
            credentials.extend(c)

        # Add generic finding if nothing else matched
        if not findings:
            findings.append(PSFinding(
                title=f"{script_name} Execution Complete",
                category=PSFindingCategory.SYSTEM_INFO,
                severity=PSFindingSeverity.INFO,
                description=f"Script {script_name} completed. Review raw output for details.",
                source_script=script_name,
                raw_data=output[:500] if output else "No output"
            ))

        return findings, credentials


__all__ = [
    "PSArsenalParser",
    "PSFinding",
    "PSCredential",
    "PSFindingCategory",
    "PSFindingSeverity",
]
