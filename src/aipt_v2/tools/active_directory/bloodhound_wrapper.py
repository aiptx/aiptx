"""
BloodHound Integration

Wrapper for BloodHound Python ingestor (bloodhound-python).
Collects Active Directory data for attack path analysis:
- Users, Groups, Computers
- ACLs and permissions
- Sessions and logged-on users
- Trust relationships
- Group Policy Objects

Usage:
    from aipt_v2.tools.active_directory import BloodHoundWrapper

    bh = BloodHoundWrapper(config)
    result = await bh.collect()
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aipt_v2.core.event_loop_manager import current_time
from aipt_v2.tools.active_directory.ad_config import ADConfig, get_ad_config


@dataclass
class BloodHoundResult:
    """Result of BloodHound collection."""
    domain: str
    status: str
    started_at: str
    finished_at: str
    duration: float
    output_files: List[str]
    collection_methods: List[str]
    statistics: Dict[str, int]
    attack_paths: List[Dict]  # Parsed attack paths if available
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BloodHoundConfig:
    """BloodHound collection configuration."""
    # Collection methods
    collect_all: bool = True
    collect_users: bool = True
    collect_groups: bool = True
    collect_computers: bool = True
    collect_sessions: bool = True
    collect_acls: bool = True
    collect_trusts: bool = True
    collect_gpos: bool = True

    # Output options
    output_dir: str = "./bloodhound_output"
    output_prefix: str = ""
    compress: bool = True  # Create ZIP file

    # Performance
    threads: int = 10
    dns_tcp: bool = False
    dns_timeout: int = 3


class BloodHoundWrapper:
    """
    BloodHound Python Ingestor Wrapper.

    Collects Active Directory data for BloodHound
    attack path analysis.
    """

    COLLECTION_METHODS = {
        "all": "All collection methods",
        "default": "Users, Groups, Computers, Sessions, Trusts, ACL",
        "users": "User enumeration",
        "groups": "Group enumeration",
        "computers": "Computer enumeration",
        "sessions": "Session enumeration",
        "acl": "ACL enumeration",
        "trusts": "Trust enumeration",
        "gpo": "GPO enumeration",
        "container": "Container enumeration"
    }

    def __init__(
        self,
        ad_config: Optional[ADConfig] = None,
        bh_config: Optional[BloodHoundConfig] = None
    ):
        """
        Initialize BloodHound wrapper.

        Args:
            ad_config: AD configuration
            bh_config: BloodHound collection configuration
        """
        self.ad_config = ad_config or ADConfig()
        self.bh_config = bh_config or BloodHoundConfig()
        self.output_files: List[str] = []
        self._installed = None

    async def check_installed(self) -> bool:
        """Check if bloodhound-python is installed."""
        if self._installed is not None:
            return self._installed

        try:
            process = await asyncio.create_subprocess_shell(
                "bloodhound-python --help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            self._installed = process.returncode == 0
        except Exception:
            self._installed = False

        return self._installed

    def _build_command(self) -> List[str]:
        """Build bloodhound-python command."""
        cmd = ["bloodhound-python"]

        # Domain and credentials
        cmd.extend(["-d", self.ad_config.domain])
        cmd.extend(["-u", self.ad_config.credentials.username])

        if self.ad_config.credentials.password:
            cmd.extend(["-p", self.ad_config.credentials.password])
        elif self.ad_config.credentials.ntlm_hash:
            # Use hash auth
            hashes = self.ad_config.credentials.ntlm_hash
            if ":" not in hashes:
                hashes = f"aad3b435b51404eeaad3b435b51404ee:{hashes}"
            cmd.extend(["--hashes", hashes])

        # Target DC
        if self.ad_config.dc_ip:
            cmd.extend(["-dc", self.ad_config.dc_ip])
            cmd.extend(["-ns", self.ad_config.dc_ip])

        # Collection methods
        if self.bh_config.collect_all:
            cmd.extend(["-c", "all"])
        else:
            methods = []
            if self.bh_config.collect_users:
                methods.append("users")
            if self.bh_config.collect_groups:
                methods.append("groups")
            if self.bh_config.collect_computers:
                methods.append("computers")
            if self.bh_config.collect_sessions:
                methods.append("sessions")
            if self.bh_config.collect_acls:
                methods.append("acl")
            if self.bh_config.collect_trusts:
                methods.append("trusts")
            if self.bh_config.collect_gpos:
                methods.append("gpo")

            if methods:
                cmd.extend(["-c", ",".join(methods)])

        # Output options
        output_dir = Path(self.bh_config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["--outputdir", str(output_dir)])

        if self.bh_config.output_prefix:
            cmd.extend(["--prefix", self.bh_config.output_prefix])

        if self.bh_config.compress:
            cmd.append("--zip")

        # Performance options
        cmd.extend(["--workers", str(self.bh_config.threads)])

        if self.bh_config.dns_tcp:
            cmd.append("--dns-tcp")

        cmd.extend(["--dns-timeout", str(self.bh_config.dns_timeout)])

        return cmd

    async def collect(self, timeout: int = 3600) -> BloodHoundResult:
        """
        Run BloodHound collection.

        Args:
            timeout: Collection timeout in seconds

        Returns:
            BloodHoundResult with collection results
        """
        if not await self.check_installed():
            raise RuntimeError(
                "bloodhound-python is not installed. "
                "Install with: pip install bloodhound"
            )

        started_at = datetime.now(timezone.utc).isoformat()
        start_time = current_time()

        cmd = self._build_command()
        print(f"[*] Running: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(f"BloodHound collection timed out after {timeout}s")

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = current_time() - start_time

        # Find output files
        output_dir = Path(self.bh_config.output_dir)
        output_files = []

        # Look for JSON files
        json_files = list(output_dir.glob("*.json"))
        output_files.extend([str(f) for f in json_files])

        # Look for ZIP files
        zip_files = list(output_dir.glob("*.zip"))
        output_files.extend([str(f) for f in zip_files])

        self.output_files = output_files

        # Parse statistics from output
        statistics = self._parse_statistics(stdout.decode() + stderr.decode())

        # Determine collection methods used
        methods = []
        if self.bh_config.collect_all:
            methods = ["all"]
        else:
            if self.bh_config.collect_users:
                methods.append("users")
            if self.bh_config.collect_groups:
                methods.append("groups")
            if self.bh_config.collect_computers:
                methods.append("computers")
            if self.bh_config.collect_sessions:
                methods.append("sessions")
            if self.bh_config.collect_acls:
                methods.append("acl")
            if self.bh_config.collect_trusts:
                methods.append("trusts")

        status = "completed" if process.returncode == 0 else "failed"

        return BloodHoundResult(
            domain=self.ad_config.domain,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            output_files=output_files,
            collection_methods=methods,
            statistics=statistics,
            attack_paths=[],  # Would need BloodHound DB analysis
            metadata={
                "return_code": process.returncode,
                "output": stdout.decode()[:1000],
                "errors": stderr.decode() if process.returncode != 0 else ""
            }
        )

    def _parse_statistics(self, output: str) -> Dict[str, int]:
        """Parse collection statistics from output."""
        stats = {
            "users": 0,
            "groups": 0,
            "computers": 0,
            "sessions": 0,
            "acls": 0,
            "trusts": 0
        }

        import re

        # Parse common output patterns
        patterns = {
            "users": r"(\d+)\s+users",
            "groups": r"(\d+)\s+groups",
            "computers": r"(\d+)\s+computers",
            "sessions": r"(\d+)\s+sessions",
            "acls": r"(\d+)\s+acls?",
            "trusts": r"(\d+)\s+trusts?"
        }

        for stat_name, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                stats[stat_name] = int(match.group(1))

        return stats

    def parse_json_output(self) -> Dict[str, List[Dict]]:
        """
        Parse collected JSON files.

        Returns:
            Dict with parsed data by type
        """
        data = {
            "users": [],
            "groups": [],
            "computers": [],
            "domains": [],
            "gpos": [],
            "ous": []
        }

        for file_path in self.output_files:
            if not file_path.endswith(".json"):
                continue

            try:
                with open(file_path, "r") as f:
                    content = json.load(f)

                # Determine type from filename or content
                file_name = Path(file_path).name.lower()

                if "users" in file_name:
                    data["users"].extend(content.get("data", []))
                elif "groups" in file_name:
                    data["groups"].extend(content.get("data", []))
                elif "computers" in file_name:
                    data["computers"].extend(content.get("data", []))
                elif "domains" in file_name:
                    data["domains"].extend(content.get("data", []))
                elif "gpos" in file_name:
                    data["gpos"].extend(content.get("data", []))
                elif "ous" in file_name:
                    data["ous"].extend(content.get("data", []))

            except Exception as e:
                print(f"[!] Error parsing {file_path}: {e}")

        return data

    def identify_high_value_targets(self) -> List[Dict]:
        """
        Identify high-value targets from collected data.

        Returns:
            List of high-value targets
        """
        targets = []
        data = self.parse_json_output()

        # Look for Domain Admins members
        for group in data.get("groups", []):
            props = group.get("Properties", {})
            name = props.get("name", "")

            if "DOMAIN ADMINS" in name.upper():
                members = group.get("Members", [])
                for member in members:
                    targets.append({
                        "type": "user",
                        "name": member.get("MemberId", ""),
                        "reason": "Domain Admin member",
                        "priority": "critical"
                    })

        # Look for computers with unconstrained delegation
        for computer in data.get("computers", []):
            props = computer.get("Properties", {})
            if props.get("unconstraineddelegation", False):
                targets.append({
                    "type": "computer",
                    "name": props.get("name", ""),
                    "reason": "Unconstrained delegation",
                    "priority": "high"
                })

        # Look for users with admincount
        for user in data.get("users", []):
            props = user.get("Properties", {})
            if props.get("admincount", False):
                targets.append({
                    "type": "user",
                    "name": props.get("name", ""),
                    "reason": "Admin count set",
                    "priority": "medium"
                })

        return targets


# Convenience function
async def run_bloodhound(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    output_dir: str = "./bloodhound_output",
    collect_all: bool = True,
    **kwargs
) -> BloodHoundResult:
    """
    Quick BloodHound collection.

    Args:
        domain: AD domain
        dc_ip: Domain Controller IP
        username: Username
        password: Password
        output_dir: Output directory
        collect_all: Collect all data

    Returns:
        BloodHoundResult
    """
    ad_config = get_ad_config(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password
    )

    bh_config = BloodHoundConfig(
        collect_all=collect_all,
        output_dir=output_dir,
        compress=True
    )

    wrapper = BloodHoundWrapper(ad_config, bh_config)
    return await wrapper.collect()
