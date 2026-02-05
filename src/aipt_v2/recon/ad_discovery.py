"""
AIPT Active Directory Discovery

Domain footprinting and reconnaissance without credentials.
Identifies domain controllers, forest structure, and attack surface.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ADServiceType(Enum):
    """AD service types discoverable via DNS"""
    LDAP = "_ldap._tcp"
    LDAPS = "_ldap._tcp.dc._msdcs"
    KERBEROS = "_kerberos._tcp"
    KPASSWD = "_kpasswd._tcp"
    GC = "_gc._tcp"  # Global Catalog
    GCS = "_ldap._tcp.gc._msdcs"  # Global Catalog SSL
    PDC = "_ldap._tcp.pdc._msdcs"  # Primary DC
    KDC = "_kerberos._tcp.dc._msdcs"  # Key Distribution Center


@dataclass
class DomainController:
    """Discovered Domain Controller"""
    hostname: str
    ip: str = ""
    domain: str = ""
    site: str = ""
    is_gc: bool = False  # Global Catalog
    is_pdc: bool = False  # Primary DC
    os_version: str = ""
    smb_signing: bool = True
    ldap_port: int = 389
    ldaps_port: int = 636
    kerberos_port: int = 88
    smb_port: int = 445
    services: list[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "domain": self.domain,
            "site": self.site,
            "is_gc": self.is_gc,
            "is_pdc": self.is_pdc,
            "os_version": self.os_version,
            "smb_signing": self.smb_signing,
            "services": self.services,
        }


@dataclass
class DomainTrust:
    """Domain trust relationship"""
    source_domain: str
    target_domain: str
    trust_type: str = ""  # parent-child, tree-root, external, forest
    trust_direction: str = ""  # inbound, outbound, bidirectional
    is_transitive: bool = False
    sid_filtering: bool = True

    def to_dict(self) -> dict:
        return {
            "source_domain": self.source_domain,
            "target_domain": self.target_domain,
            "trust_type": self.trust_type,
            "trust_direction": self.trust_direction,
            "is_transitive": self.is_transitive,
            "sid_filtering": self.sid_filtering,
        }


@dataclass
class ForestInfo:
    """Active Directory Forest information"""
    forest_name: str
    root_domain: str
    domains: list[str] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)
    forest_functional_level: str = ""
    domain_functional_level: str = ""

    def to_dict(self) -> dict:
        return {
            "forest_name": self.forest_name,
            "root_domain": self.root_domain,
            "domains": self.domains,
            "sites": self.sites,
            "forest_functional_level": self.forest_functional_level,
            "domain_functional_level": self.domain_functional_level,
        }


@dataclass
class ADDiscoveryConfig:
    """AD Discovery configuration"""
    # DNS enumeration
    enumerate_srv: bool = True
    enumerate_trusts: bool = True
    enumerate_sites: bool = True

    # Network scanning
    scan_ports: bool = True
    check_smb_signing: bool = True
    check_ldap_anonymous: bool = True
    check_null_session: bool = True

    # Timeouts
    dns_timeout: float = 5.0
    port_timeout: float = 3.0
    ldap_timeout: float = 10.0

    # Concurrency
    max_concurrent: int = 20

    # DNS servers (optional, uses system default if empty)
    dns_servers: list[str] = field(default_factory=list)


@dataclass
class ADDiscoveryResult:
    """AD Discovery results"""
    target_domain: str
    domain_controllers: list[DomainController] = field(default_factory=list)
    trusts: list[DomainTrust] = field(default_factory=list)
    forest_info: Optional[ForestInfo] = None
    naming_contexts: list[str] = field(default_factory=list)
    anonymous_ldap: bool = False
    null_session: bool = False

    # Metadata
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def get_pdc(self) -> Optional[DomainController]:
        """Get Primary Domain Controller"""
        for dc in self.domain_controllers:
            if dc.is_pdc:
                return dc
        return self.domain_controllers[0] if self.domain_controllers else None

    def get_gcs(self) -> list[DomainController]:
        """Get Global Catalog servers"""
        return [dc for dc in self.domain_controllers if dc.is_gc]

    def get_dc_ips(self) -> list[str]:
        """Get all DC IP addresses"""
        return [dc.ip for dc in self.domain_controllers if dc.ip]

    def to_dict(self) -> dict:
        return {
            "target_domain": self.target_domain,
            "domain_controllers": [dc.to_dict() for dc in self.domain_controllers],
            "trusts": [t.to_dict() for t in self.trusts],
            "forest_info": self.forest_info.to_dict() if self.forest_info else None,
            "naming_contexts": self.naming_contexts,
            "anonymous_ldap": self.anonymous_ldap,
            "null_session": self.null_session,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }


class ADDiscovery:
    """
    Active Directory domain discovery without credentials.

    Performs reconnaissance using:
    - DNS SRV record enumeration
    - LDAP RootDSE queries (anonymous)
    - SMB negotiation for domain/hostname disclosure
    - NTLM challenge parsing for domain information
    """

    # Common AD ports
    AD_PORTS = {
        88: "kerberos",
        389: "ldap",
        445: "smb",
        464: "kpasswd",
        636: "ldaps",
        3268: "gc",
        3269: "gc-ssl",
        5985: "winrm-http",
        5986: "winrm-https",
    }

    def __init__(self, config: Optional[ADDiscoveryConfig] = None):
        self.config = config or ADDiscoveryConfig()
        self._dns_resolver = None

    async def discover(self, domain: str) -> ADDiscoveryResult:
        """
        Perform full AD domain discovery.

        Args:
            domain: Target domain name (e.g., "corp.local")

        Returns:
            ADDiscoveryResult with discovered information
        """
        result = ADDiscoveryResult(target_domain=domain)
        result.start_time = datetime.utcnow()

        try:
            # Phase 1: DNS enumeration
            if self.config.enumerate_srv:
                await self._enumerate_srv_records(domain, result)

            # Phase 2: Identify PDC and GC servers
            await self._identify_special_dcs(domain, result)

            # Phase 3: Port scanning on discovered DCs
            if self.config.scan_ports:
                await self._scan_dc_ports(result)

            # Phase 4: LDAP RootDSE query (anonymous)
            if self.config.check_ldap_anonymous:
                await self._check_anonymous_ldap(result)

            # Phase 5: SMB checks
            if self.config.check_null_session:
                await self._check_null_session(result)

            if self.config.check_smb_signing:
                await self._check_smb_signing(result)

            # Phase 6: Trust enumeration via DNS
            if self.config.enumerate_trusts:
                await self._enumerate_trusts(domain, result)

        except Exception as e:
            logger.error(f"AD discovery error: {e}")
            result.errors.append(str(e))

        result.end_time = datetime.utcnow()
        if result.start_time:
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    async def _enumerate_srv_records(self, domain: str, result: ADDiscoveryResult) -> None:
        """Enumerate AD-related DNS SRV records"""
        logger.info(f"Enumerating SRV records for {domain}")

        discovered_dcs: dict[str, DomainController] = {}

        for service_type in ADServiceType:
            srv_name = f"{service_type.value}.{domain}"

            try:
                records = await self._dns_lookup_srv(srv_name)

                for priority, weight, port, target in records:
                    target = target.rstrip(".")

                    if target not in discovered_dcs:
                        discovered_dcs[target] = DomainController(
                            hostname=target,
                            domain=domain,
                        )

                    dc = discovered_dcs[target]
                    dc.services.append(service_type.name)

                    # Set port based on service
                    if service_type == ADServiceType.LDAP:
                        dc.ldap_port = port
                    elif service_type == ADServiceType.KERBEROS:
                        dc.kerberos_port = port
                    elif service_type == ADServiceType.GC:
                        dc.is_gc = True

            except Exception as e:
                logger.debug(f"Failed to query {srv_name}: {e}")

        # Resolve IP addresses
        for hostname, dc in discovered_dcs.items():
            try:
                dc.ip = await self._dns_lookup_a(hostname)
            except Exception as e:
                logger.debug(f"Failed to resolve {hostname}: {e}")

        result.domain_controllers = list(discovered_dcs.values())
        logger.info(f"Discovered {len(result.domain_controllers)} domain controllers")

    async def _identify_special_dcs(self, domain: str, result: ADDiscoveryResult) -> None:
        """Identify PDC Emulator and Global Catalog servers"""

        # Find PDC
        pdc_srv = f"_ldap._tcp.pdc._msdcs.{domain}"
        try:
            records = await self._dns_lookup_srv(pdc_srv)
            if records:
                pdc_hostname = records[0][3].rstrip(".")
                for dc in result.domain_controllers:
                    if dc.hostname == pdc_hostname:
                        dc.is_pdc = True
                        logger.info(f"PDC Emulator: {pdc_hostname}")
                        break
        except Exception as e:
            logger.debug(f"Failed to identify PDC: {e}")

        # Find Global Catalogs
        gc_srv = f"_gc._tcp.{domain}"
        try:
            records = await self._dns_lookup_srv(gc_srv)
            gc_hostnames = {r[3].rstrip(".") for r in records}
            for dc in result.domain_controllers:
                if dc.hostname in gc_hostnames:
                    dc.is_gc = True
        except Exception as e:
            logger.debug(f"Failed to identify GCs: {e}")

    async def _scan_dc_ports(self, result: ADDiscoveryResult) -> None:
        """Scan common AD ports on discovered DCs"""
        logger.info("Scanning AD ports on domain controllers")

        async def scan_dc(dc: DomainController) -> None:
            if not dc.ip:
                return

            open_ports = []
            for port, service in self.AD_PORTS.items():
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(dc.ip, port),
                        timeout=self.config.port_timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(f"{port}/{service}")
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

            if open_ports:
                dc.services.extend(open_ports)

        tasks = [scan_dc(dc) for dc in result.domain_controllers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_anonymous_ldap(self, result: ADDiscoveryResult) -> None:
        """Check for anonymous LDAP access and query RootDSE"""
        logger.info("Checking anonymous LDAP access")

        dc = result.get_pdc()
        if not dc or not dc.ip:
            return

        try:
            # Try to import ldap3
            try:
                from ldap3 import Server, Connection, ALL, ANONYMOUS
            except ImportError:
                logger.warning("ldap3 not installed, skipping anonymous LDAP check")
                return

            server = Server(dc.ip, port=dc.ldap_port, get_info=ALL, connect_timeout=self.config.ldap_timeout)
            conn = Connection(server, authentication=ANONYMOUS)

            if conn.bind():
                result.anonymous_ldap = True
                logger.warning(f"Anonymous LDAP bind successful on {dc.ip}")

                # Extract RootDSE info
                if server.info:
                    if hasattr(server.info, "naming_contexts"):
                        result.naming_contexts = list(server.info.naming_contexts or [])

                    if hasattr(server.info, "supported_ldap_versions"):
                        logger.debug(f"LDAP versions: {server.info.supported_ldap_versions}")

                    # Try to get forest/domain functional level
                    if hasattr(server.info, "other"):
                        other = server.info.other
                        if "forestFunctionality" in other:
                            level = self._functional_level_to_string(other["forestFunctionality"][0])
                            if not result.forest_info:
                                result.forest_info = ForestInfo(
                                    forest_name=result.target_domain,
                                    root_domain=result.target_domain
                                )
                            result.forest_info.forest_functional_level = level

                        if "domainFunctionality" in other:
                            level = self._functional_level_to_string(other["domainFunctionality"][0])
                            if result.forest_info:
                                result.forest_info.domain_functional_level = level

                conn.unbind()
            else:
                logger.info("Anonymous LDAP bind not allowed")

        except Exception as e:
            logger.debug(f"Anonymous LDAP check failed: {e}")

    async def _check_null_session(self, result: ADDiscoveryResult) -> None:
        """Check for SMB null session access"""
        logger.info("Checking SMB null session")

        dc = result.get_pdc()
        if not dc or not dc.ip:
            return

        try:
            # Use smbclient or impacket to check null session
            proc = await asyncio.create_subprocess_exec(
                "smbclient", "-L", f"//{dc.ip}", "-N", "-I", dc.ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.port_timeout * 2
            )

            # Check if we got share listing (indicates null session worked)
            output = stdout.decode() + stderr.decode()
            if "Sharename" in output or "IPC$" in output:
                result.null_session = True
                logger.warning(f"SMB null session allowed on {dc.ip}")
            else:
                logger.info("SMB null session not allowed")

        except FileNotFoundError:
            logger.debug("smbclient not installed, skipping null session check")
        except Exception as e:
            logger.debug(f"Null session check failed: {e}")

    async def _check_smb_signing(self, result: ADDiscoveryResult) -> None:
        """Check SMB signing requirements on DCs"""
        logger.info("Checking SMB signing")

        for dc in result.domain_controllers:
            if not dc.ip:
                continue

            try:
                # Use nmap smb2-security-mode script
                proc = await asyncio.create_subprocess_exec(
                    "nmap", "-p", "445", "--script", "smb2-security-mode",
                    dc.ip, "-oN", "-",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=30
                )

                output = stdout.decode()

                # Parse signing status
                if "Message signing enabled but not required" in output:
                    dc.smb_signing = False
                    logger.warning(f"SMB signing NOT required on {dc.hostname}")
                elif "Message signing enabled and required" in output:
                    dc.smb_signing = True
                    logger.info(f"SMB signing required on {dc.hostname}")

            except FileNotFoundError:
                logger.debug("nmap not installed, skipping SMB signing check")
                break
            except Exception as e:
                logger.debug(f"SMB signing check failed for {dc.hostname}: {e}")

    async def _enumerate_trusts(self, domain: str, result: ADDiscoveryResult) -> None:
        """Enumerate domain trusts via DNS"""
        logger.info("Enumerating domain trusts")

        # Query _kerberos._tcp for trusted domains
        # Trust records often appear in _msdcs zone
        trust_srv = f"_kerberos._tcp.dc._msdcs.{domain}"

        try:
            # Also try to find forest trust info
            # _ldap._tcp.ForestDnsZones.domain
            forest_srv = f"_ldap._tcp.ForestDnsZones.{domain}"

            records = await self._dns_lookup_srv(forest_srv)
            if records:
                # Extract unique domains from the records
                seen_domains = set()
                for _, _, _, target in records:
                    target = target.rstrip(".")
                    # Extract domain from hostname (dc.sub.domain.com -> sub.domain.com)
                    parts = target.split(".", 1)
                    if len(parts) > 1:
                        trust_domain = parts[1]
                        if trust_domain != domain and trust_domain not in seen_domains:
                            seen_domains.add(trust_domain)
                            result.trusts.append(DomainTrust(
                                source_domain=domain,
                                target_domain=trust_domain,
                                trust_type="forest",
                            ))

        except Exception as e:
            logger.debug(f"Trust enumeration via DNS failed: {e}")

    async def _dns_lookup_srv(self, name: str) -> list[tuple[int, int, int, str]]:
        """Perform DNS SRV lookup"""
        import dns.resolver

        resolver = dns.resolver.Resolver()
        if self.config.dns_servers:
            resolver.nameservers = self.config.dns_servers
        resolver.timeout = self.config.dns_timeout
        resolver.lifetime = self.config.dns_timeout

        records = []
        try:
            answers = resolver.resolve(name, "SRV")
            for rdata in answers:
                records.append((
                    rdata.priority,
                    rdata.weight,
                    rdata.port,
                    str(rdata.target)
                ))
        except Exception:
            pass

        return records

    async def _dns_lookup_a(self, hostname: str) -> str:
        """Perform DNS A record lookup"""
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            if self.config.dns_servers:
                resolver.nameservers = self.config.dns_servers
            resolver.timeout = self.config.dns_timeout

            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                return str(rdata)
        except Exception:
            # Fallback to socket
            try:
                return socket.gethostbyname(hostname)
            except socket.gaierror:
                pass

        return ""

    def _functional_level_to_string(self, level: str) -> str:
        """Convert AD functional level number to string"""
        levels = {
            "0": "Windows 2000",
            "1": "Windows 2003 Interim",
            "2": "Windows 2003",
            "3": "Windows 2008",
            "4": "Windows 2008 R2",
            "5": "Windows 2012",
            "6": "Windows 2012 R2",
            "7": "Windows 2016",
        }
        return levels.get(str(level), f"Unknown ({level})")

    # -------------------------------------------------------------------------
    # Network-based domain identification (no DNS required)
    # -------------------------------------------------------------------------

    async def identify_domain_from_smb(self, target_ip: str) -> Optional[str]:
        """
        Extract domain name from SMB negotiation.

        SMB negotiation leaks the NetBIOS domain and hostname.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, 445),
                timeout=self.config.port_timeout
            )

            # Send SMB negotiate request
            negotiate = self._build_smb_negotiate()
            writer.write(negotiate)
            await writer.drain()

            # Read response
            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.config.port_timeout
            )

            writer.close()
            await writer.wait_closed()

            # Parse domain from response
            domain = self._parse_smb_domain(response)
            return domain

        except Exception as e:
            logger.debug(f"SMB domain identification failed: {e}")
            return None

    async def identify_domain_from_ntlm(self, target_ip: str, port: int = 445) -> dict:
        """
        Extract domain info from NTLM challenge.

        NTLM Type 2 challenge contains:
        - NetBIOS domain name
        - DNS domain name
        - DNS hostname
        - Timestamp
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=self.config.port_timeout
            )

            # For SMB, we need to initiate NTLM auth to get challenge
            # This is a simplified version - full implementation would need
            # proper SMB session setup

            writer.close()
            await writer.wait_closed()

            # For now, use nmap script as fallback
            return await self._ntlm_info_via_nmap(target_ip, port)

        except Exception as e:
            logger.debug(f"NTLM info extraction failed: {e}")
            return {}

    async def _ntlm_info_via_nmap(self, target_ip: str, port: int) -> dict:
        """Use nmap ntlm-info script to extract domain information"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-p", str(port), "--script", "smb-os-discovery,ntlm-info",
                target_ip, "-oN", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=30
            )

            output = stdout.decode()
            info = {}

            # Parse output
            patterns = {
                "domain": r"Domain name:\s*(.+)",
                "fqdn": r"FQDN:\s*(.+)",
                "netbios_domain": r"NetBIOS domain name:\s*(.+)",
                "netbios_computer": r"NetBIOS computer name:\s*(.+)",
                "dns_domain": r"DNS domain:\s*(.+)",
                "dns_computer": r"DNS computer name:\s*(.+)",
                "os": r"OS:\s*(.+)",
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    info[key] = match.group(1).strip()

            return info

        except Exception as e:
            logger.debug(f"nmap NTLM info extraction failed: {e}")
            return {}

    def _build_smb_negotiate(self) -> bytes:
        """Build SMB1 negotiate request packet"""
        # Simplified SMB1 negotiate - enough to get domain info
        # NetBIOS session service header
        netbios_header = b"\x00"  # Message type
        length = b"\x00\x00\x54"  # Length (placeholder)

        # SMB header
        smb_header = b"\xffSMB"  # Protocol
        smb_header += b"\x72"  # Command: Negotiate
        smb_header += b"\x00\x00\x00\x00"  # Status
        smb_header += b"\x18"  # Flags
        smb_header += b"\x01\x28"  # Flags2
        smb_header += b"\x00" * 12  # Extra fields
        smb_header += b"\x00\x00"  # TID
        smb_header += b"\xff\xfe"  # PID
        smb_header += b"\x00\x00"  # UID
        smb_header += b"\x00\x00"  # MID

        # Negotiate request
        negotiate = b"\x00"  # Word count
        negotiate += b"\x31\x00"  # Byte count
        negotiate += b"\x02NT LM 0.12\x00"  # Dialect

        packet = netbios_header + smb_header + negotiate
        return packet

    def _parse_smb_domain(self, response: bytes) -> Optional[str]:
        """Parse domain name from SMB negotiate response"""
        try:
            # Look for domain name in response
            # This is a simplified parser - full implementation would
            # properly parse SMB structures
            if len(response) < 100:
                return None

            # Domain is typically in the security blob or OEM domain field
            # Try to find null-terminated strings
            text_start = response.find(b"\x00\x00") + 2
            if text_start > 2:
                # Extract potential domain strings
                remaining = response[text_start:]
                strings = remaining.split(b"\x00\x00")
                for s in strings:
                    try:
                        decoded = s.decode("utf-16-le", errors="ignore")
                        # Filter for domain-like strings
                        if decoded and len(decoded) > 2 and "." in decoded:
                            return decoded.strip("\x00")
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"SMB response parsing failed: {e}")

        return None


# Convenience functions
async def discover_domain(domain: str, config: Optional[ADDiscoveryConfig] = None) -> ADDiscoveryResult:
    """
    Discover Active Directory domain information.

    Args:
        domain: Target domain name
        config: Optional configuration

    Returns:
        ADDiscoveryResult with discovered information
    """
    discovery = ADDiscovery(config)
    return await discovery.discover(domain)


async def find_domain_controllers(domain: str) -> list[DomainController]:
    """
    Quick discovery of domain controllers only.

    Args:
        domain: Target domain name

    Returns:
        List of discovered domain controllers
    """
    config = ADDiscoveryConfig(
        scan_ports=False,
        check_smb_signing=False,
        check_ldap_anonymous=False,
        check_null_session=False,
        enumerate_trusts=False,
    )
    result = await discover_domain(domain, config)
    return result.domain_controllers
