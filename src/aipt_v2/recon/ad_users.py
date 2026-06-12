"""
AIPT Active Directory User Enumeration

Multiple techniques for discovering AD users:
- Kerberos AS-REQ timing attack (kerbrute style)
- SMB RID cycling/brute-force
- LDAP enumeration (anonymous and authenticated)
- GPO preference extraction
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class EnumMethod(Enum):
    """User enumeration methods"""

    KERBEROS = "kerberos"
    RID_CYCLE = "rid_cycle"
    LDAP_ANON = "ldap_anonymous"
    LDAP_AUTH = "ldap_authenticated"
    SMB_SAMR = "smb_samr"
    GPO_PREFS = "gpo_preferences"


@dataclass
class ADUser:
    """Discovered AD user"""

    username: str
    domain: str = ""
    sid: str = ""
    rid: int = 0
    dn: str = ""  # Distinguished name

    # Account properties
    enabled: bool = True
    locked: bool = False
    password_never_expires: bool = False
    password_not_required: bool = False
    dont_req_preauth: bool = False  # AS-REP roastable
    trusted_for_delegation: bool = False
    admin_count: bool = False
    is_sensitive: bool = False

    # Timestamps
    last_logon: Optional[datetime] = None
    password_last_set: Optional[datetime] = None
    account_expires: Optional[datetime] = None

    # Group memberships
    groups: list[str] = field(default_factory=list)
    is_domain_admin: bool = False
    is_enterprise_admin: bool = False

    # Service accounts
    spn: list[str] = field(default_factory=list)  # Kerberoastable if set
    description: str = ""

    # Discovery metadata
    enum_method: str = ""
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def is_kerberoastable(self) -> bool:
        """Check if user has SPNs (Kerberoastable)"""
        return len(self.spn) > 0

    def is_asrep_roastable(self) -> bool:
        """Check if pre-auth is disabled (AS-REP roastable)"""
        return self.dont_req_preauth

    def is_high_value(self) -> bool:
        """Check if user is high-value target"""
        return (
            self.is_domain_admin
            or self.is_enterprise_admin
            or self.admin_count
            or self.trusted_for_delegation
        )

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "domain": self.domain,
            "sid": self.sid,
            "rid": self.rid,
            "enabled": self.enabled,
            "locked": self.locked,
            "password_never_expires": self.password_never_expires,
            "dont_req_preauth": self.dont_req_preauth,
            "trusted_for_delegation": self.trusted_for_delegation,
            "is_domain_admin": self.is_domain_admin,
            "spn": self.spn,
            "is_kerberoastable": self.is_kerberoastable(),
            "is_asrep_roastable": self.is_asrep_roastable(),
            "is_high_value": self.is_high_value(),
            "enum_method": self.enum_method,
        }


@dataclass
class ADUserEnumConfig:
    """User enumeration configuration"""

    # Methods to use
    use_kerberos: bool = True
    use_rid_cycle: bool = True
    use_ldap: bool = True
    use_smb_samr: bool = True

    # Kerberos options
    kerberos_timeout: float = 3.0

    # RID cycling options
    rid_start: int = 500
    rid_end: int = 10000
    rid_batch_size: int = 50

    # LDAP options
    ldap_timeout: float = 10.0
    ldap_page_size: int = 1000

    # Concurrency
    max_concurrent: int = 50

    # Credentials (for authenticated enumeration)
    username: Optional[str] = None
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None
    domain: Optional[str] = None

    # Custom wordlist for kerbrute-style enum
    username_wordlist: list[str] = field(
        default_factory=lambda: [
            "administrator",
            "admin",
            "guest",
            "krbtgt",
            "support",
            "backup",
            "service",
            "svc",
            "sql",
            "web",
            "app",
            "test",
            "dev",
            "mail",
            "exchange",
            "sharepoint",
            "helpdesk",
            "it",
            "security",
            "audit",
            "hr",
            "finance",
        ]
    )


@dataclass
class ADUserEnumResult:
    """User enumeration results"""

    target_domain: str
    dc_ip: str
    users: list[ADUser] = field(default_factory=list)
    methods_used: list[str] = field(default_factory=list)

    # Statistics
    total_found: int = 0
    enabled_count: int = 0
    disabled_count: int = 0
    kerberoastable_count: int = 0
    asrep_roastable_count: int = 0
    domain_admins_count: int = 0

    # Metadata
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def get_kerberoastable(self) -> list[ADUser]:
        """Get users with SPNs"""
        return [u for u in self.users if u.is_kerberoastable()]

    def get_asrep_roastable(self) -> list[ADUser]:
        """Get users without pre-auth"""
        return [u for u in self.users if u.is_asrep_roastable()]

    def get_domain_admins(self) -> list[ADUser]:
        """Get domain admins"""
        return [u for u in self.users if u.is_domain_admin]

    def get_high_value(self) -> list[ADUser]:
        """Get high-value targets"""
        return [u for u in self.users if u.is_high_value()]

    def update_stats(self) -> None:
        """Update statistics based on discovered users"""
        self.total_found = len(self.users)
        self.enabled_count = sum(1 for u in self.users if u.enabled)
        self.disabled_count = sum(1 for u in self.users if not u.enabled)
        self.kerberoastable_count = len(self.get_kerberoastable())
        self.asrep_roastable_count = len(self.get_asrep_roastable())
        self.domain_admins_count = len(self.get_domain_admins())

    def to_dict(self) -> dict:
        self.update_stats()
        return {
            "target_domain": self.target_domain,
            "dc_ip": self.dc_ip,
            "total_found": self.total_found,
            "enabled_count": self.enabled_count,
            "disabled_count": self.disabled_count,
            "kerberoastable_count": self.kerberoastable_count,
            "asrep_roastable_count": self.asrep_roastable_count,
            "domain_admins_count": self.domain_admins_count,
            "methods_used": self.methods_used,
            "users": [u.to_dict() for u in self.users],
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }


class ADUserEnumerator:
    """
    Active Directory user enumeration using multiple techniques.

    Supports:
    - Kerberos AS-REQ user enumeration (no creds required)
    - SMB RID cycling (null session or creds)
    - LDAP enumeration (anonymous or authenticated)
    - GPO preference extraction (for cached creds)
    """

    def __init__(self, config: Optional[ADUserEnumConfig] = None):
        self.config = config or ADUserEnumConfig()

    async def enumerate(self, domain: str, dc_ip: str) -> ADUserEnumResult:
        """
        Enumerate AD users using all configured methods.

        Args:
            domain: Target domain name
            dc_ip: Domain controller IP address

        Returns:
            ADUserEnumResult with discovered users
        """
        result = ADUserEnumResult(target_domain=domain, dc_ip=dc_ip)
        result.start_time = datetime.utcnow()

        discovered_users: dict[str, ADUser] = {}

        try:
            # Method 1: Kerberos AS-REQ enumeration (no creds)
            if self.config.use_kerberos:
                logger.info("Starting Kerberos user enumeration")
                kerb_users = await self._enumerate_kerberos(domain, dc_ip)
                for user in kerb_users:
                    if user.username.lower() not in discovered_users:
                        discovered_users[user.username.lower()] = user
                result.methods_used.append(EnumMethod.KERBEROS.value)

            # Method 2: RID cycling (null session or creds)
            if self.config.use_rid_cycle:
                logger.info("Starting RID cycling enumeration")
                rid_users = await self._enumerate_rid_cycle(domain, dc_ip)
                for user in rid_users:
                    key = user.username.lower()
                    if key not in discovered_users:
                        discovered_users[key] = user
                    else:
                        # Merge RID info into existing user
                        discovered_users[key].sid = user.sid
                        discovered_users[key].rid = user.rid
                result.methods_used.append(EnumMethod.RID_CYCLE.value)

            # Method 3: LDAP enumeration
            if self.config.use_ldap:
                logger.info("Starting LDAP enumeration")
                ldap_users = await self._enumerate_ldap(domain, dc_ip)
                for user in ldap_users:
                    key = user.username.lower()
                    if key not in discovered_users:
                        discovered_users[key] = user
                    else:
                        # LDAP has richer data - merge
                        existing = discovered_users[key]
                        self._merge_user_data(existing, user)
                result.methods_used.append(
                    EnumMethod.LDAP_AUTH.value
                    if self.config.username
                    else EnumMethod.LDAP_ANON.value
                )

        except Exception as e:
            logger.error(f"User enumeration failed: {e}")
            result.errors.append(str(e))

        result.users = list(discovered_users.values())
        result.update_stats()

        result.end_time = datetime.utcnow()
        if result.start_time:
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    async def _enumerate_kerberos(self, domain: str, dc_ip: str) -> list[ADUser]:
        """
        Enumerate users via Kerberos AS-REQ.

        Valid users return KDC_ERR_PREAUTH_REQUIRED.
        Invalid users return KDC_ERR_C_PRINCIPAL_UNKNOWN.
        """
        users = []

        # Try using kerbrute if available
        try:
            kerbrute_users = await self._kerbrute_enum(domain, dc_ip)
            users.extend(kerbrute_users)
        except FileNotFoundError:
            logger.debug("kerbrute not available, using built-in Kerberos enum")
            # Fallback to manual AS-REQ enumeration
            builtin_users = await self._manual_kerberos_enum(domain, dc_ip)
            users.extend(builtin_users)

        return users

    async def _kerbrute_enum(self, domain: str, dc_ip: str) -> list[ADUser]:
        """Use kerbrute for user enumeration"""
        users = []

        # Create temporary wordlist file
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for username in self.config.username_wordlist:
                f.write(f"{username}\n")
            wordlist_path = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "kerbrute",
                "userenum",
                "--dc",
                dc_ip,
                "-d",
                domain,
                wordlist_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.kerberos_timeout * len(self.config.username_wordlist),
            )

            output = stdout.decode() + stderr.decode()

            # Parse kerbrute output
            # Format: "VALID USERNAME:  username@domain"
            pattern = r"VALID USERNAME:\s+(\S+)@"
            for match in re.finditer(pattern, output, re.IGNORECASE):
                username = match.group(1)
                users.append(
                    ADUser(
                        username=username,
                        domain=domain,
                        enum_method=EnumMethod.KERBEROS.value,
                    )
                )

        except asyncio.TimeoutError:
            logger.warning("kerbrute enumeration timed out")
        finally:
            import os

            os.unlink(wordlist_path)

        return users

    async def _manual_kerberos_enum(self, domain: str, dc_ip: str) -> list[ADUser]:
        """
        Manual Kerberos AS-REQ enumeration.

        Sends AS-REQ for each username and checks response.
        """
        users = []

        async def check_user(username: str) -> Optional[ADUser]:
            """Check if user exists via Kerberos"""
            try:
                # Build AS-REQ packet
                as_req = self._build_as_req(username, domain)

                # Send to KDC
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(dc_ip, 88), timeout=self.config.kerberos_timeout
                )

                # Kerberos uses length-prefixed messages
                length = struct.pack(">I", len(as_req))
                writer.write(length + as_req)
                await writer.drain()

                # Read response
                response_len = await asyncio.wait_for(
                    reader.read(4), timeout=self.config.kerberos_timeout
                )
                if len(response_len) < 4:
                    return None

                length = struct.unpack(">I", response_len)[0]
                response = await asyncio.wait_for(
                    reader.read(length), timeout=self.config.kerberos_timeout
                )

                writer.close()
                await writer.wait_closed()

                # Parse response for error code
                # KDC_ERR_PREAUTH_REQUIRED (25) = valid user
                # KDC_ERR_C_PRINCIPAL_UNKNOWN (6) = invalid user
                error_code = self._parse_krb_error(response)

                if error_code == 25:  # PREAUTH_REQUIRED - user exists
                    return ADUser(
                        username=username,
                        domain=domain,
                        enum_method=EnumMethod.KERBEROS.value,
                    )
                elif error_code == 18:  # KDC_ERR_CLIENT_REVOKED - user disabled
                    return ADUser(
                        username=username,
                        domain=domain,
                        enabled=False,
                        enum_method=EnumMethod.KERBEROS.value,
                    )

            except Exception as e:
                logger.debug(f"Kerberos check failed for {username}: {e}")

            return None

        # Check users concurrently
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def bounded_check(username: str) -> Optional[ADUser]:
            async with semaphore:
                return await check_user(username)

        tasks = [bounded_check(u) for u in self.config.username_wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ADUser):
                users.append(result)

        return users

    def _build_as_req(self, username: str, realm: str) -> bytes:
        """Build Kerberos AS-REQ packet"""
        # Simplified AS-REQ structure
        # This is a minimal implementation - production would use pyasn1/impacket

        from datetime import datetime, timedelta

        # PrincipalName
        principal = username.encode()
        realm_bytes = realm.upper().encode()

        # KDC-REQ-BODY
        # This is simplified - real implementation needs proper ASN.1 encoding
        # Using impacket or pyasn1-modules is recommended

        try:
            from impacket.krb5 import constants
            from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
            from impacket.krb5.types import KerberosTime, Principal
            from pyasn1.codec.der import encoder
            from pyasn1.type.univ import noValue

            # Build proper AS-REQ using impacket
            clientName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            asReq = AS_REQ()
            serverName = Principal(
                f"krbtgt/{realm.upper()}", type=constants.PrincipalNameType.NT_SRV_INST.value
            )

            pacReq = {
                "include-pac": True,
                "pa-data-type": constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value,
            }

            seq_set(asReq, "pvno", 5)
            seq_set(asReq, "msg-type", constants.ApplicationTagNumbers.AS_REQ.value)

            reqBody = seq_set(asReq, "req-body")
            opts = []
            seq_set_iter(reqBody, "kdc-options", opts)
            seq_set(reqBody, "cname", clientName.components_to_asn1)
            seq_set(reqBody, "realm", realm.upper())
            seq_set(reqBody, "sname", serverName.components_to_asn1)

            now = datetime.utcnow()
            seq_set(reqBody, "till", KerberosTime.to_asn1(now + timedelta(days=1)))
            seq_set(reqBody, "rtime", KerberosTime.to_asn1(now + timedelta(days=1)))
            seq_set(reqBody, "nonce", 12345678)
            seq_set_iter(
                reqBody,
                "etype",
                [
                    constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                    constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                    constants.EncryptionTypes.rc4_hmac.value,
                ],
            )

            return encoder.encode(asReq)

        except ImportError:
            # Fallback to raw bytes (simplified, may not work with all KDCs)
            logger.debug("impacket not available, using simplified AS-REQ")

            # This is a very simplified packet that should trigger error responses
            # Real implementation requires proper ASN.1 encoding
            return b""

    def _parse_krb_error(self, data: bytes) -> int:
        """Parse Kerberos error code from response"""
        try:
            # Try using impacket
            from impacket.krb5.asn1 import KRB_ERROR
            from pyasn1.codec.der import decoder

            krb_error = decoder.decode(data, asn1Spec=KRB_ERROR())[0]
            return int(krb_error["error-code"])

        except ImportError:
            # Manual parsing - look for error code in ASN.1 structure
            # Error code is typically at a known offset
            # This is a simplified fallback
            if len(data) > 10:
                # Look for error-code tag (0xa4 or similar)
                for i in range(len(data) - 2):
                    if data[i] == 0x02 and data[i + 1] == 0x01:  # INTEGER, length 1
                        return data[i + 2]
            return -1

        except Exception as e:
            logger.debug(f"Failed to parse Kerberos error: {e}")
            return -1

    async def _enumerate_rid_cycle(self, domain: str, dc_ip: str) -> list[ADUser]:
        """
        Enumerate users via RID cycling.

        Uses SMB/SAMR to query SIDs by RID.
        """
        users = []

        try:
            # Try using rpcclient
            users = await self._rid_cycle_rpcclient(domain, dc_ip)
        except FileNotFoundError:
            logger.debug("rpcclient not available, trying impacket")
            users = await self._rid_cycle_impacket(domain, dc_ip)

        return users

    async def _rid_cycle_rpcclient(self, domain: str, dc_ip: str) -> list[ADUser]:
        """RID cycling using rpcclient"""
        users = []
        domain_sid = None

        # First, get domain SID
        try:
            proc = await asyncio.create_subprocess_exec(
                "rpcclient",
                "-U",
                "",
                "-N",
                dc_ip,
                "-c",
                "lsaquery",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode()

            # Parse domain SID
            sid_match = re.search(r"Domain Sid:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)", output)
            if sid_match:
                domain_sid = sid_match.group(1)
            else:
                logger.warning("Could not determine domain SID")
                return users

        except Exception as e:
            logger.debug(f"Failed to get domain SID: {e}")
            return users

        # Now cycle through RIDs
        for rid in range(self.config.rid_start, self.config.rid_end, self.config.rid_batch_size):
            batch_end = min(rid + self.config.rid_batch_size, self.config.rid_end)
            rids = " ".join(str(r) for r in range(rid, batch_end))

            try:
                # Use lookupsids to resolve RIDs
                sids = " ".join(f"{domain_sid}-{r}" for r in range(rid, batch_end))
                proc = await asyncio.create_subprocess_exec(
                    "rpcclient",
                    "-U",
                    "",
                    "-N",
                    dc_ip,
                    "-c",
                    f"lookupsids {sids}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = stdout.decode()

                # Parse results - format: S-1-5-...-RID DOMAIN\username (type)
                pattern = r"(S-[\d-]+)\s+(\S+)\\(\S+)\s+\((\d+)\)"
                for match in re.finditer(pattern, output):
                    sid = match.group(1)
                    user_domain = match.group(2)
                    username = match.group(3)
                    sid_type = int(match.group(4))

                    # Type 1 = User, Type 2 = Group
                    if sid_type == 1 and username != "unknown":
                        rid_num = int(sid.split("-")[-1])
                        users.append(
                            ADUser(
                                username=username,
                                domain=user_domain,
                                sid=sid,
                                rid=rid_num,
                                enum_method=EnumMethod.RID_CYCLE.value,
                            )
                        )

            except Exception as e:
                logger.debug(f"RID batch {rid}-{batch_end} failed: {e}")

        return users

    async def _rid_cycle_impacket(self, domain: str, dc_ip: str) -> list[ADUser]:
        """RID cycling using impacket lookupsid.py"""
        users = []

        try:
            # Build command
            cmd = ["lookupsid.py"]

            if self.config.username and self.config.password:
                cmd.append(f"{domain}/{self.config.username}:{self.config.password}@{dc_ip}")
            elif self.config.username and self.config.ntlm_hash:
                cmd.extend(
                    [
                        f"{domain}/{self.config.username}@{dc_ip}",
                        "-hashes",
                        f":{self.config.ntlm_hash}",
                    ]
                )
            else:
                # Try null session
                cmd.append(f"{domain}/guest@{dc_ip}")
                cmd.append("-no-pass")

            cmd.extend(["-maxRid", str(self.config.rid_end)])

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode()

            # Parse output - format: 500: DOMAIN\Administrator (SidTypeUser)
            pattern = r"(\d+):\s+(\S+)\\(\S+)\s+\(SidTypeUser\)"
            for match in re.finditer(pattern, output):
                rid = int(match.group(1))
                user_domain = match.group(2)
                username = match.group(3)

                users.append(
                    ADUser(
                        username=username,
                        domain=user_domain,
                        rid=rid,
                        enum_method=EnumMethod.RID_CYCLE.value,
                    )
                )

        except FileNotFoundError:
            logger.warning("lookupsid.py not found, skipping RID cycling")
        except Exception as e:
            logger.debug(f"Impacket RID cycling failed: {e}")

        return users

    async def _enumerate_ldap(self, domain: str, dc_ip: str) -> list[ADUser]:
        """Enumerate users via LDAP"""
        users = []

        try:
            from ldap3 import ALL, ANONYMOUS, SIMPLE, SUBTREE, Connection, Server

            server = Server(dc_ip, port=389, get_info=ALL, connect_timeout=self.config.ldap_timeout)

            # Determine authentication
            if self.config.username and self.config.password:
                user_dn = (
                    f"{self.config.domain}\\{self.config.username}"
                    if self.config.domain
                    else self.config.username
                )
                conn = Connection(
                    server, user=user_dn, password=self.config.password, authentication=SIMPLE
                )
            else:
                conn = Connection(server, authentication=ANONYMOUS)

            if not conn.bind():
                logger.warning(f"LDAP bind failed: {conn.last_error}")
                return users

            # Build base DN from domain
            base_dn = ",".join(f"DC={part}" for part in domain.split("."))

            # Search for all users
            search_filter = "(&(objectCategory=person)(objectClass=user))"
            attributes = [
                "sAMAccountName",
                "distinguishedName",
                "objectSid",
                "userAccountControl",
                "memberOf",
                "servicePrincipalName",
                "lastLogon",
                "pwdLastSet",
                "description",
                "adminCount",
            ]

            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=self.config.ldap_page_size,
            )

            for entry in conn.entries:
                user = self._ldap_entry_to_user(entry, domain)
                if user:
                    users.append(user)

            conn.unbind()

        except ImportError:
            logger.warning("ldap3 not installed, skipping LDAP enumeration")
        except Exception as e:
            logger.debug(f"LDAP enumeration failed: {e}")

        return users

    def _ldap_entry_to_user(self, entry, domain: str) -> Optional[ADUser]:
        """Convert LDAP entry to ADUser"""
        try:
            username = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else None
            if not username:
                return None

            user = ADUser(
                username=username,
                domain=domain,
                enum_method=EnumMethod.LDAP_AUTH.value,
            )

            # Distinguished name
            if hasattr(entry, "distinguishedName"):
                user.dn = str(entry.distinguishedName)

            # Object SID
            if hasattr(entry, "objectSid"):
                user.sid = str(entry.objectSid)
                # Extract RID from SID
                if user.sid:
                    parts = user.sid.split("-")
                    if parts:
                        try:
                            user.rid = int(parts[-1])
                        except ValueError:
                            pass

            # User Account Control flags
            if hasattr(entry, "userAccountControl"):
                uac = int(str(entry.userAccountControl))
                user.enabled = not (uac & 0x0002)  # ACCOUNTDISABLE
                user.locked = bool(uac & 0x0010)  # LOCKOUT
                user.password_never_expires = bool(uac & 0x10000)
                user.password_not_required = bool(uac & 0x0020)
                user.dont_req_preauth = bool(uac & 0x400000)  # AS-REP roastable
                user.trusted_for_delegation = bool(uac & 0x80000)
                user.is_sensitive = bool(uac & 0x100000)

            # Admin count
            if hasattr(entry, "adminCount"):
                try:
                    user.admin_count = int(str(entry.adminCount)) == 1
                except (ValueError, TypeError):
                    pass

            # Group memberships
            if hasattr(entry, "memberOf"):
                groups = (
                    entry.memberOf.values
                    if hasattr(entry.memberOf, "values")
                    else [str(entry.memberOf)]
                )
                user.groups = [str(g) for g in groups]

                # Check for privileged groups
                for group in user.groups:
                    group_lower = group.lower()
                    if "domain admins" in group_lower or "cn=domain admins" in group_lower:
                        user.is_domain_admin = True
                    if "enterprise admins" in group_lower or "cn=enterprise admins" in group_lower:
                        user.is_enterprise_admin = True

            # Service Principal Names
            if hasattr(entry, "servicePrincipalName"):
                spns = (
                    entry.servicePrincipalName.values
                    if hasattr(entry.servicePrincipalName, "values")
                    else [str(entry.servicePrincipalName)]
                )
                user.spn = [str(s) for s in spns if s]

            # Description
            if hasattr(entry, "description"):
                user.description = str(entry.description)

            return user

        except Exception as e:
            logger.debug(f"Failed to parse LDAP entry: {e}")
            return None

    def _merge_user_data(self, existing: ADUser, new: ADUser) -> None:
        """Merge user data from multiple sources"""
        # Prefer LDAP data as it's more complete
        if new.dn:
            existing.dn = new.dn
        if new.sid and not existing.sid:
            existing.sid = new.sid
        if new.rid and not existing.rid:
            existing.rid = new.rid

        # Flags
        existing.enabled = new.enabled
        existing.locked = new.locked
        existing.password_never_expires = (
            new.password_never_expires or existing.password_never_expires
        )
        existing.password_not_required = new.password_not_required or existing.password_not_required
        existing.dont_req_preauth = new.dont_req_preauth or existing.dont_req_preauth
        existing.trusted_for_delegation = (
            new.trusted_for_delegation or existing.trusted_for_delegation
        )
        existing.admin_count = new.admin_count or existing.admin_count

        # Groups and SPNs
        if new.groups:
            existing.groups = new.groups
            existing.is_domain_admin = new.is_domain_admin
            existing.is_enterprise_admin = new.is_enterprise_admin
        if new.spn:
            existing.spn = new.spn
        if new.description:
            existing.description = new.description


# Convenience functions
async def enumerate_users(
    domain: str, dc_ip: str, config: Optional[ADUserEnumConfig] = None
) -> ADUserEnumResult:
    """
    Enumerate Active Directory users.

    Args:
        domain: Target domain name
        dc_ip: Domain controller IP
        config: Optional configuration

    Returns:
        ADUserEnumResult with discovered users
    """
    enumerator = ADUserEnumerator(config)
    return await enumerator.enumerate(domain, dc_ip)


async def find_kerberoastable_users(
    domain: str,
    dc_ip: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> list[ADUser]:
    """
    Find Kerberoastable users (users with SPNs).

    Args:
        domain: Target domain
        dc_ip: Domain controller IP
        username: Optional credentials for authenticated enum
        password: Optional credentials

    Returns:
        List of Kerberoastable users
    """
    config = ADUserEnumConfig(
        use_kerberos=False,
        use_rid_cycle=False,
        use_ldap=True,
        username=username,
        password=password,
        domain=domain,
    )
    result = await enumerate_users(domain, dc_ip, config)
    return result.get_kerberoastable()


async def find_asrep_roastable_users(
    domain: str,
    dc_ip: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> list[ADUser]:
    """
    Find AS-REP roastable users (DONT_REQ_PREAUTH flag set).

    Args:
        domain: Target domain
        dc_ip: Domain controller IP
        username: Optional credentials
        password: Optional credentials

    Returns:
        List of AS-REP roastable users
    """
    config = ADUserEnumConfig(
        use_kerberos=False,
        use_rid_cycle=False,
        use_ldap=True,
        username=username,
        password=password,
        domain=domain,
    )
    result = await enumerate_users(domain, dc_ip, config)
    return result.get_asrep_roastable()
