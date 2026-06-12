"""
AIPTX Active Directory Evasion Techniques

Stealth techniques for AD penetration testing:
- Timing jitter for queries
- Native tool usage
- Log evasion tactics
- Detection avoidance
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class StealthLevel(Enum):
    """Stealth levels for operations"""

    NONE = "none"  # No stealth, fastest
    LOW = "low"  # Basic delays
    MEDIUM = "medium"  # Jitter + timing
    HIGH = "high"  # Maximum stealth
    PARANOID = "paranoid"  # Extreme caution


class EvasionTechnique(Enum):
    """Available evasion techniques"""

    TIMING_JITTER = "timing_jitter"
    QUERY_THROTTLE = "query_throttle"
    NATIVE_TOOLS = "native_tools"
    KERBEROS_ONLY = "kerberos_only"
    LDAP_OVER_GC = "ldap_over_gc"
    BUSINESS_HOURS = "business_hours"
    INDIRECT_SYSCALLS = "indirect_syscalls"
    TOOL_SIGNATURE_EVASION = "tool_signature_evasion"


@dataclass
class EvasionConfig:
    """Evasion configuration"""

    stealth_level: StealthLevel = StealthLevel.MEDIUM

    # Timing
    min_delay: float = 0.5  # Minimum delay between operations (seconds)
    max_delay: float = 3.0  # Maximum delay
    jitter_factor: float = 0.3  # Random variance (0-1)

    # Query limits
    max_queries_per_minute: int = 30
    ldap_page_size: int = 100  # Smaller = stealthier

    # Time restrictions
    only_business_hours: bool = False
    business_start: int = 8  # 8 AM
    business_end: int = 18  # 6 PM

    # Protocol preferences
    prefer_kerberos: bool = True
    use_global_catalog: bool = True  # Port 3268 often less monitored

    # Tool preferences
    use_native_tools: bool = True
    randomize_user_agent: bool = True

    # Specific techniques
    enabled_techniques: list[EvasionTechnique] = field(
        default_factory=lambda: [
            EvasionTechnique.TIMING_JITTER,
            EvasionTechnique.QUERY_THROTTLE,
        ]
    )


@dataclass
class EvasionStats:
    """Statistics for evasion operations"""

    total_operations: int = 0
    total_delay_seconds: float = 0.0
    queries_this_minute: int = 0
    minute_start: datetime = field(default_factory=datetime.utcnow)
    blocked_operations: int = 0
    technique_usage: dict = field(default_factory=dict)


class ADEvasion:
    """
    AD-specific evasion techniques for stealth operations.

    Provides:
    - Timing jitter to avoid detection patterns
    - Query throttling to blend with normal traffic
    - Native tool selection for less suspicious activity
    - Business hours awareness
    - Protocol selection for reduced logging
    """

    # Native Windows tools for various operations
    NATIVE_TOOLS = {
        "user_enum": ["net user /domain", "dsquery user", "wmic useraccount list"],
        "group_enum": ["net group /domain", "dsquery group", "wmic group list"],
        "computer_enum": ["net view /domain", "dsquery computer", "nltest /dclist:"],
        "trust_enum": ["nltest /domain_trusts", "netdom trust"],
        "dc_enum": ["nltest /dsgetdc:", "nslookup -type=srv _ldap._tcp.dc._msdcs."],
        "spn_enum": ["setspn -Q */*"],
        "gpo_enum": ["gpresult /r"],
    }

    # Sensitive group names to avoid querying directly
    SENSITIVE_GROUPS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
    ]

    def __init__(self, config: Optional[EvasionConfig] = None):
        self.config = config or EvasionConfig()
        self.stats = EvasionStats()
        self._query_timestamps: list[datetime] = []

    # -------------------------------------------------------------------------
    # Timing Controls
    # -------------------------------------------------------------------------

    async def delay(self, operation: str = "generic") -> float:
        """
        Apply stealth delay with jitter.

        Args:
            operation: Type of operation (for logging)

        Returns:
            Actual delay applied
        """
        if self.config.stealth_level == StealthLevel.NONE:
            return 0.0

        # Calculate delay with jitter
        base_delay = random.uniform(self.config.min_delay, self.config.max_delay)

        if EvasionTechnique.TIMING_JITTER in self.config.enabled_techniques:
            jitter = base_delay * self.config.jitter_factor * random.uniform(-1, 1)
            delay = max(0, base_delay + jitter)
        else:
            delay = base_delay

        # Adjust based on stealth level
        multiplier = {
            StealthLevel.LOW: 0.5,
            StealthLevel.MEDIUM: 1.0,
            StealthLevel.HIGH: 2.0,
            StealthLevel.PARANOID: 4.0,
        }.get(self.config.stealth_level, 1.0)

        delay *= multiplier

        await asyncio.sleep(delay)

        self.stats.total_delay_seconds += delay
        self.stats.total_operations += 1

        logger.debug(f"Stealth delay: {delay:.2f}s for {operation}")
        return delay

    async def throttle_query(self) -> bool:
        """
        Check if query should be throttled.

        Returns:
            True if query can proceed, False if throttled
        """
        if EvasionTechnique.QUERY_THROTTLE not in self.config.enabled_techniques:
            return True

        now = datetime.utcnow()

        # Reset counter if minute has passed
        if (now - self.stats.minute_start).total_seconds() >= 60:
            self.stats.minute_start = now
            self.stats.queries_this_minute = 0

        # Check if over limit
        if self.stats.queries_this_minute >= self.config.max_queries_per_minute:
            wait_time = 60 - (now - self.stats.minute_start).total_seconds()
            if wait_time > 0:
                logger.info(f"Query throttle: waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
                self.stats.minute_start = datetime.utcnow()
                self.stats.queries_this_minute = 0

        self.stats.queries_this_minute += 1
        return True

    def is_business_hours(self) -> bool:
        """Check if current time is within business hours"""
        if not self.config.only_business_hours:
            return True

        now = datetime.now()
        hour = now.hour
        weekday = now.weekday()

        # Monday=0 to Friday=4
        if weekday > 4:
            return False

        return self.config.business_start <= hour < self.config.business_end

    async def wait_for_business_hours(self) -> None:
        """Wait until business hours if required"""
        if not self.config.only_business_hours:
            return

        while not self.is_business_hours():
            logger.info("Outside business hours, waiting...")
            await asyncio.sleep(300)  # Check every 5 minutes

    # -------------------------------------------------------------------------
    # Native Tool Recommendations
    # -------------------------------------------------------------------------

    def get_native_command(self, operation: str) -> Optional[str]:
        """
        Get native Windows command for operation.

        Using native tools is less suspicious than third-party tools.

        Args:
            operation: Type of operation

        Returns:
            Native command or None
        """
        if not self.config.use_native_tools:
            return None

        commands = self.NATIVE_TOOLS.get(operation, [])
        if commands:
            return random.choice(commands)

        return None

    def should_use_native_tool(self, tool_name: str) -> tuple[bool, Optional[str]]:
        """
        Determine if native tool should be used instead.

        Args:
            tool_name: Proposed tool name

        Returns:
            (should_use_native, native_alternative)
        """
        if self.config.stealth_level in (StealthLevel.HIGH, StealthLevel.PARANOID):
            # Map common tools to native alternatives
            alternatives = {
                "ldapsearch": ("dsquery", "ADSI"),
                "GetUserSPNs.py": ("setspn -Q */*", "PowerShell"),
                "GetNPUsers.py": ("Rubeus asreproast", "PowerShell"),
                "bloodhound-python": ("SharpHound.exe", "manual LDAP"),
                "crackmapexec": ("net use", "wmic"),
                "psexec.py": ("PsExec.exe", "sc.exe"),
            }

            if tool_name in alternatives:
                return True, alternatives[tool_name][0]

        return False, None

    # -------------------------------------------------------------------------
    # Protocol Selection
    # -------------------------------------------------------------------------

    def get_preferred_ldap_port(self) -> int:
        """
        Get preferred LDAP port for stealth.

        Global Catalog (3268) is often less monitored than LDAP (389).

        Returns:
            LDAP port number
        """
        if self.config.use_global_catalog:
            return 3268  # Global Catalog
        return 389  # Standard LDAP

    def get_preferred_auth_method(self) -> str:
        """
        Get preferred authentication method.

        Kerberos is generally less suspicious than NTLM.

        Returns:
            "kerberos" or "ntlm"
        """
        if self.config.prefer_kerberos:
            return "kerberos"
        return "ntlm"

    # -------------------------------------------------------------------------
    # Query Obfuscation
    # -------------------------------------------------------------------------

    def obfuscate_ldap_filter(self, ldap_filter: str) -> str:
        """
        Obfuscate LDAP filter to avoid detection.

        Techniques:
        - Add whitespace
        - Use alternative attributes
        - Split into multiple queries

        Args:
            ldap_filter: Original LDAP filter

        Returns:
            Obfuscated filter
        """
        if self.config.stealth_level == StealthLevel.NONE:
            return ldap_filter

        # Add random whitespace (LDAP allows this)
        obfuscated = ldap_filter.replace(")(", ") (")

        # Could add more obfuscation techniques here
        return obfuscated

    def should_avoid_query(self, query_target: str) -> bool:
        """
        Check if query target should be avoided.

        Args:
            query_target: Target of the query (e.g., group name)

        Returns:
            True if query should be avoided
        """
        if self.config.stealth_level in (StealthLevel.HIGH, StealthLevel.PARANOID):
            # Avoid direct queries to sensitive groups
            for sensitive in self.SENSITIVE_GROUPS:
                if sensitive.lower() in query_target.lower():
                    logger.warning(f"Avoiding direct query to sensitive target: {query_target}")
                    return True

        return False

    def split_query_batch(self, items: list, batch_size: Optional[int] = None) -> list[list]:
        """
        Split query items into batches for stealth.

        Smaller batches are less suspicious.

        Args:
            items: Items to query
            batch_size: Override batch size

        Returns:
            List of batches
        """
        size = batch_size or self.config.ldap_page_size

        # Reduce size for higher stealth
        if self.config.stealth_level == StealthLevel.HIGH:
            size = max(10, size // 2)
        elif self.config.stealth_level == StealthLevel.PARANOID:
            size = max(5, size // 4)

        return [items[i : i + size] for i in range(0, len(items), size)]

    # -------------------------------------------------------------------------
    # Tool Signature Evasion
    # -------------------------------------------------------------------------

    def get_random_user_agent(self) -> str:
        """Get random user agent for HTTP requests"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36",
            "Microsoft-CryptoAPI/10.0",
            "Microsoft NCSI",
        ]
        return random.choice(user_agents)

    def randomize_tool_markers(self, command: str) -> str:
        """
        Randomize known tool markers in commands.

        Some tools have detectable signatures that can be randomized.

        Args:
            command: Original command

        Returns:
            Command with randomized markers
        """
        # This is a placeholder - actual implementation would
        # modify tool-specific signatures
        return command

    # -------------------------------------------------------------------------
    # Wrapper Functions
    # -------------------------------------------------------------------------

    async def stealth_execute(
        self, func: Callable, *args, operation_name: str = "generic", **kwargs
    ) -> Any:
        """
        Execute function with stealth measures.

        Args:
            func: Function to execute
            *args: Function arguments
            operation_name: Name for logging
            **kwargs: Function keyword arguments

        Returns:
            Function result
        """
        # Wait for business hours if required
        await self.wait_for_business_hours()

        # Apply throttling
        await self.throttle_query()

        # Apply delay
        await self.delay(operation_name)

        # Execute function
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)

    def get_stats(self) -> dict:
        """Get evasion statistics"""
        return {
            "total_operations": self.stats.total_operations,
            "total_delay_seconds": round(self.stats.total_delay_seconds, 2),
            "queries_this_minute": self.stats.queries_this_minute,
            "blocked_operations": self.stats.blocked_operations,
            "stealth_level": self.config.stealth_level.value,
        }


# Pre-configured evasion profiles
STEALTH_PROFILES = {
    "fast": EvasionConfig(
        stealth_level=StealthLevel.NONE,
        min_delay=0,
        max_delay=0,
    ),
    "balanced": EvasionConfig(
        stealth_level=StealthLevel.MEDIUM,
        min_delay=0.5,
        max_delay=2.0,
        max_queries_per_minute=30,
    ),
    "stealth": EvasionConfig(
        stealth_level=StealthLevel.HIGH,
        min_delay=2.0,
        max_delay=5.0,
        max_queries_per_minute=10,
        use_native_tools=True,
        prefer_kerberos=True,
    ),
    "paranoid": EvasionConfig(
        stealth_level=StealthLevel.PARANOID,
        min_delay=5.0,
        max_delay=15.0,
        max_queries_per_minute=5,
        only_business_hours=True,
        use_native_tools=True,
        prefer_kerberos=True,
        use_global_catalog=True,
        ldap_page_size=25,
    ),
}


def get_evasion_profile(name: str) -> EvasionConfig:
    """Get pre-configured evasion profile by name"""
    return STEALTH_PROFILES.get(name, STEALTH_PROFILES["balanced"])


# Convenience function
def create_stealth_wrapper(stealth_level: str = "balanced") -> ADEvasion:
    """
    Create stealth wrapper with specified level.

    Args:
        stealth_level: One of "fast", "balanced", "stealth", "paranoid"

    Returns:
        Configured ADEvasion instance
    """
    config = get_evasion_profile(stealth_level)
    return ADEvasion(config)
