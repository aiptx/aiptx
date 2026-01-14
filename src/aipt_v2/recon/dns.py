"""
AIPT DNS Analyzer

DNS enumeration and analysis.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# dns.resolver import with fallback
try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed. Install with: pip install dnspython")


@dataclass
class DNSRecord:
    """DNS record"""
    record_type: str  # A, AAAA, MX, NS, TXT, CNAME, etc.
    name: str
    value: str
    ttl: int = 0
    priority: int = 0  # For MX records

    def to_dict(self) -> dict:
        return {
            "type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
            "priority": self.priority,
        }


@dataclass
class DNSResult:
    """DNS analysis results"""
    domain: str
    records: list[DNSRecord] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    mail_servers: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)

    # Security analysis
    has_spf: bool = False
    has_dmarc: bool = False
    has_dkim: bool = False
    zone_transfer_possible: bool = False

    # Additional info
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""

    analyzed_at: datetime = field(default_factory=datetime.utcnow)

    def get_records_by_type(self, record_type: str) -> list[DNSRecord]:
        """Get records of a specific type"""
        return [r for r in self.records if r.record_type == record_type]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "nameservers": self.nameservers,
            "mail_servers": self.mail_servers,
            "ip_addresses": self.ip_addresses,
            "records_count": len(self.records),
            "security": {
                "has_spf": self.has_spf,
                "has_dmarc": self.has_dmarc,
                "has_dkim": self.has_dkim,
                "zone_transfer_possible": self.zone_transfer_possible,
            },
        }


class DNSAnalyzer:
    """
    DNS enumeration and analysis.

    Features:
    - Record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
    - Security configuration check (SPF, DMARC, DKIM)
    - Zone transfer attempt
    - Mail server discovery

    Example:
        analyzer = DNSAnalyzer()
        result = await analyzer.analyze("example.com")

        print(f"Nameservers: {result.nameservers}")
        print(f"Has SPF: {result.has_spf}")
    """

    # Record types to query
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def __init__(self, timeout: float = 5.0, nameserver: str = "8.8.8.8"):
        if not DNS_AVAILABLE:
            raise ImportError("dnspython is required. Install with: pip install dnspython")

        self.timeout = timeout
        self.nameserver = nameserver
        self._resolver = dns.resolver.Resolver()
        self._resolver.nameservers = [nameserver]
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    async def analyze(self, domain: str) -> DNSResult:
        """
        Analyze DNS configuration for a domain.

        Args:
            domain: Target domain

        Returns:
            DNSResult with discovered records
        """
        result = DNSResult(domain=domain)

        # Query all record types
        for record_type in self.RECORD_TYPES:
            records = await self._query_records(domain, record_type)
            result.records.extend(records)

            # Extract specific info
            if record_type == "A":
                result.ip_addresses.extend([r.value for r in records])
            elif record_type == "NS":
                result.nameservers.extend([r.value for r in records])
            elif record_type == "MX":
                result.mail_servers.extend([r.value for r in records])

        # Check security records
        result.has_spf = await self._check_spf(domain)
        result.has_dmarc = await self._check_dmarc(domain)
        result.has_dkim = await self._check_dkim(domain)

        # Attempt zone transfer
        result.zone_transfer_possible = await self._try_zone_transfer(domain, result.nameservers)

        return result

    async def _query_records(self, domain: str, record_type: str) -> list[DNSRecord]:
        """Query DNS records of a specific type"""
        records = []

        try:
            # Run in thread pool for async
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self._resolver.resolve(domain, record_type)
            )

            for rdata in answers:
                record = DNSRecord(
                    record_type=record_type,
                    name=domain,
                    value=str(rdata),
                    ttl=answers.ttl,
                )

                # Extract MX priority
                if record_type == "MX":
                    record.priority = rdata.preference
                    record.value = str(rdata.exchange)

                records.append(record)

        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records for {domain}")
        except dns.resolver.NoNameservers:
            logger.debug(f"No nameservers for {domain}")
        except Exception as e:
            logger.debug(f"DNS query error ({record_type}): {e}")

        return records

    async def _check_spf(self, domain: str) -> bool:
        """Check if SPF record exists"""
        records = await self._query_records(domain, "TXT")
        return any("v=spf1" in r.value.lower() for r in records)

    async def _check_dmarc(self, domain: str) -> bool:
        """Check if DMARC record exists"""
        records = await self._query_records(f"_dmarc.{domain}", "TXT")
        return any("v=dmarc1" in r.value.lower() for r in records)

    async def _check_dkim(self, domain: str, selectors: list[str] = None) -> bool:
        """Check if DKIM record exists"""
        selectors = selectors or ["default", "google", "selector1", "selector2", "s1", "s2"]

        for selector in selectors:
            records = await self._query_records(f"{selector}._domainkey.{domain}", "TXT")
            if records:
                return True

        return False

    async def _try_zone_transfer(self, domain: str, nameservers: list[str]) -> bool:
        """Attempt zone transfer"""
        for ns in nameservers[:3]:  # Try first 3 nameservers
            try:
                ns_ip = socket.gethostbyname(ns.rstrip("."))

                # Run in thread pool
                loop = asyncio.get_event_loop()
                zone = await loop.run_in_executor(
                    None,
                    lambda: dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                )

                if zone:
                    logger.warning(f"Zone transfer successful from {ns}!")
                    return True

            except Exception:
                continue

        return False


async def analyze_dns(domain: str) -> DNSResult:
    """Quick DNS analysis"""
    analyzer = DNSAnalyzer()
    return await analyzer.analyze(domain)
