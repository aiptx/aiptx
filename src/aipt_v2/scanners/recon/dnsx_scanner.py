"""
AIPTX DNSX Scanner
==================

Scanner for dnsx - fast DNS toolkit.
https://github.com/projectdiscovery/dnsx
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class DnsxConfig:
    """Configuration for dnsx scanner."""

    # Query types
    query_a: bool = True
    query_aaaa: bool = True
    query_cname: bool = True
    query_mx: bool = True
    query_ns: bool = True
    query_txt: bool = True
    query_soa: bool = False
    query_ptr: bool = False
    query_axfr: bool = False  # Zone transfer (noisy)

    # Output options
    json_output: bool = True
    response_only: bool = False

    # Rate limiting
    threads: int = 100
    rate_limit: int = -1  # Unlimited
    retries: int = 2
    timeout: int = 5

    # Resolvers
    resolver_file: Optional[str] = None
    system_resolvers: bool = True

    # Filtering
    wildcard_filter: bool = True


class DnsxScanner(BaseScanner):
    """
    Scanner for dnsx - DNS toolkit.

    Performs:
    - DNS resolution (A, AAAA, CNAME, MX, NS, TXT, etc.)
    - Wildcard detection
    - Zone transfer attempts
    - DNS misconfiguration detection

    Example:
        scanner = DnsxScanner()
        result = await scanner.scan("example.com")

        for finding in result.findings:
            print(f"{finding.host}: {finding.description}")
    """

    def __init__(self, config: Optional[DnsxConfig] = None):
        self.config = config or DnsxConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if dnsx is installed."""
        return shutil.which("dnsx") is not None

    async def scan(
        self,
        target: str,
        targets_file: Optional[str] = None,
        wordlist: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run dnsx scan.

        Args:
            target: Domain to scan
            targets_file: Optional file with subdomains
            wordlist: Optional wordlist for brute-forcing
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="dnsx", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        try:
            cmd = self._build_command(target, targets_file, wordlist)
            logger.debug(f"Running: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = process

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=kwargs.get("timeout", 300)
            )

            result.raw_output = stdout.decode("utf-8", errors="replace")
            result.findings = self.parse_output(result.raw_output)
            result.status = "completed"

        except asyncio.TimeoutError:
            result.status = "failed"
            result.errors.append("Scan timed out")
        except Exception as e:
            result.status = "failed"
            result.errors.append(str(e))
            logger.error(f"dnsx scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(
        self,
        target: str,
        targets_file: Optional[str] = None,
        wordlist: Optional[str] = None
    ) -> List[str]:
        """Build dnsx command."""
        cmd = ["dnsx"]

        # Input
        if targets_file:
            cmd.extend(["-l", targets_file])
        elif wordlist:
            cmd.extend(["-d", target, "-w", wordlist])
        else:
            cmd.extend(["-d", target])

        # Query types
        if self.config.query_a:
            cmd.append("-a")
        if self.config.query_aaaa:
            cmd.append("-aaaa")
        if self.config.query_cname:
            cmd.append("-cname")
        if self.config.query_mx:
            cmd.append("-mx")
        if self.config.query_ns:
            cmd.append("-ns")
        if self.config.query_txt:
            cmd.append("-txt")
        if self.config.query_soa:
            cmd.append("-soa")
        if self.config.query_ptr:
            cmd.append("-ptr")
        if self.config.query_axfr:
            cmd.append("-axfr")

        # Output
        if self.config.json_output:
            cmd.append("-json")
        if self.config.response_only:
            cmd.append("-resp-only")

        # Rate limiting
        cmd.extend(["-t", str(self.config.threads)])
        if self.config.rate_limit > 0:
            cmd.extend(["-rl", str(self.config.rate_limit)])
        cmd.extend(["-retry", str(self.config.retries)])

        # Resolvers
        if self.config.resolver_file:
            cmd.extend(["-r", self.config.resolver_file])

        # Filtering
        if self.config.wildcard_filter:
            cmd.append("-wd")

        cmd.append("-silent")

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse dnsx output."""
        findings = []

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                if self.config.json_output:
                    data = json.loads(line)
                    finding = self._json_to_finding(data)
                else:
                    finding = self._text_to_finding(line)

                if finding:
                    findings.append(finding)

            except json.JSONDecodeError:
                # Try text parsing as fallback
                finding = self._text_to_finding(line)
                if finding:
                    findings.append(finding)

        return findings

    def _json_to_finding(self, data: Dict[str, Any]) -> Optional[ScanFinding]:
        """Convert JSON to ScanFinding."""
        host = data.get("host", "")
        if not host:
            return None

        # Build description from DNS records
        description_parts = []
        severity = ScanSeverity.INFO
        tags = []

        # A records
        if "a" in data:
            a_records = data["a"]
            if a_records:
                description_parts.append(f"A: {', '.join(a_records[:3])}")
                tags.append("A")

        # AAAA records
        if "aaaa" in data:
            aaaa_records = data["aaaa"]
            if aaaa_records:
                description_parts.append(f"AAAA: {', '.join(aaaa_records[:2])}")
                tags.append("AAAA")

        # CNAME records
        if "cname" in data:
            cname_records = data["cname"]
            if cname_records:
                description_parts.append(f"CNAME: {', '.join(cname_records[:2])}")
                tags.append("CNAME")

        # MX records
        if "mx" in data:
            mx_records = data["mx"]
            if mx_records:
                description_parts.append(f"MX: {', '.join(mx_records[:2])}")
                tags.append("MX")

        # TXT records - might contain SPF, DKIM, etc.
        if "txt" in data:
            txt_records = data["txt"]
            if txt_records:
                description_parts.append(f"TXT: {len(txt_records)} records")
                tags.append("TXT")

                # Check for security-related TXT records
                for txt in txt_records:
                    if "v=spf1" in txt.lower():
                        tags.append("SPF")
                    if "v=dkim1" in txt.lower():
                        tags.append("DKIM")
                    if "_dmarc" in host.lower():
                        tags.append("DMARC")

        # Zone transfer
        if data.get("axfr"):
            severity = ScanSeverity.HIGH
            description_parts.append("ZONE TRANSFER POSSIBLE")
            tags.append("AXFR")

        return ScanFinding(
            title=f"DNS: {host}",
            severity=severity,
            description="; ".join(description_parts) if description_parts else "DNS record found",
            host=host,
            evidence=json.dumps(data, indent=2)[:500],
            scanner="dnsx",
            tags=tags,
        )

    def _text_to_finding(self, line: str) -> Optional[ScanFinding]:
        """Parse text line to finding."""
        parts = line.strip().split()
        if not parts:
            return None

        host = parts[0]
        record_type = parts[1] if len(parts) > 1 else "A"
        value = " ".join(parts[2:]) if len(parts) > 2 else ""

        return ScanFinding(
            title=f"DNS: {host}",
            severity=ScanSeverity.INFO,
            description=f"{record_type}: {value}" if value else record_type,
            host=host,
            scanner="dnsx",
            tags=[record_type],
        )

    async def stop(self) -> bool:
        """Stop running scan."""
        if self._process and self._running:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
            self._running = False
            return True
        return False
