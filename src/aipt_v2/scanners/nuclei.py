"""
AIPT Nuclei Scanner Integration

Template-based vulnerability scanning using Nuclei.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncIterator, Optional

from .base import BaseScanner, ScanFinding, ScanResult, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class NucleiConfig:
    """Nuclei scanner configuration"""
    # Template selection
    templates: list[str] = field(default_factory=list)  # Specific templates
    tags: list[str] = field(default_factory=list)  # Filter by tags
    severity: list[str] = field(default_factory=lambda: ["critical", "high", "medium"])
    exclude_tags: list[str] = field(default_factory=lambda: ["dos", "fuzz"])

    # Scanning options
    rate_limit: int = 150  # Requests per second
    bulk_size: int = 25
    concurrency: int = 25
    timeout: int = 10  # Per-request timeout

    # Output
    json_output: bool = True
    silent: bool = True
    no_color: bool = True

    # Advanced
    new_templates: bool = False  # Only new templates
    automatic_scan: bool = False  # Auto-detect tech stack
    headless: bool = False  # Browser-based templates


class NucleiScanner(BaseScanner):
    """
    Nuclei vulnerability scanner integration.

    Nuclei is a fast, template-based scanner that checks for:
    - CVEs
    - Misconfigurations
    - Exposed panels
    - Default credentials
    - Known vulnerabilities

    Example:
        scanner = NucleiScanner(NucleiConfig(
            severity=["critical", "high"],
            tags=["cve", "exposure"],
        ))
        result = await scanner.scan("https://target.com")

        for finding in result.get_critical_and_high():
            print(f"{finding.severity}: {finding.title}")
    """

    def __init__(self, config: Optional[NucleiConfig] = None):
        super().__init__()
        self.config = config or NucleiConfig()

    def is_available(self) -> bool:
        """Check if Nuclei is installed"""
        return self._check_tool("nuclei")

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Nuclei scan on target.

        Args:
            target: URL or host to scan
            **kwargs: Override config options

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner="nuclei", target=target)
        result.start_time = datetime.utcnow()
        result.status = "running"

        if not self.is_available():
            result.status = "failed"
            result.errors.append("Nuclei is not installed")
            return result

        # Build command
        command = self._build_command(target, **kwargs)
        logger.info(f"Running Nuclei: {' '.join(command)}")

        # Execute
        exit_code, stdout, stderr = await self._run_command(
            command,
            timeout=kwargs.get("timeout", 600.0),
        )

        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()
        result.raw_output = stdout

        if exit_code != 0 and "no results found" not in stderr.lower():
            result.status = "failed"
            result.errors.append(stderr)
        else:
            result.status = "completed"

        # Parse output
        result.findings = self.parse_output(stdout)

        logger.info(
            f"Nuclei scan complete: {len(result.findings)} findings in {result.duration_seconds:.1f}s"
        )

        return result

    async def stream_scan(self, target: str, **kwargs) -> AsyncIterator[str]:
        """Stream Nuclei output as it runs"""
        if not self.is_available():
            yield "[ERROR] Nuclei is not installed"
            return

        # Build command with streaming-friendly options
        config = NucleiConfig(**{**self.config.__dict__, **kwargs})
        config.silent = False

        command = self._build_command(target, config=config)

        async for line in self._stream_command(command, timeout=kwargs.get("timeout", 600.0)):
            yield line

    def parse_output(self, output: str) -> list[ScanFinding]:
        """Parse Nuclei JSON output"""
        findings = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                data = json.loads(line)

                severity_map = {
                    "info": ScanSeverity.INFO,
                    "low": ScanSeverity.LOW,
                    "medium": ScanSeverity.MEDIUM,
                    "high": ScanSeverity.HIGH,
                    "critical": ScanSeverity.CRITICAL,
                }

                info = data.get("info", {})
                severity_str = info.get("severity", "info").lower()

                finding = ScanFinding(
                    title=info.get("name", "Unknown"),
                    severity=severity_map.get(severity_str, ScanSeverity.INFO),
                    description=info.get("description", ""),
                    url=data.get("matched-at", data.get("host", "")),
                    host=data.get("host", ""),
                    template=data.get("template-id", ""),
                    tags=info.get("tags", []),
                    scanner="nuclei",
                )

                # Extract CVE/CWE if present
                classification = info.get("classification", {})
                if classification.get("cve-id"):
                    cves = classification["cve-id"]
                    finding.cve = cves[0] if isinstance(cves, list) else cves
                if classification.get("cwe-id"):
                    cwes = classification["cwe-id"]
                    finding.cwe = cwes[0] if isinstance(cwes, list) else cwes
                if classification.get("cvss-score"):
                    finding.cvss = float(classification["cvss-score"])

                # Extract evidence
                if data.get("extracted-results"):
                    finding.evidence = "\n".join(data["extracted-results"])
                elif data.get("matcher-name"):
                    finding.evidence = f"Matched: {data['matcher-name']}"

                # Request/response if available
                if data.get("request"):
                    finding.request = data["request"][:2000]
                if data.get("response"):
                    finding.response = data["response"][:2000]

                findings.append(finding)

            except json.JSONDecodeError:
                # Non-JSON output line, skip
                continue
            except Exception as e:
                logger.debug(f"Error parsing Nuclei output line: {e}")

        return findings

    def _build_command(self, target: str, config: Optional[NucleiConfig] = None, **kwargs) -> list[str]:
        """Build Nuclei command"""
        cfg = config or self.config

        command = ["nuclei", "-u", target]

        # Template selection
        if cfg.templates:
            for template in cfg.templates:
                command.extend(["-t", template])

        if cfg.tags:
            command.extend(["-tags", ",".join(cfg.tags)])

        if cfg.severity:
            command.extend(["-severity", ",".join(cfg.severity)])

        if cfg.exclude_tags:
            command.extend(["-exclude-tags", ",".join(cfg.exclude_tags)])

        # Rate limiting
        command.extend(["-rate-limit", str(cfg.rate_limit)])
        command.extend(["-bulk-size", str(cfg.bulk_size)])
        command.extend(["-concurrency", str(cfg.concurrency)])
        command.extend(["-timeout", str(cfg.timeout)])

        # Output format
        if cfg.json_output:
            command.append("-json")

        if cfg.silent:
            command.append("-silent")

        if cfg.no_color:
            command.append("-no-color")

        # Advanced options
        if cfg.new_templates:
            command.append("-new-templates")

        if cfg.automatic_scan:
            command.append("-automatic-scan")

        if cfg.headless:
            command.append("-headless")

        return command


# Convenience functions
async def quick_nuclei_scan(target: str, severity: list[str] = None) -> ScanResult:
    """Quick Nuclei scan with defaults"""
    config = NucleiConfig(
        severity=severity or ["critical", "high"],
        rate_limit=100,
    )
    scanner = NucleiScanner(config)
    return await scanner.scan(target)


async def full_nuclei_scan(target: str) -> ScanResult:
    """Comprehensive Nuclei scan"""
    config = NucleiConfig(
        severity=["info", "low", "medium", "high", "critical"],
        automatic_scan=True,
        rate_limit=50,  # Slower but more thorough
    )
    scanner = NucleiScanner(config)
    return await scanner.scan(target, timeout=1800.0)  # 30 minute timeout
