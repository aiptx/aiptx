"""
AIPT Base Scanner

Abstract base class for all scanner integrations.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger(__name__)


class ScanSeverity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanFinding:
    """Individual scan finding"""
    title: str
    severity: ScanSeverity
    description: str = ""
    url: str = ""
    host: str = ""
    port: int = 0

    # Details
    evidence: str = ""
    request: str = ""
    response: str = ""

    # Classification
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None

    # Scanner metadata
    scanner: str = ""
    template: str = ""
    tags: list[str] = field(default_factory=list)

    # Timestamps
    found_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "evidence": self.evidence[:500] if self.evidence else "",
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "scanner": self.scanner,
            "template": self.template,
            "tags": self.tags,
            "found_at": self.found_at.isoformat(),
        }


@dataclass
class ScanResult:
    """Complete scan result"""
    scanner: str
    target: str
    status: str = "pending"  # pending, running, completed, failed
    findings: list[ScanFinding] = field(default_factory=list)

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Statistics
    requests_made: int = 0
    errors: list[str] = field(default_factory=list)

    # Raw output
    raw_output: str = ""

    def add_finding(self, finding: ScanFinding) -> None:
        """Add a finding"""
        finding.scanner = self.scanner
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: ScanSeverity) -> list[ScanFinding]:
        """Get findings of a specific severity"""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_and_high(self) -> list[ScanFinding]:
        """Get critical and high severity findings"""
        return [
            f for f in self.findings
            if f.severity in [ScanSeverity.CRITICAL, ScanSeverity.HIGH]
        ]

    def severity_counts(self) -> dict[str, int]:
        """Get count by severity"""
        counts = {s.value: 0 for s in ScanSeverity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "target": self.target,
            "status": self.status,
            "findings_count": len(self.findings),
            "severity_counts": self.severity_counts(),
            "duration_seconds": self.duration_seconds,
            "requests_made": self.requests_made,
            "errors": self.errors,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class BaseScanner(ABC):
    """
    Abstract base class for scanner integrations.

    Subclasses must implement:
    - scan(): Perform the scan
    - is_available(): Check if scanner is installed
    - parse_output(): Parse scanner output

    Example:
        class MyScanner(BaseScanner):
            async def scan(self, target):
                result = ScanResult(scanner="my_scanner", target=target)
                # Run scan...
                return result
    """

    def __init__(self):
        self._running = False
        self._process: Optional[asyncio.subprocess.Process] = None

    @abstractmethod
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Perform scan on target"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner is available/installed"""
        pass

    @abstractmethod
    def parse_output(self, output: str) -> list[ScanFinding]:
        """Parse scanner output into findings"""
        pass

    async def stream_scan(self, target: str, **kwargs) -> AsyncIterator[str]:
        """Stream scan output (if supported)"""
        yield "Streaming not implemented for this scanner"

    async def stop(self) -> bool:
        """Stop running scan"""
        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
                return True
            except asyncio.TimeoutError:
                self._process.kill()
                return True
            except Exception:
                return False
        return True

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        return shutil.which(tool_name) is not None

    async def _run_command(
        self,
        command: list[str],
        timeout: float = 300.0,
    ) -> tuple[int, str, str]:
        """
        Run a command and return exit code, stdout, stderr.

        Args:
            command: Command and arguments
            timeout: Timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            self._running = True
            self._process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    self._process.communicate(),
                    timeout=timeout,
                )
                return (
                    self._process.returncode or 0,
                    stdout.decode("utf-8", errors="replace"),
                    stderr.decode("utf-8", errors="replace"),
                )
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
                return -1, "", "Command timed out"

        except FileNotFoundError:
            return -1, "", f"Command not found: {command[0]}"
        except Exception as e:
            return -1, "", str(e)
        finally:
            self._running = False
            self._process = None

    async def _stream_command(
        self,
        command: list[str],
        timeout: float = 300.0,
    ) -> AsyncIterator[str]:
        """Stream command output line by line"""
        try:
            self._running = True
            self._process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            start_time = asyncio.get_event_loop().time()

            async for line in self._process.stdout:
                # Check timeout
                if asyncio.get_event_loop().time() - start_time > timeout:
                    self._process.kill()
                    yield "[TIMEOUT]"
                    break

                yield line.decode("utf-8", errors="replace").rstrip()

            await self._process.wait()

        except Exception as e:
            yield f"[ERROR] {str(e)}"
        finally:
            self._running = False
            self._process = None

    @property
    def is_running(self) -> bool:
        return self._running
