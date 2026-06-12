"""
AIPTX Enterprise API Runner - Execute via enterprise scanner APIs

This runner integrates with enterprise-grade security scanners
via their REST APIs:
- Acunetix
- Burp Suite Enterprise
- Nessus
- OWASP ZAP

Each scanner has its own workflow (start scan, poll status, get results).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import aiohttp

from .base import BaseRunner, RunnerConfig, RunnerResult, RunnerStatus

logger = logging.getLogger(__name__)


class ScannerType(Enum):
    """Supported enterprise scanners"""

    ACUNETIX = "acunetix"
    BURP = "burp"
    NESSUS = "nessus"
    ZAP = "zap"


class EnterpriseAPIRunner(BaseRunner):
    """
    Execute scans via enterprise scanner APIs.

    This runner wraps enterprise scanner REST APIs and provides
    a unified interface for starting scans, polling status, and
    retrieving results.
    """

    def __init__(
        self,
        scanner_type: ScannerType,
        api_url: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        config: Optional[RunnerConfig] = None,
    ):
        super().__init__(config)
        self.runner_type = "api_enterprise"
        self.scanner_type = scanner_type
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.username = username
        self.password = password

        # Session for API calls
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            headers = {}
            if self.api_key:
                # Different scanners use different header formats
                if self.scanner_type == ScannerType.ACUNETIX:
                    headers["X-Auth"] = self.api_key
                elif self.scanner_type == ScannerType.NESSUS:
                    headers["X-ApiKeys"] = f"accessKey={self.api_key}"
                else:
                    headers["Authorization"] = f"Bearer {self.api_key}"

            self._session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    async def close(self):
        """Close HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()

    async def execute(
        self,
        tool: str,
        args: list[str],
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """
        Execute scan via enterprise API.

        For enterprise scanners, 'tool' is the scan type/profile,
        and 'args' typically contains the target URL.

        Args:
            tool: Scan type/profile name
            args: Target URL(s) and options
            timeout: Max time to wait for scan completion
            **kwargs: Additional options:
                - target: Target URL (if not in args)
                - scan_profile: Specific scan profile to use
                - poll_interval: Seconds between status checks

        Returns:
            RunnerResult with findings from the scan
        """
        target = kwargs.get("target") or (args[0] if args else None)
        if not target:
            return self._create_result(
                tool=tool,
                status=RunnerStatus.FAILED,
                error_message="No target URL provided",
            )

        effective_timeout = timeout or self.config.default_timeout
        poll_interval = kwargs.get("poll_interval", 30)
        started_at = datetime.utcnow()

        try:
            # Start the scan
            scan_id = await self._start_scan(target, tool, kwargs)
            if not scan_id:
                return self._create_result(
                    tool=tool,
                    status=RunnerStatus.FAILED,
                    error_message="Failed to start scan",
                )

            logger.info(f"Started {self.scanner_type.value} scan {scan_id} for {target}")

            # Poll for completion
            deadline = datetime.utcnow().timestamp() + effective_timeout
            scan_status = None

            while datetime.utcnow().timestamp() < deadline:
                scan_status = await self._get_scan_status(scan_id)

                if scan_status == "completed":
                    break
                elif scan_status in ["failed", "aborted", "error"]:
                    return self._create_result(
                        tool=tool,
                        status=RunnerStatus.FAILED,
                        error_message=f"Scan {scan_status}",
                        metadata={"scan_id": scan_id},
                    )

                await asyncio.sleep(poll_interval)

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            if scan_status != "completed":
                return self._create_result(
                    tool=tool,
                    status=RunnerStatus.TIMEOUT,
                    error_message=f"Scan did not complete within {effective_timeout}s",
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    metadata={"scan_id": scan_id},
                )

            # Get results
            findings = await self._get_scan_results(scan_id)

            return self._create_result(
                tool=tool,
                status=RunnerStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                findings=findings,
                findings_count=len(findings),
                metadata={
                    "scan_id": scan_id,
                    "scanner_type": self.scanner_type.value,
                    "target": target,
                },
            )

        except Exception as e:
            logger.exception(f"Error during {self.scanner_type.value} scan")
            return self._create_result(
                tool=tool,
                status=RunnerStatus.FAILED,
                error_message=str(e),
            )

    async def _start_scan(
        self,
        target: str,
        profile: str,
        options: dict[str, Any],
    ) -> Optional[str]:
        """Start a scan and return scan ID"""
        session = await self._get_session()

        if self.scanner_type == ScannerType.ACUNETIX:
            return await self._acunetix_start_scan(session, target, profile)
        elif self.scanner_type == ScannerType.BURP:
            return await self._burp_start_scan(session, target, profile)
        elif self.scanner_type == ScannerType.NESSUS:
            return await self._nessus_start_scan(session, target, profile)
        elif self.scanner_type == ScannerType.ZAP:
            return await self._zap_start_scan(session, target, profile)

        return None

    async def _get_scan_status(self, scan_id: str) -> str:
        """Get current scan status"""
        session = await self._get_session()

        if self.scanner_type == ScannerType.ACUNETIX:
            return await self._acunetix_get_status(session, scan_id)
        elif self.scanner_type == ScannerType.BURP:
            return await self._burp_get_status(session, scan_id)
        elif self.scanner_type == ScannerType.NESSUS:
            return await self._nessus_get_status(session, scan_id)
        elif self.scanner_type == ScannerType.ZAP:
            return await self._zap_get_status(session, scan_id)

        return "unknown"

    async def _get_scan_results(self, scan_id: str) -> list[dict[str, Any]]:
        """Get scan findings"""
        session = await self._get_session()

        if self.scanner_type == ScannerType.ACUNETIX:
            return await self._acunetix_get_results(session, scan_id)
        elif self.scanner_type == ScannerType.BURP:
            return await self._burp_get_results(session, scan_id)
        elif self.scanner_type == ScannerType.NESSUS:
            return await self._nessus_get_results(session, scan_id)
        elif self.scanner_type == ScannerType.ZAP:
            return await self._zap_get_results(session, scan_id)

        return []

    # Acunetix implementations
    async def _acunetix_start_scan(
        self,
        session: aiohttp.ClientSession,
        target: str,
        profile: str,
    ) -> Optional[str]:
        """Start Acunetix scan"""
        try:
            # First add target
            async with session.post(
                f"{self.api_url}/api/v1/targets",
                json={"address": target, "description": f"AIPTX scan of {target}"},
                ssl=False,
            ) as resp:
                if resp.status != 201:
                    return None
                target_data = await resp.json()
                target_id = target_data.get("target_id")

            # Start scan
            async with session.post(
                f"{self.api_url}/api/v1/scans",
                json={
                    "target_id": target_id,
                    "profile_id": profile or "11111111-1111-1111-1111-111111111111",  # Full scan
                },
                ssl=False,
            ) as resp:
                if resp.status == 201:
                    scan_data = await resp.json()
                    return scan_data.get("scan_id")

        except Exception as e:
            logger.error(f"Acunetix start scan error: {e}")

        return None

    async def _acunetix_get_status(
        self,
        session: aiohttp.ClientSession,
        scan_id: str,
    ) -> str:
        """Get Acunetix scan status"""
        try:
            async with session.get(
                f"{self.api_url}/api/v1/scans/{scan_id}",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    current_session = data.get("current_session", {})
                    status = current_session.get("status", "unknown")
                    return status
        except Exception as e:
            logger.error(f"Acunetix get status error: {e}")

        return "unknown"

    async def _acunetix_get_results(
        self,
        session: aiohttp.ClientSession,
        scan_id: str,
    ) -> list[dict[str, Any]]:
        """Get Acunetix scan results"""
        findings = []
        try:
            async with session.get(
                f"{self.api_url}/api/v1/scans/{scan_id}/results",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for vuln in data.get("vulnerabilities", []):
                        findings.append(
                            {
                                "source": "acunetix",
                                "vuln_id": vuln.get("vuln_id"),
                                "severity": vuln.get("severity"),
                                "name": vuln.get("vt_name"),
                                "url": vuln.get("affects_url"),
                                "description": vuln.get("description"),
                            }
                        )
        except Exception as e:
            logger.error(f"Acunetix get results error: {e}")

        return findings

    # Burp implementations (placeholder)
    async def _burp_start_scan(self, session, target, profile):
        logger.warning("Burp Enterprise integration not fully implemented")
        return None

    async def _burp_get_status(self, session, scan_id):
        return "unknown"

    async def _burp_get_results(self, session, scan_id):
        return []

    # Nessus implementations (placeholder)
    async def _nessus_start_scan(self, session, target, profile):
        logger.warning("Nessus integration not fully implemented")
        return None

    async def _nessus_get_status(self, session, scan_id):
        return "unknown"

    async def _nessus_get_results(self, session, scan_id):
        return []

    # ZAP implementations (placeholder)
    async def _zap_start_scan(self, session, target, profile):
        logger.warning("ZAP integration not fully implemented")
        return None

    async def _zap_get_status(self, session, scan_id):
        return "unknown"

    async def _zap_get_results(self, session, scan_id):
        return []

    async def get_status(self) -> dict[str, Any]:
        """Get enterprise API runner status"""
        session = await self._get_session()
        healthy = False

        try:
            # Test API connectivity
            if self.scanner_type == ScannerType.ACUNETIX:
                async with session.get(
                    f"{self.api_url}/api/v1/me",
                    ssl=False,
                ) as resp:
                    healthy = resp.status == 200
        except Exception:
            pass

        return {
            "healthy": healthy,
            "runner_type": self.runner_type,
            "scanner_type": self.scanner_type.value,
            "api_url": self.api_url,
        }

    async def check_tool_available(self, tool: str) -> bool:
        """Check if scanner is available"""
        status = await self.get_status()
        return status.get("healthy", False)

    async def __aenter__(self):
        await self._get_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
