"""
Nessus Vulnerability Scanner Integration for AIPTX

Provides comprehensive vulnerability assessment through Nessus Professional/Expert API.
Supports host-based scanning, compliance checks, and credential scanning.

Environment Variables:
    NESSUS_URL: Nessus server URL (default: https://localhost:8834)
    NESSUS_ACCESS_KEY: API access key
    NESSUS_SECRET_KEY: API secret key

Usage:
    from aipt_v2.tools.scanners.nessus_tool import get_nessus, nessus_scan

    nessus = get_nessus()
    if nessus.connect():
        scan_id = nessus.scan_host("192.168.1.1")
        result = nessus.wait_for_scan(scan_id)
        vulns = nessus.get_vulnerabilities(scan_id)
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


# ==================== Enums ====================

class ScanStatus(Enum):
    """Nessus scan status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELED = "canceled"
    PAUSED = "paused"
    STOPPING = "stopping"
    FAILED = "failed"


class Severity(Enum):
    """Nessus severity levels (CVSS-based)."""
    CRITICAL = 4  # CVSS >= 9.0
    HIGH = 3      # CVSS 7.0-8.9
    MEDIUM = 2    # CVSS 4.0-6.9
    LOW = 1       # CVSS 0.1-3.9
    INFO = 0      # Informational


class ScanTemplate(Enum):
    """Nessus scan templates."""
    BASIC_NETWORK = "basic"
    ADVANCED = "advanced"
    WEB_APP = "webapp"
    MALWARE = "malware"
    COMPLIANCE = "compliance"
    DISCOVERY = "discovery"


# ==================== Data Classes ====================

@dataclass
class NessusConfig:
    """Configuration for Nessus connection."""
    base_url: str = field(default_factory=lambda: os.getenv("AIPT_SCANNERS__NESSUS_URL") or os.getenv("NESSUS_URL", "https://localhost:8834"))
    access_key: str = field(default_factory=lambda: os.getenv("AIPT_SCANNERS__NESSUS_ACCESS_KEY") or os.getenv("NESSUS_ACCESS_KEY", ""))
    secret_key: str = field(default_factory=lambda: os.getenv("AIPT_SCANNERS__NESSUS_SECRET_KEY") or os.getenv("NESSUS_SECRET_KEY", ""))
    verify_ssl: bool = False
    timeout: int = 60  # Increased from 30s for high-latency networks
    max_retries: int = 3


@dataclass
class ScanResult:
    """Result of a Nessus scan."""
    scan_id: str
    status: str
    progress: int = 0
    hosts_total: int = 0
    hosts_completed: int = 0
    vulnerabilities_count: int = 0
    start_time: str = ""
    end_time: str = ""
    error: str = ""


@dataclass
class Vulnerability:
    """Nessus vulnerability finding."""
    vuln_id: str
    plugin_id: str
    plugin_name: str
    severity: int
    severity_name: str
    host: str
    port: int
    protocol: str
    description: str = ""
    solution: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    plugin_output: str = ""


# ==================== Main Tool Class ====================

class NessusTool:
    """
    Nessus Vulnerability Scanner integration.

    Provides methods for:
    - Host/network vulnerability scanning
    - Compliance scanning
    - Credential-based scanning
    - Vulnerability retrieval and export
    """

    def __init__(self, config: Optional[NessusConfig] = None):
        """Initialize Nessus tool with configuration."""
        self.config = config or NessusConfig()
        self._session = requests.Session()
        self._connected = False
        self._headers = {
            "X-ApiKeys": f"accessKey={self.config.access_key}; secretKey={self.config.secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "close",  # Avoid stale connection pooling issues
        }
        self._session.headers.update(self._headers)

        # Configure connection retry adapter for resilience
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "DELETE", "PATCH"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=1, pool_connections=1)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def _request(self, method: str, endpoint: str, data: dict = None, retries: int = None, silent: bool = False) -> dict:
        """Make authenticated request to Nessus API with retry logic.

        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request data
            retries: Number of retries (default: config.max_retries)
            silent: If True, suppress warning logs during retries (for polling)
        """
        url = f"{self.config.base_url}{endpoint}"
        retries = retries if retries is not None else self.config.max_retries
        last_error = None

        for attempt in range(retries):
            try:
                response = self._session.request(
                    method=method,
                    url=url,
                    json=data,
                    verify=self.config.verify_ssl,
                    timeout=self.config.timeout
                )
                response.raise_for_status()
                return response.json() if response.text else {}
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as e:
                last_error = e
                wait_time = min((2 ** attempt) * 2, 30)  # Cap at 30 seconds
                if not silent and attempt < retries - 1:
                    logger.debug(f"Nessus connection issue (attempt {attempt + 1}/{retries}), retrying in {wait_time}s...")
                if attempt < retries - 1:
                    time.sleep(wait_time)
            except requests.exceptions.RequestException as e:
                logger.error(f"Nessus API error: {e}")
                raise

        # All retries exhausted - only log once
        if not silent:
            logger.warning(f"Nessus unreachable after {retries} attempts (timeout={self.config.timeout}s)")
        raise last_error

    # ==================== Connection ====================

    def connect(self) -> bool:
        """Test connection to Nessus server."""
        try:
            result = self._request("GET", "/server/status")
            self._connected = result.get("status") == "ready"
            if self._connected:
                logger.info(f"Connected to Nessus at {self.config.base_url}")
            return self._connected
        except Exception as e:
            logger.error(f"Failed to connect to Nessus: {e}")
            self._connected = False
            return False

    def is_connected(self) -> bool:
        """Check if connected to Nessus."""
        return self._connected

    def get_info(self) -> Dict:
        """Get Nessus server information."""
        try:
            return self._request("GET", "/server/properties")
        except Exception:
            return {}

    # ==================== Scan Management ====================

    def list_scans(self, folder_id: int = None) -> List[Dict]:
        """List all scans."""
        endpoint = "/scans"
        if folder_id:
            endpoint += f"?folder_id={folder_id}"
        result = self._request("GET", endpoint)
        return result.get("scans", [])

    def get_templates(self) -> List[Dict]:
        """Get available scan templates."""
        result = self._request("GET", "/editor/scan/templates")
        return result.get("templates", [])

    def create_scan(
        self,
        name: str,
        targets: str,
        template: str = "basic",
        description: str = "",
        credentials: dict = None
    ) -> str:
        """
        Create a new scan.

        Args:
            name: Scan name
            targets: Comma-separated list of targets (IPs, hostnames, ranges)
            template: Scan template name
            description: Scan description
            credentials: Optional credentials for authenticated scanning

        Returns:
            Scan ID
        """
        # Get template UUID
        templates = self.get_templates()
        template_uuid = None
        for t in templates:
            if t.get("name", "").lower() == template.lower():
                template_uuid = t.get("uuid")
                break

        if not template_uuid:
            # Default to basic network scan
            template_uuid = templates[0].get("uuid") if templates else None

        settings = {
            "name": name,
            "description": description or f"AIPTX Scan - {datetime.now().isoformat()}",
            "text_targets": targets,
            "launch_now": False
        }

        data = {
            "uuid": template_uuid,
            "settings": settings
        }

        if credentials:
            data["credentials"] = credentials

        result = self._request("POST", "/scans", data)
        scan_id = str(result.get("scan", {}).get("id", ""))
        logger.info(f"Created Nessus scan: {scan_id} for {targets}")
        return scan_id

    def launch_scan(self, scan_id: str) -> bool:
        """Launch an existing scan."""
        try:
            self._request("POST", f"/scans/{scan_id}/launch")
            logger.info(f"Launched scan: {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to launch scan {scan_id}: {e}")
            return False

    def scan_host(
        self,
        target: str,
        template: str = "basic",
        name: str = None,
        credentials: dict = None
    ) -> str:
        """
        Convenience method to create and launch a scan.

        Args:
            target: Target IP/hostname
            template: Scan template
            name: Optional scan name
            credentials: Optional credentials

        Returns:
            Scan ID
        """
        name = name or f"AIPTX-{target}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        scan_id = self.create_scan(name, target, template, credentials=credentials)
        if scan_id:
            self.launch_scan(scan_id)
        return scan_id

    def get_scan_status(self, scan_id: str, silent: bool = False) -> ScanResult:
        """Get current scan status.

        Args:
            scan_id: Nessus scan ID
            silent: If True, suppress retry logs (useful for polling loops)
        """
        try:
            result = self._request("GET", f"/scans/{scan_id}", silent=silent)
            info = result.get("info", {})

            return ScanResult(
                scan_id=scan_id,
                status=info.get("status", "unknown"),
                progress=info.get("scanner_progress", 0) or 0,
                hosts_total=info.get("hostcount", 0) or 0,
                hosts_completed=info.get("hosts_done", 0) or 0,
                vulnerabilities_count=len(result.get("vulnerabilities", [])),
                start_time=info.get("scan_start", ""),
                end_time=info.get("scan_end", "")
            )
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as e:
            # Return error status instead of raising for connection issues
            return ScanResult(scan_id=scan_id, status="unreachable", error=f"Connection failed: {type(e).__name__}")
        except Exception as e:
            return ScanResult(scan_id=scan_id, status="error", error=str(e))

    def wait_for_scan(
        self,
        scan_id: str,
        timeout: int = 3600,
        poll_interval: int = 30,
        callback: Callable[[ScanResult], None] = None
    ) -> ScanResult:
        """
        Wait for scan to complete.

        Args:
            scan_id: Scan ID to monitor
            timeout: Maximum wait time in seconds
            poll_interval: Polling interval in seconds
            callback: Optional progress callback

        Returns:
            Final scan result
        """
        start_time = time.time()
        consecutive_failures = 0
        max_consecutive_failures = 5  # Give up after 5 consecutive connection failures

        while time.time() - start_time < timeout:
            result = self.get_scan_status(scan_id, silent=True)

            if callback:
                callback(result)

            # Handle connection issues during polling
            if result.status == "unreachable":
                consecutive_failures += 1
                if consecutive_failures >= max_consecutive_failures:
                    logger.warning(f"Nessus scan {scan_id}: server unreachable after {consecutive_failures} attempts")
                    return ScanResult(
                        scan_id=scan_id,
                        status="unreachable",
                        error=f"Server unreachable after {consecutive_failures} consecutive failures"
                    )
                # Wait longer before retrying
                time.sleep(poll_interval * 2)
                continue

            # Reset failure counter on successful connection
            consecutive_failures = 0

            if result.status in ["completed", "canceled", "failed"]:
                return result

            time.sleep(poll_interval)

        return ScanResult(
            scan_id=scan_id,
            status="timeout",
            error=f"Scan timed out after {timeout}s"
        )

    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        try:
            self._request("POST", f"/scans/{scan_id}/stop")
            return True
        except Exception:
            return False

    def pause_scan(self, scan_id: str) -> bool:
        """Pause a running scan."""
        try:
            self._request("POST", f"/scans/{scan_id}/pause")
            return True
        except Exception:
            return False

    def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan."""
        try:
            self._request("POST", f"/scans/{scan_id}/resume")
            return True
        except Exception:
            return False

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan."""
        try:
            self._request("DELETE", f"/scans/{scan_id}")
            return True
        except Exception:
            return False

    # ==================== Vulnerability Management ====================

    def get_vulnerabilities(self, scan_id: str, severity: int = None) -> List[Vulnerability]:
        """
        Get vulnerabilities from a scan.

        Args:
            scan_id: Scan ID
            severity: Optional minimum severity filter (0-4)

        Returns:
            List of Vulnerability objects
        """
        try:
            result = self._request("GET", f"/scans/{scan_id}")
            vulns = []

            for host in result.get("hosts", []):
                host_id = host.get("host_id")
                hostname = host.get("hostname", "unknown")

                # Get host vulnerabilities
                host_result = self._request("GET", f"/scans/{scan_id}/hosts/{host_id}")

                for vuln in host_result.get("vulnerabilities", []):
                    sev = vuln.get("severity", 0)
                    if severity is not None and sev < severity:
                        continue

                    plugin_id = vuln.get("plugin_id")

                    # Get plugin details
                    try:
                        plugin_result = self._request(
                            "GET",
                            f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"
                        )
                        plugin_info = plugin_result.get("info", {}).get("plugindescription", {})
                        plugin_attrs = plugin_info.get("pluginattributes", {})
                    except Exception:
                        plugin_info = {}
                        plugin_attrs = {}

                    vulns.append(Vulnerability(
                        vuln_id=f"{scan_id}-{host_id}-{plugin_id}",
                        plugin_id=str(plugin_id),
                        plugin_name=vuln.get("plugin_name", "Unknown"),
                        severity=sev,
                        severity_name=self._severity_name(sev),
                        host=hostname,
                        port=vuln.get("port", 0),
                        protocol=vuln.get("protocol", "tcp"),
                        description=plugin_attrs.get("description", ""),
                        solution=plugin_attrs.get("solution", ""),
                        cvss_score=float(plugin_attrs.get("cvss_base_score", 0) or 0),
                        cvss_vector=plugin_attrs.get("cvss_vector", ""),
                        cve=plugin_attrs.get("cve", []) or [],
                        references=plugin_attrs.get("see_also", []) or [],
                        plugin_output=plugin_result.get("outputs", [{}])[0].get("plugin_output", "") if plugin_result.get("outputs") else ""
                    ))

            return vulns
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    def _severity_name(self, severity: int) -> str:
        """Convert severity int to name."""
        names = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        return names.get(severity, "info")

    # ==================== AIPTX Integration ====================

    def to_finding(self, vuln: Vulnerability) -> Dict:
        """Convert Nessus vulnerability to AIPTX finding format."""
        return {
            "type": "vulnerability",
            "value": vuln.plugin_name,
            "description": vuln.description or vuln.plugin_name,
            "severity": vuln.severity_name,
            "phase": "scan",
            "tool": "nessus",
            "target": f"{vuln.host}:{vuln.port}",
            "metadata": {
                "plugin_id": vuln.plugin_id,
                "cvss_score": vuln.cvss_score,
                "cve": vuln.cve,
                "protocol": vuln.protocol,
                "solution": vuln.solution
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def export_findings(self, scan_id: str, output_path: str = None) -> List[Dict]:
        """
        Export scan findings in AIPTX format.

        Args:
            scan_id: Scan ID
            output_path: Optional file path to save JSON

        Returns:
            List of AIPTX findings
        """
        vulns = self.get_vulnerabilities(scan_id)
        findings = [self.to_finding(v) for v in vulns]

        if output_path:
            with open(output_path, "w") as f:
                json.dump(findings, f, indent=2)

        return findings


# ==================== Global Instance & Helper Functions ====================

_nessus: Optional[NessusTool] = None


def get_nessus(config: Optional[NessusConfig] = None) -> NessusTool:
    """Get or create global Nessus instance."""
    global _nessus
    if _nessus is None or config is not None:
        _nessus = NessusTool(config)
    return _nessus


def nessus_scan(target: str, template: str = "basic") -> ScanResult:
    """Quick scan a target."""
    nessus = get_nessus()
    if not nessus.connect():
        return ScanResult(scan_id="", status="error", error="Connection failed")

    scan_id = nessus.scan_host(target, template)
    return nessus.get_scan_status(scan_id)


def nessus_status(scan_id: str) -> ScanResult:
    """Get scan status."""
    return get_nessus().get_scan_status(scan_id)


def nessus_vulns(scan_id: str = None, severity: str = None) -> List[Dict]:
    """Get vulnerabilities in AIPTX format."""
    nessus = get_nessus()
    sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sev_int = sev_map.get(severity.lower()) if severity else None

    if scan_id:
        vulns = nessus.get_vulnerabilities(scan_id, sev_int)
    else:
        # Get from most recent scan
        scans = nessus.list_scans()
        if scans:
            scan_id = str(scans[0].get("id"))
            vulns = nessus.get_vulnerabilities(scan_id, sev_int)
        else:
            vulns = []

    return [nessus.to_finding(v) for v in vulns]


def nessus_summary() -> Dict:
    """Get Nessus scanner summary."""
    nessus = get_nessus()
    if not nessus.connect():
        return {"connected": False, "error": "Connection failed"}

    info = nessus.get_info()
    scans = nessus.list_scans()

    return {
        "connected": True,
        "url": nessus.config.base_url,
        "version": info.get("nessus_ui_version", "unknown"),
        "scans_count": len(scans)
    }


# ==================== CLI Testing ====================

if __name__ == "__main__":
    import sys

    print("Nessus Integration Test")
    print("=" * 50)

    nessus = get_nessus()

    if nessus.connect():
        print(f"✓ Connected to Nessus at {nessus.config.base_url}")

        info = nessus.get_info()
        print(f"  Version: {info.get('nessus_ui_version', 'unknown')}")

        scans = nessus.list_scans()
        print(f"  Scans: {len(scans)}")

        if len(sys.argv) > 1:
            target = sys.argv[1]
            print(f"\nScanning {target}...")
            scan_id = nessus.scan_host(target)
            print(f"  Scan ID: {scan_id}")

            result = nessus.wait_for_scan(scan_id, timeout=1800)
            print(f"  Status: {result.status}")

            vulns = nessus.get_vulnerabilities(scan_id)
            print(f"  Vulnerabilities: {len(vulns)}")
    else:
        print("✗ Failed to connect to Nessus")
        print("  Set NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY")
