#!/usr/bin/env python3
"""
Acunetix Scanner Tool - Plug & Play Integration for AIPT Orchestration
Provides comprehensive API integration with Acunetix Web Vulnerability Scanner.
"""

import json
import time
import logging
import requests
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class ScanProfile(Enum):
    """Acunetix scan profile types."""
    FULL_SCAN = "11111111-1111-1111-1111-111111111111"
    HIGH_RISK = "11111111-1111-1111-1111-111111111112"
    WEAK_PASSWORDS = "11111111-1111-1111-1111-111111111115"
    CRAWL_ONLY = "11111111-1111-1111-1111-111111111117"
    XSS_SCAN = "11111111-1111-1111-1111-111111111116"
    SQL_INJECTION = "11111111-1111-1111-1111-111111111113"
    MALWARE_SCAN = "11111111-1111-1111-1111-111111111120"


class ScanStatus(Enum):
    """Acunetix scan status types."""
    PENDING = "pending"
    QUEUED = "queued"
    STARTING = "starting"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    PAUSED = "paused"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AcunetixConfig:
    """Configuration for Acunetix connection."""
    base_url: str = "https://13.127.28.41:3443"
    api_key: str = "1986ad8c0a5b3df4d7028d5f3c06e936c83ef0a486ef74537812989cff1a41a7c"
    verify_ssl: bool = False
    timeout: int = 30


@dataclass
class ScanResult:
    """Result of an Acunetix scan."""
    scan_id: str
    target_id: str
    target_url: str
    status: str
    progress: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    vulnerabilities: Dict[str, int] = field(default_factory=dict)
    threat_level: int = 0


@dataclass
class Vulnerability:
    """Vulnerability finding from Acunetix."""
    vuln_id: str
    severity: str
    name: str
    description: str
    target_url: str
    affected_url: str
    recommendation: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)


class AcunetixTool:
    """
    Acunetix Scanner Tool for AIPT Orchestration.

    Provides plug-and-play integration with Acunetix Web Vulnerability Scanner.
    Supports target management, scan execution, vulnerability retrieval, and reporting.
    """

    def __init__(self, config: Optional[AcunetixConfig] = None):
        """Initialize Acunetix tool with configuration."""
        self.config = config or AcunetixConfig()
        self.session = requests.Session()
        self.session.headers.update({
            "X-Auth": self.config.api_key,
            "Content-Type": "application/json"
        })
        self.session.verify = self.config.verify_ssl
        self._connected = False

    @property
    def api_url(self) -> str:
        """Get the API base URL."""
        return f"{self.config.base_url}/api/v1"

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None,
                 params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an API request to Acunetix."""
        url = f"{self.api_url}/{endpoint}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            if response.content:
                return response.json()
            return {"success": True}
        except requests.exceptions.RequestException as e:
            logger.error(f"Acunetix API error: {e}")
            raise

    # ==================== Connection ====================

    def connect(self) -> bool:
        """Test connection to Acunetix and verify API key."""
        try:
            result = self._request("GET", "me")
            self._connected = result.get("enabled", False)
            logger.info(f"Connected to Acunetix as: {result.get('email')}")
            return self._connected
        except Exception as e:
            logger.error(f"Failed to connect to Acunetix: {e}")
            return False

    def get_info(self) -> Dict[str, Any]:
        """Get Acunetix instance information."""
        return self._request("GET", "me")

    def is_connected(self) -> bool:
        """Check if connected to Acunetix."""
        return self._connected

    # ==================== Target Management ====================

    def add_target(self, url: str, description: str = "",
                   criticality: int = 10) -> str:
        """
        Add a new target to Acunetix.

        Args:
            url: Target URL to scan
            description: Target description
            criticality: Target criticality (0-30, 10=normal, 30=critical)

        Returns:
            Target ID
        """
        data = {
            "address": url,
            "description": description or f"AIPT Target - {datetime.now().isoformat()}",
            "criticality": criticality
        }
        result = self._request("POST", "targets", data=data)
        target_id = result.get("target_id")
        logger.info(f"Added target: {url} (ID: {target_id})")
        return target_id

    def get_target(self, target_id: str) -> Dict[str, Any]:
        """Get target information by ID."""
        return self._request("GET", f"targets/{target_id}")

    def get_target_by_url(self, url: str) -> Optional[str]:
        """Find target ID by URL."""
        targets = self.list_targets()
        for target in targets:
            if target.get("address") == url:
                return target.get("target_id")
        return None

    def list_targets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List all targets."""
        result = self._request("GET", "targets", params={"l": limit})
        return result.get("targets", [])

    def delete_target(self, target_id: str) -> bool:
        """Delete a target."""
        try:
            self._request("DELETE", f"targets/{target_id}")
            logger.info(f"Deleted target: {target_id}")
            return True
        except Exception:
            return False

    def configure_target(self, target_id: str, login_url: str = None,
                         username: str = None, password: str = None,
                         custom_headers: Dict[str, str] = None) -> bool:
        """
        Configure target with authentication and custom settings.

        Args:
            target_id: Target ID
            login_url: Login page URL for authenticated scanning
            username: Login username
            password: Login password
            custom_headers: Custom HTTP headers to include
        """
        config = {}

        if login_url and username and password:
            config["login"] = {
                "kind": "automatic",
                "credentials": {
                    "enabled": True,
                    "username": username,
                    "password": password
                }
            }

        if custom_headers:
            config["custom_headers"] = [
                {"name": k, "value": v} for k, v in custom_headers.items()
            ]

        if config:
            self._request("PATCH", f"targets/{target_id}/configuration", data=config)
            logger.info(f"Configured target: {target_id}")
            return True
        return False

    # ==================== Scan Management ====================

    def start_scan(self, target_id: str,
                   profile: ScanProfile = ScanProfile.FULL_SCAN,
                   schedule: bool = False) -> str:
        """
        Start a scan on a target.

        Args:
            target_id: Target ID to scan
            profile: Scan profile to use
            schedule: If True, schedule for later (not immediate)

        Returns:
            Scan ID
        """
        data = {
            "target_id": target_id,
            "profile_id": profile.value,
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False
            }
        }
        result = self._request("POST", "scans", data=data)
        scan_id = result.get("scan_id") or self._get_latest_scan_id(target_id)
        logger.info(f"Started scan: {scan_id} with profile: {profile.name}")
        return scan_id

    def _get_latest_scan_id(self, target_id: str) -> Optional[str]:
        """Get the latest scan ID for a target."""
        scans = self.list_scans(limit=10)
        for scan in scans:
            if scan.get("target_id") == target_id:
                return scan.get("scan_id")
        return None

    def scan_url(self, url: str, profile: ScanProfile = ScanProfile.FULL_SCAN,
                 description: str = "") -> str:
        """
        Convenience method to add target and start scan in one call.

        Args:
            url: URL to scan
            profile: Scan profile to use
            description: Target description

        Returns:
            Scan ID
        """
        # Check if target already exists
        target_id = self.get_target_by_url(url)
        if not target_id:
            target_id = self.add_target(url, description)

        return self.start_scan(target_id, profile)

    def get_scan_status(self, scan_id: str) -> ScanResult:
        """Get current status of a scan."""
        result = self._request("GET", f"scans/{scan_id}")

        current = result.get("current_session", {})
        target = result.get("target", {})

        return ScanResult(
            scan_id=scan_id,
            target_id=result.get("target_id", ""),
            target_url=target.get("address", ""),
            status=current.get("status", "unknown"),
            progress=current.get("progress", 0),
            start_time=current.get("start_date"),
            vulnerabilities=current.get("severity_counts", {}),
            threat_level=current.get("threat", 0)
        )

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List all scans."""
        result = self._request("GET", "scans", params={"l": limit})
        return result.get("scans", [])

    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        try:
            self._request("POST", f"scans/{scan_id}/abort")
            logger.info(f"Stopped scan: {scan_id}")
            return True
        except Exception:
            return False

    def pause_scan(self, scan_id: str) -> bool:
        """Pause a running scan."""
        try:
            self._request("POST", f"scans/{scan_id}/pause")
            return True
        except Exception:
            return False

    def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan."""
        try:
            self._request("POST", f"scans/{scan_id}/resume")
            return True
        except Exception:
            return False

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan."""
        try:
            self._request("DELETE", f"scans/{scan_id}")
            return True
        except Exception:
            return False

    def wait_for_scan(self, scan_id: str, timeout: int = 3600,
                      poll_interval: int = 30,
                      callback: callable = None) -> ScanResult:
        """
        Wait for a scan to complete.

        Args:
            scan_id: Scan ID to wait for
            timeout: Maximum time to wait in seconds
            poll_interval: Time between status checks
            callback: Optional callback function called with ScanResult on each poll

        Returns:
            Final ScanResult
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.get_scan_status(scan_id)

            if callback:
                callback(result)

            if result.status in [ScanStatus.COMPLETED.value,
                                 ScanStatus.FAILED.value,
                                 ScanStatus.ABORTED.value]:
                return result

            logger.info(f"Scan {scan_id}: {result.status} ({result.progress}%)")
            time.sleep(poll_interval)

        raise TimeoutError(f"Scan {scan_id} did not complete within {timeout}s")

    # ==================== Vulnerability Management ====================

    def get_vulnerabilities(self, scan_id: str = None,
                           severity: Severity = None,
                           limit: int = 100) -> List[Vulnerability]:
        """
        Get vulnerabilities from scans.

        Args:
            scan_id: Optional scan ID to filter by
            severity: Optional severity filter
            limit: Maximum results to return
        """
        params = {"l": limit}
        if severity:
            params["q"] = f"severity:{severity.value}"

        result = self._request("GET", "vulnerabilities", params=params)
        vulns = []

        for v in result.get("vulnerabilities", []):
            vulns.append(Vulnerability(
                vuln_id=v.get("vuln_id", ""),
                severity=v.get("severity", "info"),
                name=v.get("vt_name", "Unknown"),
                description=v.get("vt_description", ""),
                target_url=v.get("target", {}).get("address", ""),
                affected_url=v.get("affects_url", ""),
                recommendation=v.get("recommendation", ""),
                cvss_score=v.get("cvss_score"),
                cwe_id=v.get("cwe_id")
            ))

        return vulns

    def get_vulnerability_details(self, vuln_id: str) -> Dict[str, Any]:
        """Get detailed vulnerability information."""
        return self._request("GET", f"vulnerabilities/{vuln_id}")

    def get_scan_vulnerabilities(self, scan_id: str) -> List[Vulnerability]:
        """Get all vulnerabilities for a specific scan."""
        # Get scan to find target
        scan = self._request("GET", f"scans/{scan_id}")
        target_id = scan.get("target_id")

        # Get vulnerabilities for target
        result = self._request("GET", f"targets/{target_id}/vulnerabilities")
        vulns = []

        for v in result.get("vulnerabilities", []):
            vulns.append(Vulnerability(
                vuln_id=v.get("vuln_id", ""),
                severity=v.get("severity", "info"),
                name=v.get("vt_name", "Unknown"),
                description="",  # Need to fetch details separately
                target_url=scan.get("target", {}).get("address", ""),
                affected_url=v.get("affects_url", "")
            ))

        return vulns

    # ==================== Reporting ====================

    def generate_report(self, scan_id: str,
                        template: str = "11111111-1111-1111-1111-111111111111",
                        format_type: str = "pdf") -> str:
        """
        Generate a report for a scan.

        Args:
            scan_id: Scan ID to report on
            template: Report template ID
            format_type: Report format (pdf, html)

        Returns:
            Report ID
        """
        # Get scan to find source
        scan = self._request("GET", f"scans/{scan_id}")

        data = {
            "template_id": template,
            "source": {
                "list_type": "scans",
                "id_list": [scan_id]
            }
        }
        result = self._request("POST", "reports", data=data)
        return result.get("report_id", "")

    def get_report_status(self, report_id: str) -> Dict[str, Any]:
        """Get report generation status."""
        return self._request("GET", f"reports/{report_id}")

    def download_report(self, report_id: str, output_path: str) -> str:
        """
        Download a generated report.

        Args:
            report_id: Report ID
            output_path: Path to save the report

        Returns:
            Path to saved report
        """
        url = f"{self.api_url}/reports/{report_id}/download"
        response = self.session.get(url, stream=True)
        response.raise_for_status()

        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.info(f"Report saved to: {output_path}")
        return output_path

    # ==================== Statistics & Dashboard ====================

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        try:
            return self._request("GET", "dashboard/stats")
        except Exception:
            # Fallback: calculate from scans
            scans = self.list_scans(limit=100)
            stats = {
                "total_scans": len(scans),
                "completed": sum(1 for s in scans if s.get("current_session", {}).get("status") == "completed"),
                "running": sum(1 for s in scans if s.get("current_session", {}).get("status") == "processing"),
                "vulnerabilities": {
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
                }
            }
            for scan in scans:
                counts = scan.get("current_session", {}).get("severity_counts", {})
                for sev in stats["vulnerabilities"]:
                    stats["vulnerabilities"][sev] += counts.get(sev, 0)
            return stats

    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of all scans with vulnerability counts."""
        scans = self.list_scans(limit=50)
        summary = {
            "total_scans": len(scans),
            "by_status": {},
            "total_vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "recent_scans": []
        }

        for scan in scans:
            status = scan.get("current_session", {}).get("status", "unknown")
            summary["by_status"][status] = summary["by_status"].get(status, 0) + 1

            counts = scan.get("current_session", {}).get("severity_counts", {})
            for sev in summary["total_vulnerabilities"]:
                summary["total_vulnerabilities"][sev] += counts.get(sev, 0)

            if len(summary["recent_scans"]) < 10:
                summary["recent_scans"].append({
                    "scan_id": scan.get("scan_id"),
                    "target": scan.get("target", {}).get("address"),
                    "status": status,
                    "progress": scan.get("current_session", {}).get("progress", 0),
                    "vulnerabilities": counts
                })

        return summary

    # ==================== Orchestration Helpers ====================

    def to_finding(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Acunetix vulnerability to AIPT finding format."""
        return {
            "type": "vulnerability",
            "value": vuln.name,
            "description": vuln.description or f"{vuln.name} at {vuln.affected_url}",
            "severity": vuln.severity,
            "phase": "scanning",
            "tool": "acunetix",
            "metadata": {
                "vuln_id": vuln.vuln_id,
                "target_url": vuln.target_url,
                "affected_url": vuln.affected_url,
                "cvss_score": vuln.cvss_score,
                "cwe_id": vuln.cwe_id
            }
        }

    def export_findings(self, scan_id: str, output_path: str = None) -> List[Dict[str, Any]]:
        """
        Export scan findings in AIPT format.

        Args:
            scan_id: Scan ID to export
            output_path: Optional path to save JSON

        Returns:
            List of findings in AIPT format
        """
        vulns = self.get_scan_vulnerabilities(scan_id)
        findings = [self.to_finding(v) for v in vulns]

        if output_path:
            with open(output_path, 'w') as f:
                json.dump(findings, f, indent=2)
            logger.info(f"Exported {len(findings)} findings to {output_path}")

        return findings


# ==================== Standalone Functions for Orchestration ====================

# Global instance for quick access
_acunetix: Optional[AcunetixTool] = None


def get_acunetix(config: Optional[AcunetixConfig] = None) -> AcunetixTool:
    """Get or create Acunetix tool instance."""
    global _acunetix
    if _acunetix is None or config is not None:
        _acunetix = AcunetixTool(config)
        _acunetix.connect()
    return _acunetix


def acunetix_scan(url: str, profile: str = "full") -> ScanResult:
    """
    Quick scan function for orchestration.

    Args:
        url: URL to scan
        profile: Scan profile (full, high_risk, xss, sqli, crawl)

    Returns:
        ScanResult
    """
    profiles = {
        "full": ScanProfile.FULL_SCAN,
        "high_risk": ScanProfile.HIGH_RISK,
        "xss": ScanProfile.XSS_SCAN,
        "sqli": ScanProfile.SQL_INJECTION,
        "crawl": ScanProfile.CRAWL_ONLY,
        "malware": ScanProfile.MALWARE_SCAN
    }

    acunetix = get_acunetix()
    scan_id = acunetix.scan_url(url, profiles.get(profile, ScanProfile.FULL_SCAN))
    return acunetix.get_scan_status(scan_id)


def acunetix_status(scan_id: str) -> ScanResult:
    """Get scan status."""
    return get_acunetix().get_scan_status(scan_id)


def acunetix_vulns(scan_id: str = None, severity: str = None) -> List[Dict[str, Any]]:
    """Get vulnerabilities as AIPT findings."""
    acunetix = get_acunetix()
    sev = Severity(severity) if severity else None
    vulns = acunetix.get_vulnerabilities(scan_id, sev)
    return [acunetix.to_finding(v) for v in vulns]


def acunetix_summary() -> Dict[str, Any]:
    """Get scan summary."""
    return get_acunetix().get_scan_summary()


# ==================== CLI for Testing ====================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Acunetix Scanner Tool")
    parser.add_argument("command", choices=["test", "scan", "status", "vulns", "summary"])
    parser.add_argument("--url", help="Target URL for scanning")
    parser.add_argument("--scan-id", help="Scan ID for status/vulns")
    parser.add_argument("--profile", default="full", help="Scan profile")

    args = parser.parse_args()

    acunetix = get_acunetix()

    if args.command == "test":
        print("Testing Acunetix connection...")
        if acunetix.connect():
            info = acunetix.get_info()
            print(f"✓ Connected as: {info.get('email')}")
            print(f"✓ Access: {info.get('access_rights')}")
        else:
            print("✗ Connection failed")

    elif args.command == "scan":
        if not args.url:
            print("Error: --url required for scan")
        else:
            result = acunetix_scan(args.url, args.profile)
            print(f"Scan started: {result.scan_id}")
            print(f"Status: {result.status}")

    elif args.command == "status":
        if not args.scan_id:
            print("Error: --scan-id required")
        else:
            result = acunetix_status(args.scan_id)
            print(f"Scan: {result.scan_id}")
            print(f"Target: {result.target_url}")
            print(f"Status: {result.status} ({result.progress}%)")
            print(f"Vulnerabilities: {result.vulnerabilities}")

    elif args.command == "vulns":
        findings = acunetix_vulns(args.scan_id)
        print(f"Found {len(findings)} vulnerabilities:")
        for f in findings[:10]:
            print(f"  [{f['severity'].upper()}] {f['value']}")

    elif args.command == "summary":
        summary = acunetix_summary()
        print(f"Total Scans: {summary['total_scans']}")
        print(f"By Status: {summary['by_status']}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
