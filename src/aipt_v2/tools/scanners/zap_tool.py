"""
OWASP ZAP (Zed Attack Proxy) Integration for AIPTX

Provides web application security testing through ZAP's REST API.
Supports spidering, active scanning, and passive scanning.

Environment Variables:
    ZAP_URL: ZAP API URL (default: http://localhost:8080)
    ZAP_API_KEY: API key for authentication

Usage:
    from aipt_v2.tools.scanners.zap_tool import get_zap, zap_scan

    zap = get_zap()
    if zap.connect():
        scan_id = zap.active_scan("https://example.com")
        result = zap.wait_for_scan(scan_id)
        alerts = zap.get_alerts()
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

logger = logging.getLogger(__name__)


# ==================== Enums ====================

class ScanStatus(Enum):
    """ZAP scan status."""
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


class RiskLevel(Enum):
    """ZAP alert risk levels."""
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFORMATIONAL = 0


class ConfidenceLevel(Enum):
    """ZAP alert confidence levels."""
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    FALSE_POSITIVE = 0


# ==================== Data Classes ====================

@dataclass
class ZAPConfig:
    """Configuration for ZAP connection."""
    base_url: str = field(default_factory=lambda: os.getenv("AIPT_SCANNERS__ZAP_URL") or os.getenv("ZAP_URL", "http://localhost:8080"))
    api_key: str = field(default_factory=lambda: os.getenv("AIPT_SCANNERS__ZAP_API_KEY") or os.getenv("ZAP_API_KEY", ""))
    timeout: int = 120  # Increased for slow/remote networks


@dataclass
class ScanResult:
    """Result of a ZAP scan."""
    scan_id: str
    status: str
    progress: int = 0
    alerts_count: int = 0
    urls_found: int = 0
    start_time: str = ""
    end_time: str = ""
    error: str = ""


@dataclass
class Alert:
    """ZAP security alert."""
    alert_id: str
    name: str
    risk: int
    risk_name: str
    confidence: int
    confidence_name: str
    url: str
    description: str = ""
    solution: str = ""
    reference: str = ""
    cwe_id: int = 0
    wasc_id: int = 0
    evidence: str = ""
    param: str = ""
    attack: str = ""
    other_info: str = ""


# ==================== Main Tool Class ====================

class ZAPTool:
    """
    OWASP ZAP integration for AIPTX.

    Provides methods for:
    - URL spidering
    - Active vulnerability scanning
    - Passive scanning
    - Alert retrieval and management
    """

    def __init__(self, config: Optional[ZAPConfig] = None):
        """Initialize ZAP tool with configuration."""
        self.config = config or ZAPConfig()
        self._session = requests.Session()
        self._connected = False

    def _request(self, component: str, action: str, params: dict = None) -> dict:
        """Make request to ZAP API."""
        url = f"{self.config.base_url}/JSON/{component}/view/{action}/"
        params = params or {}
        if self.config.api_key:
            params["apikey"] = self.config.api_key

        try:
            response = self._session.get(url, params=params, timeout=self.config.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"ZAP API error: {e}")
            raise

    def _action(self, component: str, action: str, params: dict = None) -> dict:
        """Execute ZAP API action."""
        url = f"{self.config.base_url}/JSON/{component}/action/{action}/"
        params = params or {}
        if self.config.api_key:
            params["apikey"] = self.config.api_key

        try:
            response = self._session.get(url, params=params, timeout=self.config.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"ZAP API action error: {e}")
            raise

    # ==================== Connection ====================

    def connect(self) -> bool:
        """Test connection to ZAP."""
        try:
            result = self._request("core", "version")
            self._connected = "version" in result
            if self._connected:
                logger.info(f"Connected to ZAP at {self.config.base_url}")
            return self._connected
        except Exception as e:
            logger.error(f"Failed to connect to ZAP: {e}")
            self._connected = False
            return False

    def is_connected(self) -> bool:
        """Check if connected to ZAP."""
        return self._connected

    def get_info(self) -> Dict:
        """Get ZAP version and info."""
        try:
            version = self._request("core", "version")
            return {"version": version.get("version", "unknown")}
        except Exception:
            return {}

    # ==================== Context Management ====================

    def new_session(self, name: str = None) -> bool:
        """Create a new ZAP session."""
        try:
            params = {}
            if name:
                params["name"] = name
            self._action("core", "newSession", params)
            return True
        except Exception:
            return False

    def set_mode(self, mode: str = "standard") -> bool:
        """Set ZAP mode (safe, protect, standard, attack)."""
        try:
            self._action("core", "setMode", {"mode": mode})
            return True
        except Exception:
            return False

    # ==================== Spider ====================

    def spider(self, url: str, max_children: int = 0, recurse: bool = True) -> str:
        """
        Start spidering a URL.

        Args:
            url: Target URL to spider
            max_children: Max children to crawl (0 = unlimited)
            recurse: Whether to recurse into found URLs

        Returns:
            Spider scan ID
        """
        try:
            params = {
                "url": url,
                "maxChildren": str(max_children),
                "recurse": str(recurse).lower()
            }
            result = self._action("spider", "scan", params)
            scan_id = result.get("scan", "")
            logger.info(f"Started spider scan: {scan_id} for {url}")
            return str(scan_id)
        except Exception as e:
            logger.error(f"Failed to start spider: {e}")
            return ""

    def get_spider_status(self, scan_id: str) -> int:
        """Get spider progress (0-100)."""
        try:
            result = self._request("spider", "status", {"scanId": scan_id})
            return int(result.get("status", 0))
        except Exception:
            return 0

    def wait_for_spider(self, scan_id: str, timeout: int = 300) -> bool:
        """Wait for spider to complete."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            progress = self.get_spider_status(scan_id)
            if progress >= 100:
                return True
            time.sleep(5)
        return False

    def get_spider_results(self, scan_id: str) -> List[str]:
        """Get URLs found by spider."""
        try:
            result = self._request("spider", "results", {"scanId": scan_id})
            return result.get("results", [])
        except Exception:
            return []

    # ==================== Active Scan ====================

    def active_scan(
        self,
        url: str,
        recurse: bool = True,
        in_scope_only: bool = False,
        scan_policy: str = None
    ) -> str:
        """
        Start active vulnerability scan.

        Args:
            url: Target URL to scan
            recurse: Scan recursively
            in_scope_only: Only scan URLs in scope
            scan_policy: Scan policy name (optional)

        Returns:
            Active scan ID
        """
        try:
            params = {
                "url": url,
                "recurse": str(recurse).lower(),
                "inScopeOnly": str(in_scope_only).lower()
            }
            if scan_policy:
                params["scanPolicyName"] = scan_policy

            result = self._action("ascan", "scan", params)
            scan_id = result.get("scan", "")
            logger.info(f"Started active scan: {scan_id} for {url}")
            return str(scan_id)
        except Exception as e:
            logger.error(f"Failed to start active scan: {e}")
            return ""

    def get_scan_status(self, scan_id: str) -> ScanResult:
        """Get active scan status."""
        try:
            status_result = self._request("ascan", "status", {"scanId": scan_id})
            progress = int(status_result.get("status", 0))

            # Get alerts count
            alerts = self.get_alerts()

            status = "running" if progress < 100 else "completed"

            return ScanResult(
                scan_id=scan_id,
                status=status,
                progress=progress,
                alerts_count=len(alerts)
            )
        except Exception as e:
            return ScanResult(scan_id=scan_id, status="error", error=str(e))

    def wait_for_scan(
        self,
        scan_id: str,
        timeout: int = 3600,
        poll_interval: int = 10,
        callback: Callable[[ScanResult], None] = None
    ) -> ScanResult:
        """
        Wait for active scan to complete.

        Args:
            scan_id: Scan ID to monitor
            timeout: Maximum wait time in seconds
            poll_interval: Polling interval in seconds
            callback: Optional progress callback

        Returns:
            Final scan result
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.get_scan_status(scan_id)

            if callback:
                callback(result)

            if result.progress >= 100 or result.status in ["completed", "stopped", "error"]:
                result.status = "completed" if result.progress >= 100 else result.status
                return result

            time.sleep(poll_interval)

        return ScanResult(
            scan_id=scan_id,
            status="timeout",
            error=f"Scan timed out after {timeout}s"
        )

    def stop_scan(self, scan_id: str) -> bool:
        """Stop an active scan."""
        try:
            self._action("ascan", "stop", {"scanId": scan_id})
            return True
        except Exception:
            return False

    def pause_scan(self, scan_id: str) -> bool:
        """Pause an active scan."""
        try:
            self._action("ascan", "pause", {"scanId": scan_id})
            return True
        except Exception:
            return False

    def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan."""
        try:
            self._action("ascan", "resume", {"scanId": scan_id})
            return True
        except Exception:
            return False

    # ==================== Full Scan (Spider + Active) ====================

    def full_scan(self, url: str, spider_timeout: int = 300) -> str:
        """
        Run a full scan (spider + active scan).

        Args:
            url: Target URL
            spider_timeout: Max time for spider phase

        Returns:
            Active scan ID
        """
        # First spider the target
        spider_id = self.spider(url)
        if spider_id:
            self.wait_for_spider(spider_id, spider_timeout)

        # Then run active scan
        return self.active_scan(url)

    # ==================== Alert Management ====================

    def get_alerts(
        self,
        base_url: str = None,
        risk: str = None,
        start: int = 0,
        count: int = 1000
    ) -> List[Alert]:
        """
        Get security alerts.

        Args:
            base_url: Filter by base URL
            risk: Filter by risk level (high, medium, low, informational)
            start: Start index
            count: Number of alerts to retrieve

        Returns:
            List of Alert objects
        """
        try:
            params = {"start": str(start), "count": str(count)}
            if base_url:
                params["baseurl"] = base_url
            if risk:
                params["riskId"] = str(self._risk_to_int(risk))

            result = self._request("alert", "alerts", params)
            alerts = []

            for a in result.get("alerts", []):
                alerts.append(Alert(
                    alert_id=str(a.get("id", "")),
                    name=a.get("name", "Unknown"),
                    risk=int(a.get("riskcode", 0)),
                    risk_name=a.get("risk", "Unknown"),
                    confidence=int(a.get("confidence", 0)),
                    confidence_name=a.get("confidence", "Unknown"),
                    url=a.get("url", ""),
                    description=a.get("description", ""),
                    solution=a.get("solution", ""),
                    reference=a.get("reference", ""),
                    cwe_id=int(a.get("cweid", 0) or 0),
                    wasc_id=int(a.get("wascid", 0) or 0),
                    evidence=a.get("evidence", ""),
                    param=a.get("param", ""),
                    attack=a.get("attack", ""),
                    other_info=a.get("other", "")
                ))

            return alerts
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []

    def _risk_to_int(self, risk: str) -> int:
        """Convert risk string to int."""
        mapping = {"high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0}
        return mapping.get(risk.lower(), 0)

    def get_alerts_summary(self) -> Dict:
        """Get summary of alerts by risk level."""
        try:
            result = self._request("alert", "alertsSummary")
            return result.get("alertsSummary", {})
        except Exception:
            return {}

    # ==================== AIPTX Integration ====================

    def to_finding(self, alert: Alert) -> Dict:
        """Convert ZAP alert to AIPTX finding format."""
        severity_map = {3: "high", 2: "medium", 1: "low", 0: "info"}

        return {
            "type": "vulnerability",
            "value": alert.name,
            "description": alert.description or alert.name,
            "severity": severity_map.get(alert.risk, "info"),
            "phase": "scan",
            "tool": "zap",
            "target": alert.url,
            "metadata": {
                "alert_id": alert.alert_id,
                "risk": alert.risk_name,
                "confidence": alert.confidence_name,
                "cwe_id": alert.cwe_id,
                "wasc_id": alert.wasc_id,
                "solution": alert.solution,
                "evidence": alert.evidence[:500] if alert.evidence else "",
                "param": alert.param,
                "attack": alert.attack
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def export_findings(self, output_path: str = None, base_url: str = None) -> List[Dict]:
        """
        Export alerts in AIPTX format.

        Args:
            output_path: Optional file path to save JSON
            base_url: Optional URL filter

        Returns:
            List of AIPTX findings
        """
        alerts = self.get_alerts(base_url=base_url)
        findings = [self.to_finding(a) for a in alerts]

        if output_path:
            with open(output_path, "w") as f:
                json.dump(findings, f, indent=2)

        return findings


# ==================== Global Instance & Helper Functions ====================

_zap: Optional[ZAPTool] = None


def get_zap(config: Optional[ZAPConfig] = None) -> ZAPTool:
    """Get or create global ZAP instance."""
    global _zap
    if _zap is None or config is not None:
        _zap = ZAPTool(config)
    return _zap


def zap_scan(url: str, full: bool = True) -> ScanResult:
    """Quick scan a target."""
    zap = get_zap()
    if not zap.connect():
        return ScanResult(scan_id="", status="error", error="Connection failed")

    if full:
        scan_id = zap.full_scan(url)
    else:
        scan_id = zap.active_scan(url)

    return zap.get_scan_status(scan_id)


def zap_status(scan_id: str) -> ScanResult:
    """Get scan status."""
    return get_zap().get_scan_status(scan_id)


def zap_alerts(base_url: str = None, risk: str = None) -> List[Dict]:
    """Get alerts in AIPTX format."""
    zap = get_zap()
    alerts = zap.get_alerts(base_url=base_url, risk=risk)
    return [zap.to_finding(a) for a in alerts]


def zap_summary() -> Dict:
    """Get ZAP scanner summary."""
    zap = get_zap()
    if not zap.connect():
        return {"connected": False, "error": "Connection failed"}

    info = zap.get_info()
    alerts_summary = zap.get_alerts_summary()

    return {
        "connected": True,
        "url": zap.config.base_url,
        "version": info.get("version", "unknown"),
        "alerts": alerts_summary
    }


# ==================== CLI Testing ====================

if __name__ == "__main__":
    import sys

    print("OWASP ZAP Integration Test")
    print("=" * 50)

    zap = get_zap()

    if zap.connect():
        print(f"✓ Connected to ZAP at {zap.config.base_url}")

        info = zap.get_info()
        print(f"  Version: {info.get('version', 'unknown')}")

        if len(sys.argv) > 1:
            target = sys.argv[1]
            print(f"\nScanning {target}...")

            # Spider first
            spider_id = zap.spider(target)
            print(f"  Spider ID: {spider_id}")
            zap.wait_for_spider(spider_id)
            urls = zap.get_spider_results(spider_id)
            print(f"  URLs found: {len(urls)}")

            # Active scan
            scan_id = zap.active_scan(target)
            print(f"  Scan ID: {scan_id}")

            result = zap.wait_for_scan(scan_id, timeout=1800)
            print(f"  Status: {result.status}")

            alerts = zap.get_alerts()
            print(f"  Alerts: {len(alerts)}")

            for alert in alerts[:5]:
                print(f"    [{alert.risk_name}] {alert.name}")
    else:
        print("✗ Failed to connect to ZAP")
        print("  Set ZAP_URL and ZAP_API_KEY environment variables")
