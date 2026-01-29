#!/usr/bin/env python3
"""
Burp Suite Scanner Tool - Plug & Play Integration for AIPT Orchestration
Provides comprehensive API integration with Burp Suite Pro REST API.

Burp Suite Pro REST API Endpoints:
    PUT  /configuration        - Configure Burp settings
    GET  /issue_definitions    - Get all issue definitions
    POST /scan                 - Start a new scan
    GET  /scan/[task_id]       - Get scan progress and issues
"""

import json
import os
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


class ScanStatus(Enum):
    """Burp Suite scan status types."""
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class IssueSeverity(Enum):
    """Vulnerability severity levels in Burp."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueConfidence(Enum):
    """Issue confidence levels in Burp."""
    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


@dataclass
class BurpConfig:
    """Configuration for Burp Suite connection."""
    base_url: str = field(default_factory=lambda: os.getenv("AIPT_SCANNERS__BURP_URL") or os.getenv("BURP_URL", "http://localhost:1337/v0.1"))
    api_key: str = field(default_factory=lambda: os.getenv("AIPT_SCANNERS__BURP_API_KEY") or os.getenv("BURP_API_KEY", ""))
    verify_ssl: bool = False
    timeout: int = 120  # Increased for slow/remote networks


@dataclass
class ScanResult:
    """Result of a Burp Suite scan."""
    task_id: str
    target_url: str
    status: str
    request_count: int = 0
    error_count: int = 0
    insertion_point_count: int = 0
    issue_events: List[Dict] = field(default_factory=list)
    audit_items: List[Dict] = field(default_factory=list)
    progress: int = 0  # Scan progress percentage (0-100)


@dataclass
class Issue:
    """Security issue/vulnerability from Burp Suite."""
    issue_type: str
    name: str
    severity: str
    confidence: str
    host: str
    path: str
    origin: str
    description: str = ""
    remediation: str = ""
    serial_number: str = ""
    evidence: List[Dict] = field(default_factory=list)


class BurpTool:
    """
    Burp Suite Scanner Tool for AIPT Orchestration.

    Provides plug-and-play integration with Burp Suite Pro REST API extension.
    Supports scan execution, issue retrieval, and configuration.

    API Documentation: http://[server]:1337/ (HTML interface)
    """

    def __init__(self, config: Optional[BurpConfig] = None):
        """Initialize Burp Suite tool with configuration."""
        self.config = config or BurpConfig()
        self.session = requests.Session()
        self._setup_session()
        self._connected = False
        self._issue_definitions: Dict[str, Dict] = {}

    def _setup_session(self):
        """Setup the requests session."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        # Burp REST API uses API key directly in Authorization header
        if self.config.api_key:
            headers["Authorization"] = self.config.api_key
        self.session.headers.update(headers)
        self.session.verify = self.config.verify_ssl

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None,
                 params: Optional[Dict] = None, silent_404: bool = False) -> Any:
        """Make an API request to Burp Suite."""
        # Ensure base_url doesn't have trailing slash and endpoint doesn't have leading slash
        base = self.config.base_url.rstrip('/')
        ep = endpoint.lstrip('/')
        url = f"{base}/{ep}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            # Handle different response types
            if response.content:
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    return response.json()
                return response.text

            # For 201/202 responses, return location header
            if response.status_code in [201, 202]:
                location = response.headers.get('Location', '')
                return {"success": True, "location": location, "task_id": location.split('/')[-1] if location else ""}

            return {"success": True}
        except requests.exceptions.HTTPError as e:
            # Don't log 404 errors for optional endpoints
            if response.status_code == 404 and silent_404:
                logger.debug(f"Burp Suite API endpoint not found (optional): {endpoint}")
            else:
                logger.error(f"Burp Suite API error: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Burp Suite API error: {e}")
            raise

    # ==================== Connection ====================

    def connect(self) -> bool:
        """Test connection to Burp Suite."""
        try:
            # Check if server is reachable by hitting the versioned endpoint
            response = self.session.get(f"{self.config.base_url}/", timeout=self.config.timeout)

            # Check for Burp version header (present on all responses)
            burp_version = response.headers.get('X-Burp-Version', '')

            if not burp_version:
                # Try root URL for version header
                root_url = self.config.base_url.replace('/v0.1', '').replace('/v1', '')
                root_response = self.session.get(root_url, timeout=self.config.timeout)
                burp_version = root_response.headers.get('X-Burp-Version', '')

            if burp_version:
                logger.info(f"Burp Suite version: {burp_version}")
                self._connected = True

                # Try to get issue definitions (optional - not all versions support this)
                try:
                    result = self._request("GET", "issue_definitions", silent_404=True)
                    if isinstance(result, list):
                        for issue_def in result:
                            type_index = issue_def.get("type_index", "")
                            if type_index:
                                self._issue_definitions[type_index] = issue_def
                        logger.info(f"Loaded {len(self._issue_definitions)} issue definitions")
                except Exception:
                    # issue_definitions not available in this version - that's OK
                    pass  # Silently ignore - this is expected for some Burp versions

                logger.info(f"Connected to Burp Suite API at {self.config.base_url}")
                return True
            else:
                logger.error("No X-Burp-Version header found - server may not be Burp Suite")
                return False

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Cannot connect to Burp Suite at {self.config.base_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Burp Suite: {e}")
            return False

    def get_info(self) -> Dict[str, Any]:
        """Get Burp Suite instance information."""
        return {
            "server": self.config.base_url,
            "connected": self._connected,
            "issue_definitions_loaded": len(self._issue_definitions),
            "type": "Burp Suite Pro REST API"
        }

    def is_connected(self) -> bool:
        """Check if connected to Burp Suite."""
        return self._connected

    # ==================== Configuration ====================

    def configure(self, config_data: Dict[str, Any]) -> bool:
        """
        Configure Burp Suite settings.

        Args:
            config_data: Configuration dictionary (see Burp API docs)

        Returns:
            Success status
        """
        try:
            self._request("PUT", "/configuration", data=config_data)
            logger.info("Burp configuration updated")
            return True
        except Exception as e:
            logger.error(f"Failed to configure Burp: {e}")
            return False

    def set_scope(self, urls: List[str], exclude_urls: List[str] = None) -> bool:
        """
        Set target scope in Burp.

        Args:
            urls: URLs to include in scope
            exclude_urls: URLs to exclude from scope
        """
        config = {
            "target": {
                "scope": {
                    "include": [{"enabled": True, "prefix": url} for url in urls],
                    "exclude": [{"enabled": True, "prefix": url} for url in (exclude_urls or [])]
                }
            }
        }
        return self.configure(config)

    # ==================== Issue Definitions ====================

    def get_issue_definitions(self) -> List[Dict[str, Any]]:
        """Get all Burp issue definitions."""
        if not self._issue_definitions:
            try:
                # Use silent_404=True since this endpoint is optional in some Burp versions
                result = self._request("GET", "/issue_definitions", silent_404=True)
                if isinstance(result, list):
                    for issue_def in result:
                        type_index = issue_def.get("type_index", "")
                        if type_index:
                            self._issue_definitions[type_index] = issue_def
            except requests.exceptions.HTTPError:
                # 404 or other HTTP error - endpoint not available, that's OK
                pass
            except Exception as e:
                logger.debug(f"Could not load issue definitions: {e}")
        return list(self._issue_definitions.values())

    def get_issue_definition(self, type_index: str) -> Optional[Dict[str, Any]]:
        """Get a specific issue definition by type."""
        if not self._issue_definitions:
            self.get_issue_definitions()
        return self._issue_definitions.get(type_index)

    # ==================== Scan Management ====================

    def start_scan(self, url: str, scope: List[str] = None,
                   configuration: Dict = None) -> str:
        """
        Start a new scan.

        Args:
            url: Target URL to scan
            scope: Additional URLs for scope (optional)
            configuration: Scan configuration (optional)

        Returns:
            Task ID for the scan
        """
        scan_data = {
            "urls": [url] + (scope or [])
        }

        if configuration:
            scan_data["configuration"] = configuration

        result = self._request("POST", "/scan", data=scan_data)

        task_id = ""
        if isinstance(result, dict):
            task_id = result.get("task_id", "")
            if not task_id and result.get("location"):
                task_id = result["location"].split("/")[-1]

        logger.info(f"Started scan: {task_id} for {url}")
        return task_id

    def scan_url(self, url: str) -> str:
        """
        Convenience method to scan a URL directly.

        Args:
            url: URL to scan

        Returns:
            Task ID
        """
        return self.start_scan(url)

    def get_scan_status(self, task_id: str, after: str = None,
                        issue_events: int = None) -> ScanResult:
        """
        Get current status of a scan.

        Args:
            task_id: Scan task ID
            after: Return events after this marker (for incremental updates)
            issue_events: Maximum number of issue events to return

        Returns:
            ScanResult with current status
        """
        params = {}
        if after:
            params["after"] = after
        if issue_events:
            params["issue_events"] = issue_events

        result = self._request("GET", f"/scan/{task_id}", params=params)

        if not isinstance(result, dict):
            result = {}

        # Calculate progress from scan metrics if available
        progress = 0
        scan_status = result.get("scan_status", "unknown").lower()
        if scan_status in ["succeeded", "completed"]:
            progress = 100
        elif scan_status == "running":
            # Estimate progress from crawl metrics
            metrics = result.get("scan_metrics", {})
            crawl_requests = metrics.get("crawl_request_count", 0)
            audit_requests = metrics.get("audit_request_count", 0)
            total_requests = crawl_requests + audit_requests
            # Rough estimate: assume crawl is done when we have requests
            if total_requests > 0:
                progress = min(95, 10 + (audit_requests * 85 // max(1, crawl_requests + audit_requests)))
            else:
                progress = 10
        elif scan_status == "queued":
            progress = 0

        return ScanResult(
            task_id=task_id,
            target_url=result.get("scan_metrics", {}).get("crawl_and_audit_urls", [""])[0] if result.get("scan_metrics") else "",
            status=result.get("scan_status", "unknown"),
            request_count=result.get("scan_metrics", {}).get("request_count", 0),
            error_count=result.get("scan_metrics", {}).get("crawl_and_audit_error_count", 0),
            insertion_point_count=result.get("scan_metrics", {}).get("insertion_point_count", 0),
            issue_events=result.get("issue_events", []),
            audit_items=result.get("audit_items", []),
            progress=progress
        )

    def wait_for_scan(self, task_id: str, timeout: int = 3600,
                      poll_interval: int = 30,
                      callback: callable = None) -> ScanResult:
        """
        Wait for a scan to complete.

        Args:
            task_id: Task ID to wait for
            timeout: Maximum time to wait in seconds
            poll_interval: Time between status checks
            callback: Optional callback function

        Returns:
            Final ScanResult
        """
        start_time = time.time()
        terminal_statuses = ["succeeded", "failed", "cancelled"]

        while time.time() - start_time < timeout:
            result = self.get_scan_status(task_id)

            if callback:
                callback(result)

            if result.status.lower() in terminal_statuses:
                return result

            logger.info(f"Scan {task_id}: {result.status} (requests: {result.request_count})")
            time.sleep(poll_interval)

        raise TimeoutError(f"Scan {task_id} did not complete within {timeout}s")

    # ==================== Issue Management ====================

    def get_issues(self, task_id: str) -> List[Issue]:
        """
        Get issues from a scan.

        Args:
            task_id: Scan task ID

        Returns:
            List of Issue objects
        """
        result = self.get_scan_status(task_id, issue_events=1000)
        issues = []

        for event in result.issue_events:
            issue_data = event.get("issue", {})
            type_index = issue_data.get("type_index", "")

            # Get issue definition for name and description
            issue_def = self.get_issue_definition(type_index) or {}

            issues.append(Issue(
                issue_type=type_index,
                name=issue_def.get("name", issue_data.get("name", "Unknown")),
                severity=issue_data.get("severity", "info"),
                confidence=issue_data.get("confidence", "tentative"),
                host=issue_data.get("origin", ""),
                path=issue_data.get("path", ""),
                origin=issue_data.get("origin", ""),
                description=issue_def.get("description", ""),
                remediation=issue_def.get("remediation", ""),
                serial_number=str(issue_data.get("serial_number", "")),
                evidence=issue_data.get("evidence", [])
            ))

        return issues

    def get_all_issues(self, task_id: str) -> List[Dict[str, Any]]:
        """Get all issues with full details for a scan."""
        issues = self.get_issues(task_id)
        return [self.to_finding(i) for i in issues]

    def get_scan_issues(self, task_id: str) -> List[Issue]:
        """
        Alias for get_issues for orchestrator compatibility.

        Args:
            task_id: Scan task ID

        Returns:
            List of Issue objects
        """
        return self.get_issues(task_id)

    # ==================== Statistics ====================

    def get_scan_summary(self, task_id: str = None) -> Dict[str, Any]:
        """Get scan summary."""
        if not task_id:
            return {
                "connected": self._connected,
                "issue_definitions": len(self._issue_definitions),
                "message": "Provide task_id for scan-specific summary"
            }

        result = self.get_scan_status(task_id, issue_events=1000)

        # Count issues by severity
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for event in result.issue_events:
            sev = event.get("issue", {}).get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "task_id": task_id,
            "status": result.status,
            "request_count": result.request_count,
            "error_count": result.error_count,
            "issue_count": len(result.issue_events),
            "issues_by_severity": severity_counts
        }

    # ==================== Orchestration Helpers ====================

    def to_finding(self, issue: Issue) -> Dict[str, Any]:
        """Convert Burp issue to AIPT finding format."""
        return {
            "type": "vulnerability",
            "value": issue.name,
            "description": issue.description or f"{issue.name} at {issue.path}",
            "severity": issue.severity,
            "phase": "scanning",
            "tool": "burpsuite",
            "metadata": {
                "issue_type": issue.issue_type,
                "confidence": issue.confidence,
                "host": issue.host,
                "path": issue.path,
                "origin": issue.origin,
                "remediation": issue.remediation,
                "serial_number": issue.serial_number
            }
        }

    def export_findings(self, task_id: str, output_path: str = None) -> List[Dict[str, Any]]:
        """
        Export scan findings in AIPT format.

        Args:
            task_id: Task ID to export
            output_path: Optional path to save JSON

        Returns:
            List of findings in AIPT format
        """
        issues = self.get_issues(task_id)
        findings = [self.to_finding(i) for i in issues]

        if output_path:
            with open(output_path, 'w') as f:
                json.dump(findings, f, indent=2)
            logger.info(f"Exported {len(findings)} findings to {output_path}")

        return findings


# ==================== Standalone Functions for Orchestration ====================

# Global instance for quick access
_burp: Optional[BurpTool] = None


def get_burp(config: Optional[BurpConfig] = None) -> BurpTool:
    """Get or create Burp Suite tool instance."""
    global _burp
    if _burp is None or config is not None:
        _burp = BurpTool(config)
        _burp.connect()
    return _burp


def burp_scan(url: str) -> ScanResult:
    """
    Quick scan function for orchestration.

    Args:
        url: URL to scan

    Returns:
        ScanResult
    """
    burp = get_burp()
    task_id = burp.scan_url(url)
    return burp.get_scan_status(task_id)


def burp_status(task_id: str) -> ScanResult:
    """Get scan status."""
    return get_burp().get_scan_status(task_id)


def burp_issues(task_id: str = None, severity: str = None) -> List[Dict[str, Any]]:
    """Get issues as AIPT findings."""
    if not task_id:
        return []
    burp = get_burp()
    issues = burp.get_issues(task_id)
    findings = [burp.to_finding(i) for i in issues]

    # Filter by severity if specified
    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]

    return findings


def burp_summary(task_id: str = None) -> Dict[str, Any]:
    """Get scan summary."""
    return get_burp().get_scan_summary(task_id)


# ==================== CLI for Testing ====================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Burp Suite Scanner Tool")
    parser.add_argument("command", choices=["test", "scan", "status", "issues", "summary", "definitions"])
    parser.add_argument("--url", help="Target URL for scanning")
    parser.add_argument("--task-id", help="Task ID for status/issues")

    args = parser.parse_args()

    config = BurpConfig()
    burp = BurpTool(config)

    if args.command == "test":
        print("Testing Burp Suite connection...")
        print(f"Server: {config.base_url}")
        if burp.connect():
            info = burp.get_info()
            print(f"✓ Connected to Burp Suite Pro")
            print(f"✓ Issue definitions loaded: {info.get('issue_definitions_loaded')}")
        else:
            print("✗ Connection failed")

    elif args.command == "definitions":
        print("Loading issue definitions...")
        if burp.connect():
            defs = burp.get_issue_definitions()
            print(f"Found {len(defs)} issue definitions:")
            for d in defs[:10]:
                print(f"  - [{d.get('type_index')}] {d.get('name')}")
            if len(defs) > 10:
                print(f"  ... and {len(defs) - 10} more")

    elif args.command == "scan":
        if not args.url:
            print("Error: --url required for scan")
        else:
            if burp.connect():
                task_id = burp.scan_url(args.url)
                print(f"Scan started!")
                print(f"Task ID: {task_id}")
                print(f"Check status: python burp_tool.py status --task-id {task_id}")

    elif args.command == "status":
        if not args.task_id:
            print("Error: --task-id required")
        else:
            if burp.connect():
                result = burp.get_scan_status(args.task_id)
                print(f"Task ID: {result.task_id}")
                print(f"Status: {result.status}")
                print(f"Requests: {result.request_count}")
                print(f"Errors: {result.error_count}")
                print(f"Issues found: {len(result.issue_events)}")

    elif args.command == "issues":
        if not args.task_id:
            print("Error: --task-id required")
        else:
            if burp.connect():
                findings = burp.get_all_issues(args.task_id)
                print(f"Found {len(findings)} issues:")
                for f in findings[:10]:
                    print(f"  [{f['severity'].upper()}] {f['value']}")
                if len(findings) > 10:
                    print(f"  ... and {len(findings) - 10} more")

    elif args.command == "summary":
        if burp.connect():
            summary = burp.get_scan_summary(args.task_id)
            print("Burp Suite Summary:")
            for k, v in summary.items():
                print(f"  {k}: {v}")
