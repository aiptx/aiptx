"""
AIPTX Trivy Scanner
===================

Scanner for trivy - comprehensive vulnerability scanner.
https://github.com/aquasecurity/trivy
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


@dataclass
class TrivyConfig:
    """Configuration for trivy scanner."""

    # Scan type
    scan_type: str = "fs"  # fs, image, repo, config, sbom

    # Security checks
    vuln_type: str = "os,library"  # os, library
    scanners: str = "vuln,secret,misconfig"  # vuln, misconfig, secret, license

    # Severity filter
    severity: str = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
    ignore_unfixed: bool = False

    # Output
    format: str = "json"
    output_file: Optional[str] = None

    # Database
    skip_db_update: bool = False
    offline_scan: bool = False
    db_repository: Optional[str] = None

    # Cache
    cache_dir: Optional[str] = None
    clear_cache: bool = False

    # Timeout
    timeout: str = "5m"


class TrivyScanner(BaseScanner):
    """
    Scanner for trivy - vulnerability scanner for containers and filesystems.

    Scans:
    - Container images
    - Filesystems
    - Git repositories
    - Kubernetes configs
    - IaC files (Terraform, CloudFormation)
    - SBOMs

    Example:
        scanner = TrivyScanner()

        # Scan filesystem
        result = await scanner.scan("/path/to/project")

        # Scan container image
        result = await scanner.scan("nginx:latest", scan_type="image")
    """

    def __init__(self, config: Optional[TrivyConfig] = None):
        self.config = config or TrivyConfig()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def is_available(self) -> bool:
        """Check if trivy is installed."""
        return shutil.which("trivy") is not None

    async def scan(
        self,
        target: str,
        scan_type: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run trivy scan.

        Args:
            target: Path, image name, or repository URL
            scan_type: Override scan type (fs, image, repo, config)
            **kwargs: Additional options

        Returns:
            ScanResult with vulnerability findings
        """
        result = ScanResult(scanner="trivy", target=target)
        result.start_time = datetime.utcnow()
        self._running = True

        actual_scan_type = scan_type or self.config.scan_type

        try:
            cmd = self._build_command(target, actual_scan_type)
            logger.debug(f"Running: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = process

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=kwargs.get("timeout", 600)
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
            logger.error(f"trivy scan failed: {e}")
        finally:
            self._running = False
            result.end_time = datetime.utcnow()
            if result.start_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

        return result

    def _build_command(self, target: str, scan_type: str) -> List[str]:
        """Build trivy command."""
        cmd = ["trivy", scan_type]

        # Format
        cmd.extend(["--format", self.config.format])

        # Scanners
        cmd.extend(["--scanners", self.config.scanners])

        # Severity
        cmd.extend(["--severity", self.config.severity])

        # Vuln type
        if "vuln" in self.config.scanners:
            cmd.extend(["--vuln-type", self.config.vuln_type])

        # Ignore unfixed
        if self.config.ignore_unfixed:
            cmd.append("--ignore-unfixed")

        # Database options
        if self.config.skip_db_update:
            cmd.append("--skip-db-update")
        if self.config.offline_scan:
            cmd.append("--offline-scan")
        if self.config.db_repository:
            cmd.extend(["--db-repository", self.config.db_repository])

        # Cache
        if self.config.cache_dir:
            cmd.extend(["--cache-dir", self.config.cache_dir])
        if self.config.clear_cache:
            cmd.append("--clear-cache")

        # Timeout
        cmd.extend(["--timeout", self.config.timeout])

        # Output file
        if self.config.output_file:
            cmd.extend(["--output", self.config.output_file])

        # Target
        cmd.append(target)

        return cmd

    def parse_output(self, output: str) -> List[ScanFinding]:
        """Parse trivy JSON output."""
        findings = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.warning("Failed to parse trivy JSON output")
            return findings

        # Handle different output structures
        results = data.get("Results", [])

        for result in results:
            target_name = result.get("Target", "")
            result_class = result.get("Class", "")
            result_type = result.get("Type", "")

            # Vulnerabilities
            for vuln in result.get("Vulnerabilities", []):
                finding = self._vuln_to_finding(vuln, target_name, result_type)
                if finding:
                    findings.append(finding)

            # Misconfigurations
            for misconfig in result.get("Misconfigurations", []):
                finding = self._misconfig_to_finding(misconfig, target_name)
                if finding:
                    findings.append(finding)

            # Secrets
            for secret in result.get("Secrets", []):
                finding = self._secret_to_finding(secret, target_name)
                if finding:
                    findings.append(finding)

        return findings

    def _vuln_to_finding(
        self,
        vuln: Dict[str, Any],
        target: str,
        pkg_type: str,
    ) -> Optional[ScanFinding]:
        """Convert vulnerability to finding."""
        vuln_id = vuln.get("VulnerabilityID", "")
        if not vuln_id:
            return None

        pkg_name = vuln.get("PkgName", "")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")
        title = vuln.get("Title", "")
        description = vuln.get("Description", "")

        # Map severity
        severity_map = {
            "CRITICAL": ScanSeverity.CRITICAL,
            "HIGH": ScanSeverity.HIGH,
            "MEDIUM": ScanSeverity.MEDIUM,
            "LOW": ScanSeverity.LOW,
            "UNKNOWN": ScanSeverity.INFO,
        }
        severity = severity_map.get(vuln.get("Severity", "UNKNOWN"), ScanSeverity.INFO)

        # Build description
        desc_parts = []
        if title:
            desc_parts.append(title)
        if pkg_name:
            desc_parts.append(f"Package: {pkg_name} ({installed_version})")
        if fixed_version:
            desc_parts.append(f"Fixed in: {fixed_version}")

        tags = ["trivy", "vulnerability", pkg_type.lower()] if pkg_type else ["trivy", "vulnerability"]

        # Check if it's a CVE
        cwe = None
        if vuln_id.startswith("CVE-"):
            tags.append("cve")

        # Get CWE IDs
        cwe_ids = vuln.get("CweIDs", [])
        if cwe_ids:
            cwe = cwe_ids[0]

        return ScanFinding(
            title=f"{vuln_id}: {pkg_name}",
            severity=severity,
            description="; ".join(desc_parts) if desc_parts else description[:200],
            evidence=f"Target: {target}",
            cwe=cwe,
            scanner="trivy",
            tags=tags,
        )

    def _misconfig_to_finding(
        self,
        misconfig: Dict[str, Any],
        target: str,
    ) -> Optional[ScanFinding]:
        """Convert misconfiguration to finding."""
        avd_id = misconfig.get("AVDID", misconfig.get("ID", ""))
        title = misconfig.get("Title", "")
        description = misconfig.get("Description", "")
        message = misconfig.get("Message", "")
        resolution = misconfig.get("Resolution", "")

        # Map severity
        severity_map = {
            "CRITICAL": ScanSeverity.CRITICAL,
            "HIGH": ScanSeverity.HIGH,
            "MEDIUM": ScanSeverity.MEDIUM,
            "LOW": ScanSeverity.LOW,
        }
        severity = severity_map.get(misconfig.get("Severity", "LOW"), ScanSeverity.LOW)

        # Build description
        desc = message or description[:200]
        if resolution:
            desc += f" | Fix: {resolution[:100]}"

        return ScanFinding(
            title=f"{avd_id}: {title[:60]}",
            severity=severity,
            description=desc,
            evidence=f"Target: {target}",
            scanner="trivy",
            tags=["trivy", "misconfiguration", "iac"],
        )

    def _secret_to_finding(
        self,
        secret: Dict[str, Any],
        target: str,
    ) -> Optional[ScanFinding]:
        """Convert secret to finding."""
        rule_id = secret.get("RuleID", "")
        category = secret.get("Category", "")
        title = secret.get("Title", "Secret Detected")
        match = secret.get("Match", "")

        return ScanFinding(
            title=f"Secret: {title}",
            severity=ScanSeverity.HIGH,
            description=f"Category: {category}, Rule: {rule_id}",
            evidence=f"Match: {match[:50]}..." if len(match) > 50 else f"Match: {match}",
            scanner="trivy",
            tags=["trivy", "secret", category.lower().replace(" ", "_")],
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


async def scan_image(image: str, **kwargs) -> ScanResult:
    """Convenience function to scan a container image."""
    scanner = TrivyScanner()
    return await scanner.scan(image, scan_type="image", **kwargs)


async def scan_filesystem(path: str, **kwargs) -> ScanResult:
    """Convenience function to scan a filesystem path."""
    scanner = TrivyScanner()
    return await scanner.scan(path, scan_type="fs", **kwargs)


async def scan_repo(url: str, **kwargs) -> ScanResult:
    """Convenience function to scan a git repository."""
    scanner = TrivyScanner()
    return await scanner.scan(url, scan_type="repo", **kwargs)
