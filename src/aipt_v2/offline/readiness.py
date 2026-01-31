"""
AIPTX Offline Readiness Checker
===============================

Verifies that the system is ready for fully offline operation.
Checks all required data sources, tools, and configurations.
"""

import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Result of a single readiness check."""

    name: str
    passed: bool
    critical: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "critical": self.critical,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ReadinessResult:
    """Overall readiness check result."""

    ready: bool
    checks: List[CheckResult]
    critical_failures: List[str]
    warnings: List[str]
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ready": self.ready,
            "checks": [c.to_dict() for c in self.checks],
            "critical_failures": self.critical_failures,
            "warnings": self.warnings,
            "timestamp": self.timestamp.isoformat(),
        }

    def summary(self) -> str:
        """Generate human-readable summary."""
        passed = sum(1 for c in self.checks if c.passed)
        total = len(self.checks)
        status = "READY" if self.ready else "NOT READY"

        lines = [
            f"Offline Readiness: {status}",
            f"Checks Passed: {passed}/{total}",
        ]

        if self.critical_failures:
            lines.append(f"\nCritical Failures ({len(self.critical_failures)}):")
            for failure in self.critical_failures:
                lines.append(f"  - {failure}")

        if self.warnings:
            lines.append(f"\nWarnings ({len(self.warnings)}):")
            for warning in self.warnings:
                lines.append(f"  - {warning}")

        return "\n".join(lines)


class OfflineReadinessChecker:
    """
    Checks if AIPTX is ready for offline operation.

    Verifies:
    - Required data sources (nuclei templates, wordlists, etc.)
    - Required tools are installed
    - Ollama is running and has models
    - Configuration is correct

    Example:
        checker = OfflineReadinessChecker()
        result = await checker.check_all()

        if result.ready:
            print("System is ready for offline operation!")
        else:
            print(result.summary())
    """

    # Required data sources
    REQUIRED_DATA = {
        "nuclei_templates": {
            "path": "nuclei-templates",
            "min_files": 5000,
            "critical": True,
            "description": "Nuclei vulnerability templates",
        },
        "wordlists": {
            "path": "wordlists",
            "min_files": 100,
            "critical": True,
            "description": "Wordlists for fuzzing and brute-forcing",
        },
        "exploitdb": {
            "path": "exploitdb",
            "min_files": 40000,
            "critical": False,
            "description": "ExploitDB archive for searchsploit",
        },
        "cve_database": {
            "path": "cve",
            "min_files": 1,
            "critical": False,
            "description": "CVE/NVD vulnerability database",
        },
    }

    # Required tools
    REQUIRED_TOOLS = {
        "core": {
            "tools": ["nmap", "nuclei", "httpx", "subfinder"],
            "critical": True,
            "description": "Core scanning tools",
        },
        "recon": {
            "tools": ["amass", "dnsx", "katana", "waybackurls"],
            "critical": False,
            "description": "Reconnaissance tools",
        },
        "scanning": {
            "tools": ["nikto", "ffuf", "gobuster"],
            "critical": False,
            "description": "Web scanning tools",
        },
        "exploitation": {
            "tools": ["sqlmap", "hydra"],
            "critical": False,
            "description": "Exploitation tools",
        },
    }

    def __init__(self, data_path: Optional[Path] = None, ollama_url: str = "http://localhost:11434"):
        """
        Initialize the readiness checker.

        Args:
            data_path: Path to offline data directory
            ollama_url: URL of Ollama server
        """
        self.data_path = data_path or Path.home() / ".aiptx" / "data"
        self.ollama_url = ollama_url

    async def check_all(self) -> ReadinessResult:
        """
        Run all readiness checks.

        Returns:
            ReadinessResult with all check results
        """
        checks: List[CheckResult] = []

        # Run all checks concurrently
        data_checks = await self._check_data_sources()
        checks.extend(data_checks)

        tool_checks = await self._check_tools()
        checks.extend(tool_checks)

        ollama_check = await self._check_ollama()
        checks.append(ollama_check)

        config_check = self._check_configuration()
        checks.append(config_check)

        # Determine overall readiness
        critical_failures = [
            c.message for c in checks if not c.passed and c.critical
        ]
        warnings = [
            c.message for c in checks if not c.passed and not c.critical
        ]

        ready = len(critical_failures) == 0

        return ReadinessResult(
            ready=ready,
            checks=checks,
            critical_failures=critical_failures,
            warnings=warnings,
        )

    async def _check_data_sources(self) -> List[CheckResult]:
        """Check all required data sources."""
        results = []

        for source_key, source_info in self.REQUIRED_DATA.items():
            path = self.data_path / source_info["path"]

            if not path.exists():
                results.append(CheckResult(
                    name=f"data_{source_key}",
                    passed=False,
                    critical=source_info["critical"],
                    message=f"Missing {source_info['description']}: {path}",
                    details={"path": str(path), "exists": False},
                ))
                continue

            # Count files
            try:
                file_count = len([f for f in path.rglob("*") if f.is_file()])
                min_files = source_info["min_files"]

                if file_count >= min_files:
                    results.append(CheckResult(
                        name=f"data_{source_key}",
                        passed=True,
                        critical=source_info["critical"],
                        message=f"{source_info['description']}: OK ({file_count} files)",
                        details={"path": str(path), "file_count": file_count},
                    ))
                else:
                    results.append(CheckResult(
                        name=f"data_{source_key}",
                        passed=False,
                        critical=source_info["critical"],
                        message=f"{source_info['description']}: Incomplete ({file_count}/{min_files} files)",
                        details={"path": str(path), "file_count": file_count, "min_required": min_files},
                    ))
            except Exception as e:
                results.append(CheckResult(
                    name=f"data_{source_key}",
                    passed=False,
                    critical=source_info["critical"],
                    message=f"Error checking {source_info['description']}: {e}",
                    details={"error": str(e)},
                ))

        return results

    async def _check_tools(self) -> List[CheckResult]:
        """Check all required tools are installed."""
        results = []

        for group_key, group_info in self.REQUIRED_TOOLS.items():
            available = []
            missing = []

            for tool in group_info["tools"]:
                if shutil.which(tool):
                    available.append(tool)
                else:
                    missing.append(tool)

            if not missing:
                results.append(CheckResult(
                    name=f"tools_{group_key}",
                    passed=True,
                    critical=group_info["critical"],
                    message=f"{group_info['description']}: All installed",
                    details={"available": available},
                ))
            else:
                results.append(CheckResult(
                    name=f"tools_{group_key}",
                    passed=False,
                    critical=group_info["critical"],
                    message=f"{group_info['description']}: Missing {', '.join(missing)}",
                    details={"available": available, "missing": missing},
                ))

        return results

    async def _check_ollama(self) -> CheckResult:
        """Check if Ollama is running and has models."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                # Check if Ollama is running
                response = await client.get(f"{self.ollama_url}/api/tags")
                response.raise_for_status()

                data = response.json()
                models = data.get("models", [])

                if not models:
                    return CheckResult(
                        name="ollama",
                        passed=False,
                        critical=True,
                        message="Ollama running but no models installed",
                        details={"running": True, "models": []},
                    )

                model_names = [m.get("name", "unknown") for m in models]

                # Check for recommended models
                recommended = ["mistral", "llama", "deepseek", "codellama", "phi"]
                has_recommended = any(
                    any(rec in name.lower() for rec in recommended)
                    for name in model_names
                )

                if has_recommended:
                    return CheckResult(
                        name="ollama",
                        passed=True,
                        critical=True,
                        message=f"Ollama ready with {len(models)} models",
                        details={"running": True, "models": model_names},
                    )
                else:
                    return CheckResult(
                        name="ollama",
                        passed=True,
                        critical=True,
                        message=f"Ollama running but no recommended models ({', '.join(recommended[:3])}...)",
                        details={"running": True, "models": model_names, "warning": "No recommended models"},
                    )

        except httpx.ConnectError:
            return CheckResult(
                name="ollama",
                passed=False,
                critical=True,
                message="Ollama not running at " + self.ollama_url,
                details={"running": False, "error": "Connection refused"},
            )
        except Exception as e:
            return CheckResult(
                name="ollama",
                passed=False,
                critical=True,
                message=f"Error checking Ollama: {e}",
                details={"error": str(e)},
            )

    def _check_configuration(self) -> CheckResult:
        """Check configuration is correct for offline mode."""
        issues = []

        # Check data path exists
        if not self.data_path.exists():
            issues.append(f"Data path does not exist: {self.data_path}")

        # Check config file exists
        config_file = Path.home() / ".aiptx" / ".env"
        if not config_file.exists():
            issues.append("No configuration file found (~/.aiptx/.env)")

        if issues:
            return CheckResult(
                name="configuration",
                passed=False,
                critical=False,
                message="Configuration issues: " + "; ".join(issues),
                details={"issues": issues},
            )

        return CheckResult(
            name="configuration",
            passed=True,
            critical=False,
            message="Configuration OK",
            details={"config_file": str(config_file)},
        )

    def get_missing_critical(self) -> List[str]:
        """
        Get list of missing critical components.

        Returns:
            List of missing critical component descriptions
        """
        missing = []

        # Check critical data
        for source_key, source_info in self.REQUIRED_DATA.items():
            if not source_info["critical"]:
                continue

            path = self.data_path / source_info["path"]
            if not path.exists():
                missing.append(source_info["description"])
                continue

            file_count = len([f for f in path.rglob("*") if f.is_file()])
            if file_count < source_info["min_files"]:
                missing.append(f"{source_info['description']} (incomplete)")

        # Check critical tools
        for group_key, group_info in self.REQUIRED_TOOLS.items():
            if not group_info["critical"]:
                continue

            for tool in group_info["tools"]:
                if not shutil.which(tool):
                    missing.append(f"Tool: {tool}")

        return missing

    async def quick_check(self) -> bool:
        """
        Quick check if system is likely ready.

        Returns:
            True if critical components are available
        """
        # Check Ollama
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2) as client:
                response = await client.get(f"{self.ollama_url}/api/tags")
                if response.status_code != 200:
                    return False
        except Exception:
            return False

        # Check critical data paths exist
        for source_key, source_info in self.REQUIRED_DATA.items():
            if source_info["critical"]:
                path = self.data_path / source_info["path"]
                if not path.exists():
                    return False

        # Check critical tools
        for group_key, group_info in self.REQUIRED_TOOLS.items():
            if group_info["critical"]:
                for tool in group_info["tools"]:
                    if not shutil.which(tool):
                        return False

        return True
