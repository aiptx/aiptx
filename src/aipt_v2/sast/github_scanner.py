"""
AIPTX GitHub Scanner - Repository Security Scanning

Scans GitHub repositories for security issues:
- Clones/downloads repository
- Runs SAST analysis
- Detects secrets in history
- Analyzes CI/CD configurations
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from aipt_v2.sast.analyzer import SASTAnalyzer, SASTConfig, SASTResult

logger = logging.getLogger(__name__)


@dataclass
class GitHubScanConfig:
    """Configuration for GitHub scanning."""
    clone_depth: int = 1  # Shallow clone depth
    scan_history: bool = False  # Scan git history for secrets
    scan_branches: list[str] = field(default_factory=lambda: ["main", "master"])
    scan_ci_configs: bool = True  # Scan CI/CD configurations
    github_token: Optional[str] = None  # For private repos
    max_repo_size_mb: int = 500  # Max repo size
    cleanup_after: bool = True  # Remove cloned repo
    sast_config: Optional[SASTConfig] = None


@dataclass
class CIConfigFinding:
    """Finding from CI/CD configuration analysis."""
    file_path: str
    issue: str
    severity: str
    line: Optional[int] = None
    remediation: str = ""


@dataclass
class GitHubScanResult:
    """Result of GitHub repository scan."""
    repo_url: str
    repo_name: str
    branch: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    sast_result: Optional[SASTResult] = None
    ci_findings: list[CIConfigFinding] = field(default_factory=list)
    history_secrets: list[dict] = field(default_factory=list)
    repo_metadata: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def total_findings(self) -> int:
        total = len(self.ci_findings) + len(self.history_secrets)
        if self.sast_result:
            total += len(self.sast_result.findings)
        return total


class GitHubScanner:
    """
    GitHub repository security scanner.

    Provides:
    - Repository cloning/downloading
    - SAST analysis of source code
    - Secret detection in git history
    - CI/CD configuration analysis

    Usage:
        scanner = GitHubScanner()
        result = await scanner.scan("https://github.com/owner/repo")
    """

    def __init__(self, config: Optional[GitHubScanConfig] = None):
        """
        Initialize GitHub scanner.

        Args:
            config: Scanning configuration
        """
        self.config = config or GitHubScanConfig()
        self._temp_dir: Optional[str] = None

    async def scan(
        self,
        repo_url: str,
        branch: Optional[str] = None,
        progress_callback: Optional[callable] = None,
    ) -> GitHubScanResult:
        """
        Scan a GitHub repository.

        Args:
            repo_url: GitHub repository URL
            branch: Branch to scan (default: main/master)
            progress_callback: Called with progress updates

        Returns:
            GitHubScanResult with findings
        """
        result = GitHubScanResult(
            repo_url=repo_url,
            repo_name=self._extract_repo_name(repo_url),
            branch=branch or "main",
            started_at=datetime.now(),
        )

        try:
            # Create temp directory
            self._temp_dir = tempfile.mkdtemp(prefix="aiptx_github_")

            # Clone repository
            if progress_callback:
                await self._notify_progress(progress_callback, "Cloning repository...")

            repo_path = await self._clone_repository(repo_url, branch)

            if not repo_path:
                result.error = "Failed to clone repository"
                return result

            # Get repo metadata
            result.repo_metadata = await self._get_repo_metadata(repo_path)

            # Run SAST analysis
            if progress_callback:
                await self._notify_progress(progress_callback, "Running SAST analysis...")

            sast_config = self.config.sast_config or SASTConfig()
            analyzer = SASTAnalyzer(sast_config)
            result.sast_result = await analyzer.scan_directory(
                repo_path,
                progress_callback=progress_callback,
            )

            # Scan CI/CD configurations
            if self.config.scan_ci_configs:
                if progress_callback:
                    await self._notify_progress(progress_callback, "Analyzing CI/CD configs...")
                result.ci_findings = await self._scan_ci_configs(repo_path)

            # Scan git history for secrets
            if self.config.scan_history:
                if progress_callback:
                    await self._notify_progress(progress_callback, "Scanning git history...")
                result.history_secrets = await self._scan_git_history(repo_path)

            result.completed_at = datetime.now()

        except Exception as e:
            logger.error(f"GitHub scan error: {e}", exc_info=True)
            result.error = str(e)

        finally:
            # Cleanup
            if self.config.cleanup_after and self._temp_dir:
                try:
                    shutil.rmtree(self._temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp dir: {e}")

        return result

    async def scan_local_repo(
        self,
        repo_path: str,
        progress_callback: Optional[callable] = None,
    ) -> GitHubScanResult:
        """
        Scan a local git repository.

        Args:
            repo_path: Path to local repository
            progress_callback: Progress callback

        Returns:
            GitHubScanResult
        """
        result = GitHubScanResult(
            repo_url=f"file://{repo_path}",
            repo_name=os.path.basename(repo_path),
            branch="local",
            started_at=datetime.now(),
        )

        try:
            # Get repo metadata
            result.repo_metadata = await self._get_repo_metadata(repo_path)

            # Run SAST analysis
            sast_config = self.config.sast_config or SASTConfig()
            analyzer = SASTAnalyzer(sast_config)
            result.sast_result = await analyzer.scan_directory(
                repo_path,
                progress_callback=progress_callback,
            )

            # Scan CI/CD configurations
            if self.config.scan_ci_configs:
                result.ci_findings = await self._scan_ci_configs(repo_path)

            # Scan git history
            if self.config.scan_history:
                result.history_secrets = await self._scan_git_history(repo_path)

            result.completed_at = datetime.now()

        except Exception as e:
            logger.error(f"Local repo scan error: {e}", exc_info=True)
            result.error = str(e)

        return result

    def _extract_repo_name(self, url: str) -> str:
        """Extract repository name from URL."""
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        return path

    async def _clone_repository(
        self,
        repo_url: str,
        branch: Optional[str],
    ) -> Optional[str]:
        """Clone repository to temp directory."""
        repo_path = os.path.join(self._temp_dir, "repo")

        # Build git clone command
        cmd = ["git", "clone", "--depth", str(self.config.clone_depth)]

        if branch:
            cmd.extend(["--branch", branch])

        # Add authentication if token provided
        if self.config.github_token:
            parsed = urlparse(repo_url)
            auth_url = f"https://{self.config.github_token}@{parsed.netloc}{parsed.path}"
            cmd.append(auth_url)
        else:
            cmd.append(repo_url)

        cmd.append(repo_path)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Git clone failed: {stderr.decode()}")
                return None

            return repo_path

        except Exception as e:
            logger.error(f"Clone error: {e}")
            return None

    async def _get_repo_metadata(self, repo_path: str) -> dict:
        """Get repository metadata."""
        metadata = {
            "languages": {},
            "file_count": 0,
            "total_lines": 0,
        }

        try:
            # Count files by language
            for root, _, files in os.walk(repo_path):
                if ".git" in root:
                    continue

                for filename in files:
                    metadata["file_count"] += 1

                    ext = filename.split(".")[-1].lower() if "." in filename else "other"
                    metadata["languages"][ext] = metadata["languages"].get(ext, 0) + 1

                    # Count lines
                    try:
                        file_path = os.path.join(root, filename)
                        with open(file_path, "r", errors="ignore") as f:
                            metadata["total_lines"] += sum(1 for _ in f)
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"Metadata extraction error: {e}")

        return metadata

    async def _scan_ci_configs(self, repo_path: str) -> list[CIConfigFinding]:
        """Scan CI/CD configuration files for security issues."""
        findings = []

        # CI/CD configuration files to check
        ci_files = [
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".travis.yml",
            "azure-pipelines.yml",
            ".circleci/config.yml",
            "bitbucket-pipelines.yml",
        ]

        import glob

        for pattern in ci_files:
            for file_path in glob.glob(os.path.join(repo_path, pattern)):
                findings.extend(await self._analyze_ci_file(file_path))

        return findings

    async def _analyze_ci_file(self, file_path: str) -> list[CIConfigFinding]:
        """Analyze a single CI configuration file."""
        findings = []

        try:
            with open(file_path, "r") as f:
                content = f.read()
                lines = content.split("\n")

            rel_path = os.path.basename(file_path)

            # Check for common CI security issues
            checks = [
                (r"--no-verify", "Git hooks bypassed", "medium",
                 "Remove --no-verify to enable git hooks"),
                (r"npm\s+config\s+set\s+strict-ssl\s+false", "SSL verification disabled", "high",
                 "Enable SSL verification"),
                (r"curl\s+-k\s+", "Insecure curl (no cert validation)", "high",
                 "Remove -k flag from curl"),
                (r"wget\s+--no-check-certificate", "Insecure wget", "high",
                 "Enable certificate checking"),
                (r"\$\{\{\s*secrets\.", "Secret usage (verify proper handling)", "info",
                 "Ensure secrets are properly scoped"),
                (r"password\s*:\s*['\"][^$]+['\"]", "Hardcoded password in CI", "critical",
                 "Use secrets instead of hardcoded passwords"),
                (r"pip\s+install\s+--trusted-host", "Trusted host override", "medium",
                 "Use HTTPS package sources"),
                (r"sudo\s+", "Sudo usage in CI", "low",
                 "Minimize use of sudo in CI"),
                (r"docker\s+run.*--privileged", "Privileged Docker container", "high",
                 "Avoid privileged containers"),
            ]

            import re

            for i, line in enumerate(lines, 1):
                for pattern, issue, severity, remediation in checks:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(
                            CIConfigFinding(
                                file_path=rel_path,
                                issue=issue,
                                severity=severity,
                                line=i,
                                remediation=remediation,
                            )
                        )

        except Exception as e:
            logger.debug(f"CI file analysis error: {e}")

        return findings

    async def _scan_git_history(self, repo_path: str) -> list[dict]:
        """Scan git history for secrets."""
        secrets = []

        try:
            # Use git log to search for potential secrets
            cmd = [
                "git", "-C", repo_path, "log",
                "--all", "--full-history",
                "-p", "--max-count=100",  # Limit history depth
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await process.communicate()

            if process.returncode == 0:
                diff_content = stdout.decode(errors="ignore")
                secrets = self._find_secrets_in_diff(diff_content)

        except Exception as e:
            logger.debug(f"Git history scan error: {e}")

        return secrets

    def _find_secrets_in_diff(self, diff_content: str) -> list[dict]:
        """Find potential secrets in git diff output."""
        import re

        secrets = []
        secret_patterns = [
            (r"(?i)password\s*[=:]\s*['\"][^'\"]{8,}['\"]", "password"),
            (r"(?i)api_key\s*[=:]\s*['\"][^'\"]+['\"]", "api_key"),
            (r"ghp_[0-9a-zA-Z]{36}", "github_token"),
            (r"sk_live_[0-9a-zA-Z]{24}", "stripe_key"),
            (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
            (r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----", "private_key"),
        ]

        current_commit = None
        current_file = None

        for line in diff_content.split("\n"):
            # Track commit
            if line.startswith("commit "):
                current_commit = line.split()[1][:8]

            # Track file
            if line.startswith("+++ b/"):
                current_file = line[6:]

            # Check added lines for secrets
            if line.startswith("+") and not line.startswith("+++"):
                for pattern, secret_type in secret_patterns:
                    if re.search(pattern, line):
                        secrets.append({
                            "type": secret_type,
                            "commit": current_commit,
                            "file": current_file,
                            "line_preview": line[:100],
                        })

        return secrets

    async def _notify_progress(self, callback: callable, message: str) -> None:
        """Send progress notification."""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback({"status": message})
            else:
                callback({"status": message})
        except Exception:
            pass


# Convenience function
async def scan_github_repo(
    repo_url: str,
    branch: Optional[str] = None,
    **config_kwargs,
) -> GitHubScanResult:
    """
    Convenience function to scan a GitHub repository.

    Args:
        repo_url: GitHub repository URL
        branch: Branch to scan
        **config_kwargs: GitHubScanConfig parameters

    Returns:
        GitHubScanResult
    """
    config = GitHubScanConfig(**config_kwargs)
    scanner = GitHubScanner(config)
    return await scanner.scan(repo_url, branch)
