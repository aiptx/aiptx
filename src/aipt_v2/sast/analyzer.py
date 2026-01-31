"""
AIPTX SAST Analyzer - Core Static Analysis Engine

The SAST Analyzer orchestrates:
- Language detection
- Code parsing
- Rule matching
- Finding generation
- Report creation
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from aipt_v2.sast.parsers import (
    get_parser_for_file,
    get_supported_extensions,
    ParsedFile,
)
from aipt_v2.sast.rules import (
    get_rules_for_language,
    SecretDetectionRules,
    RuleMatch,
    RuleSeverity,
)
from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    FindingStatus,
    VulnerabilityType,
)

logger = logging.getLogger(__name__)


@dataclass
class SASTConfig:
    """Configuration for SAST analysis."""
    max_file_size_mb: float = 5.0
    max_files: int = 10000
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "**/node_modules/**",
        "**/.git/**",
        "**/vendor/**",
        "**/dist/**",
        "**/build/**",
        "**/__pycache__/**",
        "**/*.min.js",
        "**/*.min.css",
    ])
    enabled_categories: list[str] = field(default_factory=list)  # Empty = all
    min_severity: RuleSeverity = RuleSeverity.LOW
    enable_secrets_detection: bool = True
    parallel_files: int = 10


@dataclass
class SASTFinding:
    """A finding from SAST analysis."""
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    file_path: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    code_snippet: str = ""
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    remediation: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    confidence: float = 0.8
    references: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_finding(self) -> Finding:
        """Convert to standard Finding object."""
        # Map severity
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        severity = severity_map.get(self.severity.lower(), FindingSeverity.MEDIUM)

        # Map category to vulnerability type
        vuln_type_map = {
            "injection": VulnerabilityType.SQLI,
            "xss": VulnerabilityType.XSS,
            "ssrf": VulnerabilityType.SSRF,
            "path_traversal": VulnerabilityType.LFI,
            "deserialization": VulnerabilityType.DESERIALIZATION,
            "xxe": VulnerabilityType.XXE,
            "crypto": VulnerabilityType.WEAK_CRYPTO,
            "auth": VulnerabilityType.AUTH_BYPASS,
            "secrets": VulnerabilityType.INFO_DISCLOSURE,
            "config": VulnerabilityType.MISCONFIG,
        }
        vuln_type = vuln_type_map.get(self.category.lower(), VulnerabilityType.OTHER)

        return Finding(
            title=self.title,
            description=self.description,
            severity=severity,
            vuln_type=vuln_type,
            target=self.file_path,
            url=f"file://{self.file_path}",
            component=self.file_path,
            line=self.line,
            code_snippet=self.code_snippet,
            confidence=self.confidence,
            cwe_ids=self.cwe_ids,
            remediation=self.remediation,
            status=FindingStatus.NEW,
            source="sast",
            metadata={
                "rule_id": self.rule_id,
                "category": self.category,
                "owasp_ids": self.owasp_ids,
                "references": self.references,
            },
        )


@dataclass
class SASTResult:
    """Result of SAST analysis."""
    target_path: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: list[SASTFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_with_findings: int = 0
    parse_errors: list[str] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0

    def get_findings_by_severity(self, severity: str) -> list[SASTFinding]:
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def get_statistics(self) -> dict:
        """Get analysis statistics."""
        stats = {
            "total_findings": len(self.findings),
            "files_scanned": self.files_scanned,
            "files_with_findings": self.files_with_findings,
            "duration_seconds": self.duration_seconds,
            "by_severity": {},
            "by_category": {},
        }

        for finding in self.findings:
            # By severity
            sev = finding.severity.lower()
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

            # By category
            cat = finding.category
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        return stats


class SASTAnalyzer:
    """
    Core SAST analysis engine.

    Provides static analysis capabilities:
    - Multi-language support (Python, JS, Java, Go)
    - Rule-based detection
    - Secret detection
    - Data flow analysis
    - Parallel file processing

    Usage:
        analyzer = SASTAnalyzer()
        result = await analyzer.scan_directory("/path/to/project")
        for finding in result.findings:
            print(f"{finding.severity}: {finding.title} at {finding.file_path}:{finding.line}")
    """

    def __init__(self, config: Optional[SASTConfig] = None):
        """
        Initialize SAST analyzer.

        Args:
            config: Analysis configuration
        """
        self.config = config or SASTConfig()
        self._secrets_rules = SecretDetectionRules() if self.config.enable_secrets_detection else None

    async def scan_directory(
        self,
        directory: str,
        progress_callback: Optional[callable] = None,
    ) -> SASTResult:
        """
        Scan a directory for security issues.

        Args:
            directory: Path to directory
            progress_callback: Called with progress updates

        Returns:
            SASTResult with findings
        """
        result = SASTResult(
            target_path=directory,
            started_at=datetime.now(),
        )

        # Find files to scan
        files = self._find_files(directory)
        logger.info(f"[SAST] Found {len(files)} files to scan in {directory}")

        if not files:
            result.completed_at = datetime.now()
            return result

        # Process files in parallel
        semaphore = asyncio.Semaphore(self.config.parallel_files)

        async def scan_with_semaphore(file_path: str) -> list[SASTFinding]:
            async with semaphore:
                return await self._scan_file(file_path, result)

        # Create tasks
        tasks = [scan_with_semaphore(f) for f in files]

        # Execute with progress tracking
        completed = 0
        for coro in asyncio.as_completed(tasks):
            findings = await coro
            result.findings.extend(findings)
            if findings:
                result.files_with_findings += 1

            completed += 1
            result.files_scanned = completed

            if progress_callback:
                try:
                    if asyncio.iscoroutinefunction(progress_callback):
                        await progress_callback({
                            "completed": completed,
                            "total": len(files),
                            "findings": len(result.findings),
                        })
                    else:
                        progress_callback({
                            "completed": completed,
                            "total": len(files),
                            "findings": len(result.findings),
                        })
                except Exception as e:
                    logger.warning(f"Progress callback error: {e}")

        result.completed_at = datetime.now()
        result.statistics = result.get_statistics()

        logger.info(
            f"[SAST] Scan complete: {len(result.findings)} findings in "
            f"{result.files_with_findings}/{result.files_scanned} files"
        )

        return result

    async def scan_file(self, file_path: str) -> list[SASTFinding]:
        """
        Scan a single file for security issues.

        Args:
            file_path: Path to file

        Returns:
            List of findings
        """
        result = SASTResult(target_path=file_path, started_at=datetime.now())
        findings = await self._scan_file(file_path, result)
        return findings

    async def scan_content(
        self,
        content: str,
        file_path: str,
        language: Optional[str] = None,
    ) -> list[SASTFinding]:
        """
        Scan source code content directly.

        Args:
            content: Source code content
            file_path: File path (for reporting and language detection)
            language: Optional language override

        Returns:
            List of findings
        """
        findings = []

        # Get parser
        parser = get_parser_for_file(file_path)
        if not parser and language:
            # Try language-based lookup
            ext_map = {"python": "py", "javascript": "js", "java": "java", "go": "go"}
            fake_path = f"file.{ext_map.get(language.lower(), language)}"
            parser = get_parser_for_file(fake_path)

        if parser:
            try:
                parsed = parser.parse(content, file_path)
                findings.extend(self._analyze_parsed(parsed))
            except Exception as e:
                logger.debug(f"Parse error for {file_path}: {e}")

        # Apply secret detection
        if self._secrets_rules:
            matches = self._secrets_rules.match_content(content, file_path)
            findings.extend(self._matches_to_findings(matches))

        return findings

    async def _scan_file(
        self,
        file_path: str,
        result: SASTResult,
    ) -> list[SASTFinding]:
        """Scan a single file."""
        findings = []

        try:
            # Check file size
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if file_size_mb > self.config.max_file_size_mb:
                logger.debug(f"Skipping large file: {file_path} ({file_size_mb:.1f}MB)")
                return findings

            # Get parser for file
            parser = get_parser_for_file(file_path)
            if not parser:
                return findings

            # Read and parse file
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            parsed = parser.parse(content, file_path)

            if parsed.parse_errors:
                result.parse_errors.extend(parsed.parse_errors)

            # Analyze parsed file
            findings.extend(self._analyze_parsed(parsed))

            # Apply secret detection
            if self._secrets_rules:
                matches = self._secrets_rules.match_content(content, file_path)
                findings.extend(self._matches_to_findings(matches))

        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
            result.parse_errors.append(f"{file_path}: {e}")

        return findings

    def _analyze_parsed(self, parsed: ParsedFile) -> list[SASTFinding]:
        """Analyze a parsed file with language-specific rules."""
        findings = []

        # Get language-specific rules
        ruleset = get_rules_for_language(parsed.language.value)

        # Match rules against file
        matches = ruleset.match_file(parsed)
        findings.extend(self._matches_to_findings(matches))

        # Convert security patterns from parser
        for pattern in parsed.security_patterns:
            findings.append(
                SASTFinding(
                    rule_id=f"PATTERN-{pattern.pattern_type.upper()}",
                    title=f"Security Pattern: {pattern.pattern_type}",
                    description=pattern.context.get("description", f"Detected {pattern.pattern_type} pattern"),
                    severity="medium",
                    category=pattern.pattern_type,
                    file_path=pattern.location.file_path,
                    line=pattern.location.line,
                    code_snippet=pattern.code,
                )
            )

        # Analyze data flows
        for flow in parsed.data_flows:
            findings.append(
                SASTFinding(
                    rule_id="DATAFLOW-001",
                    title=f"Data Flow: {flow.source} to {flow.sink}",
                    description=f"User input from {flow.source} flows to {flow.sink}",
                    severity="medium",
                    category="injection",
                    file_path=flow.source_location.file_path,
                    line=flow.source_location.line,
                    code_snippet=parsed.get_line(flow.source_location.line),
                    cwe_ids=["CWE-20"],
                    remediation=f"Validate/sanitize data before using in {flow.sink}",
                )
            )

        return findings

    def _matches_to_findings(self, matches: list[RuleMatch]) -> list[SASTFinding]:
        """Convert rule matches to SAST findings."""
        findings = []

        for match in matches:
            findings.append(
                SASTFinding(
                    rule_id=match.rule.id,
                    title=match.rule.name,
                    description=match.rule.description,
                    severity=match.rule.severity.value,
                    category=match.rule.category.value,
                    file_path=match.file_path,
                    line=match.line,
                    column=match.column,
                    code_snippet=match.code_snippet,
                    context_before=match.context_before,
                    context_after=match.context_after,
                    remediation=match.rule.remediation,
                    cwe_ids=match.rule.cwe_ids,
                    owasp_ids=match.rule.owasp_ids,
                    confidence=match.confidence,
                    references=match.rule.references,
                )
            )

        return findings

    def _find_files(self, directory: str) -> list[str]:
        """Find files to scan in directory."""
        import fnmatch

        files = []
        supported_exts = get_supported_extensions()
        directory = os.path.abspath(directory)

        for root, dirs, filenames in os.walk(directory):
            # Apply exclude patterns to directories
            dirs[:] = [
                d for d in dirs
                if not any(
                    fnmatch.fnmatch(os.path.join(root, d), pattern)
                    for pattern in self.config.exclude_patterns
                )
            ]

            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, directory)

                # Check exclude patterns
                if any(fnmatch.fnmatch(rel_path, p) for p in self.config.exclude_patterns):
                    continue

                # Check extension
                ext = filename.split(".")[-1].lower() if "." in filename else ""
                if ext not in supported_exts:
                    continue

                # Check include patterns (if specified)
                if self.config.include_patterns:
                    if not any(fnmatch.fnmatch(rel_path, p) for p in self.config.include_patterns):
                        continue

                files.append(file_path)

                if len(files) >= self.config.max_files:
                    logger.warning(f"Reached max files limit ({self.config.max_files})")
                    return files

        return files


# Convenience functions
async def scan_directory(
    directory: str,
    **config_kwargs,
) -> SASTResult:
    """
    Convenience function to scan a directory.

    Args:
        directory: Path to directory
        **config_kwargs: SASTConfig parameters

    Returns:
        SASTResult
    """
    config = SASTConfig(**config_kwargs)
    analyzer = SASTAnalyzer(config)
    return await analyzer.scan_directory(directory)


async def scan_file(file_path: str) -> list[SASTFinding]:
    """
    Convenience function to scan a single file.

    Args:
        file_path: Path to file

    Returns:
        List of SASTFindings
    """
    analyzer = SASTAnalyzer()
    return await analyzer.scan_file(file_path)
