"""
AIPTX Smart Deduplicator - Fingerprint-based finding deduplication with merge

This module deduplicates normalized findings using fingerprint matching and
intelligently merges duplicate findings to preserve the best evidence.

Key features:
- SHA256 fingerprint-based grouping (same vuln at same location = duplicate)
- Smart merge strategy: keeps highest severity, prefers CONFIRMED status
- Evidence combination from all duplicates
- Merge tracking for audit trail
- No duplicate fingerprints in output

The deduplicated findings are passed to the Verification Policy Engine.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aipt_v2.models.finding_v2 import (
    FindingV2,
    SeverityV2,
    VerificationStatusV2,
    merge_findings_v2,
)

logger = logging.getLogger(__name__)


@dataclass
class DeduplicationStats:
    """Statistics from deduplication process"""
    total_input: int
    total_output: int
    duplicates_merged: int
    by_category: dict[str, int]
    by_severity: dict[str, int]
    largest_merge_group: int
    merge_details: list[dict[str, Any]]  # Details of each merge operation


def generate_fingerprint(finding: FindingV2) -> str:
    """
    Get the fingerprint for a finding.

    The fingerprint is already computed in FindingV2.__post_init__,
    but this function is exposed for external use if needed.

    The fingerprint is a SHA256 hash of:
    - Normalized host (lowercase, no port)
    - URL path (no query, no fragment, no trailing slash)
    - HTTP method (uppercase)
    - Parameter name (if any)
    - Vulnerability type
    - Category
    - Root cause signature
    """
    return finding.fingerprint


class Deduplicator:
    """
    Smart deduplication engine for FindingV2 objects.

    Groups findings by fingerprint and merges duplicates using a smart
    strategy that preserves the best evidence and highest confidence.

    Usage:
        deduplicator = Deduplicator()
        deduped = deduplicator.deduplicate(findings)
    """

    def __init__(self, strict_mode: bool = True):
        """
        Initialize deduplicator.

        Args:
            strict_mode: If True, raise on any issues. If False, log warnings and continue.
        """
        self.strict_mode = strict_mode
        self.stats: DeduplicationStats | None = None

    def deduplicate(self, findings: list[FindingV2]) -> list[FindingV2]:
        """
        Deduplicate a list of findings using fingerprint matching.

        Process:
        1. Group findings by fingerprint
        2. For single-finding groups, keep as-is
        3. For multi-finding groups, merge into single finding
        4. Validate no duplicate fingerprints remain
        5. Return deduplicated list sorted by severity

        Args:
            findings: List of normalized FindingV2 objects

        Returns:
            Deduplicated list of FindingV2 objects
        """
        if not findings:
            self.stats = DeduplicationStats(
                total_input=0,
                total_output=0,
                duplicates_merged=0,
                by_category={},
                by_severity={},
                largest_merge_group=0,
                merge_details=[],
            )
            return []

        logger.info(f"Deduplicating {len(findings)} findings...")

        # Group by fingerprint
        fingerprint_groups: dict[str, list[FindingV2]] = defaultdict(list)
        for finding in findings:
            fingerprint_groups[finding.fingerprint].append(finding)

        # Process groups
        deduplicated: list[FindingV2] = []
        merge_details: list[dict[str, Any]] = []
        largest_group = 0
        total_merged = 0

        for fingerprint, group in fingerprint_groups.items():
            if len(group) == 1:
                # Single finding, no merge needed
                deduplicated.append(group[0])
            else:
                # Multiple findings with same fingerprint - merge them
                merged = self._merge_group(group)
                deduplicated.append(merged)

                # Track merge details
                merge_details.append({
                    "fingerprint": fingerprint,
                    "merged_count": len(group),
                    "merged_ids": [f.id for f in group],
                    "result_id": merged.id,
                    "result_title": merged.title,
                    "result_severity": merged.severity.value,
                })

                largest_group = max(largest_group, len(group))
                total_merged += len(group) - 1  # -1 because one becomes the result

                logger.debug(
                    f"Merged {len(group)} findings with fingerprint {fingerprint[:16]}... "
                    f"into '{merged.title}'"
                )

        # Validate no duplicates remain
        output_fingerprints = [f.fingerprint for f in deduplicated]
        if len(output_fingerprints) != len(set(output_fingerprints)):
            msg = "Deduplication failed: duplicate fingerprints still exist!"
            if self.strict_mode:
                raise RuntimeError(msg)
            logger.error(msg)

        # Sort by severity (critical first) then by discovery time
        # Normalize datetimes to naive UTC for comparison
        def normalize_dt(dt):
            if dt.tzinfo is not None:
                return dt.replace(tzinfo=None)
            return dt

        deduplicated.sort(
            key=lambda f: (
                -[SeverityV2.INFO, SeverityV2.LOW, SeverityV2.MEDIUM, SeverityV2.HIGH, SeverityV2.CRITICAL].index(f.severity),
                normalize_dt(f.discovered_at),
            )
        )

        # Collect stats
        by_category: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        for f in deduplicated:
            by_category[f.category.value] += 1
            by_severity[f.severity.value] += 1

        self.stats = DeduplicationStats(
            total_input=len(findings),
            total_output=len(deduplicated),
            duplicates_merged=total_merged,
            by_category=dict(by_category),
            by_severity=dict(by_severity),
            largest_merge_group=largest_group,
            merge_details=merge_details,
        )

        logger.info(
            f"Deduplication complete: {len(findings)} -> {len(deduplicated)} findings "
            f"({total_merged} duplicates merged)"
        )

        return deduplicated

    def _merge_group(self, group: list[FindingV2]) -> FindingV2:
        """
        Merge a group of findings with the same fingerprint.

        Uses merge_findings_v2() to combine findings pairwise,
        always keeping the best evidence and highest confidence.
        """
        if len(group) == 1:
            return group[0]

        # Sort to get best finding first (CONFIRMED > LIKELY > etc.)
        status_priority = {
            VerificationStatusV2.CONFIRMED: 0,
            VerificationStatusV2.LIKELY: 1,
            VerificationStatusV2.MANUAL_REVIEW: 2,
            VerificationStatusV2.IN_PROGRESS: 3,
            VerificationStatusV2.PENDING: 4,
            VerificationStatusV2.NEEDS_REVIEW: 5,
            VerificationStatusV2.SUPPRESSED_FP: 6,
        }

        severity_priority = {
            SeverityV2.CRITICAL: 0,
            SeverityV2.HIGH: 1,
            SeverityV2.MEDIUM: 2,
            SeverityV2.LOW: 3,
            SeverityV2.INFO: 4,
        }

        sorted_group = sorted(
            group,
            key=lambda f: (
                status_priority.get(f.verification_status, 99),
                severity_priority.get(f.severity, 99),
            )
        )

        # Start with best finding
        result = sorted_group[0]

        # Merge in rest
        for duplicate in sorted_group[1:]:
            result = merge_findings_v2(result, duplicate)

        return result

    def get_stats(self) -> DeduplicationStats | None:
        """Get statistics from the last deduplication run"""
        return self.stats

    def deduplicate_with_report(self, findings: list[FindingV2]) -> tuple[list[FindingV2], dict[str, Any]]:
        """
        Deduplicate and return both results and a detailed report.

        Args:
            findings: List of normalized FindingV2 objects

        Returns:
            Tuple of (deduplicated findings, stats dict)
        """
        deduplicated = self.deduplicate(findings)

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_input": self.stats.total_input if self.stats else 0,
            "total_output": self.stats.total_output if self.stats else 0,
            "reduction_percent": (
                round((1 - len(deduplicated) / len(findings)) * 100, 1)
                if findings else 0
            ),
            "duplicates_merged": self.stats.duplicates_merged if self.stats else 0,
            "by_category": self.stats.by_category if self.stats else {},
            "by_severity": self.stats.by_severity if self.stats else {},
            "largest_merge_group": self.stats.largest_merge_group if self.stats else 0,
            "merge_operations": self.stats.merge_details if self.stats else [],
        }

        return deduplicated, report


class CrossTargetDeduplicator(Deduplicator):
    """
    Extended deduplicator for cross-target deduplication.

    Useful when scanning multiple targets and wanting to identify
    findings that appear across different targets (e.g., same CVE
    affecting multiple hosts).
    """

    def deduplicate_cross_target(
        self,
        findings: list[FindingV2],
        normalize_target: bool = True
    ) -> tuple[list[FindingV2], list[dict[str, Any]]]:
        """
        Deduplicate while identifying cross-target patterns.

        Args:
            findings: List of findings from multiple targets
            normalize_target: If True, generate fingerprints ignoring target

        Returns:
            Tuple of (deduplicated findings, cross-target patterns)
        """
        # First do normal deduplication
        deduplicated = self.deduplicate(findings)

        # Identify cross-target patterns
        patterns = self._find_cross_target_patterns(deduplicated)

        return deduplicated, patterns

    def _find_cross_target_patterns(self, findings: list[FindingV2]) -> list[dict[str, Any]]:
        """Find patterns that appear across multiple targets"""
        # Group by vuln_type + category (ignoring target)
        pattern_groups: dict[str, list[FindingV2]] = defaultdict(list)

        for finding in findings:
            pattern_key = f"{finding.category.value}|{finding.vuln_type}"
            pattern_groups[pattern_key].append(finding)

        # Find patterns appearing in multiple targets
        patterns = []
        for pattern_key, group in pattern_groups.items():
            targets = set(f.target for f in group)
            if len(targets) > 1:
                patterns.append({
                    "pattern": pattern_key,
                    "category": group[0].category.value,
                    "vuln_type": group[0].vuln_type,
                    "affected_targets": list(targets),
                    "affected_count": len(targets),
                    "total_findings": len(group),
                    "severity": max(f.severity for f in group).value,
                    "example_title": group[0].title,
                })

        # Sort by affected count
        patterns.sort(key=lambda p: -p["affected_count"])

        return patterns
