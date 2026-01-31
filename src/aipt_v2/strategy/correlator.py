"""
AIPTX SAST-DAST Correlator - Finding Correlation

Correlates findings from static (SAST) and dynamic (DAST) analysis:
- Matches source vulnerabilities to runtime exploits
- Increases confidence when both detect the same issue
- Identifies confirmed vs. potential vulnerabilities
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from aipt_v2.sast.analyzer import SASTFinding
from aipt_v2.agents.shared.finding_repository import Finding, FindingSeverity

logger = logging.getLogger(__name__)


class CorrelationType(str, Enum):
    """Types of correlation between findings."""
    EXACT = "exact"              # Same vulnerability confirmed by both
    RELATED = "related"          # Related vulnerabilities
    SAST_ONLY = "sast_only"      # Only found in source
    DAST_ONLY = "dast_only"      # Only found at runtime
    COMPLEMENTARY = "complementary"  # Different aspects of same issue


class ConfidenceLevel(str, Enum):
    """Confidence level after correlation."""
    CONFIRMED = "confirmed"      # Both SAST and DAST agree
    HIGH = "high"               # Strong indicators from one source
    MEDIUM = "medium"           # Some indicators
    LOW = "low"                 # Weak indicators


@dataclass
class CorrelatedFinding:
    """A finding with correlation information."""
    primary_finding: Finding | SASTFinding
    correlated_findings: list[Finding | SASTFinding] = field(default_factory=list)
    correlation_type: CorrelationType = CorrelationType.SAST_ONLY
    confidence_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    correlation_score: float = 0.0
    correlation_reason: str = ""
    combined_evidence: list[dict] = field(default_factory=list)

    @property
    def title(self) -> str:
        return self.primary_finding.title

    @property
    def severity(self) -> str:
        if isinstance(self.primary_finding, Finding):
            return self.primary_finding.severity.value
        return self.primary_finding.severity

    @property
    def is_confirmed(self) -> bool:
        return self.confidence_level == ConfidenceLevel.CONFIRMED

    def to_finding(self) -> Finding:
        """Convert to a standard Finding with correlation data."""
        if isinstance(self.primary_finding, Finding):
            finding = self.primary_finding
        else:
            finding = self.primary_finding.to_finding()

        # Update confidence based on correlation
        if self.confidence_level == ConfidenceLevel.CONFIRMED:
            finding.confidence = min(1.0, finding.confidence + 0.2)
        elif self.confidence_level == ConfidenceLevel.HIGH:
            finding.confidence = min(1.0, finding.confidence + 0.1)

        # Add correlation metadata
        finding.metadata["correlation"] = {
            "type": self.correlation_type.value,
            "confidence": self.confidence_level.value,
            "score": self.correlation_score,
            "correlated_count": len(self.correlated_findings),
        }

        return finding


class SASTDASTCorrelator:
    """
    Correlates SAST and DAST findings.

    Provides:
    - Matching of source-level findings to runtime findings
    - Confidence boosting for correlated findings
    - Deduplication of redundant findings
    - Combined evidence from multiple sources

    Usage:
        correlator = SASTDASTCorrelator()
        correlated = correlator.correlate(sast_findings, dast_findings)
    """

    def __init__(self):
        """Initialize correlator."""
        # Mapping of vulnerability types for correlation
        self._vuln_type_map = {
            # SAST category -> DAST vulnerability types
            "injection": ["sqli", "cmdi", "ldapi", "xpathi", "ssrf"],
            "sql_injection": ["sqli"],
            "xss": ["xss", "dom_xss"],
            "path_traversal": ["lfi", "rfi", "path_traversal"],
            "deserialization": ["deserialization", "rce"],
            "xxe": ["xxe"],
            "crypto": ["weak_crypto", "sensitive_exposure"],
            "auth": ["auth_bypass", "session", "idor"],
            "secrets": ["info_disclosure", "sensitive_exposure"],
            "ssrf": ["ssrf"],
        }

    def correlate(
        self,
        sast_findings: list[SASTFinding],
        dast_findings: list[Finding],
    ) -> list[CorrelatedFinding]:
        """
        Correlate SAST and DAST findings.

        Args:
            sast_findings: Findings from static analysis
            dast_findings: Findings from dynamic analysis

        Returns:
            List of correlated findings
        """
        correlated = []
        used_sast = set()
        used_dast = set()

        # First pass: Find exact matches
        for i, sast in enumerate(sast_findings):
            for j, dast in enumerate(dast_findings):
                if j in used_dast:
                    continue

                score = self._calculate_correlation_score(sast, dast)

                if score >= 0.7:  # High correlation threshold
                    correlated.append(
                        CorrelatedFinding(
                            primary_finding=dast,  # DAST has runtime evidence
                            correlated_findings=[sast],
                            correlation_type=CorrelationType.EXACT,
                            confidence_level=ConfidenceLevel.CONFIRMED,
                            correlation_score=score,
                            correlation_reason=self._generate_reason(sast, dast, score),
                        )
                    )
                    used_sast.add(i)
                    used_dast.add(j)
                    break

                elif score >= 0.4:  # Related correlation threshold
                    correlated.append(
                        CorrelatedFinding(
                            primary_finding=dast,
                            correlated_findings=[sast],
                            correlation_type=CorrelationType.RELATED,
                            confidence_level=ConfidenceLevel.HIGH,
                            correlation_score=score,
                            correlation_reason=self._generate_reason(sast, dast, score),
                        )
                    )
                    used_sast.add(i)
                    used_dast.add(j)
                    break

        # Second pass: Add uncorrelated SAST findings
        for i, sast in enumerate(sast_findings):
            if i not in used_sast:
                correlated.append(
                    CorrelatedFinding(
                        primary_finding=sast,
                        correlation_type=CorrelationType.SAST_ONLY,
                        confidence_level=self._sast_confidence(sast),
                        correlation_reason="Source-level finding not confirmed at runtime",
                    )
                )

        # Third pass: Add uncorrelated DAST findings
        for j, dast in enumerate(dast_findings):
            if j not in used_dast:
                correlated.append(
                    CorrelatedFinding(
                        primary_finding=dast,
                        correlation_type=CorrelationType.DAST_ONLY,
                        confidence_level=self._dast_confidence(dast),
                        correlation_reason="Runtime finding without source correlation",
                    )
                )

        # Sort by confidence and severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        confidence_order = {
            ConfidenceLevel.CONFIRMED: 0,
            ConfidenceLevel.HIGH: 1,
            ConfidenceLevel.MEDIUM: 2,
            ConfidenceLevel.LOW: 3,
        }

        correlated.sort(
            key=lambda c: (
                confidence_order.get(c.confidence_level, 5),
                severity_order.get(c.severity.lower(), 5),
            )
        )

        logger.info(
            f"[Correlator] {len(correlated)} findings: "
            f"{sum(1 for c in correlated if c.is_confirmed)} confirmed, "
            f"{sum(1 for c in correlated if c.correlation_type == CorrelationType.SAST_ONLY)} SAST-only, "
            f"{sum(1 for c in correlated if c.correlation_type == CorrelationType.DAST_ONLY)} DAST-only"
        )

        return correlated

    def _calculate_correlation_score(
        self,
        sast: SASTFinding,
        dast: Finding,
    ) -> float:
        """Calculate correlation score between SAST and DAST findings."""
        score = 0.0

        # Same file/URL correlation
        if self._paths_match(sast.file_path, dast.url or dast.target):
            score += 0.3

        # Same vulnerability type
        sast_cat = sast.category.lower()
        dast_type = dast.vuln_type.value.lower()

        if sast_cat in self._vuln_type_map:
            if any(vt in dast_type for vt in self._vuln_type_map[sast_cat]):
                score += 0.4
        elif sast_cat == dast_type:
            score += 0.4

        # Same line (if applicable)
        if sast.line and dast.line and abs(sast.line - dast.line) <= 5:
            score += 0.2

        # CWE match
        sast_cwes = set(sast.cwe_ids)
        dast_cwes = set(dast.cwe_ids) if dast.cwe_ids else set()
        if sast_cwes & dast_cwes:
            score += 0.2

        # Code snippet similarity
        if sast.code_snippet and dast.code_snippet:
            if self._similar_code(sast.code_snippet, dast.code_snippet):
                score += 0.1

        return min(1.0, score)

    def _paths_match(self, sast_path: str, dast_url: str) -> bool:
        """Check if SAST file path matches DAST URL."""
        if not sast_path or not dast_url:
            return False

        # Extract filename from SAST path
        sast_file = sast_path.split("/")[-1].split("\\")[-1]

        # Check if file name appears in URL
        if sast_file.replace(".py", "").replace(".js", "") in dast_url:
            return True

        # Check for common patterns
        # e.g., views.py -> /api/users matches users in both
        sast_name = re.sub(r"\.(py|js|java|go)$", "", sast_file).lower()
        url_parts = dast_url.lower().split("/")

        return sast_name in url_parts

    def _similar_code(self, code1: str, code2: str) -> bool:
        """Check if two code snippets are similar."""
        # Simple word-based similarity
        words1 = set(re.findall(r"\w+", code1.lower()))
        words2 = set(re.findall(r"\w+", code2.lower()))

        if not words1 or not words2:
            return False

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union > 0.3 if union else False

    def _sast_confidence(self, sast: SASTFinding) -> ConfidenceLevel:
        """Determine confidence level for SAST-only finding."""
        # Higher confidence for certain types
        high_confidence_cats = ["sql_injection", "command_injection", "secrets", "hardcoded_secret"]

        if sast.category.lower() in high_confidence_cats:
            return ConfidenceLevel.HIGH

        if sast.severity.lower() in ["critical", "high"]:
            return ConfidenceLevel.MEDIUM

        return ConfidenceLevel.LOW

    def _dast_confidence(self, dast: Finding) -> ConfidenceLevel:
        """Determine confidence level for DAST-only finding."""
        # DAST findings are generally higher confidence (runtime evidence)
        if dast.confidence >= 0.8:
            return ConfidenceLevel.HIGH

        if dast.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
            return ConfidenceLevel.HIGH

        return ConfidenceLevel.MEDIUM

    def _generate_reason(
        self,
        sast: SASTFinding,
        dast: Finding,
        score: float,
    ) -> str:
        """Generate explanation for correlation."""
        reasons = []

        if score >= 0.7:
            reasons.append(f"Strong correlation (score: {score:.2f})")
        else:
            reasons.append(f"Moderate correlation (score: {score:.2f})")

        reasons.append(f"SAST: {sast.category} in {sast.file_path}:{sast.line}")
        reasons.append(f"DAST: {dast.vuln_type.value} at {dast.url or dast.target}")

        return "; ".join(reasons)


def correlate_findings(
    sast_findings: list[SASTFinding],
    dast_findings: list[Finding],
) -> list[CorrelatedFinding]:
    """
    Convenience function to correlate findings.

    Args:
        sast_findings: SAST findings
        dast_findings: DAST findings

    Returns:
        Correlated findings
    """
    correlator = SASTDASTCorrelator()
    return correlator.correlate(sast_findings, dast_findings)
