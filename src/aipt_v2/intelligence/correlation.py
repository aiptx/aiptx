"""
AIPT Cross-Target Correlation Engine

Finds patterns and insights across multiple penetration tests:
- Identifies common vulnerabilities across targets
- Detects systemic issues in an organization
- Provides portfolio-level risk assessment
- Tracks vulnerability trends over time

This provides strategic insights beyond individual target assessments.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from collections import defaultdict

from aipt_v2.models.findings import Finding, Severity, VulnerabilityType

logger = logging.getLogger(__name__)


@dataclass
class TargetSummary:
    """Summary of findings for a single target."""
    target: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_vuln_types: list[str]
    scan_date: datetime
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total_findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "top_vuln_types": self.top_vuln_types,
            "scan_date": self.scan_date.isoformat(),
            "risk_score": self.risk_score,
        }


@dataclass
class CommonVulnerability:
    """A vulnerability type found across multiple targets."""
    vuln_type: str
    occurrence_count: int
    affected_targets: list[str]
    average_severity: str
    is_systemic: bool
    remediation_priority: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "occurrence_count": self.occurrence_count,
            "affected_targets": self.affected_targets,
            "percentage_affected": len(self.affected_targets),
            "average_severity": self.average_severity,
            "is_systemic": self.is_systemic,
            "remediation_priority": self.remediation_priority,
        }


@dataclass
class SystemicIssue:
    """A systemic issue identified across the portfolio."""
    issue_type: str
    description: str
    affected_percentage: float
    affected_targets: list[str]
    root_cause_hypothesis: str
    remediation_recommendation: str
    priority: int  # 1-5, 1 being highest

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_type": self.issue_type,
            "description": self.description,
            "affected_percentage": self.affected_percentage,
            "affected_targets": self.affected_targets,
            "root_cause_hypothesis": self.root_cause_hypothesis,
            "remediation_recommendation": self.remediation_recommendation,
            "priority": self.priority,
        }


@dataclass
class PortfolioReport:
    """Comprehensive portfolio analysis report."""
    analyzed_at: datetime
    total_targets: int
    total_findings: int

    # Summaries
    target_summaries: list[TargetSummary]
    common_vulnerabilities: list[CommonVulnerability]
    systemic_issues: list[SystemicIssue]

    # Risk metrics
    overall_risk_score: float
    highest_risk_target: str
    lowest_risk_target: str

    # Trends
    vuln_type_distribution: dict[str, int]
    severity_distribution: dict[str, int]

    # Recommendations
    strategic_recommendations: list[str]
    quick_wins: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzed_at": self.analyzed_at.isoformat(),
            "total_targets": self.total_targets,
            "total_findings": self.total_findings,
            "target_summaries": [s.to_dict() for s in self.target_summaries],
            "common_vulnerabilities": [v.to_dict() for v in self.common_vulnerabilities],
            "systemic_issues": [i.to_dict() for i in self.systemic_issues],
            "overall_risk_score": self.overall_risk_score,
            "highest_risk_target": self.highest_risk_target,
            "lowest_risk_target": self.lowest_risk_target,
            "vuln_type_distribution": self.vuln_type_distribution,
            "severity_distribution": self.severity_distribution,
            "strategic_recommendations": self.strategic_recommendations,
            "quick_wins": self.quick_wins,
        }

    def to_executive_summary(self) -> str:
        """Generate executive summary text."""
        lines = [
            f"# Portfolio Security Assessment",
            f"",
            f"**Analysis Date:** {self.analyzed_at.strftime('%Y-%m-%d')}",
            f"**Targets Analyzed:** {self.total_targets}",
            f"**Total Findings:** {self.total_findings}",
            f"**Overall Risk Score:** {self.overall_risk_score:.1f}/100",
            f"",
            f"## Key Findings",
            f"",
        ]

        # Add systemic issues
        if self.systemic_issues:
            lines.append("### Systemic Issues Identified")
            for issue in self.systemic_issues[:3]:
                lines.append(f"- **{issue.issue_type}**: {issue.description}")
                lines.append(f"  - Affects {issue.affected_percentage:.0f}% of targets")
            lines.append("")

        # Add common vulnerabilities
        if self.common_vulnerabilities:
            lines.append("### Most Common Vulnerabilities")
            for vuln in self.common_vulnerabilities[:5]:
                lines.append(f"- {vuln.vuln_type}: {vuln.occurrence_count} occurrences across {len(vuln.affected_targets)} targets")
            lines.append("")

        # Add recommendations
        lines.append("## Strategic Recommendations")
        for i, rec in enumerate(self.strategic_recommendations[:5], 1):
            lines.append(f"{i}. {rec}")

        return "\n".join(lines)


class CrossTargetAnalyzer:
    """
    Analyzes findings across multiple targets for patterns and insights.

    Identifies:
    - Common vulnerabilities across targets
    - Systemic issues suggesting organizational problems
    - Risk distribution and prioritization
    - Strategic remediation recommendations

    Example:
        analyzer = CrossTargetAnalyzer()

        # Add findings from multiple targets
        analyzer.add_target_findings("app1.example.com", findings1)
        analyzer.add_target_findings("app2.example.com", findings2)
        analyzer.add_target_findings("api.example.com", findings3)

        # Generate portfolio report
        report = analyzer.analyze_portfolio()
        print(report.to_executive_summary())
    """

    def __init__(self):
        self.target_findings: dict[str, list[Finding]] = {}
        self.scan_dates: dict[str, datetime] = {}

    def add_target_findings(
        self,
        target: str,
        findings: list[Finding],
        scan_date: datetime = None,
    ):
        """
        Add findings from a target.

        Args:
            target: Target identifier (domain, IP, app name)
            findings: List of findings from this target
            scan_date: When the scan was performed
        """
        self.target_findings[target] = findings
        self.scan_dates[target] = scan_date or datetime.utcnow()

        logger.debug(f"Added {len(findings)} findings for target: {target}")

    def analyze_portfolio(self) -> PortfolioReport:
        """
        Analyze all targets and generate a portfolio report.

        Returns:
            PortfolioReport with comprehensive analysis
        """
        if not self.target_findings:
            return self._empty_report()

        # Generate target summaries
        target_summaries = [
            self._summarize_target(target, findings)
            for target, findings in self.target_findings.items()
        ]

        # Find common vulnerabilities
        common_vulns = self._find_common_vulnerabilities()

        # Identify systemic issues
        systemic_issues = self._identify_systemic_issues(common_vulns)

        # Calculate distributions
        vuln_distribution = self._calculate_vuln_distribution()
        severity_distribution = self._calculate_severity_distribution()

        # Calculate risk scores
        for summary in target_summaries:
            summary.risk_score = self._calculate_risk_score(summary)

        target_summaries.sort(key=lambda s: s.risk_score, reverse=True)
        overall_risk = sum(s.risk_score for s in target_summaries) / len(target_summaries)

        # Generate recommendations
        recommendations = self._generate_recommendations(common_vulns, systemic_issues)
        quick_wins = self._identify_quick_wins()

        return PortfolioReport(
            analyzed_at=datetime.utcnow(),
            total_targets=len(self.target_findings),
            total_findings=sum(len(f) for f in self.target_findings.values()),
            target_summaries=target_summaries,
            common_vulnerabilities=common_vulns,
            systemic_issues=systemic_issues,
            overall_risk_score=overall_risk,
            highest_risk_target=target_summaries[0].target if target_summaries else "",
            lowest_risk_target=target_summaries[-1].target if target_summaries else "",
            vuln_type_distribution=vuln_distribution,
            severity_distribution=severity_distribution,
            strategic_recommendations=recommendations,
            quick_wins=quick_wins,
        )

    def _summarize_target(self, target: str, findings: list[Finding]) -> TargetSummary:
        """Create a summary for a single target."""
        severity_counts = defaultdict(int)
        vuln_type_counts = defaultdict(int)

        for f in findings:
            severity_counts[f.severity.value] += 1
            vuln_type_counts[f.vuln_type.value] += 1

        # Get top vuln types
        sorted_types = sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)
        top_types = [t[0] for t in sorted_types[:5]]

        return TargetSummary(
            target=target,
            total_findings=len(findings),
            critical_count=severity_counts.get("critical", 0),
            high_count=severity_counts.get("high", 0),
            medium_count=severity_counts.get("medium", 0),
            low_count=severity_counts.get("low", 0),
            top_vuln_types=top_types,
            scan_date=self.scan_dates.get(target, datetime.utcnow()),
        )

    def _find_common_vulnerabilities(self) -> list[CommonVulnerability]:
        """Find vulnerabilities that appear across multiple targets."""
        # Count occurrences of each vuln type per target
        vuln_by_target: dict[str, set[str]] = defaultdict(set)
        vuln_severity: dict[str, list[Severity]] = defaultdict(list)

        for target, findings in self.target_findings.items():
            for f in findings:
                vuln_type = f.vuln_type.value
                vuln_by_target[vuln_type].add(target)
                vuln_severity[vuln_type].append(f.severity)

        # Build common vulnerability list
        common = []
        total_targets = len(self.target_findings)

        for vuln_type, affected_targets in vuln_by_target.items():
            if len(affected_targets) < 2:
                continue  # Only include if affects multiple targets

            # Calculate average severity
            severities = vuln_severity[vuln_type]
            severity_values = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            avg_value = sum(severity_values.get(s.value, 0) for s in severities) / len(severities)
            avg_severity = "critical" if avg_value >= 3.5 else "high" if avg_value >= 2.5 else "medium" if avg_value >= 1.5 else "low"

            # Determine if systemic (affects >50% of targets)
            is_systemic = len(affected_targets) >= total_targets * 0.5

            # Calculate remediation priority
            priority = 1 if is_systemic and avg_value >= 3 else 2 if avg_value >= 3 else 3 if is_systemic else 4

            common.append(CommonVulnerability(
                vuln_type=vuln_type,
                occurrence_count=len(severities),
                affected_targets=list(affected_targets),
                average_severity=avg_severity,
                is_systemic=is_systemic,
                remediation_priority=priority,
            ))

        # Sort by priority
        common.sort(key=lambda c: (c.remediation_priority, -c.occurrence_count))

        return common

    def _identify_systemic_issues(
        self,
        common_vulns: list[CommonVulnerability],
    ) -> list[SystemicIssue]:
        """Identify systemic issues from common vulnerabilities."""
        issues = []
        total_targets = len(self.target_findings)

        # Check for input validation issues
        input_vulns = ["sql_injection", "xss_reflected", "xss_stored", "command_injection"]
        input_affected = set()
        for cv in common_vulns:
            if cv.vuln_type in input_vulns:
                input_affected.update(cv.affected_targets)

        if len(input_affected) >= total_targets * 0.5:
            issues.append(SystemicIssue(
                issue_type="Input Validation",
                description="Widespread input validation failures across the portfolio",
                affected_percentage=(len(input_affected) / total_targets) * 100,
                affected_targets=list(input_affected),
                root_cause_hypothesis="Lack of centralized input validation framework or developer training",
                remediation_recommendation="Implement organization-wide input validation library and secure coding training",
                priority=1,
            ))

        # Check for authentication issues
        auth_vulns = ["auth_bypass", "weak_password", "session_fixation", "idor"]
        auth_affected = set()
        for cv in common_vulns:
            if cv.vuln_type in auth_vulns:
                auth_affected.update(cv.affected_targets)

        if len(auth_affected) >= total_targets * 0.3:
            issues.append(SystemicIssue(
                issue_type="Authentication & Authorization",
                description="Repeated authentication and authorization weaknesses",
                affected_percentage=(len(auth_affected) / total_targets) * 100,
                affected_targets=list(auth_affected),
                root_cause_hypothesis="Inconsistent identity management practices or outdated authentication frameworks",
                remediation_recommendation="Standardize on a secure authentication framework and implement centralized authorization",
                priority=1,
            ))

        # Check for configuration issues
        config_vulns = ["misconfiguration", "default_credentials", "information_disclosure"]
        config_affected = set()
        for cv in common_vulns:
            if cv.vuln_type in config_vulns:
                config_affected.update(cv.affected_targets)

        if len(config_affected) >= total_targets * 0.4:
            issues.append(SystemicIssue(
                issue_type="Security Configuration",
                description="Widespread security misconfiguration issues",
                affected_percentage=(len(config_affected) / total_targets) * 100,
                affected_targets=list(config_affected),
                root_cause_hypothesis="Lack of security hardening standards or deployment automation",
                remediation_recommendation="Implement security configuration baselines and automated compliance checking",
                priority=2,
            ))

        # Check for crypto issues
        crypto_vulns = ["weak_crypto", "sensitive_data_exposure"]
        crypto_affected = set()
        for cv in common_vulns:
            if cv.vuln_type in crypto_vulns:
                crypto_affected.update(cv.affected_targets)

        if len(crypto_affected) >= total_targets * 0.3:
            issues.append(SystemicIssue(
                issue_type="Cryptographic Practices",
                description="Weak cryptography and data protection practices",
                affected_percentage=(len(crypto_affected) / total_targets) * 100,
                affected_targets=list(crypto_affected),
                root_cause_hypothesis="Outdated crypto libraries or lack of data classification",
                remediation_recommendation="Update cryptographic libraries and implement data classification program",
                priority=2,
            ))

        return issues

    def _calculate_vuln_distribution(self) -> dict[str, int]:
        """Calculate vulnerability type distribution."""
        distribution = defaultdict(int)
        for findings in self.target_findings.values():
            for f in findings:
                distribution[f.vuln_type.value] += 1
        return dict(sorted(distribution.items(), key=lambda x: x[1], reverse=True))

    def _calculate_severity_distribution(self) -> dict[str, int]:
        """Calculate severity distribution."""
        distribution = defaultdict(int)
        for findings in self.target_findings.values():
            for f in findings:
                distribution[f.severity.value] += 1
        return dict(distribution)

    def _calculate_risk_score(self, summary: TargetSummary) -> float:
        """Calculate risk score for a target (0-100)."""
        # Weight by severity
        weights = {"critical": 40, "high": 25, "medium": 10, "low": 3}

        raw_score = (
            summary.critical_count * weights["critical"] +
            summary.high_count * weights["high"] +
            summary.medium_count * weights["medium"] +
            summary.low_count * weights["low"]
        )

        # Normalize to 0-100 (cap at 100)
        return min(100, raw_score)

    def _generate_recommendations(
        self,
        common_vulns: list[CommonVulnerability],
        systemic_issues: list[SystemicIssue],
    ) -> list[str]:
        """Generate strategic recommendations."""
        recommendations = []

        # Add recommendations for systemic issues
        for issue in systemic_issues[:3]:
            recommendations.append(issue.remediation_recommendation)

        # Add recommendations for common vulnerabilities
        vuln_recommendations = {
            "sql_injection": "Implement parameterized queries and ORM across all applications",
            "xss_reflected": "Deploy Content Security Policy headers and output encoding libraries",
            "xss_stored": "Implement strict input sanitization and output encoding",
            "idor": "Implement centralized authorization checks on all object access",
            "auth_bypass": "Review and strengthen authentication mechanisms organization-wide",
            "misconfiguration": "Develop security configuration baselines for all platforms",
            "default_credentials": "Establish credential rotation and default password policies",
        }

        for cv in common_vulns[:5]:
            if cv.vuln_type in vuln_recommendations:
                rec = vuln_recommendations[cv.vuln_type]
                if rec not in recommendations:
                    recommendations.append(rec)

        return recommendations[:10]

    def _identify_quick_wins(self) -> list[str]:
        """Identify quick wins across the portfolio."""
        quick_wins = []

        # Check for easy-to-fix issues
        for target, findings in self.target_findings.items():
            for f in findings:
                if f.vuln_type in [VulnerabilityType.DEFAULT_CREDENTIALS, VulnerabilityType.MISCONFIGURATION]:
                    quick_wins.append(f"Fix {f.vuln_type.value} on {target}: {f.title}")

        # Deduplicate and limit
        seen = set()
        unique_wins = []
        for win in quick_wins:
            if win not in seen:
                seen.add(win)
                unique_wins.append(win)

        return unique_wins[:10]

    def _empty_report(self) -> PortfolioReport:
        """Return an empty portfolio report."""
        return PortfolioReport(
            analyzed_at=datetime.utcnow(),
            total_targets=0,
            total_findings=0,
            target_summaries=[],
            common_vulnerabilities=[],
            systemic_issues=[],
            overall_risk_score=0,
            highest_risk_target="",
            lowest_risk_target="",
            vuln_type_distribution={},
            severity_distribution={},
            strategic_recommendations=[],
            quick_wins=[],
        )

    def export_to_json(self) -> str:
        """Export analysis to JSON."""
        report = self.analyze_portfolio()
        return json.dumps(report.to_dict(), indent=2, default=str)

    def clear(self):
        """Clear all target data."""
        self.target_findings.clear()
        self.scan_dates.clear()
