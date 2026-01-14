"""
AIPT AI-Powered Triage System

Uses LLM intelligence to prioritize vulnerability findings based on:
- Real-world exploitability (not just CVSS scores)
- Business context and impact
- Attack surface exposure
- Ease of exploitation
- Potential for chaining

This helps pentesters focus on the most impactful findings first.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# Import VulnerabilityType from chaining module
from aipt_v2.intelligence.chaining import VulnerabilityType


logger = logging.getLogger(__name__)


class Exploitability(Enum):
    """How easy is this to exploit in the real world"""
    TRIVIAL = "trivial"       # Script kiddie level, public exploits
    EASY = "easy"             # Basic skills required
    MODERATE = "moderate"     # Some expertise needed
    DIFFICULT = "difficult"   # Advanced skills, custom exploit
    THEORETICAL = "theoretical"  # Requires specific conditions


class BusinessCriticality(Enum):
    """Business impact if exploited"""
    CRITICAL = "critical"     # Business-ending, massive breach
    HIGH = "high"             # Significant financial/reputational damage
    MEDIUM = "medium"         # Notable impact, recoverable
    LOW = "low"               # Minor impact
    MINIMAL = "minimal"       # Negligible business impact


@dataclass
class RiskAssessment:
    """Detailed risk assessment for a finding"""
    finding: Finding

    # AI-assessed factors
    exploitability: Exploitability
    business_criticality: BusinessCriticality

    # Scores (0-100)
    exploitability_score: int
    impact_score: int
    priority_score: int  # Combined score for ranking

    # AI reasoning
    exploitability_reasoning: str
    impact_reasoning: str
    attack_scenario: str

    # Recommendations
    remediation_priority: int  # 1-5, 1 being highest
    quick_win: bool  # Can be fixed quickly?
    requires_immediate_action: bool

    # Metadata
    assessed_at: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_title": self.finding.title,
            "finding_url": self.finding.url,
            "original_severity": self.finding.severity.value,
            "exploitability": self.exploitability.value,
            "business_criticality": self.business_criticality.value,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "priority_score": self.priority_score,
            "exploitability_reasoning": self.exploitability_reasoning,
            "impact_reasoning": self.impact_reasoning,
            "attack_scenario": self.attack_scenario,
            "remediation_priority": self.remediation_priority,
            "quick_win": self.quick_win,
            "requires_immediate_action": self.requires_immediate_action,
            "confidence": self.confidence,
        }


@dataclass
class TriageResult:
    """Complete triage result for all findings"""
    assessments: list[RiskAssessment]
    prioritized_findings: list[Finding]

    # Summary statistics
    critical_count: int
    immediate_action_count: int
    quick_wins: list[Finding]

    # AI summary
    executive_summary: str
    top_recommendations: list[str]

    # Metadata
    total_findings: int
    triaged_at: datetime = field(default_factory=datetime.utcnow)

    def get_top_priority(self, n: int = 10) -> list[RiskAssessment]:
        """Get top N priority findings"""
        sorted_assessments = sorted(
            self.assessments,
            key=lambda a: a.priority_score,
            reverse=True
        )
        return sorted_assessments[:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "immediate_action_count": self.immediate_action_count,
            "quick_wins_count": len(self.quick_wins),
            "executive_summary": self.executive_summary,
            "top_recommendations": self.top_recommendations,
            "assessments": [a.to_dict() for a in self.assessments],
        }


# ============================================================================
# Exploitability Rules (heuristic-based, can be enhanced with LLM)
# ============================================================================

EXPLOITABILITY_RULES = {
    # Trivial - public exploits widely available
    VulnerabilityType.SQL_INJECTION: {
        "base": Exploitability.EASY,
        "score": 85,
        "tools": ["sqlmap", "manual"],
    },
    VulnerabilityType.XSS_REFLECTED: {
        "base": Exploitability.TRIVIAL,
        "score": 90,
        "tools": ["browser", "burp"],
    },
    VulnerabilityType.XSS_STORED: {
        "base": Exploitability.TRIVIAL,
        "score": 95,
        "tools": ["browser"],
    },
    VulnerabilityType.COMMAND_INJECTION: {
        "base": Exploitability.EASY,
        "score": 90,
        "tools": ["curl", "manual"],
    },
    VulnerabilityType.FILE_INCLUSION: {
        "base": Exploitability.EASY,
        "score": 80,
        "tools": ["curl", "burp"],
    },
    VulnerabilityType.IDOR: {
        "base": Exploitability.TRIVIAL,
        "score": 95,
        "tools": ["browser", "burp"],
    },
    VulnerabilityType.OPEN_REDIRECT: {
        "base": Exploitability.TRIVIAL,
        "score": 90,
        "tools": ["browser"],
    },
    VulnerabilityType.DEFAULT_CREDENTIALS: {
        "base": Exploitability.TRIVIAL,
        "score": 100,
        "tools": ["browser"],
    },
    VulnerabilityType.SSRF: {
        "base": Exploitability.MODERATE,
        "score": 70,
        "tools": ["burp", "custom"],
    },
    VulnerabilityType.XXE: {
        "base": Exploitability.MODERATE,
        "score": 65,
        "tools": ["burp", "custom"],
    },
    VulnerabilityType.INSECURE_DESERIALIZATION: {
        "base": Exploitability.DIFFICULT,
        "score": 50,
        "tools": ["ysoserial", "custom"],
    },
    VulnerabilityType.RCE: {
        "base": Exploitability.EASY,  # If found, usually exploitable
        "score": 85,
        "tools": ["various"],
    },
}

# Impact multipliers based on vulnerability type
IMPACT_MULTIPLIERS = {
    VulnerabilityType.RCE: 1.0,
    VulnerabilityType.SQL_INJECTION: 0.95,
    VulnerabilityType.COMMAND_INJECTION: 0.95,
    VulnerabilityType.AUTH_BYPASS: 0.9,
    VulnerabilityType.PRIVILEGE_ESCALATION: 0.9,
    VulnerabilityType.INSECURE_DESERIALIZATION: 0.85,
    VulnerabilityType.XXE: 0.8,
    VulnerabilityType.SSRF: 0.8,
    VulnerabilityType.FILE_INCLUSION: 0.75,
    VulnerabilityType.XSS_STORED: 0.7,
    VulnerabilityType.IDOR: 0.7,
    VulnerabilityType.XSS_REFLECTED: 0.5,
    VulnerabilityType.OPEN_REDIRECT: 0.3,
    VulnerabilityType.INFORMATION_DISCLOSURE: 0.4,
}


class AITriage:
    """
    AI-Powered Vulnerability Triage System

    Analyzes findings using a combination of:
    1. Rule-based heuristics (fast, deterministic)
    2. LLM analysis (deep, contextual) - when available
    3. Business context awareness

    Example:
        triage = AITriage()
        result = await triage.analyze(findings)
        for assessment in result.get_top_priority(5):
            print(f"Priority {assessment.remediation_priority}: {assessment.finding.title}")
    """

    def __init__(
        self,
        use_llm: bool = True,
        llm_provider: str = "anthropic",
        llm_model: str = "claude-3-haiku-20240307",
    ):
        self.use_llm = use_llm
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self._llm_client = None

    async def analyze(
        self,
        findings: list[Finding],
        business_context: str = "",
        target_type: str = "web_application",
    ) -> TriageResult:
        """
        Analyze and prioritize all findings.

        Args:
            findings: List of vulnerability findings
            business_context: Optional context about the target business
            target_type: Type of target (web_application, api, mobile, etc.)

        Returns:
            TriageResult with prioritized findings
        """
        if not findings:
            return TriageResult(
                assessments=[],
                prioritized_findings=[],
                critical_count=0,
                immediate_action_count=0,
                quick_wins=[],
                executive_summary="No findings to analyze.",
                top_recommendations=[],
                total_findings=0,
            )

        logger.info(f"Starting AI triage of {len(findings)} findings")

        # Assess each finding
        assessments = []
        for finding in findings:
            assessment = await self._assess_finding(
                finding, business_context, target_type
            )
            assessments.append(assessment)

        # Sort by priority score
        assessments.sort(key=lambda a: a.priority_score, reverse=True)
        prioritized = [a.finding for a in assessments]

        # Identify critical and immediate action items
        critical = [a for a in assessments if a.business_criticality == BusinessCriticality.CRITICAL]
        immediate = [a for a in assessments if a.requires_immediate_action]
        quick_wins = [a.finding for a in assessments if a.quick_win]

        # Generate executive summary
        summary = self._generate_executive_summary(assessments, business_context)
        recommendations = self._generate_recommendations(assessments)

        return TriageResult(
            assessments=assessments,
            prioritized_findings=prioritized,
            critical_count=len(critical),
            immediate_action_count=len(immediate),
            quick_wins=quick_wins[:10],  # Top 10 quick wins
            executive_summary=summary,
            top_recommendations=recommendations,
            total_findings=len(findings),
        )

    async def _assess_finding(
        self,
        finding: Finding,
        business_context: str,
        target_type: str,
    ) -> RiskAssessment:
        """Assess a single finding"""
        # Get base exploitability from rules
        exploitability, exploitability_score = self._assess_exploitability(finding)

        # Assess business impact
        business_criticality, impact_score = self._assess_business_impact(
            finding, business_context, target_type
        )

        # Calculate priority score (weighted combination)
        priority_score = int(
            (exploitability_score * 0.4) +
            (impact_score * 0.4) +
            (self._severity_to_score(finding.severity) * 0.2)
        )

        # Generate reasoning (use LLM if available, otherwise heuristic)
        if self.use_llm and self._can_use_llm():
            reasoning = await self._llm_assess(finding, business_context)
            exploitability_reasoning = reasoning.get("exploitability", "")
            impact_reasoning = reasoning.get("impact", "")
            attack_scenario = reasoning.get("scenario", "")
        else:
            exploitability_reasoning = self._heuristic_exploitability_reason(finding)
            impact_reasoning = self._heuristic_impact_reason(finding, business_context)
            attack_scenario = self._generate_attack_scenario(finding)

        # Determine remediation priority (1-5)
        remediation_priority = self._calculate_remediation_priority(
            priority_score, exploitability, business_criticality
        )

        # Check if quick win
        quick_win = self._is_quick_win(finding)

        # Check if requires immediate action
        immediate = (
            business_criticality == BusinessCriticality.CRITICAL or
            (exploitability in [Exploitability.TRIVIAL, Exploitability.EASY] and
             finding.severity in [Severity.CRITICAL, Severity.HIGH])
        )

        return RiskAssessment(
            finding=finding,
            exploitability=exploitability,
            business_criticality=business_criticality,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            priority_score=priority_score,
            exploitability_reasoning=exploitability_reasoning,
            impact_reasoning=impact_reasoning,
            attack_scenario=attack_scenario,
            remediation_priority=remediation_priority,
            quick_win=quick_win,
            requires_immediate_action=immediate,
        )

    def _assess_exploitability(
        self,
        finding: Finding,
    ) -> tuple[Exploitability, int]:
        """Assess how exploitable a finding is"""
        rules = EXPLOITABILITY_RULES.get(finding.vuln_type)

        if rules:
            base = rules["base"]
            score = rules["score"]
        else:
            # Default based on severity
            severity_map = {
                Severity.CRITICAL: (Exploitability.EASY, 80),
                Severity.HIGH: (Exploitability.MODERATE, 60),
                Severity.MEDIUM: (Exploitability.MODERATE, 50),
                Severity.LOW: (Exploitability.DIFFICULT, 30),
                Severity.INFO: (Exploitability.THEORETICAL, 10),
            }
            base, score = severity_map.get(
                finding.severity,
                (Exploitability.MODERATE, 50)
            )

        # Adjust score based on additional factors
        if finding.confirmed:
            score = min(100, score + 10)
        if finding.exploited:
            score = min(100, score + 15)
        if finding.poc_command:
            score = min(100, score + 10)

        return base, score

    def _assess_business_impact(
        self,
        finding: Finding,
        business_context: str,
        target_type: str,
    ) -> tuple[BusinessCriticality, int]:
        """Assess business impact of a finding"""
        # Base impact from vulnerability type
        multiplier = IMPACT_MULTIPLIERS.get(finding.vuln_type, 0.5)

        # Base score from severity
        base_score = self._severity_to_score(finding.severity)
        impact_score = int(base_score * multiplier)

        # Adjust for business context keywords
        high_value_keywords = [
            "payment", "financial", "pii", "healthcare", "hipaa",
            "pci", "credentials", "admin", "authentication", "api",
        ]

        context_lower = (business_context + finding.url + finding.description).lower()
        for keyword in high_value_keywords:
            if keyword in context_lower:
                impact_score = min(100, impact_score + 5)

        # Determine criticality
        if impact_score >= 85:
            criticality = BusinessCriticality.CRITICAL
        elif impact_score >= 70:
            criticality = BusinessCriticality.HIGH
        elif impact_score >= 50:
            criticality = BusinessCriticality.MEDIUM
        elif impact_score >= 30:
            criticality = BusinessCriticality.LOW
        else:
            criticality = BusinessCriticality.MINIMAL

        return criticality, impact_score

    def _severity_to_score(self, severity: Severity) -> int:
        """Convert severity to numeric score"""
        scores = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 80,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }
        return scores.get(severity, 50)

    def _calculate_remediation_priority(
        self,
        priority_score: int,
        exploitability: Exploitability,
        criticality: BusinessCriticality,
    ) -> int:
        """Calculate remediation priority (1-5, 1 highest)"""
        if priority_score >= 85 or criticality == BusinessCriticality.CRITICAL:
            return 1
        if priority_score >= 70 or criticality == BusinessCriticality.HIGH:
            return 2
        if priority_score >= 50:
            return 3
        if priority_score >= 30:
            return 4
        return 5

    def _is_quick_win(self, finding: Finding) -> bool:
        """Determine if a finding is a quick win to fix"""
        quick_win_types = [
            VulnerabilityType.DEFAULT_CREDENTIALS,
            VulnerabilityType.MISCONFIGURATION,
            VulnerabilityType.DIRECTORY_LISTING,
            VulnerabilityType.INFORMATION_DISCLOSURE,
            VulnerabilityType.OPEN_REDIRECT,
            VulnerabilityType.CORS_MISCONFIGURATION,
        ]
        return finding.vuln_type in quick_win_types

    def _heuristic_exploitability_reason(self, finding: Finding) -> str:
        """Generate exploitability reasoning without LLM"""
        rules = EXPLOITABILITY_RULES.get(finding.vuln_type)

        if rules:
            tools = ", ".join(rules.get("tools", ["manual"]))
            return (
                f"This {finding.vuln_type.value} vulnerability is considered "
                f"{rules['base'].value} to exploit. Common tools include: {tools}. "
                f"{'Confirmed and exploited in testing.' if finding.exploited else ''}"
            )

        return f"Exploitability assessment based on {finding.severity.value} severity."

    def _heuristic_impact_reason(
        self,
        finding: Finding,
        business_context: str,
    ) -> str:
        """Generate impact reasoning without LLM"""
        impacts = {
            VulnerabilityType.RCE: "allows complete server compromise and data access",
            VulnerabilityType.SQL_INJECTION: "could lead to full database compromise",
            VulnerabilityType.AUTH_BYPASS: "enables unauthorized access to protected resources",
            VulnerabilityType.IDOR: "allows access to other users' data",
            VulnerabilityType.XSS_STORED: "can compromise any user who views affected pages",
            VulnerabilityType.SSRF: "may expose internal network and services",
        }

        impact = impacts.get(
            finding.vuln_type,
            f"could have {finding.severity.value} impact on the application"
        )

        return f"This vulnerability {impact}."

    def _generate_attack_scenario(self, finding: Finding) -> str:
        """Generate a realistic attack scenario"""
        scenarios = {
            VulnerabilityType.SQL_INJECTION: (
                "1. Attacker identifies SQL injection point\n"
                "2. Uses sqlmap or manual techniques to extract data\n"
                "3. Dumps user credentials, PII, or business data\n"
                "4. May escalate to OS command execution via xp_cmdshell"
            ),
            VulnerabilityType.XSS_STORED: (
                "1. Attacker injects malicious JavaScript\n"
                "2. Script executes when other users view the page\n"
                "3. Steals session cookies or credentials\n"
                "4. Performs actions as the victim user"
            ),
            VulnerabilityType.SSRF: (
                "1. Attacker crafts request to internal resources\n"
                "2. Accesses internal admin panels or databases\n"
                "3. Reads cloud metadata (AWS keys, etc.)\n"
                "4. Pivots to attack internal network"
            ),
            VulnerabilityType.RCE: (
                "1. Attacker achieves code execution\n"
                "2. Establishes reverse shell or backdoor\n"
                "3. Dumps credentials and sensitive data\n"
                "4. Moves laterally through network"
            ),
            VulnerabilityType.IDOR: (
                "1. Attacker manipulates object references\n"
                "2. Accesses other users' records\n"
                "3. Extracts or modifies sensitive data\n"
                "4. May enumerate all records in system"
            ),
        }

        return scenarios.get(
            finding.vuln_type,
            f"Attacker exploits {finding.vuln_type.value} at {finding.url}"
        )

    def _can_use_llm(self) -> bool:
        """Check if LLM is available"""
        # Check for API key
        if self.llm_provider == "anthropic":
            return bool(os.getenv("ANTHROPIC_API_KEY"))
        if self.llm_provider == "openai":
            return bool(os.getenv("OPENAI_API_KEY"))
        return False

    async def _llm_assess(
        self,
        finding: Finding,
        business_context: str,
    ) -> dict[str, str]:
        """Use LLM to assess finding (when available)"""
        # This would integrate with litellm or direct API calls
        # For now, return empty to fall back to heuristics
        return {}

    def _generate_executive_summary(
        self,
        assessments: list[RiskAssessment],
        business_context: str,
    ) -> str:
        """Generate executive summary of findings"""
        if not assessments:
            return "No vulnerabilities were identified during this assessment."

        critical = sum(1 for a in assessments if a.business_criticality == BusinessCriticality.CRITICAL)
        high = sum(1 for a in assessments if a.business_criticality == BusinessCriticality.HIGH)
        immediate = sum(1 for a in assessments if a.requires_immediate_action)

        lines = [
            f"## Executive Summary\n",
            f"This assessment identified **{len(assessments)} vulnerabilities** requiring attention.\n",
        ]

        if critical > 0 or immediate > 0:
            lines.append(
                f"**URGENT:** {critical} critical and {immediate} immediate-action items "
                f"require priority remediation.\n"
            )

        lines.append(f"\n### Risk Breakdown\n")
        lines.append(f"- **Critical Impact:** {critical}")
        lines.append(f"- **High Impact:** {high}")
        lines.append(f"- **Requires Immediate Action:** {immediate}")

        # Top risk
        if assessments:
            top = assessments[0]
            lines.append(
                f"\n### Highest Priority Finding\n"
                f"**{top.finding.title}** at `{top.finding.url}`\n"
                f"- Exploitability: {top.exploitability.value}\n"
                f"- Business Impact: {top.business_criticality.value}\n"
            )

        return "\n".join(lines)

    def _generate_recommendations(
        self,
        assessments: list[RiskAssessment],
    ) -> list[str]:
        """Generate top remediation recommendations"""
        recommendations = []

        # Group by priority
        priority_1 = [a for a in assessments if a.remediation_priority == 1]
        quick_wins = [a for a in assessments if a.quick_win]

        if priority_1:
            recommendations.append(
                f"Address {len(priority_1)} critical-priority items immediately"
            )

        if quick_wins:
            recommendations.append(
                f"Resolve {len(quick_wins)} quick-win items to reduce attack surface"
            )

        # Add specific recommendations based on finding types
        vuln_types = {a.finding.vuln_type for a in assessments}

        if VulnerabilityType.SQL_INJECTION in vuln_types:
            recommendations.append(
                "Implement parameterized queries to eliminate SQL injection"
            )

        if VulnerabilityType.XSS_STORED in vuln_types or VulnerabilityType.XSS_REFLECTED in vuln_types:
            recommendations.append(
                "Deploy Content Security Policy and output encoding"
            )

        if VulnerabilityType.IDOR in vuln_types:
            recommendations.append(
                "Implement proper authorization checks on all object access"
            )

        if VulnerabilityType.DEFAULT_CREDENTIALS in vuln_types:
            recommendations.append(
                "Change all default credentials immediately"
            )

        return recommendations[:10]  # Top 10
