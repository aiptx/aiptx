"""
AIPT LLM-Powered Vulnerability Analyzer

Uses LLM intelligence to perform deep analysis of findings:
- Discover novel attack chains beyond predefined rules
- Assess real-world exploitability with context
- Generate attack narratives for reports
- Identify implicit vulnerabilities from patterns

This enhances the rule-based chaining with intelligent reasoning.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from aipt_v2.models.findings import Finding, Severity, VulnerabilityType

logger = logging.getLogger(__name__)


ANALYSIS_PROMPT = """You are an elite penetration tester analyzing vulnerability findings.

## Findings to Analyze
```json
{findings_json}
```

## Target Context
- **Target**: {target}
- **Technology Stack**: {tech_stack}
- **Business Type**: {business_context}

## Your Analysis Tasks

### 1. Attack Chain Discovery
Identify which vulnerabilities can be CHAINED together for greater impact.
Look for chains that go beyond obvious patterns:
- Can a low-severity finding enable a critical attack?
- Are there implicit trust relationships being exploited?
- Can multiple medium findings combine into a critical issue?

### 2. Implicit Vulnerability Detection
Based on patterns in the findings, identify IMPLICIT vulnerabilities:
- If SQLi exists, input validation is likely weak everywhere
- If one IDOR exists, authorization logic may be flawed globally
- If secrets are exposed, key management is likely poor

### 3. Real-World Exploitation Assessment
For each significant finding, assess:
- How easy would this be to exploit in practice?
- What would an attacker need (skills, tools, time)?
- What's the realistic business impact?

### 4. Executive Risk Summary
Provide a business-focused summary suitable for executives.

## Output Format (JSON)
```json
{{
    "attack_chains": [
        {{
            "name": "Descriptive chain name",
            "steps": [
                {{
                    "finding_title": "Name of finding",
                    "action": "What attacker does",
                    "outcome": "What attacker achieves"
                }}
            ],
            "final_impact": "Ultimate impact if chain exploited",
            "confidence": "high|medium|low",
            "reasoning": "Why this chain works",
            "cvss_amplification": 1.5
        }}
    ],
    "implicit_vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "reasoning": "Why we suspect this exists",
            "indicators": ["evidence1", "evidence2"],
            "recommended_test": "How to verify"
        }}
    ],
    "exploitation_assessments": [
        {{
            "finding_title": "Finding name",
            "real_world_difficulty": "trivial|easy|moderate|difficult|theoretical",
            "required_skills": "Description of needed skills",
            "time_estimate": "Minutes/hours to exploit",
            "impact_assessment": "Business impact description"
        }}
    ],
    "executive_summary": "2-3 paragraph executive summary",
    "top_risks": ["risk1", "risk2", "risk3"],
    "immediate_actions": ["action1", "action2"]
}}
```"""


@dataclass
class DiscoveredChain:
    """An attack chain discovered by LLM analysis."""
    name: str
    steps: list[dict[str, str]]
    final_impact: str
    confidence: str
    reasoning: str
    cvss_amplification: float = 1.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "steps": self.steps,
            "final_impact": self.final_impact,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "cvss_amplification": self.cvss_amplification,
        }


@dataclass
class ImplicitVulnerability:
    """A suspected vulnerability inferred from patterns."""
    vuln_type: str
    reasoning: str
    indicators: list[str]
    recommended_test: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.vuln_type,
            "reasoning": self.reasoning,
            "indicators": self.indicators,
            "recommended_test": self.recommended_test,
        }


@dataclass
class ExploitationAssessment:
    """Real-world exploitation assessment for a finding."""
    finding_title: str
    real_world_difficulty: str
    required_skills: str
    time_estimate: str
    impact_assessment: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "real_world_difficulty": self.real_world_difficulty,
            "required_skills": self.required_skills,
            "time_estimate": self.time_estimate,
            "impact_assessment": self.impact_assessment,
        }


@dataclass
class LLMAnalysisResult:
    """Complete result of LLM vulnerability analysis."""
    attack_chains: list[DiscoveredChain]
    implicit_vulnerabilities: list[ImplicitVulnerability]
    exploitation_assessments: list[ExploitationAssessment]
    executive_summary: str
    top_risks: list[str]
    immediate_actions: list[str]
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    llm_model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "implicit_vulnerabilities": [v.to_dict() for v in self.implicit_vulnerabilities],
            "exploitation_assessments": [a.to_dict() for a in self.exploitation_assessments],
            "executive_summary": self.executive_summary,
            "top_risks": self.top_risks,
            "immediate_actions": self.immediate_actions,
            "analyzed_at": self.analyzed_at.isoformat(),
            "llm_model": self.llm_model,
        }

    def get_high_confidence_chains(self) -> list[DiscoveredChain]:
        """Get only high-confidence attack chains."""
        return [c for c in self.attack_chains if c.confidence == "high"]

    def get_critical_actions(self) -> list[str]:
        """Get actions that require immediate attention."""
        return self.immediate_actions[:5]


class LLMVulnerabilityAnalyzer:
    """
    LLM-powered deep vulnerability analysis.

    Goes beyond rule-based chaining to discover novel attack paths
    and assess real-world exploitability.

    Example:
        analyzer = LLMVulnerabilityAnalyzer()
        result = await analyzer.analyze(
            findings=findings,
            target="https://example.com",
            tech_stack=["WordPress", "PHP", "MySQL"],
            business_context="E-commerce platform handling payments"
        )

        for chain in result.get_high_confidence_chains():
            print(f"Attack Chain: {chain.name}")
            print(f"Impact: {chain.final_impact}")
    """

    def __init__(
        self,
        llm_provider: str = "anthropic",
        llm_model: str = "claude-3-5-sonnet-20241022",
    ):
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self._llm = None

    async def _get_llm(self):
        """Get or create LLM client."""
        if self._llm is None:
            try:
                import litellm
                self._llm = litellm
            except ImportError:
                logger.warning("litellm not installed")
                return None
        return self._llm

    async def analyze(
        self,
        findings: list[Finding],
        target: str = "",
        tech_stack: list[str] = None,
        business_context: str = "",
    ) -> LLMAnalysisResult:
        """
        Perform deep LLM analysis of findings.

        Args:
            findings: List of vulnerability findings to analyze
            target: Target URL or domain
            tech_stack: Detected technologies
            business_context: Business context for impact assessment

        Returns:
            LLMAnalysisResult with discovered chains and assessments
        """
        if not findings:
            return self._empty_result()

        llm = await self._get_llm()
        if llm is None or not self._has_api_key():
            logger.warning("LLM not available, returning basic analysis")
            return self._basic_analysis(findings)

        # Prepare findings for LLM (limit to top 30 to fit context)
        sorted_findings = sorted(findings, key=lambda f: f.severity, reverse=True)
        top_findings = sorted_findings[:30]

        findings_json = json.dumps(
            [f.to_dict() for f in top_findings],
            indent=2,
            default=str
        )

        prompt = ANALYSIS_PROMPT.format(
            findings_json=findings_json,
            target=target,
            tech_stack=", ".join(tech_stack) if tech_stack else "Unknown",
            business_context=business_context or "General web application",
        )

        try:
            response = await self._call_llm(prompt)
            result = self._parse_response(response)
            result.llm_model = self.llm_model
            return result
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._basic_analysis(findings)

    async def analyze_single_finding(
        self,
        finding: Finding,
        context: str = "",
    ) -> ExploitationAssessment:
        """
        Analyze a single finding for real-world exploitability.

        Args:
            finding: The finding to analyze
            context: Additional context about the target

        Returns:
            ExploitationAssessment for the finding
        """
        prompt = f"""Analyze this vulnerability for real-world exploitability:

Finding: {finding.title}
Type: {finding.vuln_type.value}
Severity: {finding.severity.value}
URL: {finding.url}
Evidence: {finding.evidence[:500] if finding.evidence else 'None'}
Context: {context}

Provide a JSON response:
{{
    "real_world_difficulty": "trivial|easy|moderate|difficult|theoretical",
    "required_skills": "Description",
    "time_estimate": "Time to exploit",
    "impact_assessment": "Business impact"
}}"""

        try:
            response = await self._call_llm(prompt)
            data = self._extract_json(response)
            return ExploitationAssessment(
                finding_title=finding.title,
                real_world_difficulty=data.get("real_world_difficulty", "moderate"),
                required_skills=data.get("required_skills", "Security knowledge"),
                time_estimate=data.get("time_estimate", "Unknown"),
                impact_assessment=data.get("impact_assessment", finding.description),
            )
        except Exception as e:
            logger.warning(f"Single finding analysis failed: {e}")
            return self._default_assessment(finding)

    async def discover_chains(
        self,
        findings: list[Finding],
    ) -> list[DiscoveredChain]:
        """
        Focus specifically on discovering attack chains.

        This is useful when you just want chain discovery without
        full analysis.

        Args:
            findings: Findings to analyze for chains

        Returns:
            List of discovered attack chains
        """
        result = await self.analyze(findings)
        return result.attack_chains

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM and get response."""
        llm = await self._get_llm()

        model_str = f"{self.llm_provider}/{self.llm_model}"
        if self.llm_provider == "anthropic" and not self.llm_model.startswith("anthropic/"):
            model_str = f"anthropic/{self.llm_model}"
        elif self.llm_provider == "openai" and not self.llm_model.startswith("openai/"):
            model_str = f"openai/{self.llm_model}"

        response = await llm.acompletion(
            model=model_str,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4000,
            temperature=0.3,
        )

        return response.choices[0].message.content

    def _parse_response(self, response: str) -> LLMAnalysisResult:
        """Parse LLM response into structured result."""
        data = self._extract_json(response)

        # Parse attack chains
        chains = []
        for chain_data in data.get("attack_chains", []):
            chains.append(DiscoveredChain(
                name=chain_data.get("name", "Unknown Chain"),
                steps=chain_data.get("steps", []),
                final_impact=chain_data.get("final_impact", ""),
                confidence=chain_data.get("confidence", "medium"),
                reasoning=chain_data.get("reasoning", ""),
                cvss_amplification=chain_data.get("cvss_amplification", 1.5),
            ))

        # Parse implicit vulnerabilities
        implicit = []
        for vuln_data in data.get("implicit_vulnerabilities", []):
            implicit.append(ImplicitVulnerability(
                vuln_type=vuln_data.get("type", "unknown"),
                reasoning=vuln_data.get("reasoning", ""),
                indicators=vuln_data.get("indicators", []),
                recommended_test=vuln_data.get("recommended_test", ""),
            ))

        # Parse exploitation assessments
        assessments = []
        for assess_data in data.get("exploitation_assessments", []):
            assessments.append(ExploitationAssessment(
                finding_title=assess_data.get("finding_title", ""),
                real_world_difficulty=assess_data.get("real_world_difficulty", "moderate"),
                required_skills=assess_data.get("required_skills", ""),
                time_estimate=assess_data.get("time_estimate", ""),
                impact_assessment=assess_data.get("impact_assessment", ""),
            ))

        return LLMAnalysisResult(
            attack_chains=chains,
            implicit_vulnerabilities=implicit,
            exploitation_assessments=assessments,
            executive_summary=data.get("executive_summary", "Analysis complete."),
            top_risks=data.get("top_risks", []),
            immediate_actions=data.get("immediate_actions", []),
        )

    def _extract_json(self, response: str) -> dict:
        """Extract JSON from LLM response."""
        # Try to find JSON block
        json_start = response.find("{")
        json_end = response.rfind("}") + 1

        if json_start >= 0 and json_end > json_start:
            json_str = response[json_start:json_end]
            return json.loads(json_str)

        # Try to find code block
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            if end > start:
                return json.loads(response[start:end].strip())

        raise ValueError("No valid JSON found in response")

    def _empty_result(self) -> LLMAnalysisResult:
        """Return empty result for no findings."""
        return LLMAnalysisResult(
            attack_chains=[],
            implicit_vulnerabilities=[],
            exploitation_assessments=[],
            executive_summary="No findings to analyze.",
            top_risks=[],
            immediate_actions=[],
        )

    def _basic_analysis(self, findings: list[Finding]) -> LLMAnalysisResult:
        """Provide basic analysis without LLM."""
        # Count by severity for summary
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)

        summary = f"Analysis identified {len(findings)} findings: {critical} critical, {high} high severity."

        # Basic risk identification
        risks = []
        if critical > 0:
            risks.append(f"{critical} critical vulnerabilities require immediate remediation")
        if high > 0:
            risks.append(f"{high} high-severity issues pose significant risk")

        # Basic actions
        actions = []
        for f in sorted(findings, key=lambda x: x.severity, reverse=True)[:3]:
            actions.append(f"Address {f.vuln_type.value}: {f.title}")

        return LLMAnalysisResult(
            attack_chains=[],
            implicit_vulnerabilities=[],
            exploitation_assessments=[],
            executive_summary=summary,
            top_risks=risks[:5],
            immediate_actions=actions[:5],
        )

    def _default_assessment(self, finding: Finding) -> ExploitationAssessment:
        """Create default assessment for a finding."""
        difficulty_map = {
            Severity.CRITICAL: "easy",
            Severity.HIGH: "moderate",
            Severity.MEDIUM: "moderate",
            Severity.LOW: "difficult",
            Severity.INFO: "theoretical",
        }

        return ExploitationAssessment(
            finding_title=finding.title,
            real_world_difficulty=difficulty_map.get(finding.severity, "moderate"),
            required_skills="Security testing knowledge",
            time_estimate="Varies",
            impact_assessment=finding.description or f"{finding.severity.value} impact",
        )

    def _has_api_key(self) -> bool:
        """Check if API key is available."""
        if self.llm_provider == "anthropic":
            return bool(os.getenv("ANTHROPIC_API_KEY"))
        if self.llm_provider == "openai":
            return bool(os.getenv("OPENAI_API_KEY"))
        return False
