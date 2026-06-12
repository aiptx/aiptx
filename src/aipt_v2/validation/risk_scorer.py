"""
AIPTX Risk Scorer - Multi-factor Risk Assessment.

Combines CVSS, EPSS, business impact, and contextual factors
for comprehensive vulnerability risk scoring.

Integrated from Zen-AI-Pentest for AIPTX v5.2.

Example usage:
    from aipt_v2.validation import RiskScorer

    scorer = RiskScorer()
    score = await scorer.calculate_risk_score(finding, context)

    print(f"Risk Score: {score.final_score:.2f}")
    print(f"Priority: {score.priority}")
    print(f"Recommendations: {score.recommendations}")
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level classification."""

    CRITICAL = "critical"  # >= 0.9
    HIGH = "high"  # 0.7-0.9
    MEDIUM = "medium"  # 0.4-0.7
    LOW = "low"  # 0.1-0.4
    INFO = "info"  # < 0.1

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """Convert numeric score to risk level."""
        if score >= 0.9:
            return cls.CRITICAL
        elif score >= 0.7:
            return cls.HIGH
        elif score >= 0.4:
            return cls.MEDIUM
        elif score >= 0.1:
            return cls.LOW
        return cls.INFO


class AssetCriticality(Enum):
    """Asset criticality levels."""

    CRITICAL = ("critical", 1.0)  # Core business systems
    HIGH = ("high", 0.8)  # Important systems
    MEDIUM = ("medium", 0.5)  # Standard systems
    LOW = ("low", 0.3)  # Non-critical systems
    MINIMAL = ("minimal", 0.1)  # Test/dev systems

    def __init__(self, label: str, weight: float):
        self.label = label
        self.weight = weight


class DataClassification(Enum):
    """Data classification levels."""

    RESTRICTED = ("restricted", 1.0)  # PII, PCI, PHI
    CONFIDENTIAL = ("confidential", 0.8)  # Internal sensitive
    INTERNAL = ("internal", 0.4)  # Internal only
    PUBLIC = ("public", 0.1)  # Public data

    def __init__(self, label: str, weight: float):
        self.label = label
        self.weight = weight


@dataclass
class EPSSResult:
    """Result from EPSS API query."""

    cve_id: str
    epss_score: float  # 0-1 probability
    percentile: float  # 0-100 percentile
    model_version: str = ""
    query_date: datetime = field(default_factory=datetime.now)

    @property
    def risk_level(self) -> str:
        """Get risk level from EPSS score."""
        if self.epss_score >= 0.7:
            return "CRITICAL"
        elif self.epss_score >= 0.4:
            return "HIGH"
        elif self.epss_score >= 0.1:
            return "MEDIUM"
        return "LOW"


@dataclass
class RiskScore:
    """Comprehensive risk score result."""

    final_score: float  # 0-1 overall risk
    risk_level: RiskLevel
    priority: int  # 1-5, 1 = highest

    # Component scores
    cvss_score: float
    epss_score: float
    business_impact_score: float
    exploitability_score: float
    context_score: float

    # Multipliers applied
    multipliers: Dict[str, float] = field(default_factory=dict)

    # Recommendations
    recommendations: List[str] = field(default_factory=list)

    # Metadata
    calculated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "final_score": round(self.final_score, 3),
            "risk_level": self.risk_level.value,
            "priority": self.priority,
            "components": {
                "cvss": round(self.cvss_score, 3),
                "epss": round(self.epss_score, 3),
                "business_impact": round(self.business_impact_score, 3),
                "exploitability": round(self.exploitability_score, 3),
                "context": round(self.context_score, 3),
            },
            "multipliers": self.multipliers,
            "recommendations": self.recommendations,
            "calculated_at": self.calculated_at.isoformat(),
        }


class RiskScorer:
    """
    Multi-factor Risk Scorer.

    Combines CVSS, EPSS, business impact, and context
    for comprehensive vulnerability risk assessment.
    """

    # Base weights (sum to 1.0)
    WEIGHTS = {
        "cvss": 0.25,
        "epss": 0.20,
        "business_impact": 0.20,
        "exploitability": 0.15,
        "context": 0.20,
    }

    # Context multipliers
    MULTIPLIERS = {
        "internet_exposed": 1.4,
        "exploit_available": 1.3,
        "active_exploitation": 1.5,
        "no_patch": 1.2,
        "no_auth_required": 1.2,
        "no_user_interaction": 1.1,
    }

    # EPSS API endpoint
    EPSS_API = "https://api.first.org/data/v1/epss"

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        """
        Initialize the Risk Scorer.

        Args:
            custom_weights: Optional custom weights for components
        """
        self.weights = custom_weights or self.WEIGHTS.copy()
        self._epss_cache: Dict[str, EPSSResult] = {}
        logger.info("RiskScorer initialized")

    async def calculate_risk_score(
        self, finding: Any, context: Optional[Dict[str, Any]] = None
    ) -> RiskScore:
        """
        Calculate comprehensive risk score for a finding.

        Args:
            finding: AIPTX Finding object
            context: Additional context (asset info, exposure, etc.)

        Returns:
            RiskScore with detailed breakdown
        """
        context = context or {}

        # Extract finding attributes
        cvss = getattr(finding, "cvss_score", None) or 0.0
        cve_ids = getattr(finding, "cve_ids", []) or []
        severity = getattr(finding, "severity", "medium")
        if hasattr(severity, "value"):
            severity = severity.value

        # 1. CVSS component (normalized to 0-1)
        cvss_score = cvss / 10.0

        # If no CVSS, estimate from severity
        if cvss_score == 0:
            cvss_score = self._estimate_cvss_from_severity(severity)

        # 2. EPSS component
        epss_score = 0.0
        if cve_ids:
            epss_results = await self.get_epss_scores(cve_ids)
            if epss_results:
                epss_score = max(r.epss_score for r in epss_results)

        # 3. Business impact
        business_impact = self._calculate_business_impact(
            asset_criticality=context.get("asset_criticality", "medium"),
            data_classification=context.get("data_classification", "internal"),
            affected_users=context.get("affected_users", 0),
            revenue_impact=context.get("revenue_impact", False),
        )

        # 4. Exploitability
        exploitability = self._calculate_exploitability(
            exploit_available=context.get("exploit_available", False),
            skill_required=context.get("skill_required", "low"),
            attack_complexity=context.get("attack_complexity", "low"),
        )

        # 5. Context score
        context_score, multipliers = self._calculate_context(
            internet_exposed=context.get("internet_exposed", False),
            active_exploitation=context.get("active_exploitation", False),
            patch_available=context.get("patch_available", True),
            auth_required=context.get("auth_required", True),
            user_interaction=context.get("user_interaction", True),
        )

        # Calculate weighted base score
        base_score = (
            cvss_score * self.weights["cvss"]
            + epss_score * self.weights["epss"]
            + business_impact * self.weights["business_impact"]
            + exploitability * self.weights["exploitability"]
            + context_score * self.weights["context"]
        )

        # Apply multipliers
        total_multiplier = 1.0
        for name, mult in multipliers.items():
            total_multiplier *= mult

        final_score = min(1.0, base_score * total_multiplier)

        # Determine risk level and priority
        risk_level = RiskLevel.from_score(final_score)
        priority = self._calculate_priority(final_score, multipliers)

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_level, multipliers, context)

        return RiskScore(
            final_score=final_score,
            risk_level=risk_level,
            priority=priority,
            cvss_score=cvss_score,
            epss_score=epss_score,
            business_impact_score=business_impact,
            exploitability_score=exploitability,
            context_score=context_score,
            multipliers=multipliers,
            recommendations=recommendations,
        )

    async def get_epss_scores(self, cve_ids: List[str]) -> List[EPSSResult]:
        """
        Fetch EPSS scores for CVE IDs from FIRST.org API.

        Args:
            cve_ids: List of CVE IDs (e.g., ["CVE-2021-44228"])

        Returns:
            List of EPSSResult objects
        """
        results = []

        # Check cache first
        uncached = []
        for cve_id in cve_ids:
            if cve_id in self._epss_cache:
                results.append(self._epss_cache[cve_id])
            else:
                uncached.append(cve_id)

        if not uncached:
            return results

        # Query EPSS API
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                cve_list = ",".join(uncached)
                response = await client.get(self.EPSS_API, params={"cve": cve_list})
                response.raise_for_status()
                data = response.json()

                for item in data.get("data", []):
                    epss_result = EPSSResult(
                        cve_id=item.get("cve", ""),
                        epss_score=float(item.get("epss", 0)),
                        percentile=float(item.get("percentile", 0)) * 100,
                        model_version=data.get("model_version", ""),
                    )
                    results.append(epss_result)
                    self._epss_cache[epss_result.cve_id] = epss_result

        except Exception as e:
            logger.warning(f"EPSS API query failed: {e}")
            # Return estimated scores for uncached CVEs
            for cve_id in uncached:
                results.append(self._estimate_epss(cve_id))

        return results

    def _estimate_cvss_from_severity(self, severity: str) -> float:
        """Estimate CVSS from severity level."""
        severity_map = {
            "critical": 0.95,
            "high": 0.8,
            "medium": 0.55,
            "low": 0.3,
            "info": 0.1,
        }
        return severity_map.get(severity.lower(), 0.5)

    def _estimate_epss(self, cve_id: str) -> EPSSResult:
        """Estimate EPSS when API unavailable."""
        # Extract year from CVE ID for age-based estimation
        try:
            year = int(cve_id.split("-")[1])
            current_year = datetime.now().year
            age_years = current_year - year

            # Newer CVEs tend to have higher exploitation probability
            if age_years <= 1:
                base_score = 0.15
            elif age_years <= 3:
                base_score = 0.10
            else:
                base_score = 0.05

            return EPSSResult(
                cve_id=cve_id,
                epss_score=base_score,
                percentile=50.0,
                model_version="estimated",
            )
        except (IndexError, ValueError):
            return EPSSResult(
                cve_id=cve_id,
                epss_score=0.05,
                percentile=30.0,
                model_version="estimated",
            )

    def _calculate_business_impact(
        self,
        asset_criticality: str,
        data_classification: str,
        affected_users: int,
        revenue_impact: bool,
    ) -> float:
        """Calculate business impact score."""
        # Asset criticality
        criticality_map = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "minimal": 0.1,
        }
        criticality_score = criticality_map.get(asset_criticality.lower(), 0.5)

        # Data classification
        classification_map = {
            "restricted": 1.0,
            "confidential": 0.8,
            "internal": 0.4,
            "public": 0.1,
        }
        data_score = classification_map.get(data_classification.lower(), 0.4)

        # User impact
        user_score = 0.0
        if affected_users >= 10000:
            user_score = 1.0
        elif affected_users >= 1000:
            user_score = 0.8
        elif affected_users >= 100:
            user_score = 0.5
        elif affected_users >= 10:
            user_score = 0.3

        # Revenue impact
        revenue_score = 0.5 if revenue_impact else 0.0

        # Weighted combination
        return criticality_score * 0.4 + data_score * 0.3 + user_score * 0.2 + revenue_score * 0.1

    def _calculate_exploitability(
        self,
        exploit_available: bool,
        skill_required: str,
        attack_complexity: str,
    ) -> float:
        """Calculate exploitability score."""
        score = 0.3  # Base score

        # Exploit availability
        if exploit_available:
            score += 0.4

        # Skill required
        skill_map = {
            "none": 0.3,
            "low": 0.2,
            "medium": 0.1,
            "high": 0.0,
        }
        score += skill_map.get(skill_required.lower(), 0.1)

        # Attack complexity
        complexity_map = {
            "low": 0.2,
            "medium": 0.1,
            "high": 0.0,
        }
        score += complexity_map.get(attack_complexity.lower(), 0.1)

        return min(1.0, score)

    def _calculate_context(
        self,
        internet_exposed: bool,
        active_exploitation: bool,
        patch_available: bool,
        auth_required: bool,
        user_interaction: bool,
    ) -> tuple[float, Dict[str, float]]:
        """Calculate context score and multipliers."""
        score = 0.3  # Base score
        multipliers = {}

        if internet_exposed:
            score += 0.3
            multipliers["internet_exposed"] = self.MULTIPLIERS["internet_exposed"]

        if active_exploitation:
            score += 0.4
            multipliers["active_exploitation"] = self.MULTIPLIERS["active_exploitation"]

        if not patch_available:
            score += 0.2
            multipliers["no_patch"] = self.MULTIPLIERS["no_patch"]

        if not auth_required:
            score += 0.1
            multipliers["no_auth_required"] = self.MULTIPLIERS["no_auth_required"]

        if not user_interaction:
            score += 0.1
            multipliers["no_user_interaction"] = self.MULTIPLIERS["no_user_interaction"]

        return min(1.0, score), multipliers

    def _calculate_priority(self, final_score: float, multipliers: Dict[str, float]) -> int:
        """Calculate remediation priority (1 = highest)."""
        # Base priority from score
        if final_score >= 0.9:
            priority = 1
        elif final_score >= 0.7:
            priority = 2
        elif final_score >= 0.4:
            priority = 3
        elif final_score >= 0.2:
            priority = 4
        else:
            priority = 5

        # Urgent conditions override
        if "active_exploitation" in multipliers:
            priority = 1
        elif "internet_exposed" in multipliers and priority > 2:
            priority = 2

        return priority

    def _generate_recommendations(
        self, risk_level: RiskLevel, multipliers: Dict[str, float], context: Dict[str, Any]
    ) -> List[str]:
        """Generate risk-based recommendations."""
        recommendations = []

        # Base recommendations by risk level
        if risk_level == RiskLevel.CRITICAL:
            recommendations.append("CRITICAL: Immediate remediation required")
            recommendations.append("Escalate to security leadership")
            recommendations.append("Consider emergency change procedures")
        elif risk_level == RiskLevel.HIGH:
            recommendations.append("HIGH: Remediate within 7 days")
            recommendations.append("Assign dedicated resources")
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.append("MEDIUM: Remediate within 30 days")
        elif risk_level == RiskLevel.LOW:
            recommendations.append("LOW: Address in next maintenance window")
        else:
            recommendations.append("INFO: Track for awareness")

        # Context-specific recommendations
        if "active_exploitation" in multipliers:
            recommendations.insert(0, "ACTIVE EXPLOITATION DETECTED")
            recommendations.append("Isolate affected systems immediately")
            recommendations.append("Enable enhanced monitoring")

        if "internet_exposed" in multipliers:
            recommendations.append("Implement WAF or rate limiting")
            recommendations.append("Consider IP-based access controls")

        if "no_patch" in multipliers:
            recommendations.append("Implement compensating controls")
            recommendations.append("Monitor for vendor patch release")

        if "no_auth_required" in multipliers:
            recommendations.append("Add authentication layer")

        return recommendations


# Convenience functions
async def calculate_risk(finding: Any, context: Optional[Dict[str, Any]] = None) -> RiskScore:
    """
    Convenience function to calculate risk score.

    Args:
        finding: AIPTX Finding object
        context: Additional context

    Returns:
        RiskScore
    """
    scorer = RiskScorer()
    return await scorer.calculate_risk_score(finding, context)


async def get_epss(cve_ids: List[str]) -> List[EPSSResult]:
    """
    Convenience function to fetch EPSS scores.

    Args:
        cve_ids: List of CVE IDs

    Returns:
        List of EPSSResult
    """
    scorer = RiskScorer()
    return await scorer.get_epss_scores(cve_ids)
