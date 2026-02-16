"""
AIPTX False Positive Reduction Engine.

Multi-factor validation combining:
- Multi-LLM consensus voting
- Bayesian filtering based on historical patterns
- Business impact assessment
- CVSS + EPSS scoring
- Context-aware analysis

Integrated from Zen-AI-Pentest for AIPTX v5.2.

Example usage:
    from aipt_v2.validation import FalsePositiveEngine
    from aipt_v2.models import Finding

    engine = FalsePositiveEngine(llm=llm_client)
    result = await engine.validate_finding(finding, context)

    if result.is_false_positive:
        print(f"False positive detected: {result.reasoning}")
    else:
        print(f"Confirmed vulnerability, priority: {result.priority}")
"""

import asyncio
import hashlib
import json
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """Confidence levels for validation results."""

    VERY_HIGH = "very_high"    # >= 0.90
    HIGH = "high"              # 0.75-0.90
    MEDIUM = "medium"          # 0.50-0.75
    LOW = "low"                # 0.25-0.50
    VERY_LOW = "very_low"      # < 0.25

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        """Convert numeric score to confidence level."""
        if score >= 0.90:
            return cls.VERY_HIGH
        elif score >= 0.75:
            return cls.HIGH
        elif score >= 0.50:
            return cls.MEDIUM
        elif score >= 0.25:
            return cls.LOW
        return cls.VERY_LOW


class FindingStatus(Enum):
    """Status of a security finding after validation."""

    CONFIRMED = "confirmed"           # Verified exploitable
    LIKELY = "likely"                 # High confidence, awaiting verification
    SUSPECTED = "suspected"           # Medium confidence
    FALSE_POSITIVE = "false_positive" # Determined to be FP
    UNDER_REVIEW = "under_review"     # Needs manual review
    SUPPRESSED = "suppressed"         # User-suppressed


@dataclass
class CVSSData:
    """CVSS v3.1/v4.0 scoring data."""

    version: str = "3.1"
    base_score: float = 0.0
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    vector_string: str = ""

    # CVSS v3.1 base metrics
    attack_vector: Optional[str] = None       # N, A, L, P
    attack_complexity: Optional[str] = None   # L, H
    privileges_required: Optional[str] = None # N, L, H
    user_interaction: Optional[str] = None    # N, R
    scope: Optional[str] = None               # U, C
    confidentiality_impact: Optional[str] = None  # N, L, H
    integrity_impact: Optional[str] = None    # N, L, H
    availability_impact: Optional[str] = None # N, L, H

    def get_effective_score(self) -> float:
        """Get the most specific CVSS score available."""
        if self.environmental_score is not None:
            return self.environmental_score
        if self.temporal_score is not None:
            return self.temporal_score
        return self.base_score

    def get_severity(self) -> str:
        """Get severity label from CVSS score."""
        score = self.get_effective_score()
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "None"


@dataclass
class EPSSData:
    """EPSS (Exploit Prediction Scoring System) data."""

    cve_id: str
    epss_score: float      # 0-1 probability of exploitation
    percentile: float      # Percentile ranking
    date: datetime = field(default_factory=datetime.now)

    def is_high_probability(self) -> bool:
        """Check if exploitation probability is high (>=0.5)."""
        return self.epss_score >= 0.5

    def get_risk_level(self) -> str:
        """Classify EPSS risk level."""
        if self.epss_score >= 0.7:
            return "CRITICAL"
        elif self.epss_score >= 0.4:
            return "HIGH"
        elif self.epss_score >= 0.1:
            return "MEDIUM"
        return "LOW"


@dataclass
class RiskFactors:
    """Collection of risk factors for a finding."""

    cvss_data: CVSSData = field(default_factory=CVSSData)
    epss_score: float = 0.0
    business_impact: float = 0.0      # 0-1 scale
    exploitability: float = 0.0       # 0-1 scale
    asset_criticality: float = 0.0    # 0-1 scale

    # Context factors
    internet_exposed: bool = False
    data_classification: str = "internal"  # public, internal, confidential, restricted
    patch_available: bool = True
    exploit_code_available: bool = False
    active_exploitation: bool = False

    # Network context
    network_segment: str = "internal"
    authentication_required: bool = True
    user_interaction_required: bool = False

    def get_weighted_risk_score(self) -> float:
        """Calculate weighted risk score."""
        cvss_weight = self.cvss_data.get_effective_score() / 10.0

        weights = {
            "cvss": 0.25,
            "epss": 0.20,
            "business_impact": 0.20,
            "exploitability": 0.15,
            "asset_criticality": 0.15,
            "context": 0.05,
        }

        # Context multipliers
        context_multiplier = 1.0
        if self.internet_exposed:
            context_multiplier += 0.3
        if self.exploit_code_available:
            context_multiplier += 0.2
        if self.active_exploitation:
            context_multiplier += 0.4
        if not self.patch_available:
            context_multiplier += 0.1

        score = (
            cvss_weight * weights["cvss"]
            + self.epss_score * weights["epss"]
            + self.business_impact * weights["business_impact"]
            + self.exploitability * weights["exploitability"]
            + self.asset_criticality * weights["asset_criticality"]
        ) * min(2.0, context_multiplier)

        return min(1.0, score)


@dataclass
class FPValidationResult:
    """Result of false positive validation."""

    finding_id: str
    is_false_positive: bool
    confidence: float
    confidence_level: ConfidenceLevel
    status: FindingStatus
    risk_score: float
    priority: int  # 1 = highest, 999 = lowest (FP)
    reasoning: str
    recommendations: List[str] = field(default_factory=list)
    validation_methods: List[str] = field(default_factory=list)
    llm_votes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "is_false_positive": self.is_false_positive,
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level.value,
            "status": self.status.value,
            "risk_score": round(self.risk_score, 3),
            "priority": self.priority,
            "reasoning": self.reasoning,
            "recommendations": self.recommendations,
            "validation_methods": self.validation_methods,
            "llm_votes": self.llm_votes,
        }


@dataclass
class HistoricalFinding:
    """Historical finding for pattern matching."""

    finding_hash: str
    is_false_positive: bool
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    user_feedback: Optional[bool] = None
    feedback_timestamp: Optional[datetime] = None


class BayesianFilter:
    """
    Bayesian filter for false positive detection.

    Uses Naive Bayes classification trained on historical
    finding descriptions to predict FP probability.
    """

    def __init__(self):
        self.word_probs_fp: Dict[str, float] = defaultdict(lambda: 0.5)
        self.word_probs_tp: Dict[str, float] = defaultdict(lambda: 0.5)
        self.fp_count = 0
        self.tp_count = 0
        self.min_samples = 5

    def train(self, text: str, is_false_positive: bool):
        """Train the filter with a labeled sample."""
        words = self._extract_features(text)

        if is_false_positive:
            self.fp_count += 1
            for word in words:
                current = self.word_probs_fp[word]
                self.word_probs_fp[word] = (current * self.fp_count + 1) / (self.fp_count + 2)
        else:
            self.tp_count += 1
            for word in words:
                current = self.word_probs_tp[word]
                self.word_probs_tp[word] = (current * self.tp_count + 1) / (self.tp_count + 2)

    def predict(self, text: str) -> Tuple[bool, float]:
        """
        Predict if text indicates a false positive.

        Returns:
            Tuple of (is_fp, probability)
        """
        words = self._extract_features(text)
        if not words:
            return False, 0.5

        # Naive Bayes calculation with log probabilities
        fp_prob = math.log(self.fp_count + 1) - math.log(self.fp_count + self.tp_count + 2)
        tp_prob = math.log(self.tp_count + 1) - math.log(self.fp_count + self.tp_count + 2)

        for word in words:
            fp_prob += math.log(self.word_probs_fp[word] + 0.01)
            tp_prob += math.log(self.word_probs_tp[word] + 0.01)

        # Normalize to probabilities
        fp_prob = math.exp(fp_prob)
        tp_prob = math.exp(tp_prob)
        total = fp_prob + tp_prob

        if total == 0:
            return False, 0.5

        fp_likelihood = fp_prob / total
        return fp_likelihood > 0.5, fp_likelihood

    def _extract_features(self, text: str) -> List[str]:
        """Extract feature words from text."""
        stopwords = {"the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
                     "and", "or", "but", "in", "on", "at", "to", "for", "of", "with"}
        words = text.lower().split()
        return [w.strip(".,;:!?()[]{}") for w in words if len(w) > 3 and w not in stopwords]


class FalsePositiveDatabase:
    """
    Database for historical findings and FP patterns.

    Stores fingerprints of validated findings for
    quick lookup and Bayesian filter training.
    """

    def __init__(self, storage_path: Optional[Union[str, Path]] = None):
        self.storage_path = Path(storage_path) if storage_path else None
        self.findings: Dict[str, HistoricalFinding] = {}
        self.bayesian_filter = BayesianFilter()
        self.similarity_threshold = 0.85

        if self.storage_path and self.storage_path.exists():
            self._load_from_storage()

    def add_finding(
        self,
        finding_hash: str,
        description: str,
        is_false_positive: bool,
        user_feedback: Optional[bool] = None
    ):
        """Add or update a finding in the database."""
        now = datetime.now()

        if finding_hash in self.findings:
            hist = self.findings[finding_hash]
            hist.last_seen = now
            hist.occurrence_count += 1
            if user_feedback is not None:
                hist.user_feedback = user_feedback
                hist.feedback_timestamp = now
        else:
            self.findings[finding_hash] = HistoricalFinding(
                finding_hash=finding_hash,
                is_false_positive=is_false_positive,
                first_seen=now,
                last_seen=now,
                user_feedback=user_feedback,
            )

        # Train Bayesian filter
        self.bayesian_filter.train(description, is_false_positive)

        if self.storage_path:
            self._save_to_storage()

    def check_historical_match(self, finding_hash: str) -> Optional[HistoricalFinding]:
        """Check for exact or similar historical match."""
        if finding_hash in self.findings:
            return self.findings[finding_hash]
        return None

    def get_fp_likelihood(self, description: str) -> float:
        """Get FP likelihood from Bayesian filter."""
        _, fp_likelihood = self.bayesian_filter.predict(description)
        return fp_likelihood

    def _load_from_storage(self):
        """Load database from JSON file."""
        try:
            with open(self.storage_path, "r") as f:
                data = json.load(f)
                for item in data.get("findings", []):
                    hist = HistoricalFinding(
                        finding_hash=item["finding_hash"],
                        is_false_positive=item["is_false_positive"],
                        first_seen=datetime.fromisoformat(item["first_seen"]),
                        last_seen=datetime.fromisoformat(item["last_seen"]),
                        occurrence_count=item["occurrence_count"],
                        user_feedback=item.get("user_feedback"),
                        feedback_timestamp=(
                            datetime.fromisoformat(item["feedback_timestamp"])
                            if item.get("feedback_timestamp") else None
                        ),
                    )
                    self.findings[hist.finding_hash] = hist
                logger.info(f"Loaded {len(self.findings)} historical findings")
        except Exception as e:
            logger.warning(f"Could not load FP database: {e}")

    def _save_to_storage(self):
        """Save database to JSON file."""
        try:
            data = {
                "findings": [
                    {
                        "finding_hash": h.finding_hash,
                        "is_false_positive": h.is_false_positive,
                        "first_seen": h.first_seen.isoformat(),
                        "last_seen": h.last_seen.isoformat(),
                        "occurrence_count": h.occurrence_count,
                        "user_feedback": h.user_feedback,
                        "feedback_timestamp": (
                            h.feedback_timestamp.isoformat() if h.feedback_timestamp else None
                        ),
                    }
                    for h in self.findings.values()
                ]
            }
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save FP database: {e}")


class LLMVotingEngine:
    """
    Multi-LLM consensus voting for finding validation.

    Queries multiple LLM providers and aggregates their
    opinions to determine if a finding is a false positive.
    """

    def __init__(self, consensus_threshold: float = 0.6):
        self.llm_clients: Dict[str, Any] = {}
        self.consensus_threshold = consensus_threshold

    def register_llm(self, name: str, client: Any):
        """Register an LLM client for voting."""
        self.llm_clients[name] = client
        logger.info(f"Registered LLM '{name}' for FP voting")

    async def vote_on_finding(
        self,
        title: str,
        description: str,
        severity: str,
        vuln_type: str,
        evidence: Dict[str, Any]
    ) -> Tuple[Dict[str, str], float]:
        """
        Conduct multi-LLM voting on a finding.

        Returns:
            Tuple of (votes_by_llm, consensus_confidence)
        """
        if not self.llm_clients:
            logger.warning("No LLMs registered, skipping voting")
            return {}, 0.5

        votes: Dict[str, str] = {}
        tasks = []

        for name, client in self.llm_clients.items():
            task = self._query_llm(
                name, client, title, description, severity, vuln_type, evidence
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for name, result in zip(self.llm_clients.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"LLM {name} error: {result}")
                continue
            votes[name] = result

        if not votes:
            return {}, 0.0

        # Calculate consensus
        fp_votes = sum(1 for v in votes.values() if v == "FALSE_POSITIVE")
        total_votes = len(votes)
        fp_ratio = fp_votes / total_votes

        # Confidence based on agreement
        agreement = abs(fp_ratio - 0.5) * 2  # 0 = split, 1 = unanimous
        confidence = 0.5 + (agreement * 0.4)

        logger.debug(f"LLM Voting: {fp_votes}/{total_votes} FP votes, confidence: {confidence:.2f}")
        return votes, confidence

    async def _query_llm(
        self,
        name: str,
        client: Any,
        title: str,
        description: str,
        severity: str,
        vuln_type: str,
        evidence: Dict[str, Any]
    ) -> str:
        """Query a single LLM for its opinion."""
        prompt = self._build_prompt(title, description, severity, vuln_type, evidence)

        try:
            if hasattr(client, "complete"):
                response = await client.complete(prompt)
                return self._parse_response(response)
            elif hasattr(client, "generate"):
                response = await client.generate(prompt)
                return self._parse_response(response)
            else:
                # Fallback to heuristic
                return self._heuristic_decision(description, severity)
        except Exception as e:
            logger.error(f"LLM {name} query failed: {e}")
            raise

    def _build_prompt(
        self,
        title: str,
        description: str,
        severity: str,
        vuln_type: str,
        evidence: Dict[str, Any]
    ) -> str:
        """Build the analysis prompt for LLMs."""
        return f"""Analyze this security finding and determine if it's likely a FALSE POSITIVE:

**Title:** {title}
**Severity:** {severity}
**Type:** {vuln_type}
**Description:** {description}

**Evidence:**
{json.dumps(evidence, indent=2, default=str)[:2000]}

Consider:
1. Is the vulnerability actually exploitable in this context?
2. Is the evidence conclusive or ambiguous?
3. Are there mitigating factors (WAF, input validation, etc.)?
4. Could this be a scanner misconfiguration or noise?

Respond with ONLY "TRUE_POSITIVE" or "FALSE_POSITIVE".
"""

    def _parse_response(self, response: str) -> str:
        """Parse LLM response to vote."""
        response_lower = response.lower().strip()
        if "false_positive" in response_lower or "false positive" in response_lower:
            return "FALSE_POSITIVE"
        return "TRUE_POSITIVE"

    def _heuristic_decision(self, description: str, severity: str) -> str:
        """Heuristic fallback when LLM unavailable."""
        fp_indicators = [
            "informational", "note", "best practice", "recommendation",
            "consider", "might be", "possibly", "could potentially",
        ]
        desc_lower = description.lower()
        indicator_count = sum(1 for ind in fp_indicators if ind in desc_lower)

        if indicator_count >= 2 or severity.lower() in ["info", "low"]:
            return "FALSE_POSITIVE"
        return "TRUE_POSITIVE"


class FalsePositiveEngine:
    """
    Main False Positive Reduction Engine.

    Combines multi-factor validation:
    - Historical pattern matching with Bayesian filtering
    - Multi-LLM consensus voting
    - CVSS + EPSS risk scoring
    - Business impact assessment
    - Context-aware analysis
    """

    # Thresholds
    FP_CONFIDENCE_THRESHOLD = 0.75
    CONFIRMED_THRESHOLD = 0.85

    # Risk weights
    CVSS_WEIGHT = 0.25
    EPSS_WEIGHT = 0.20
    BUSINESS_WEIGHT = 0.20
    EXPLOITABILITY_WEIGHT = 0.15
    CONTEXT_WEIGHT = 0.20

    def __init__(
        self,
        llm: Any = None,
        fp_database_path: Optional[Union[str, Path]] = None,
        enable_llm_voting: bool = True,
    ):
        """
        Initialize the False Positive Engine.

        Args:
            llm: LLM client for analysis (optional)
            fp_database_path: Path to FP database file
            enable_llm_voting: Whether to enable multi-LLM voting
        """
        self.fp_database = FalsePositiveDatabase(fp_database_path)
        self.llm_voting = LLMVotingEngine() if enable_llm_voting else None

        # Register primary LLM if provided
        if llm and self.llm_voting:
            self.llm_voting.register_llm("primary", llm)

        logger.info("FalsePositiveEngine initialized")

    async def validate_finding(
        self,
        finding: Any,
        context: Optional[Dict[str, Any]] = None
    ) -> FPValidationResult:
        """
        Validate a finding and determine if it's a false positive.

        Args:
            finding: AIPTX Finding object
            context: Additional context (asset info, network exposure, etc.)

        Returns:
            FPValidationResult with validation details
        """
        context = context or {}
        validation_methods = []

        # Extract finding attributes
        finding_id = getattr(finding, "fingerprint", str(id(finding)))
        title = getattr(finding, "title", "")
        description = getattr(finding, "description", "")
        severity = getattr(finding, "severity", "medium")
        if hasattr(severity, "value"):
            severity = severity.value
        vuln_type = getattr(finding, "vuln_type", "unknown")
        if hasattr(vuln_type, "value"):
            vuln_type = vuln_type.value
        cvss_score = getattr(finding, "cvss_score", None) or 0.0
        evidence = getattr(finding, "evidence", "") or ""
        cve_ids = getattr(finding, "cve_ids", []) or []

        # Build evidence dict
        evidence_dict = {
            "raw_evidence": evidence[:1000] if isinstance(evidence, str) else str(evidence)[:1000],
            "request": getattr(finding, "request", "")[:500] if getattr(finding, "request", None) else "",
            "response": getattr(finding, "response", "")[:500] if getattr(finding, "response", None) else "",
        }

        # 1. Historical validation
        finding_hash = self._generate_hash(title, description, vuln_type)
        historical = self.fp_database.check_historical_match(finding_hash)
        validation_methods.append("historical")

        # 2. Bayesian filter
        bayesian_fp_prob = self.fp_database.get_fp_likelihood(f"{title} {description}")
        validation_methods.append("bayesian")

        # 3. Multi-LLM voting
        llm_votes: Dict[str, str] = {}
        llm_confidence = 0.5
        if self.llm_voting and self.llm_voting.llm_clients:
            llm_votes, llm_confidence = await self.llm_voting.vote_on_finding(
                title, description, severity, vuln_type, evidence_dict
            )
            validation_methods.append("llm_voting")

        # 4. Build risk factors
        risk_factors = RiskFactors(
            cvss_data=CVSSData(base_score=cvss_score),
            internet_exposed=context.get("internet_exposed", False),
            data_classification=context.get("data_classification", "internal"),
            exploit_code_available=context.get("exploit_available", False),
            active_exploitation=context.get("active_exploitation", False),
            asset_criticality=context.get("asset_criticality", 0.5),
            business_impact=context.get("business_impact", 0.5),
        )

        # 5. Calculate risk score
        risk_score = self._calculate_risk_score(risk_factors)
        validation_methods.append("risk_scoring")

        # 6. Context analysis
        context_score = self._analyze_context(description, severity, risk_factors)
        validation_methods.append("context_analysis")

        # Make decision
        is_fp, confidence, reasoning = self._make_decision(
            historical, bayesian_fp_prob, llm_votes, llm_confidence,
            risk_score, context_score, description, severity
        )

        # Determine status
        status = self._determine_status(is_fp, confidence)

        # Calculate priority
        priority = self._calculate_priority(is_fp, risk_score, risk_factors)

        # Generate recommendations
        recommendations = self._generate_recommendations(is_fp, risk_score, risk_factors)

        # Store in database for future learning
        self.fp_database.add_finding(finding_hash, f"{title} {description}", is_fp)

        result = FPValidationResult(
            finding_id=finding_id,
            is_false_positive=is_fp,
            confidence=confidence,
            confidence_level=ConfidenceLevel.from_score(confidence),
            status=status,
            risk_score=risk_score,
            priority=priority,
            reasoning=reasoning,
            recommendations=recommendations,
            validation_methods=validation_methods,
            llm_votes=llm_votes,
        )

        logger.info(
            f"Finding {finding_id[:8]}... validated: "
            f"FP={is_fp}, confidence={confidence:.2f}, priority={priority}"
        )
        return result

    async def validate_findings(
        self,
        findings: List[Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[FPValidationResult]:
        """
        Validate multiple findings in parallel.

        Args:
            findings: List of AIPTX Finding objects
            context: Shared context for all findings

        Returns:
            List of FPValidationResult objects
        """
        tasks = [self.validate_finding(f, context) for f in findings]
        return await asyncio.gather(*tasks)

    def prioritize_findings(
        self,
        results: List[FPValidationResult]
    ) -> List[FPValidationResult]:
        """
        Sort findings by priority (confirmed true positives first).

        Args:
            results: List of validation results

        Returns:
            Sorted list with highest priority first
        """
        def priority_key(r: FPValidationResult) -> Tuple[int, float]:
            return (r.priority, -r.risk_score)

        return sorted(results, key=priority_key)

    async def learn_from_feedback(
        self,
        finding_id: str,
        finding_description: str,
        is_false_positive: bool
    ):
        """
        Learn from user feedback to improve accuracy.

        Args:
            finding_id: Finding identifier
            finding_description: Finding description text
            is_false_positive: User's determination
        """
        finding_hash = hashlib.sha256(finding_id.encode()).hexdigest()[:16]
        self.fp_database.add_finding(
            finding_hash,
            finding_description,
            is_false_positive,
            user_feedback=is_false_positive
        )
        logger.info(f"Learned from feedback for {finding_id[:8]}...: FP={is_false_positive}")

    def register_llm(self, name: str, client: Any):
        """Register an additional LLM for voting."""
        if self.llm_voting:
            self.llm_voting.register_llm(name, client)

    def _generate_hash(self, title: str, description: str, vuln_type: str) -> str:
        """Generate finding hash for deduplication."""
        content = f"{title}:{description[:200]}:{vuln_type}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _calculate_risk_score(self, factors: RiskFactors) -> float:
        """Calculate composite risk score."""
        cvss_component = (factors.cvss_data.get_effective_score() / 10.0) * self.CVSS_WEIGHT
        epss_component = factors.epss_score * self.EPSS_WEIGHT
        business_component = factors.business_impact * self.BUSINESS_WEIGHT
        exploitability_component = factors.exploitability * self.EXPLOITABILITY_WEIGHT

        # Context multipliers
        context_multiplier = 1.0
        if factors.internet_exposed:
            context_multiplier += 0.4
        if factors.exploit_code_available:
            context_multiplier += 0.3
        if factors.active_exploitation:
            context_multiplier += 0.5
        if not factors.patch_available:
            context_multiplier += 0.2
        if not factors.authentication_required:
            context_multiplier += 0.2
        if not factors.user_interaction_required:
            context_multiplier += 0.1

        context_component = (context_multiplier - 1.0) * self.CONTEXT_WEIGHT

        base_score = cvss_component + epss_component + business_component + exploitability_component
        risk_score = min(1.0, base_score * (1 + context_component))

        return risk_score

    def _analyze_context(
        self,
        description: str,
        severity: str,
        risk_factors: RiskFactors
    ) -> float:
        """Analyze contextual factors."""
        score = 0.5

        # Asset criticality boost
        score += risk_factors.asset_criticality * 0.3

        # Internet exposure
        if risk_factors.internet_exposed:
            score += 0.2

        # Data classification
        data_weights = {
            "public": 0.0,
            "internal": 0.1,
            "confidential": 0.2,
            "restricted": 0.3
        }
        score += data_weights.get(risk_factors.data_classification, 0.1)

        return min(1.0, score)

    def _make_decision(
        self,
        historical: Optional[HistoricalFinding],
        bayesian_prob: float,
        llm_votes: Dict[str, str],
        llm_confidence: float,
        risk_score: float,
        context_score: float,
        description: str,
        severity: str
    ) -> Tuple[bool, float, str]:
        """Make the final FP/TP decision."""
        reasons = []

        # Historical feedback has highest priority
        if historical and historical.user_feedback is not None:
            return (
                historical.user_feedback,
                0.95,
                f"Based on historical feedback ({historical.occurrence_count} occurrences)"
            )

        # Aggregated indicators
        fp_indicators = 0
        total_indicators = 0

        # Historical pattern
        if historical:
            if historical.is_false_positive:
                fp_indicators += 1
            total_indicators += 1
            reasons.append(f"Historical: seen {historical.occurrence_count}x")

        # Bayesian filter
        if bayesian_prob > 0.7:
            fp_indicators += 1
            reasons.append(f"Bayesian FP probability: {bayesian_prob:.2f}")
        total_indicators += 1

        # LLM voting
        if llm_votes:
            fp_votes = sum(1 for v in llm_votes.values() if v == "FALSE_POSITIVE")
            if fp_votes > len(llm_votes) / 2:
                fp_indicators += 1
            total_indicators += 1
            reasons.append(f"LLM votes: {fp_votes}/{len(llm_votes)} FP")

        # Low risk score suggests FP
        if risk_score < 0.2:
            fp_indicators += 1
            reasons.append(f"Low risk score: {risk_score:.2f}")
        total_indicators += 1

        # FP patterns in description
        fp_patterns = [
            "informational", "low severity", "best practice",
            "consider implementing", "might be", "possibly",
            "could potentially", "recommendation"
        ]
        desc_lower = description.lower()
        pattern_matches = sum(1 for p in fp_patterns if p in desc_lower)
        if pattern_matches >= 2:
            fp_indicators += 1
            reasons.append(f"FP patterns found: {pattern_matches}")
        total_indicators += 1

        # Decision
        fp_ratio = fp_indicators / total_indicators if total_indicators > 0 else 0
        is_fp = fp_ratio >= 0.5

        # Confidence calculation
        confidence = 0.5 + (abs(fp_ratio - 0.5) * 2) * 0.4
        if historical:
            confidence += 0.1
        if llm_votes:
            confidence += 0.05
        confidence = min(0.95, confidence)

        reasoning = "; ".join(reasons) if reasons else "Based on combined analysis"

        return is_fp, confidence, reasoning

    def _determine_status(self, is_fp: bool, confidence: float) -> FindingStatus:
        """Determine finding status based on validation."""
        if is_fp and confidence >= self.FP_CONFIDENCE_THRESHOLD:
            return FindingStatus.FALSE_POSITIVE
        elif confidence >= self.CONFIRMED_THRESHOLD:
            return FindingStatus.CONFIRMED
        elif confidence >= 0.6:
            return FindingStatus.LIKELY
        else:
            return FindingStatus.SUSPECTED

    def _calculate_priority(
        self,
        is_fp: bool,
        risk_score: float,
        risk_factors: RiskFactors
    ) -> int:
        """Calculate remediation priority (1 = highest)."""
        if is_fp:
            return 999  # Lowest priority for FPs

        # Base priority from risk score
        if risk_score >= 0.8:
            priority = 1
        elif risk_score >= 0.6:
            priority = 2
        elif risk_score >= 0.4:
            priority = 3
        elif risk_score >= 0.2:
            priority = 4
        else:
            priority = 5

        # Adjustments
        if risk_factors.internet_exposed:
            priority = max(1, priority - 1)
        if risk_factors.active_exploitation:
            priority = 1
        if not risk_factors.patch_available:
            priority = max(1, priority - 1)

        return priority

    def _generate_recommendations(
        self,
        is_fp: bool,
        risk_score: float,
        risk_factors: RiskFactors
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        if is_fp:
            recommendations.append("Mark as false positive and suppress")
            recommendations.append("Review scanner configuration")
        else:
            if risk_score >= 0.8:
                recommendations.append("IMMEDIATE REMEDIATION REQUIRED")
                recommendations.append("Notify security team")
            elif risk_score >= 0.6:
                recommendations.append("High priority - fix within 7 days")
            elif risk_score >= 0.4:
                recommendations.append("Medium priority - fix within 30 days")
            else:
                recommendations.append("Low priority - include in regular patch cycle")

            if risk_factors.internet_exposed:
                recommendations.append("Reduce internet exposure or implement WAF")

            if not risk_factors.patch_available:
                recommendations.append("Implement compensating controls")

            if risk_factors.active_exploitation:
                recommendations.append("ACTIVE EXPLOITATION - isolate affected systems")

        return recommendations


# Convenience function for direct use
async def validate_finding(
    finding: Any,
    context: Optional[Dict[str, Any]] = None,
    llm: Any = None
) -> FPValidationResult:
    """
    Convenience function to validate a single finding.

    Args:
        finding: AIPTX Finding object
        context: Additional context
        llm: Optional LLM client

    Returns:
        FPValidationResult
    """
    engine = FalsePositiveEngine(llm=llm)
    return await engine.validate_finding(finding, context)
