"""
AIPTX Beast Mode - Success Predictor
====================================

Predict payload success probability using historical data
and context analysis.
"""

from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass, field
from typing import Any, Optional

from aipt_v2.learning.feedback_collector import FeedbackCollector, get_collector
from aipt_v2.learning.payload_memory import PayloadMemory, get_memory
from aipt_v2.learning.context_analyzer import TargetContext

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    """Result of success prediction."""
    payload: str
    predicted_success_rate: float
    confidence: float
    factors: dict[str, float] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload": self.payload,
            "predicted_success_rate": self.predicted_success_rate,
            "confidence": self.confidence,
            "factors": self.factors,
            "recommendations": self.recommendations,
        }


class SuccessPredictor:
    """
    Predict the success probability of payloads.

    Uses historical feedback data and context analysis to estimate
    how likely a payload is to succeed against a target.
    """

    def __init__(
        self,
        feedback_collector: FeedbackCollector | None = None,
        payload_memory: PayloadMemory | None = None,
    ):
        """
        Initialize the success predictor.

        Args:
            feedback_collector: Feedback collector instance
            payload_memory: Payload memory instance
        """
        self._feedback = feedback_collector or get_collector()
        self._memory = payload_memory or get_memory()

        # Weights for different factors
        self._weights = {
            "historical_rate": 0.35,
            "waf_compatibility": 0.25,
            "context_match": 0.20,
            "mutation_effectiveness": 0.10,
            "recency": 0.10,
        }

    def predict(
        self,
        payload: str,
        payload_type: str,
        context: TargetContext | None = None,
        mutations_applied: list[str] | None = None,
    ) -> PredictionResult:
        """
        Predict success probability for a payload.

        Args:
            payload: The payload to evaluate
            payload_type: Type of payload (sqli, xss, etc.)
            context: Target context if available
            mutations_applied: Mutations applied to this payload

        Returns:
            PredictionResult with prediction and factors
        """
        factors = {}
        recommendations = []

        # 1. Historical success rate
        historical_rate = self._feedback.get_success_rate(
            payload=payload,
            payload_type=payload_type,
        )
        factors["historical_rate"] = historical_rate

        # 2. WAF compatibility
        waf_rate = 0.5  # Default
        if context and context.waf:
            stored = self._memory.get(payload)
            if stored and context.waf in stored.waf_compatibility:
                waf_rate = stored.waf_compatibility[context.waf]
            else:
                # Check general WAF rates for this payload type
                waf_rate = self._feedback.get_success_rate(
                    payload_type=payload_type,
                    waf=context.waf,
                )

            if waf_rate < 0.3:
                recommendations.append(f"Consider WAF bypass mutations for {context.waf}")

        factors["waf_compatibility"] = waf_rate

        # 3. Context match
        context_score = 0.5  # Default
        if context:
            stored = self._memory.get(payload)
            if stored:
                # Check if payload has worked in similar contexts
                context_keywords = []
                if context.backend_language:
                    context_keywords.append(context.backend_language)
                if context.database:
                    context_keywords.append(context.database)
                if context.framework:
                    context_keywords.append(context.framework)

                matches = sum(
                    1 for kw in context_keywords
                    if any(kw.lower() in c.lower() for c in stored.contexts_successful)
                )
                if context_keywords:
                    context_score = 0.5 + (matches / len(context_keywords)) * 0.5

        factors["context_match"] = context_score

        # 4. Mutation effectiveness
        mutation_score = 0.5  # Default
        if mutations_applied:
            mutation_rates = self._feedback.get_mutation_effectiveness(
                payload_type=payload_type,
                waf=context.waf if context else None,
            )
            if mutation_rates:
                applied_rates = [
                    mutation_rates.get(m, 0.5) for m in mutations_applied
                ]
                if applied_rates:
                    mutation_score = sum(applied_rates) / len(applied_rates)

                    # Recommend better mutations
                    best_mutations = sorted(
                        mutation_rates.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:3]
                    for mut_name, rate in best_mutations:
                        if rate > mutation_score and mut_name not in mutations_applied:
                            recommendations.append(f"Try mutation: {mut_name} ({rate:.0%} success)")

        factors["mutation_effectiveness"] = mutation_score

        # 5. Recency factor
        recency_score = 0.5  # Default
        stored = self._memory.get(payload)
        if stored and stored.last_success:
            # Newer successes are weighted higher
            from datetime import datetime, timezone
            try:
                last_success = datetime.fromisoformat(stored.last_success.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)
                days_since = (now - last_success).days

                # Decay function: recent = higher score
                recency_score = math.exp(-days_since / 30)  # ~0.37 after 30 days
            except (ValueError, AttributeError):
                pass

        factors["recency"] = recency_score

        # Calculate weighted prediction
        prediction = sum(
            factors[factor] * weight
            for factor, weight in self._weights.items()
        )

        # Calculate confidence based on data availability
        data_points = 0
        if stored:
            data_points = stored.total_uses
        confidence = min(1.0, 0.3 + (data_points / 20) * 0.7)

        # Clamp prediction to valid range
        prediction = max(0.0, min(1.0, prediction))

        return PredictionResult(
            payload=payload,
            predicted_success_rate=prediction,
            confidence=confidence,
            factors=factors,
            recommendations=recommendations,
        )

    def rank_payloads(
        self,
        payloads: list[str],
        payload_type: str,
        context: TargetContext | None = None,
    ) -> list[tuple[str, float]]:
        """
        Rank payloads by predicted success probability.

        Args:
            payloads: List of payloads to rank
            payload_type: Type of payloads
            context: Target context if available

        Returns:
            List of (payload, predicted_rate) tuples, sorted by rate
        """
        predictions = []

        for payload in payloads:
            result = self.predict(payload, payload_type, context)
            predictions.append((payload, result.predicted_success_rate))

        # Sort by predicted success rate (highest first)
        predictions.sort(key=lambda x: x[1], reverse=True)

        return predictions

    def get_best_payload(
        self,
        payload_type: str,
        context: TargetContext | None = None,
        candidates: list[str] | None = None,
    ) -> tuple[str, float] | None:
        """
        Get the best payload for a scenario.

        Args:
            payload_type: Type of payload needed
            context: Target context if available
            candidates: Optional list of candidate payloads

        Returns:
            (payload, predicted_rate) tuple or None
        """
        if candidates:
            ranked = self.rank_payloads(candidates, payload_type, context)
            return ranked[0] if ranked else None

        # Get from memory
        stored_payloads = self._memory.get_best(
            payload_type=payload_type,
            waf=context.waf if context else None,
            limit=10,
        )

        if not stored_payloads:
            return None

        # Rank the stored payloads
        payloads = [sp.payload for sp in stored_payloads]
        ranked = self.rank_payloads(payloads, payload_type, context)

        return ranked[0] if ranked else None

    def should_try_payload(
        self,
        payload: str,
        payload_type: str,
        context: TargetContext | None = None,
        threshold: float = 0.3,
    ) -> bool:
        """
        Determine if a payload is worth trying.

        Args:
            payload: The payload to evaluate
            payload_type: Type of payload
            context: Target context if available
            threshold: Minimum predicted success rate

        Returns:
            True if payload is worth trying
        """
        result = self.predict(payload, payload_type, context)
        return result.predicted_success_rate >= threshold

    def get_prediction_explanation(
        self,
        result: PredictionResult,
    ) -> str:
        """
        Generate human-readable explanation of prediction.

        Args:
            result: The prediction result

        Returns:
            Explanation string
        """
        explanation_parts = [
            f"Predicted success rate: {result.predicted_success_rate:.0%} "
            f"(confidence: {result.confidence:.0%})",
            "",
            "Contributing factors:",
        ]

        for factor, value in sorted(result.factors.items(), key=lambda x: x[1], reverse=True):
            weight = self._weights.get(factor, 0)
            contribution = value * weight
            bar = "█" * int(value * 10) + "░" * (10 - int(value * 10))
            explanation_parts.append(
                f"  {factor}: {bar} {value:.0%} (weight: {weight:.0%})"
            )

        if result.recommendations:
            explanation_parts.extend(["", "Recommendations:"])
            for rec in result.recommendations:
                explanation_parts.append(f"  • {rec}")

        return "\n".join(explanation_parts)


def predict_success(
    payload: str,
    payload_type: str,
    context: TargetContext | None = None,
    mutations_applied: list[str] | None = None,
) -> PredictionResult:
    """Convenience function to predict success."""
    predictor = SuccessPredictor()
    return predictor.predict(payload, payload_type, context, mutations_applied)


__all__ = [
    "PredictionResult",
    "SuccessPredictor",
    "predict_success",
]
