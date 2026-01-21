"""
AIPTX Beast Mode - Adaptive Learning System
============================================

Learn from every exploitation attempt to improve future success rates.

Components:
- feedback_collector: Log payload results with context
- payload_memory: Store and retrieve successful payloads
- context_analyzer: Analyze target context for optimization
- success_predictor: Predict payload success probability
"""

from __future__ import annotations

from aipt_v2.learning.feedback_collector import (
    FeedbackCollector,
    PayloadFeedback,
    collect_feedback,
)
from aipt_v2.learning.payload_memory import (
    PayloadMemory,
    StoredPayload,
    get_best_payloads,
)
from aipt_v2.learning.context_analyzer import (
    ContextAnalyzer,
    TargetContext,
    analyze_context,
)
from aipt_v2.learning.success_predictor import (
    SuccessPredictor,
    PredictionResult,
    predict_success,
)

__all__ = [
    # Feedback
    "FeedbackCollector",
    "PayloadFeedback",
    "collect_feedback",
    # Memory
    "PayloadMemory",
    "StoredPayload",
    "get_best_payloads",
    # Context
    "ContextAnalyzer",
    "TargetContext",
    "analyze_context",
    # Prediction
    "SuccessPredictor",
    "PredictionResult",
    "predict_success",
]
