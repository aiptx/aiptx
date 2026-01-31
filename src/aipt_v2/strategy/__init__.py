"""
AIPTX Strategy Module - Zero-Config Target Analysis

Provides intelligent target analysis and scan strategy generation:
- Automatic target type detection
- Technology stack identification
- AI-driven scan planning
- SAST-DAST correlation

Usage:
    from aipt_v2.strategy import TargetAnalyzer, AIStrategyGenerator

    # Analyze target
    analyzer = TargetAnalyzer()
    profile = await analyzer.analyze("https://example.com")

    # Generate strategy
    generator = AIStrategyGenerator()
    strategy = await generator.generate(profile)
"""

from aipt_v2.strategy.target_analyzer import (
    TargetAnalyzer,
    TargetProfile,
    TargetType,
    Technology,
    analyze_target,
)
from aipt_v2.strategy.ai_planner import (
    AIStrategyGenerator,
    ScanPlan,
    ScanPhase,
    generate_scan_plan,
)
from aipt_v2.strategy.correlator import (
    SASTDASTCorrelator,
    CorrelatedFinding,
    correlate_findings,
)

__all__ = [
    # Target analyzer
    "TargetAnalyzer",
    "TargetProfile",
    "TargetType",
    "Technology",
    "analyze_target",
    # AI planner
    "AIStrategyGenerator",
    "ScanPlan",
    "ScanPhase",
    "generate_scan_plan",
    # Correlator
    "SASTDASTCorrelator",
    "CorrelatedFinding",
    "correlate_findings",
]
