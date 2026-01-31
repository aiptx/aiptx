"""
AIPTX Business Logic Testing Module

Provides automated detection and exploitation of business logic
vulnerabilities through pattern matching and AI-generated tests.

Features:
- Race condition detection (double-spend, TOCTOU)
- Price/amount manipulation testing
- Workflow bypass detection
- Access control testing (IDOR, privilege escalation)
- Rate limiting bypass testing
- AI-powered test generation

Usage:
    from aipt_v2.business_logic import (
        BusinessLogicAnalyzer,
        AITestGenerator,
        TestExecutor,
        analyze_business_logic,
    )

    # Quick analysis
    result = await analyze_business_logic("https://target.com")

    # Full workflow
    analyzer = BusinessLogicAnalyzer("https://target.com")
    scan_result = await analyzer.analyze()

    # AI-generated tests
    generator = AITestGenerator()
    tests = generator.generate_from_workflows(scan_result.workflows)

    # Execute tests
    executor = TestExecutor("https://target.com")
    report = await executor.execute_all(tests)
"""

from aipt_v2.business_logic.analyzer import (
    BusinessLogicAnalyzer,
    BusinessLogicFinding,
    BusinessLogicScanResult,
    Workflow,
    analyze_business_logic,
)
from aipt_v2.business_logic.test_generator import (
    AITestGenerator,
    GeneratedTest,
    GenerationContext,
)
from aipt_v2.business_logic.executor import (
    TestExecutor,
    ExecutionResult,
    ExecutionReport,
    execute_business_logic_tests,
)
from aipt_v2.business_logic.patterns import (
    TestPattern,
    TestCase,
    TestResult,
    PatternCategory,
    get_all_patterns,
    get_patterns_by_category,
)

__all__ = [
    # Analyzer
    "BusinessLogicAnalyzer",
    "BusinessLogicFinding",
    "BusinessLogicScanResult",
    "Workflow",
    "analyze_business_logic",
    # Test Generator
    "AITestGenerator",
    "GeneratedTest",
    "GenerationContext",
    # Executor
    "TestExecutor",
    "ExecutionResult",
    "ExecutionReport",
    "execute_business_logic_tests",
    # Patterns
    "TestPattern",
    "TestCase",
    "TestResult",
    "PatternCategory",
    "get_all_patterns",
    "get_patterns_by_category",
]
