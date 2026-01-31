"""
AIPTX SAST Module - Static Application Security Testing

Provides source code analysis for security vulnerabilities:
- Multi-language support (Python, JS/TS, Java, Go)
- Rule-based detection with CWE/OWASP mappings
- Secret detection (API keys, passwords, tokens)
- Data flow analysis
- GitHub repository scanning

Usage:
    from aipt_v2.sast import SASTAnalyzer, scan_directory

    # Scan a directory
    result = await scan_directory("/path/to/project")

    # Or use the analyzer directly
    analyzer = SASTAnalyzer()
    result = await analyzer.scan_directory("/path/to/project")

    for finding in result.findings:
        print(f"{finding.severity}: {finding.title}")
"""

from aipt_v2.sast.analyzer import (
    SASTAnalyzer,
    SASTConfig,
    SASTFinding,
    SASTResult,
    scan_directory,
    scan_file,
)
from aipt_v2.sast.parsers import (
    BaseParser,
    ParsedFile,
    PythonParser,
    JavaScriptParser,
    JavaParser,
    GoParser,
    get_parser_for_file,
    get_supported_extensions,
)
from aipt_v2.sast.rules import (
    Rule,
    RuleMatch,
    RuleSeverity,
    RuleCategory,
    RuleSet,
    SecretDetectionRules,
    PythonSecurityRules,
    JavaScriptSecurityRules,
    JavaSecurityRules,
    GoSecurityRules,
    get_rules_for_language,
)

__all__ = [
    # Core analyzer
    "SASTAnalyzer",
    "SASTConfig",
    "SASTFinding",
    "SASTResult",
    "scan_directory",
    "scan_file",
    # Parsers
    "BaseParser",
    "ParsedFile",
    "PythonParser",
    "JavaScriptParser",
    "JavaParser",
    "GoParser",
    "get_parser_for_file",
    "get_supported_extensions",
    # Rules
    "Rule",
    "RuleMatch",
    "RuleSeverity",
    "RuleCategory",
    "RuleSet",
    "SecretDetectionRules",
    "PythonSecurityRules",
    "JavaScriptSecurityRules",
    "JavaSecurityRules",
    "GoSecurityRules",
    "get_rules_for_language",
]
