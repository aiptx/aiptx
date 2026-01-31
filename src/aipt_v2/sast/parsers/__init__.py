"""
AIPTX SAST Parsers - Language-Specific Code Parsers

Each parser transforms source code into a standardized
representation for security analysis.

Supported Languages:
- Python (AST-based)
- JavaScript/TypeScript (regex + pattern matching)
- Java (regex + pattern matching)
- Go (regex + pattern matching)
"""

from typing import Optional

from aipt_v2.sast.parsers.base import (
    BaseParser,
    ParsedFile,
    CodeLocation,
    ParsedFunction,
    ParsedClass,
    ParsedVariable,
    ParsedImport,
    DataFlow,
)
from aipt_v2.sast.parsers.python_parser import PythonParser
from aipt_v2.sast.parsers.javascript_parser import JavaScriptParser
from aipt_v2.sast.parsers.java_parser import JavaParser
from aipt_v2.sast.parsers.go_parser import GoParser

__all__ = [
    # Base
    "BaseParser",
    "ParsedFile",
    "CodeLocation",
    "ParsedFunction",
    "ParsedClass",
    "ParsedVariable",
    "ParsedImport",
    "DataFlow",
    # Language parsers
    "PythonParser",
    "JavaScriptParser",
    "JavaParser",
    "GoParser",
]


def get_parser_for_file(file_path: str) -> Optional[BaseParser]:
    """
    Get appropriate parser for a file based on extension.

    Args:
        file_path: Path to the file

    Returns:
        Parser instance or None if unsupported
    """
    ext = file_path.lower().split(".")[-1] if "." in file_path else ""

    parser_map = {
        "py": PythonParser,
        "js": JavaScriptParser,
        "jsx": JavaScriptParser,
        "ts": JavaScriptParser,
        "tsx": JavaScriptParser,
        "mjs": JavaScriptParser,
        "java": JavaParser,
        "go": GoParser,
    }

    parser_class = parser_map.get(ext)
    return parser_class() if parser_class else None


def get_supported_extensions() -> list[str]:
    """Get list of supported file extensions."""
    return ["py", "js", "jsx", "ts", "tsx", "mjs", "java", "go"]
