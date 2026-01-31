"""
AIPTX SAST Base Parser - Abstract Parser Interface

Defines the standardized representation for parsed code
that all language-specific parsers must produce.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Language(str, Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    UNKNOWN = "unknown"


@dataclass
class CodeLocation:
    """Location in source code."""
    file_path: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line}"

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass
class ParsedImport:
    """Parsed import statement."""
    module: str
    names: list[str] = field(default_factory=list)
    alias: Optional[str] = None
    location: Optional[CodeLocation] = None
    is_relative: bool = False


@dataclass
class ParsedVariable:
    """Parsed variable/assignment."""
    name: str
    value: Optional[str] = None
    type_hint: Optional[str] = None
    location: Optional[CodeLocation] = None
    is_constant: bool = False
    scope: str = "global"  # global, class, function, block


@dataclass
class ParsedParameter:
    """Function/method parameter."""
    name: str
    type_hint: Optional[str] = None
    default_value: Optional[str] = None
    is_variadic: bool = False  # *args, **kwargs


@dataclass
class ParsedFunction:
    """Parsed function/method."""
    name: str
    parameters: list[ParsedParameter] = field(default_factory=list)
    return_type: Optional[str] = None
    body: str = ""
    location: Optional[CodeLocation] = None
    decorators: list[str] = field(default_factory=list)
    is_async: bool = False
    is_method: bool = False
    class_name: Optional[str] = None
    docstring: Optional[str] = None

    # Security-relevant attributes
    calls: list[str] = field(default_factory=list)  # Functions called
    sql_queries: list[str] = field(default_factory=list)
    user_inputs: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)


@dataclass
class ParsedClass:
    """Parsed class definition."""
    name: str
    base_classes: list[str] = field(default_factory=list)
    methods: list[ParsedFunction] = field(default_factory=list)
    attributes: list[ParsedVariable] = field(default_factory=list)
    location: Optional[CodeLocation] = None
    decorators: list[str] = field(default_factory=list)
    docstring: Optional[str] = None


@dataclass
class DataFlow:
    """Data flow from source to sink."""
    source: str  # Where data originates (user input, file, etc.)
    source_location: CodeLocation
    sink: str  # Where data goes (SQL query, command, response)
    sink_location: CodeLocation
    path: list[str] = field(default_factory=list)  # Variable chain
    is_sanitized: bool = False
    sanitizers: list[str] = field(default_factory=list)


@dataclass
class SecurityPattern:
    """Pattern found during parsing that may be security-relevant."""
    pattern_type: str  # sql_query, command_exec, file_read, etc.
    code: str
    location: CodeLocation
    context: dict = field(default_factory=dict)


@dataclass
class ParsedFile:
    """Complete parsed file representation."""
    file_path: str
    language: Language
    imports: list[ParsedImport] = field(default_factory=list)
    functions: list[ParsedFunction] = field(default_factory=list)
    classes: list[ParsedClass] = field(default_factory=list)
    variables: list[ParsedVariable] = field(default_factory=list)
    security_patterns: list[SecurityPattern] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    raw_content: str = ""
    lines: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def get_line(self, line_number: int) -> str:
        """Get a specific line (1-indexed)."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""

    def get_context(self, line: int, context_lines: int = 3) -> list[str]:
        """Get lines around a specific line for context."""
        start = max(1, line - context_lines)
        end = min(len(self.lines), line + context_lines)
        return self.lines[start - 1:end]


class BaseParser(ABC):
    """
    Abstract base class for language-specific parsers.

    Each parser transforms source code into a standardized
    ParsedFile representation for security analysis.
    """

    @property
    @abstractmethod
    def language(self) -> Language:
        """Get the language this parser handles."""
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> list[str]:
        """Get file extensions this parser handles."""
        pass

    @abstractmethod
    def parse(self, content: str, file_path: str) -> ParsedFile:
        """
        Parse source code content.

        Args:
            content: Source code content
            file_path: Path to the file (for location tracking)

        Returns:
            ParsedFile with extracted information
        """
        pass

    def parse_file(self, file_path: str) -> ParsedFile:
        """
        Parse a file from disk.

        Args:
            file_path: Path to the file

        Returns:
            ParsedFile with extracted information
        """
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.parse(content, file_path)

    def can_parse(self, file_path: str) -> bool:
        """Check if this parser can handle the given file."""
        ext = file_path.lower().split(".")[-1] if "." in file_path else ""
        return ext in self.file_extensions

    def _extract_strings(self, content: str) -> list[tuple[str, int]]:
        """
        Extract string literals from code.

        Returns list of (string_value, line_number) tuples.
        """
        import re

        strings = []
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Single and double quoted strings
            for match in re.finditer(r'["\']([^"\'\\]|\\.)*["\']', line):
                strings.append((match.group()[1:-1], i))

            # Template literals (JS)
            for match in re.finditer(r'`([^`\\]|\\.)*`', line):
                strings.append((match.group()[1:-1], i))

        return strings

    def _find_security_patterns(
        self, content: str, file_path: str
    ) -> list[SecurityPattern]:
        """
        Find common security-relevant patterns.

        Override in subclasses for language-specific patterns.
        """
        patterns = []
        lines = content.split("\n")

        # Common patterns across languages
        security_indicators = {
            "sql_query": [
                r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+',
                r'(?i)execute\s*\(',
                r'(?i)raw\s*\(',
            ],
            "command_exec": [
                r'(?i)(exec|system|popen|spawn|shell)',
                r'(?i)subprocess',
                r'(?i)os\.system',
            ],
            "file_operation": [
                r'(?i)(open|read|write|fopen|fread|fwrite)',
                r'(?i)file_get_contents',
            ],
            "crypto": [
                r'(?i)(md5|sha1|encrypt|decrypt|hash)',
                r'(?i)(AES|DES|RSA)',
            ],
            "auth": [
                r'(?i)(password|passwd|secret|token|api_key|apikey)',
                r'(?i)(authenticate|authorize|login)',
            ],
            "network": [
                r'(?i)(http|https|ftp|socket|request)',
                r'(?i)(curl|fetch|ajax)',
            ],
        }

        import re

        for i, line in enumerate(lines, 1):
            for pattern_type, regexes in security_indicators.items():
                for regex in regexes:
                    if re.search(regex, line):
                        patterns.append(
                            SecurityPattern(
                                pattern_type=pattern_type,
                                code=line.strip(),
                                location=CodeLocation(
                                    file_path=file_path,
                                    line=i,
                                ),
                            )
                        )
                        break  # One match per type per line

        return patterns
