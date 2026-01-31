"""
AIPTX Java Parser - Pattern-Based Java Code Analysis

Uses regex and pattern matching for Java code analysis
focusing on security-relevant patterns.
"""

from __future__ import annotations

import re
from typing import Optional

from aipt_v2.sast.parsers.base import (
    BaseParser,
    Language,
    ParsedFile,
    ParsedFunction,
    ParsedClass,
    ParsedVariable,
    ParsedImport,
    ParsedParameter,
    CodeLocation,
    SecurityPattern,
    DataFlow,
)


class JavaParser(BaseParser):
    """
    Java code parser using pattern matching.

    Extracts:
    - Classes and interfaces
    - Methods with parameters
    - Imports
    - Fields
    - Security patterns (SQL injection, XXE, etc.)
    """

    @property
    def language(self) -> Language:
        return Language.JAVA

    @property
    def file_extensions(self) -> list[str]:
        return ["java"]

    def parse(self, content: str, file_path: str) -> ParsedFile:
        """Parse Java source code."""
        parsed = ParsedFile(
            file_path=file_path,
            language=self.language,
            raw_content=content,
            lines=content.split("\n"),
        )

        # Remove comments
        clean_content = self._remove_comments(content)

        # Extract components
        parsed.imports = self._extract_imports(clean_content, file_path)
        parsed.classes = self._extract_classes(clean_content, file_path)
        parsed.variables = self._extract_fields(clean_content, file_path)
        parsed.security_patterns = self._find_java_security_patterns(content, file_path)
        parsed.data_flows = self._analyze_data_flows(parsed)

        # Extract functions from classes
        for cls in parsed.classes:
            parsed.functions.extend(cls.methods)

        return parsed

    def _remove_comments(self, content: str) -> str:
        """Remove Java comments while preserving line numbers."""
        # Remove single-line comments
        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
        # Remove multi-line comments
        content = re.sub(r"/\*[\s\S]*?\*/", lambda m: "\n" * m.group().count("\n"), content)
        return content

    def _extract_imports(self, content: str, file_path: str) -> list[ParsedImport]:
        """Extract Java imports."""
        imports = []
        lines = content.split("\n")

        import_pattern = re.compile(r"import\s+(static\s+)?([a-zA-Z0-9_.]+(?:\.\*)?)\s*;")

        for i, line in enumerate(lines, 1):
            match = import_pattern.search(line)
            if match:
                is_static = bool(match.group(1))
                full_import = match.group(2)

                # Split into module and class
                parts = full_import.rsplit(".", 1)
                module = parts[0] if len(parts) > 1 else ""
                name = parts[-1]

                imports.append(
                    ParsedImport(
                        module=module,
                        names=[name],
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

        return imports

    def _extract_classes(self, content: str, file_path: str) -> list[ParsedClass]:
        """Extract class definitions."""
        classes = []
        lines = content.split("\n")

        # Class/interface pattern
        class_pattern = re.compile(
            r"(?:public\s+|private\s+|protected\s+)?"
            r"(?:abstract\s+|final\s+)?"
            r"(class|interface|enum)\s+(\w+)"
            r"(?:\s+extends\s+(\w+))?"
            r"(?:\s+implements\s+([^{]+))?"
        )

        in_class = False
        current_class = None
        brace_count = 0
        class_start_line = 0

        for i, line in enumerate(lines, 1):
            # Check for class start
            match = class_pattern.search(line)
            if match and not in_class:
                in_class = True
                class_start_line = i
                class_type = match.group(1)
                class_name = match.group(2)
                extends = match.group(3)
                implements = match.group(4)

                bases = []
                if extends:
                    bases.append(extends.strip())
                if implements:
                    bases.extend([i.strip() for i in implements.split(",")])

                current_class = ParsedClass(
                    name=class_name,
                    base_classes=bases,
                    location=CodeLocation(file_path=file_path, line=i),
                )
                brace_count = line.count("{") - line.count("}")
                continue

            if in_class:
                brace_count += line.count("{") - line.count("}")

                # Look for methods
                method = self._extract_method(line, i, file_path, current_class.name if current_class else None)
                if method and current_class:
                    current_class.methods.append(method)

                # Look for fields
                field = self._extract_field(line, i, file_path)
                if field and current_class:
                    current_class.attributes.append(field)

                if brace_count <= 0:
                    in_class = False
                    if current_class:
                        current_class.location = CodeLocation(
                            file_path=file_path,
                            line=class_start_line,
                            end_line=i,
                        )
                        classes.append(current_class)
                    current_class = None

        return classes

    def _extract_method(
        self, line: str, line_num: int, file_path: str, class_name: Optional[str]
    ) -> Optional[ParsedFunction]:
        """Extract a method from a line."""
        # Method pattern
        method_pattern = re.compile(
            r"(?:public\s+|private\s+|protected\s+)?"
            r"(?:static\s+|final\s+|synchronized\s+|abstract\s+)*"
            r"(?:<[^>]+>\s+)?"  # Generic return type
            r"(\w+(?:<[^>]+>)?(?:\[\])?)\s+"  # Return type
            r"(\w+)\s*"  # Method name
            r"\(([^)]*)\)"  # Parameters
        )

        match = method_pattern.search(line)
        if match:
            return_type = match.group(1)
            method_name = match.group(2)
            params_str = match.group(3)

            # Skip if it looks like a control structure
            if method_name in ["if", "for", "while", "switch", "catch", "try"]:
                return None

            params = self._parse_parameters(params_str)

            return ParsedFunction(
                name=method_name,
                parameters=params,
                return_type=return_type,
                is_method=True,
                class_name=class_name,
                location=CodeLocation(file_path=file_path, line=line_num),
            )

        return None

    def _extract_field(self, line: str, line_num: int, file_path: str) -> Optional[ParsedVariable]:
        """Extract a field declaration."""
        # Field pattern (simplified)
        field_pattern = re.compile(
            r"(?:public\s+|private\s+|protected\s+)"
            r"(?:static\s+|final\s+)*"
            r"(\w+(?:<[^>]+>)?(?:\[\])?)\s+"  # Type
            r"(\w+)\s*"  # Name
            r"(?:=\s*([^;]+))?"  # Optional value
            r"\s*;"
        )

        match = field_pattern.search(line)
        if match:
            return ParsedVariable(
                name=match.group(2),
                type_hint=match.group(1),
                value=match.group(3).strip() if match.group(3) else None,
                is_constant="final" in line.lower(),
                scope="class",
                location=CodeLocation(file_path=file_path, line=line_num),
            )

        return None

    def _extract_fields(self, content: str, file_path: str) -> list[ParsedVariable]:
        """Extract field declarations (outside of classes)."""
        # This is mainly for completeness; most fields are inside classes
        return []

    def _parse_parameters(self, params_str: str) -> list[ParsedParameter]:
        """Parse method parameters."""
        params = []
        if not params_str.strip():
            return params

        # Handle annotations in parameters
        params_str = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", params_str)

        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue

            # Handle varargs
            is_variadic = "..." in param
            param = param.replace("...", "")

            parts = param.split()
            if len(parts) >= 2:
                type_hint = parts[-2]
                name = parts[-1]
            else:
                type_hint = None
                name = parts[0] if parts else param

            params.append(
                ParsedParameter(
                    name=name,
                    type_hint=type_hint,
                    is_variadic=is_variadic,
                )
            )

        return params

    def _find_java_security_patterns(
        self, content: str, file_path: str
    ) -> list[SecurityPattern]:
        """Find Java-specific security patterns."""
        patterns = self._find_security_patterns(content, file_path)
        lines = content.split("\n")

        # Java-specific dangerous patterns
        dangerous_patterns = {
            "sql_injection": [
                (r'Statement\s*\w*\s*=', "Statement usage - use PreparedStatement"),
                (r'createStatement\s*\(', "createStatement - use prepareStatement"),
                (r'executeQuery\s*\(\s*["\'].*\+', "SQL with string concatenation"),
                (r'executeUpdate\s*\(\s*["\'].*\+', "SQL with string concatenation"),
            ],
            "command_injection": [
                (r'Runtime\.getRuntime\(\)\.exec\s*\(', "Runtime.exec - command injection"),
                (r'ProcessBuilder\s*\(', "ProcessBuilder - command injection"),
                (r'new\s+ProcessBuilder', "ProcessBuilder - command injection"),
            ],
            "xxe": [
                (r'DocumentBuilderFactory', "XML parsing - check XXE protection"),
                (r'SAXParserFactory', "SAX parsing - check XXE protection"),
                (r'XMLInputFactory', "StAX parsing - check XXE protection"),
                (r'TransformerFactory', "XSLT - check XXE protection"),
                (r'SchemaFactory', "Schema - check XXE protection"),
            ],
            "deserialization": [
                (r'ObjectInputStream', "ObjectInputStream - unsafe deserialization"),
                (r'readObject\s*\(', "readObject - unsafe deserialization"),
                (r'XMLDecoder', "XMLDecoder - unsafe deserialization"),
                (r'XStream', "XStream - check deserialization safety"),
            ],
            "path_traversal": [
                (r'new\s+File\s*\([^)]*\+', "File with concatenation"),
                (r'new\s+FileInputStream\s*\([^)]*\+', "FileInputStream with concatenation"),
                (r'Paths\.get\s*\([^)]*\+', "Paths.get with concatenation"),
            ],
            "ldap_injection": [
                (r'LdapContext', "LDAP - check for injection"),
                (r'DirContext', "Directory context - check for injection"),
                (r'search\s*\([^)]*\+', "LDAP search with concatenation"),
            ],
            "ssrf": [
                (r'new\s+URL\s*\([^)]*\+', "URL with concatenation"),
                (r'HttpURLConnection', "HTTP connection - check SSRF"),
                (r'openConnection\s*\(', "openConnection - check SSRF"),
            ],
            "hardcoded_secret": [
                (r'(?i)password\s*=\s*"[^"]+"', "Hardcoded password"),
                (r'(?i)secret\s*=\s*"[^"]+"', "Hardcoded secret"),
                (r'(?i)apiKey\s*=\s*"[^"]+"', "Hardcoded API key"),
            ],
            "weak_crypto": [
                (r'getInstance\s*\(\s*"MD5"', "MD5 - weak hash"),
                (r'getInstance\s*\(\s*"SHA-?1"', "SHA1 - weak hash"),
                (r'getInstance\s*\(\s*"DES"', "DES - weak encryption"),
                (r'SecureRandom\(\)', "SecureRandom without seed"),
            ],
            "xss": [
                (r'getParameter\s*\(', "Request parameter - check XSS"),
                (r'getHeader\s*\(', "Request header - check XSS"),
                (r'\.write\s*\([^)]*getParameter', "Direct output of parameter"),
            ],
            "insecure_config": [
                (r'setAllowFileAccess\s*\(\s*true', "WebView file access enabled"),
                (r'setJavaScriptEnabled\s*\(\s*true', "WebView JS enabled"),
                (r'ALLOW_ALL_HOSTNAME_VERIFIER', "Hostname verification disabled"),
                (r'TrustAllCerts', "All certificates trusted"),
            ],
        }

        for i, line in enumerate(lines, 1):
            for pattern_type, regex_list in dangerous_patterns.items():
                for regex, description in regex_list:
                    if re.search(regex, line, re.IGNORECASE):
                        patterns.append(
                            SecurityPattern(
                                pattern_type=pattern_type,
                                code=line.strip(),
                                location=CodeLocation(file_path=file_path, line=i),
                                context={"description": description},
                            )
                        )

        return patterns

    def _analyze_data_flows(self, parsed: ParsedFile) -> list[DataFlow]:
        """Analyze data flows from sources to sinks."""
        flows = []

        # Common user input sources in Java
        sources = {
            "getParameter": "HTTP parameter",
            "getHeader": "HTTP header",
            "getCookies": "Cookie",
            "getInputStream": "Request body",
            "getReader": "Request reader",
            "getPathInfo": "URL path",
            "getQueryString": "Query string",
        }

        # Dangerous sinks
        sinks = {
            "executeQuery": "SQL execution",
            "executeUpdate": "SQL execution",
            "exec(": "Command execution",
            "ProcessBuilder": "Command execution",
            "ObjectInputStream": "Deserialization",
            "write(": "Output",
        }

        content = parsed.raw_content

        for source, source_type in sources.items():
            if source in content:
                for sink, sink_type in sinks.items():
                    if sink in content:
                        for i, line in enumerate(parsed.lines, 1):
                            if source in line:
                                flows.append(
                                    DataFlow(
                                        source=source_type,
                                        source_location=CodeLocation(
                                            file_path=parsed.file_path, line=i
                                        ),
                                        sink=sink_type,
                                        sink_location=CodeLocation(
                                            file_path=parsed.file_path, line=i
                                        ),
                                        path=["user_input"],
                                    )
                                )
                                break

        return flows
