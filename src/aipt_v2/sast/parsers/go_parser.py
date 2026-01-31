"""
AIPTX Go Parser - Pattern-Based Go Code Analysis

Uses regex and pattern matching for Go code analysis
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


class GoParser(BaseParser):
    """
    Go code parser using pattern matching.

    Extracts:
    - Functions and methods
    - Structs (as classes)
    - Imports
    - Variables and constants
    - Security patterns
    """

    @property
    def language(self) -> Language:
        return Language.GO

    @property
    def file_extensions(self) -> list[str]:
        return ["go"]

    def parse(self, content: str, file_path: str) -> ParsedFile:
        """Parse Go source code."""
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
        parsed.functions = self._extract_functions(clean_content, file_path)
        parsed.classes = self._extract_structs(clean_content, file_path)
        parsed.variables = self._extract_variables(clean_content, file_path)
        parsed.security_patterns = self._find_go_security_patterns(content, file_path)
        parsed.data_flows = self._analyze_data_flows(parsed)

        return parsed

    def _remove_comments(self, content: str) -> str:
        """Remove Go comments while preserving line numbers."""
        # Remove single-line comments
        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
        # Remove multi-line comments
        content = re.sub(r"/\*[\s\S]*?\*/", lambda m: "\n" * m.group().count("\n"), content)
        return content

    def _extract_imports(self, content: str, file_path: str) -> list[ParsedImport]:
        """Extract Go imports."""
        imports = []
        lines = content.split("\n")

        # Single import: import "package"
        single_pattern = re.compile(r'import\s+(?:(\w+)\s+)?"([^"]+)"')

        # Multi-import block
        in_import_block = False
        import_block_start = 0

        for i, line in enumerate(lines, 1):
            # Check for import block start
            if "import (" in line:
                in_import_block = True
                import_block_start = i
                continue

            # Check for import block end
            if in_import_block and ")" in line:
                in_import_block = False
                continue

            # Parse imports in block
            if in_import_block:
                match = re.search(r'(?:(\w+)\s+)?"([^"]+)"', line)
                if match:
                    alias = match.group(1)
                    module = match.group(2)
                    imports.append(
                        ParsedImport(
                            module=module,
                            alias=alias,
                            location=CodeLocation(file_path=file_path, line=i),
                        )
                    )
                continue

            # Single import
            match = single_pattern.search(line)
            if match:
                alias = match.group(1)
                module = match.group(2)
                imports.append(
                    ParsedImport(
                        module=module,
                        alias=alias,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

        return imports

    def _extract_functions(self, content: str, file_path: str) -> list[ParsedFunction]:
        """Extract function definitions."""
        functions = []
        lines = content.split("\n")

        # Function pattern: func name(params) return { or func (receiver) name(params) return {
        func_pattern = re.compile(
            r"func\s+"
            r"(?:\((\w+)\s+\*?(\w+)\)\s+)?"  # Optional receiver
            r"(\w+)\s*"  # Function name
            r"\(([^)]*)\)"  # Parameters
            r"(?:\s*\(([^)]*)\)|\s*(\w+(?:\.\w+)*))?"  # Return type(s)
        )

        for i, line in enumerate(lines, 1):
            match = func_pattern.search(line)
            if match:
                receiver_name = match.group(1)
                receiver_type = match.group(2)
                func_name = match.group(3)
                params_str = match.group(4)
                return_types = match.group(5) or match.group(6)

                params = self._parse_parameters(params_str)

                func = ParsedFunction(
                    name=func_name,
                    parameters=params,
                    return_type=return_types,
                    is_method=bool(receiver_type),
                    class_name=receiver_type,
                    location=CodeLocation(file_path=file_path, line=i),
                )

                functions.append(func)

        return functions

    def _extract_structs(self, content: str, file_path: str) -> list[ParsedClass]:
        """Extract struct definitions (treated as classes)."""
        structs = []
        lines = content.split("\n")

        # Struct pattern
        struct_pattern = re.compile(r"type\s+(\w+)\s+struct\s*\{")

        in_struct = False
        current_struct = None
        brace_count = 0

        for i, line in enumerate(lines, 1):
            match = struct_pattern.search(line)
            if match and not in_struct:
                in_struct = True
                current_struct = ParsedClass(
                    name=match.group(1),
                    location=CodeLocation(file_path=file_path, line=i),
                )
                brace_count = line.count("{") - line.count("}")
                continue

            if in_struct:
                brace_count += line.count("{") - line.count("}")

                # Parse struct fields
                field_match = re.search(r"^\s*(\w+)\s+(\S+)", line)
                if field_match and current_struct:
                    field_name = field_match.group(1)
                    field_type = field_match.group(2)
                    # Skip embedded types and methods
                    if not field_name[0].isupper() or field_type.strip():
                        current_struct.attributes.append(
                            ParsedVariable(
                                name=field_name,
                                type_hint=field_type,
                                scope="class",
                                location=CodeLocation(file_path=file_path, line=i),
                            )
                        )

                if brace_count <= 0:
                    in_struct = False
                    if current_struct:
                        structs.append(current_struct)
                    current_struct = None

        # Associate methods with structs
        for func in self._extract_functions(content, file_path):
            if func.is_method and func.class_name:
                for struct in structs:
                    if struct.name == func.class_name:
                        struct.methods.append(func)
                        break

        return structs

    def _extract_variables(self, content: str, file_path: str) -> list[ParsedVariable]:
        """Extract variable and constant declarations."""
        variables = []
        lines = content.split("\n")

        # var/const patterns
        var_pattern = re.compile(
            r"(?:var|const)\s+(\w+)\s+(?:(\S+)\s*)?=\s*(.+?)$"
        )

        # Short declaration
        short_pattern = re.compile(r"(\w+)\s*:=\s*(.+?)$")

        for i, line in enumerate(lines, 1):
            # var/const
            match = var_pattern.search(line)
            if match:
                variables.append(
                    ParsedVariable(
                        name=match.group(1),
                        type_hint=match.group(2),
                        value=match.group(3).strip(),
                        is_constant="const" in line,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )
                continue

            # Short declaration (only at package level)
            if ":=" in line and not line.strip().startswith("//"):
                match = short_pattern.search(line)
                if match:
                    variables.append(
                        ParsedVariable(
                            name=match.group(1),
                            value=match.group(2).strip(),
                            location=CodeLocation(file_path=file_path, line=i),
                        )
                    )

        return variables

    def _parse_parameters(self, params_str: str) -> list[ParsedParameter]:
        """Parse function parameters."""
        params = []
        if not params_str.strip():
            return params

        # Go parameters: name type, name type, ... or name, name type
        # Split by comma but handle cases like func(a, b int)
        parts = params_str.split(",")
        current_type = None

        # Process in reverse to handle grouped params
        processed = []
        for part in reversed(parts):
            part = part.strip()
            if not part:
                continue

            tokens = part.split()
            if len(tokens) >= 2:
                # name type
                current_type = " ".join(tokens[1:])
                processed.append((tokens[0], current_type))
            elif len(tokens) == 1 and current_type:
                # name only, use previous type
                processed.append((tokens[0], current_type))
            elif len(tokens) == 1:
                # Single token, could be variadic or just name
                processed.append((tokens[0], None))

        for name, type_hint in reversed(processed):
            is_variadic = type_hint and type_hint.startswith("...")
            if is_variadic and type_hint:
                type_hint = type_hint[3:]

            params.append(
                ParsedParameter(
                    name=name,
                    type_hint=type_hint,
                    is_variadic=is_variadic,
                )
            )

        return params

    def _find_go_security_patterns(
        self, content: str, file_path: str
    ) -> list[SecurityPattern]:
        """Find Go-specific security patterns."""
        patterns = self._find_security_patterns(content, file_path)
        lines = content.split("\n")

        # Go-specific dangerous patterns
        dangerous_patterns = {
            "sql_injection": [
                (r'db\.(Query|Exec)\s*\([^,)]*\+', "SQL with string concatenation"),
                (r'fmt\.Sprintf\s*\([^)]*SELECT', "SQL with Sprintf"),
                (r'fmt\.Sprintf\s*\([^)]*INSERT', "SQL with Sprintf"),
                (r'fmt\.Sprintf\s*\([^)]*UPDATE', "SQL with Sprintf"),
                (r'fmt\.Sprintf\s*\([^)]*DELETE', "SQL with Sprintf"),
            ],
            "command_injection": [
                (r'exec\.Command\s*\([^)]*\+', "exec.Command with concatenation"),
                (r'exec\.CommandContext\s*\([^)]*\+', "exec.CommandContext with concatenation"),
                (r'os\.StartProcess', "os.StartProcess - command execution"),
            ],
            "path_traversal": [
                (r'os\.Open\s*\([^)]*\+', "os.Open with concatenation"),
                (r'ioutil\.ReadFile\s*\([^)]*\+', "ReadFile with concatenation"),
                (r'filepath\.Join\s*\([^)]*\.\.', "filepath.Join with .."),
            ],
            "ssrf": [
                (r'http\.Get\s*\([^)]*\+', "http.Get with dynamic URL"),
                (r'http\.Post\s*\([^)]*\+', "http.Post with dynamic URL"),
                (r'http\.NewRequest\s*\([^)]*\+', "http.NewRequest with dynamic URL"),
            ],
            "hardcoded_secret": [
                (r'(?i)password\s*[=:]\s*"[^"]+"', "Hardcoded password"),
                (r'(?i)secret\s*[=:]\s*"[^"]+"', "Hardcoded secret"),
                (r'(?i)apiKey\s*[=:]\s*"[^"]+"', "Hardcoded API key"),
                (r'(?i)token\s*[=:]\s*"[A-Za-z0-9+/=]{20,}"', "Hardcoded token"),
            ],
            "weak_crypto": [
                (r'md5\.New\(', "MD5 - weak hash"),
                (r'sha1\.New\(', "SHA1 - weak hash"),
                (r'des\.NewCipher', "DES - weak encryption"),
                (r'rc4\.NewCipher', "RC4 - weak encryption"),
            ],
            "tls_config": [
                (r'InsecureSkipVerify:\s*true', "TLS verification disabled"),
                (r'MinVersion:\s*tls\.VersionSSL', "SSL version allowed"),
                (r'MinVersion:\s*tls\.VersionTLS10', "TLS 1.0 allowed"),
            ],
            "race_condition": [
                (r'go\s+\w+\s*\(', "Goroutine - check for race conditions"),
            ],
            "template_injection": [
                (r'template\.HTML\s*\(', "template.HTML - bypasses escaping"),
                (r'template\.JS\s*\(', "template.JS - bypasses escaping"),
                (r'template\.URL\s*\(', "template.URL - bypasses escaping"),
            ],
            "error_handling": [
                (r'_\s*=\s*\w+\(', "Ignored error return"),
                (r'defer\s+\w+\.Close\(\)', "Deferred close without error check"),
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

        # Common user input sources in Go
        sources = {
            "r.URL.Query()": "Query parameter",
            "r.FormValue": "Form value",
            "r.PostFormValue": "POST form value",
            "r.Header.Get": "HTTP header",
            "r.Body": "Request body",
            "r.Cookie": "Cookie",
            "os.Args": "Command line argument",
            "os.Getenv": "Environment variable",
        }

        # Dangerous sinks
        sinks = {
            "db.Query": "SQL execution",
            "db.Exec": "SQL execution",
            "exec.Command": "Command execution",
            "os.Open": "File operation",
            "http.Get": "HTTP request",
            "template.HTML": "HTML output",
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
