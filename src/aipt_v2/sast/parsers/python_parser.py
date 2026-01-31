"""
AIPTX Python Parser - AST-Based Python Code Analysis

Uses Python's built-in AST module for accurate parsing
and extraction of security-relevant patterns.
"""

from __future__ import annotations

import ast
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


class PythonParser(BaseParser):
    """
    Python code parser using AST.

    Extracts:
    - Functions and methods with parameters
    - Classes with inheritance
    - Imports (absolute and relative)
    - Variables and constants
    - Security patterns (SQL, commands, etc.)
    - Basic data flow (source to sink)
    """

    @property
    def language(self) -> Language:
        return Language.PYTHON

    @property
    def file_extensions(self) -> list[str]:
        return ["py"]

    def parse(self, content: str, file_path: str) -> ParsedFile:
        """Parse Python source code."""
        parsed = ParsedFile(
            file_path=file_path,
            language=self.language,
            raw_content=content,
            lines=content.split("\n"),
        )

        try:
            tree = ast.parse(content, filename=file_path)
            self._extract_from_ast(tree, parsed, file_path)
        except SyntaxError as e:
            parsed.parse_errors.append(f"Syntax error: {e}")
            # Fall back to regex-based parsing
            self._fallback_parse(content, parsed, file_path)

        # Find security patterns
        parsed.security_patterns = self._find_python_security_patterns(
            content, file_path
        )

        # Analyze data flows
        parsed.data_flows = self._analyze_data_flows(parsed)

        return parsed

    def _extract_from_ast(
        self, tree: ast.AST, parsed: ParsedFile, file_path: str
    ) -> None:
        """Extract information from AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parsed.imports.append(
                        ParsedImport(
                            module=alias.name,
                            alias=alias.asname,
                            location=CodeLocation(
                                file_path=file_path,
                                line=node.lineno,
                                column=node.col_offset,
                            ),
                        )
                    )

            elif isinstance(node, ast.ImportFrom):
                parsed.imports.append(
                    ParsedImport(
                        module=node.module or "",
                        names=[a.name for a in node.names],
                        is_relative=node.level > 0,
                        location=CodeLocation(
                            file_path=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                        ),
                    )
                )

            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                func = self._parse_function(node, file_path)
                parsed.functions.append(func)

            elif isinstance(node, ast.ClassDef):
                cls = self._parse_class(node, file_path)
                parsed.classes.append(cls)

            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        parsed.variables.append(
                            ParsedVariable(
                                name=target.id,
                                value=ast.unparse(node.value) if hasattr(ast, 'unparse') else str(node.value),
                                location=CodeLocation(
                                    file_path=file_path,
                                    line=node.lineno,
                                    column=node.col_offset,
                                ),
                                is_constant=target.id.isupper(),
                            )
                        )

    def _parse_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> ParsedFunction:
        """Parse a function definition."""
        params = []
        for arg in node.args.args:
            params.append(
                ParsedParameter(
                    name=arg.arg,
                    type_hint=ast.unparse(arg.annotation) if arg.annotation and hasattr(ast, 'unparse') else None,
                )
            )

        # Handle *args and **kwargs
        if node.args.vararg:
            params.append(
                ParsedParameter(name=f"*{node.args.vararg.arg}", is_variadic=True)
            )
        if node.args.kwarg:
            params.append(
                ParsedParameter(name=f"**{node.args.kwarg.arg}", is_variadic=True)
            )

        # Get decorators
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(ast.unparse(dec) if hasattr(ast, 'unparse') else str(dec))
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.append(dec.func.id)

        # Get docstring
        docstring = ast.get_docstring(node)

        # Extract function calls
        calls = self._extract_calls(node)

        # Extract SQL patterns
        sql_queries = self._extract_sql_patterns(node)

        func = ParsedFunction(
            name=node.name,
            parameters=params,
            return_type=ast.unparse(node.returns) if node.returns and hasattr(ast, 'unparse') else None,
            body=ast.unparse(node) if hasattr(ast, 'unparse') else "",
            location=CodeLocation(
                file_path=file_path,
                line=node.lineno,
                column=node.col_offset,
                end_line=node.end_lineno,
            ),
            decorators=decorators,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            docstring=docstring,
            calls=calls,
            sql_queries=sql_queries,
        )

        return func

    def _parse_class(self, node: ast.ClassDef, file_path: str) -> ParsedClass:
        """Parse a class definition."""
        # Get base classes
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(ast.unparse(base) if hasattr(ast, 'unparse') else str(base))

        # Get methods
        methods = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method = self._parse_function(item, file_path)
                method.is_method = True
                method.class_name = node.name
                methods.append(method)

        # Get class attributes
        attributes = []
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        attributes.append(
                            ParsedVariable(
                                name=target.id,
                                scope="class",
                                location=CodeLocation(
                                    file_path=file_path,
                                    line=item.lineno,
                                ),
                            )
                        )

        # Get decorators
        decorators = [
            dec.id if isinstance(dec, ast.Name) else ast.unparse(dec) if hasattr(ast, 'unparse') else str(dec)
            for dec in node.decorator_list
        ]

        return ParsedClass(
            name=node.name,
            base_classes=bases,
            methods=methods,
            attributes=attributes,
            location=CodeLocation(
                file_path=file_path,
                line=node.lineno,
                column=node.col_offset,
                end_line=node.end_lineno,
            ),
            decorators=decorators,
            docstring=ast.get_docstring(node),
        )

    def _extract_calls(self, node: ast.AST) -> list[str]:
        """Extract function calls from a node."""
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    calls.append(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    calls.append(
                        ast.unparse(child.func) if hasattr(ast, 'unparse') else child.func.attr
                    )
        return calls

    def _extract_sql_patterns(self, node: ast.AST) -> list[str]:
        """Extract SQL query patterns from code."""
        sql_patterns = []
        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"]

        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                value_upper = child.value.upper()
                if any(kw in value_upper for kw in sql_keywords):
                    sql_patterns.append(child.value)
            elif isinstance(child, ast.JoinedStr):  # f-string
                try:
                    # Try to reconstruct the f-string
                    parts = []
                    for value in child.values:
                        if isinstance(value, ast.Constant):
                            parts.append(str(value.value))
                    joined = "".join(parts).upper()
                    if any(kw in joined for kw in sql_keywords):
                        sql_patterns.append(ast.unparse(child) if hasattr(ast, 'unparse') else "f-string SQL")
                except Exception:
                    pass

        return sql_patterns

    def _fallback_parse(
        self, content: str, parsed: ParsedFile, file_path: str
    ) -> None:
        """Regex-based fallback parsing for invalid syntax."""
        lines = content.split("\n")

        # Find function definitions
        func_pattern = re.compile(r"^\s*(async\s+)?def\s+(\w+)\s*\(([^)]*)\)")
        for i, line in enumerate(lines, 1):
            match = func_pattern.match(line)
            if match:
                is_async = bool(match.group(1))
                name = match.group(2)
                params_str = match.group(3)

                params = []
                if params_str.strip():
                    for p in params_str.split(","):
                        p = p.strip()
                        if p and p != "self":
                            params.append(ParsedParameter(name=p.split(":")[0].split("=")[0].strip()))

                parsed.functions.append(
                    ParsedFunction(
                        name=name,
                        parameters=params,
                        is_async=is_async,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

        # Find class definitions
        class_pattern = re.compile(r"^\s*class\s+(\w+)\s*(?:\(([^)]*)\))?:")
        for i, line in enumerate(lines, 1):
            match = class_pattern.match(line)
            if match:
                name = match.group(1)
                bases = []
                if match.group(2):
                    bases = [b.strip() for b in match.group(2).split(",")]

                parsed.classes.append(
                    ParsedClass(
                        name=name,
                        base_classes=bases,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

        # Find imports
        import_pattern = re.compile(r"^\s*(?:from\s+(\S+)\s+)?import\s+(.+)")
        for i, line in enumerate(lines, 1):
            match = import_pattern.match(line)
            if match:
                module = match.group(1) or ""
                names = [n.strip() for n in match.group(2).split(",")]
                parsed.imports.append(
                    ParsedImport(
                        module=module if module else names[0],
                        names=names if module else [],
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

    def _find_python_security_patterns(
        self, content: str, file_path: str
    ) -> list[SecurityPattern]:
        """Find Python-specific security patterns."""
        patterns = self._find_security_patterns(content, file_path)
        lines = content.split("\n")

        # Python-specific dangerous patterns
        dangerous_patterns = {
            "code_execution": [
                (r"\beval\s*\(", "eval() - arbitrary code execution"),
                (r"\bexec\s*\(", "exec() - arbitrary code execution"),
                (r"\bcompile\s*\(", "compile() - code compilation"),
                (r"__import__\s*\(", "__import__() - dynamic import"),
            ],
            "command_injection": [
                (r"\bos\.system\s*\(", "os.system() - command execution"),
                (r"\bos\.popen\s*\(", "os.popen() - command execution"),
                (r"\bsubprocess\.(run|call|Popen|check_output)\s*\(", "subprocess - command execution"),
                (r"\bcommands\.(getoutput|getstatusoutput)\s*\(", "commands module - deprecated"),
            ],
            "sql_injection": [
                (r'cursor\.(execute|executemany)\s*\(\s*["\'].*%', "SQL with string formatting"),
                (r'cursor\.(execute|executemany)\s*\(\s*f["\']', "SQL with f-string"),
                (r'\.raw\s*\(', "Django raw SQL"),
                (r'\.extra\s*\(', "Django extra() - potential SQL injection"),
            ],
            "path_traversal": [
                (r'open\s*\([^)]*\+', "open() with string concatenation"),
                (r'os\.path\.join\s*\([^)]*request', "os.path.join with user input"),
            ],
            "deserialization": [
                (r"\bpickle\.(loads?|Unpickler)\s*\(", "pickle - unsafe deserialization"),
                (r"\byaml\.load\s*\([^)]*\)", "yaml.load() without Loader"),
                (r"\bjsonpickle\.decode\s*\(", "jsonpickle - unsafe deserialization"),
            ],
            "xxe": [
                (r"etree\.parse\s*\(", "XML parsing - potential XXE"),
                (r"xml\.etree", "XML parsing - check for XXE protection"),
                (r"lxml\.etree", "lxml parsing - check for XXE protection"),
            ],
            "ssrf": [
                (r"requests\.(get|post|put|delete|head|options)\s*\([^)]*\+", "requests with dynamic URL"),
                (r"urllib\.request\.urlopen\s*\(", "urllib - potential SSRF"),
                (r"http\.client\.HTTPConnection\s*\(", "HTTP client - potential SSRF"),
            ],
            "hardcoded_secret": [
                (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
                (r'(?i)(api_key|apikey|api_secret)\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
                (r'(?i)(secret|token)\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', "Hardcoded secret/token"),
            ],
            "weak_crypto": [
                (r"\bhashlib\.md5\s*\(", "MD5 - weak hash"),
                (r"\bhashlib\.sha1\s*\(", "SHA1 - weak hash"),
                (r"DES\.|Blowfish\.", "Weak encryption algorithm"),
            ],
            "debug_enabled": [
                (r"DEBUG\s*=\s*True", "Debug mode enabled"),
                (r"app\.run\s*\([^)]*debug\s*=\s*True", "Flask debug mode"),
            ],
        }

        for i, line in enumerate(lines, 1):
            for pattern_type, regex_list in dangerous_patterns.items():
                for regex, description in regex_list:
                    if re.search(regex, line):
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

        # Common user input sources in Python
        sources = {
            "request.": "HTTP request",
            "request.GET": "GET parameter",
            "request.POST": "POST parameter",
            "request.args": "Flask request args",
            "request.form": "Flask form data",
            "request.json": "JSON body",
            "input(": "Console input",
            "sys.argv": "Command line argument",
            "os.environ": "Environment variable",
        }

        # Dangerous sinks
        sinks = {
            "cursor.execute": "SQL execution",
            "os.system": "Command execution",
            "subprocess.": "Command execution",
            "eval(": "Code execution",
            "exec(": "Code execution",
            "open(": "File operation",
            "render_template_string": "Template injection",
        }

        # Simple analysis: check if any function uses both source and sink
        for func in parsed.functions:
            body = func.body.lower() if func.body else ""

            found_sources = []
            found_sinks = []

            for source, source_type in sources.items():
                if source.lower() in body:
                    found_sources.append((source, source_type))

            for sink, sink_type in sinks.items():
                if sink.lower() in body:
                    found_sinks.append((sink, sink_type))

            # Create flows for each source-sink pair
            for source, source_type in found_sources:
                for sink, sink_type in found_sinks:
                    if func.location:
                        flows.append(
                            DataFlow(
                                source=source_type,
                                source_location=func.location,
                                sink=sink_type,
                                sink_location=func.location,
                                path=[func.name],
                            )
                        )

        return flows
