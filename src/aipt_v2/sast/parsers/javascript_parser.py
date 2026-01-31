"""
AIPTX JavaScript/TypeScript Parser - Pattern-Based Analysis

Uses regex and pattern matching for JavaScript and TypeScript
code analysis since Python doesn't have a native JS AST parser.
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


class JavaScriptParser(BaseParser):
    """
    JavaScript/TypeScript code parser.

    Extracts:
    - Functions (regular, arrow, async)
    - Classes with methods
    - Imports (ES6 and CommonJS)
    - Variables and constants
    - Security patterns (XSS, injection, etc.)
    """

    @property
    def language(self) -> Language:
        return Language.JAVASCRIPT

    @property
    def file_extensions(self) -> list[str]:
        return ["js", "jsx", "ts", "tsx", "mjs"]

    def parse(self, content: str, file_path: str) -> ParsedFile:
        """Parse JavaScript/TypeScript source code."""
        parsed = ParsedFile(
            file_path=file_path,
            language=self.language,
            raw_content=content,
            lines=content.split("\n"),
        )

        # Remove comments for cleaner parsing
        clean_content = self._remove_comments(content)

        # Extract components
        parsed.imports = self._extract_imports(clean_content, file_path)
        parsed.functions = self._extract_functions(clean_content, file_path)
        parsed.classes = self._extract_classes(clean_content, file_path)
        parsed.variables = self._extract_variables(clean_content, file_path)
        parsed.security_patterns = self._find_js_security_patterns(content, file_path)
        parsed.data_flows = self._analyze_data_flows(parsed)

        return parsed

    def _remove_comments(self, content: str) -> str:
        """Remove JavaScript comments while preserving line numbers."""
        # Remove single-line comments
        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
        # Remove multi-line comments (preserve newlines)
        content = re.sub(r"/\*[\s\S]*?\*/", lambda m: "\n" * m.group().count("\n"), content)
        return content

    def _extract_imports(self, content: str, file_path: str) -> list[ParsedImport]:
        """Extract ES6 and CommonJS imports."""
        imports = []
        lines = content.split("\n")

        # ES6 imports: import { x, y } from 'module'
        es6_pattern = re.compile(
            r"import\s+(?:(\*\s+as\s+\w+)|(\{[^}]+\})|(\w+))\s+from\s+['\"]([^'\"]+)['\"]"
        )

        # Default import: import x from 'module'
        default_pattern = re.compile(
            r"import\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]"
        )

        # CommonJS require: const x = require('module')
        require_pattern = re.compile(
            r"(?:const|let|var)\s+(?:(\{[^}]+\})|(\w+))\s*=\s*require\s*\(['\"]([^'\"]+)['\"]\)"
        )

        for i, line in enumerate(lines, 1):
            # ES6 imports
            match = es6_pattern.search(line)
            if match:
                module = match.group(4)
                names = []
                if match.group(2):  # Named imports
                    names = [n.strip() for n in match.group(2).strip("{}").split(",")]
                imports.append(
                    ParsedImport(
                        module=module,
                        names=names,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )
                continue

            # Default import
            match = default_pattern.search(line)
            if match:
                imports.append(
                    ParsedImport(
                        module=match.group(2),
                        names=[match.group(1)],
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )
                continue

            # CommonJS require
            match = require_pattern.search(line)
            if match:
                module = match.group(3)
                names = []
                if match.group(1):  # Destructured require
                    names = [n.strip() for n in match.group(1).strip("{}").split(",")]
                elif match.group(2):  # Simple require
                    names = [match.group(2)]
                imports.append(
                    ParsedImport(
                        module=module,
                        names=names,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

        return imports

    def _extract_functions(self, content: str, file_path: str) -> list[ParsedFunction]:
        """Extract function definitions."""
        functions = []
        lines = content.split("\n")

        # Regular function: function name(params) { or async function name(params) {
        func_pattern = re.compile(
            r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)"
        )

        # Arrow function: const name = (params) => or const name = async (params) =>
        arrow_pattern = re.compile(
            r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?([^)=]*)\)?\s*=>"
        )

        # Method pattern (simplified): name(params) { inside class
        method_pattern = re.compile(
            r"^\s*(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{"
        )

        for i, line in enumerate(lines, 1):
            # Regular functions
            match = func_pattern.search(line)
            if match:
                name = match.group(1)
                params_str = match.group(2)
                is_async = "async" in line.split("function")[0]

                params = self._parse_parameters(params_str)
                functions.append(
                    ParsedFunction(
                        name=name,
                        parameters=params,
                        is_async=is_async,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )
                continue

            # Arrow functions
            match = arrow_pattern.search(line)
            if match:
                name = match.group(1)
                params_str = match.group(2)
                is_async = "async" in line.split("=")[0]

                params = self._parse_parameters(params_str)
                functions.append(
                    ParsedFunction(
                        name=name,
                        parameters=params,
                        is_async=is_async,
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

        return functions

    def _extract_classes(self, content: str, file_path: str) -> list[ParsedClass]:
        """Extract class definitions."""
        classes = []
        lines = content.split("\n")

        # Class pattern: class Name extends Base {
        class_pattern = re.compile(
            r"(?:export\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?"
        )

        in_class = False
        current_class = None
        brace_count = 0

        for i, line in enumerate(lines, 1):
            # Check for class start
            match = class_pattern.search(line)
            if match and not in_class:
                in_class = True
                current_class = ParsedClass(
                    name=match.group(1),
                    base_classes=[match.group(2)] if match.group(2) else [],
                    location=CodeLocation(file_path=file_path, line=i),
                )
                brace_count = line.count("{") - line.count("}")
                continue

            if in_class:
                brace_count += line.count("{") - line.count("}")

                # Look for methods
                method_match = re.search(
                    r"^\s*(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{",
                    line
                )
                if method_match and current_class:
                    method_name = method_match.group(1)
                    if method_name not in ["if", "for", "while", "switch", "catch"]:
                        params = self._parse_parameters(method_match.group(2))
                        current_class.methods.append(
                            ParsedFunction(
                                name=method_name,
                                parameters=params,
                                is_method=True,
                                is_async="async" in line.split(method_name)[0],
                                class_name=current_class.name,
                                location=CodeLocation(file_path=file_path, line=i),
                            )
                        )

                if brace_count <= 0:
                    in_class = False
                    if current_class:
                        classes.append(current_class)
                    current_class = None

        return classes

    def _extract_variables(self, content: str, file_path: str) -> list[ParsedVariable]:
        """Extract variable declarations."""
        variables = []
        lines = content.split("\n")

        # Variable patterns
        var_pattern = re.compile(
            r"(?:export\s+)?(const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(.+?)(?:;|$)"
        )

        for i, line in enumerate(lines, 1):
            match = var_pattern.search(line)
            if match:
                decl_type = match.group(1)
                name = match.group(2)
                value = match.group(3).strip()

                # Skip function/class assignments (handled elsewhere)
                if re.match(r"(?:async\s+)?function\s+", value):
                    continue
                if re.match(r"class\s+", value):
                    continue

                variables.append(
                    ParsedVariable(
                        name=name,
                        value=value[:100] if len(value) > 100 else value,
                        is_constant=decl_type == "const",
                        location=CodeLocation(file_path=file_path, line=i),
                    )
                )

        return variables

    def _parse_parameters(self, params_str: str) -> list[ParsedParameter]:
        """Parse function parameters."""
        params = []
        if not params_str.strip():
            return params

        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue

            # Handle TypeScript type annotations
            name = param.split(":")[0].strip()
            type_hint = None
            if ":" in param:
                type_hint = param.split(":")[1].strip()

            # Handle default values
            default_value = None
            if "=" in name:
                name, default_value = name.split("=", 1)
                name = name.strip()
                default_value = default_value.strip()

            # Handle rest parameters
            is_variadic = name.startswith("...")
            if is_variadic:
                name = name[3:]

            params.append(
                ParsedParameter(
                    name=name,
                    type_hint=type_hint,
                    default_value=default_value,
                    is_variadic=is_variadic,
                )
            )

        return params

    def _find_js_security_patterns(
        self, content: str, file_path: str
    ) -> list[SecurityPattern]:
        """Find JavaScript-specific security patterns."""
        patterns = self._find_security_patterns(content, file_path)
        lines = content.split("\n")

        # JavaScript-specific dangerous patterns
        dangerous_patterns = {
            "xss": [
                (r"\.innerHTML\s*=", "innerHTML assignment - potential XSS"),
                (r"\.outerHTML\s*=", "outerHTML assignment - potential XSS"),
                (r"document\.write\s*\(", "document.write() - potential XSS"),
                (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML - potential XSS"),
                (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML"),
                (r"\$\([^)]+\)\.html\s*\(", "jQuery .html() - potential XSS"),
            ],
            "code_execution": [
                (r"\beval\s*\(", "eval() - arbitrary code execution"),
                (r"new\s+Function\s*\(", "new Function() - code execution"),
                (r"setTimeout\s*\(\s*['\"]", "setTimeout with string - code execution"),
                (r"setInterval\s*\(\s*['\"]", "setInterval with string - code execution"),
            ],
            "prototype_pollution": [
                (r"__proto__", "__proto__ access - prototype pollution"),
                (r"Object\.assign\s*\([^,]+,\s*(?:req|request)", "Object.assign with user input"),
                (r"\.constructor\s*\[", "constructor access - prototype pollution"),
            ],
            "sql_injection": [
                (r'\.query\s*\(\s*[`"\'].*\$\{', "SQL with template literal"),
                (r'\.query\s*\(\s*["\'].*\+', "SQL with string concatenation"),
                (r'\.execute\s*\(\s*[`"\'].*\$\{', "SQL execute with template"),
            ],
            "command_injection": [
                (r"child_process\.exec\s*\(", "child_process.exec - command injection"),
                (r"child_process\.spawn\s*\(", "child_process.spawn - command injection"),
                (r"require\s*\(['\"]child_process['\"]\)", "child_process import"),
            ],
            "path_traversal": [
                (r"fs\.(readFile|writeFile|readdir)\s*\([^)]*\+", "fs operation with concatenation"),
                (r"path\.join\s*\([^)]*req\.", "path.join with user input"),
                (r"res\.sendFile\s*\([^)]*\+", "sendFile with concatenation"),
            ],
            "open_redirect": [
                (r"res\.redirect\s*\([^)]*req\.", "redirect with user input"),
                (r"window\.location\s*=\s*[^'\"]+", "dynamic window.location"),
                (r"location\.href\s*=\s*[^'\"]+", "dynamic location.href"),
            ],
            "hardcoded_secret": [
                (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded password"),
                (r'(?i)(api_key|apikey|api_secret)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded API key"),
                (r'(?i)(secret|token)\s*[=:]\s*["\'][A-Za-z0-9+/=]{20,}["\']', "Hardcoded secret"),
                (r'(?i)jwt\s*[=:]\s*["\']eyJ[A-Za-z0-9_-]+', "Hardcoded JWT"),
            ],
            "insecure_config": [
                (r"cors\s*\(\s*\)", "CORS with no options"),
                (r"origin:\s*['\"]\\*['\"]", "CORS allow all origins"),
                (r"secure:\s*false", "Cookie secure flag disabled"),
                (r"httpOnly:\s*false", "Cookie httpOnly disabled"),
            ],
            "nosql_injection": [
                (r"\$where\s*:", "MongoDB $where - NoSQL injection"),
                (r"\$regex\s*:", "MongoDB $regex - potential ReDoS"),
                (r"\.find\s*\(\s*\{[^}]*req\.", "MongoDB find with user input"),
            ],
            "ssrf": [
                (r"axios\.(get|post|put|delete)\s*\([^)]*\+", "Axios with dynamic URL"),
                (r"fetch\s*\([^)]*\+", "fetch with dynamic URL"),
                (r"request\s*\([^)]*\+", "request with dynamic URL"),
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

        # Common user input sources in JavaScript
        sources = {
            "req.body": "HTTP request body",
            "req.query": "Query parameter",
            "req.params": "URL parameter",
            "req.headers": "HTTP header",
            "req.cookies": "Cookie",
            "document.location": "URL",
            "window.location": "URL",
            "localStorage": "Local storage",
            "sessionStorage": "Session storage",
        }

        # Dangerous sinks
        sinks = {
            ".innerHTML": "DOM XSS sink",
            "document.write": "DOM XSS sink",
            ".query(": "SQL execution",
            ".exec(": "Command execution",
            "eval(": "Code execution",
            "res.redirect": "Redirect",
            "fs.readFile": "File read",
        }

        content = parsed.raw_content.lower()

        # Simple heuristic: check if both source and sink exist
        for source, source_type in sources.items():
            if source.lower() in content:
                for sink, sink_type in sinks.items():
                    if sink.lower() in content:
                        # Find approximate locations
                        for i, line in enumerate(parsed.lines, 1):
                            if source.lower() in line.lower():
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
