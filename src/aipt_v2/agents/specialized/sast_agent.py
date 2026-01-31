"""
AIPTX SAST Agent - Static Application Security Testing

Analyzes source code for security vulnerabilities:
- Hardcoded secrets
- SQL injection patterns
- Command injection
- XSS vulnerabilities
- Insecure deserialization
- Path traversal
- Dependency vulnerabilities
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from aipt_v2.agents.specialized.base_specialized import (
    SpecializedAgent,
    AgentCapability,
    AgentConfig,
)
from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    VulnerabilityType,
    Evidence,
)

logger = logging.getLogger(__name__)


# Security rules for different languages
SECURITY_RULES = {
    "python": {
        "sql_injection": [
            (r'execute\s*\([^)]*\+[^)]*\)', "SQL string concatenation"),
            (r'execute\s*\([^)]*%[^)]*\)', "SQL format string"),
            (r'execute\s*\(f["\'][^"\']*{[^}]*}', "SQL f-string interpolation"),
            (r'cursor\.execute\s*\([^,]+\+', "Cursor execute with concatenation"),
        ],
        "command_injection": [
            (r'os\.system\s*\([^)]*\+', "os.system with concatenation"),
            (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', "subprocess with shell=True"),
            (r'os\.popen\s*\([^)]*\+', "os.popen with concatenation"),
            (r'eval\s*\([^)]*\)', "eval() usage"),
            (r'exec\s*\([^)]*\)', "exec() usage"),
        ],
        "secrets": [
            (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
            (r'(?i)(api_key|apikey|api_secret)\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded API key"),
            (r'(?i)(secret|token)\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded secret/token"),
            (r'(?i)aws_access_key_id\s*=\s*["\']AKIA[A-Z0-9]{16}["\']', "AWS Access Key"),
            (r'(?i)aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']', "AWS Secret Key"),
        ],
        "xss": [
            (r'render_template_string\s*\([^)]*\+', "Template string injection"),
            (r'Markup\s*\([^)]*\+', "Unsafe Markup construction"),
        ],
        "deserialization": [
            (r'pickle\.loads?\s*\(', "Unsafe pickle deserialization"),
            (r'yaml\.load\s*\([^)]*\)', "Unsafe YAML load (use safe_load)"),
            (r'marshal\.loads?\s*\(', "Unsafe marshal deserialization"),
        ],
        "path_traversal": [
            (r'open\s*\([^)]*\+[^)]*\)', "File open with concatenation"),
            (r'send_file\s*\([^)]*\+', "send_file with user input"),
        ],
    },
    "javascript": {
        "sql_injection": [
            (r'query\s*\([^)]*\+[^)]*\)', "SQL string concatenation"),
            (r'execute\s*\(`[^`]*\$\{', "SQL template literal injection"),
        ],
        "command_injection": [
            (r'child_process\.exec\s*\([^)]*\+', "exec with concatenation"),
            (r'child_process\.execSync\s*\([^)]*\+', "execSync with concatenation"),
            (r'eval\s*\([^)]*\)', "eval() usage"),
        ],
        "secrets": [
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
            (r'(?i)(api_key|apikey|api_secret)\s*[:=]\s*["\'][^"\']{16,}["\']', "Hardcoded API key"),
            (r'(?i)(secret|token)\s*[:=]\s*["\'][^"\']{16,}["\']', "Hardcoded secret/token"),
        ],
        "xss": [
            (r'innerHTML\s*=\s*[^;]*\+', "innerHTML with concatenation"),
            (r'document\.write\s*\([^)]*\+', "document.write with concatenation"),
            (r'\.html\s*\([^)]*\+', "jQuery .html() with concatenation"),
            (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
        ],
        "deserialization": [
            (r'JSON\.parse\s*\(', "JSON.parse (verify input source)"),
            (r'serialize\s*\(', "serialize usage"),
        ],
        "path_traversal": [
            (r'path\.join\s*\([^)]*req\.', "Path join with user input"),
            (r'fs\.readFile\s*\([^)]*\+', "readFile with concatenation"),
        ],
        "prototype_pollution": [
            (r'Object\.assign\s*\([^)]*,\s*req\.', "Object.assign with user input"),
            (r'\[req\.[^\]]+\]\s*=', "Dynamic property assignment"),
        ],
    },
    "java": {
        "sql_injection": [
            (r'Statement\.execute\s*\([^)]*\+', "Statement with concatenation"),
            (r'createQuery\s*\([^)]*\+', "HQL/JPQL with concatenation"),
        ],
        "command_injection": [
            (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', "Runtime.exec with concatenation"),
            (r'ProcessBuilder\s*\([^)]*\+', "ProcessBuilder with concatenation"),
        ],
        "secrets": [
            (r'(?i)(password|passwd)\s*=\s*"[^"]{8,}"', "Hardcoded password"),
            (r'(?i)(apiKey|api_key)\s*=\s*"[^"]{16,}"', "Hardcoded API key"),
        ],
        "xxe": [
            (r'DocumentBuilderFactory\.newInstance\(\)', "XXE: Check if DTD disabled"),
            (r'SAXParserFactory\.newInstance\(\)', "XXE: Check if DTD disabled"),
            (r'XMLInputFactory\.newInstance\(\)', "XXE: Check if DTD disabled"),
        ],
        "deserialization": [
            (r'ObjectInputStream\s*\(', "Unsafe deserialization"),
            (r'readObject\s*\(\)', "readObject usage"),
        ],
    },
    "go": {
        "sql_injection": [
            (r'db\.Query\s*\([^)]*\+', "SQL with concatenation"),
            (r'db\.Exec\s*\([^)]*\+', "SQL exec with concatenation"),
            (r'fmt\.Sprintf\s*\([^)]*SELECT', "SQL in Sprintf"),
        ],
        "command_injection": [
            (r'exec\.Command\s*\([^)]*\+', "exec.Command with concatenation"),
            (r'os\.exec\s*\([^)]*\+', "os.exec with concatenation"),
        ],
        "secrets": [
            (r'(?i)(password|passwd)\s*:?=\s*"[^"]{8,}"', "Hardcoded password"),
            (r'(?i)(apiKey|api_key)\s*:?=\s*"[^"]{16,}"', "Hardcoded API key"),
        ],
        "path_traversal": [
            (r'filepath\.Join\s*\([^)]*,\s*r\.', "filepath.Join with user input"),
            (r'os\.Open\s*\([^)]*\+', "os.Open with concatenation"),
        ],
    },
}

# File extensions by language
LANGUAGE_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
    "java": [".java"],
    "go": [".go"],
}


class SASTAgent(SpecializedAgent):
    """
    Static Application Security Testing agent.

    Analyzes source code for:
    - Injection vulnerabilities
    - Hardcoded secrets
    - Insecure configurations
    - Dangerous function usage
    - Dependency vulnerabilities
    """

    name = "SASTAgent"

    def __init__(self, *args, source_path: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.source_path = source_path or self.config.custom_config.get("source_path")
        self._files_scanned = 0
        self._total_files = 0

    def get_capabilities(self) -> list[AgentCapability]:
        return [
            AgentCapability.CODE_ANALYSIS,
            AgentCapability.SECRET_DETECTION,
            AgentCapability.DEPENDENCY_SCAN,
            AgentCapability.TAINT_ANALYSIS,
        ]

    async def run(self) -> dict[str, Any]:
        """Execute SAST analysis."""
        await self.initialize()
        self._progress.status = "running"

        results = {
            "files_scanned": 0,
            "findings_by_type": {},
            "languages_detected": [],
            "findings_count": 0,
            "success": True,
        }

        try:
            if not self.source_path:
                # Try to get source from target (GitHub URL, etc.)
                self.source_path = await self._resolve_source_path()

            if not self.source_path or not os.path.exists(self.source_path):
                logger.warning(f"Source path not found: {self.source_path}")
                results["success"] = False
                results["error"] = "Source path not found"
                return results

            # Phase 1: Discover files (10%)
            await self.update_progress("Discovering source files", 0)
            files = await self._discover_files()
            self._total_files = len(files)
            results["files_scanned"] = self._total_files

            # Detect languages
            results["languages_detected"] = list(set(
                lang for lang, exts in LANGUAGE_EXTENSIONS.items()
                for f in files if any(f.endswith(ext) for ext in exts)
            ))

            # Phase 2: Scan for secrets (30%)
            self.check_cancelled()
            await self.update_progress("Scanning for secrets", 10)
            await self._scan_for_secrets(files)

            # Phase 3: Scan for injection vulnerabilities (50%)
            self.check_cancelled()
            await self.update_progress("Scanning for injection vulnerabilities", 30)
            await self._scan_for_injections(files)

            # Phase 4: Scan dependencies (70%)
            self.check_cancelled()
            await self.update_progress("Scanning dependencies", 50)
            await self._scan_dependencies()

            # Phase 5: Run external SAST tools (90%)
            self.check_cancelled()
            await self.update_progress("Running external SAST tools", 70)
            await self._run_external_tools()

            await self.update_progress("Complete", 100)
            results["findings_count"] = self._findings_count

        except asyncio.CancelledError:
            logger.info("SASTAgent cancelled")
            results["success"] = False
            results["error"] = "Cancelled"
        except Exception as e:
            logger.error(f"SASTAgent error: {e}", exc_info=True)
            results["success"] = False
            results["error"] = str(e)
        finally:
            await self.cleanup()

        return results

    async def _resolve_source_path(self) -> Optional[str]:
        """Resolve source path from target (clone repo if needed)."""
        target = self.target

        # Check if target is a GitHub URL
        if "github.com" in target:
            return await self._clone_github_repo(target)

        # Check if target is a local path
        if os.path.exists(target):
            return target

        return None

    async def _clone_github_repo(self, url: str) -> Optional[str]:
        """Clone a GitHub repository."""
        import tempfile

        try:
            temp_dir = tempfile.mkdtemp(prefix="aiptx_sast_")
            process = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", url, temp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.wait()
            return temp_dir
        except Exception as e:
            logger.error(f"Failed to clone repo: {e}")
            return None

    async def _discover_files(self) -> list[str]:
        """Discover all source files in the path."""
        files = []
        all_extensions = []
        for exts in LANGUAGE_EXTENSIONS.values():
            all_extensions.extend(exts)

        for root, _, filenames in os.walk(self.source_path):
            # Skip common non-source directories
            if any(skip in root for skip in [
                "node_modules", ".git", "__pycache__", "venv",
                ".venv", "dist", "build", "vendor"
            ]):
                continue

            for filename in filenames:
                if any(filename.endswith(ext) for ext in all_extensions):
                    files.append(os.path.join(root, filename))

        return files

    async def _scan_for_secrets(self, files: list[str]) -> None:
        """Scan files for hardcoded secrets."""
        secret_patterns = []
        for lang_rules in SECURITY_RULES.values():
            if "secrets" in lang_rules:
                secret_patterns.extend(lang_rules["secrets"])

        for i, file_path in enumerate(files):
            self.check_cancelled()

            try:
                content = await self._read_file(file_path)
                if not content:
                    continue

                for line_num, line in enumerate(content.split("\n"), 1):
                    for pattern, description in secret_patterns:
                        if re.search(pattern, line):
                            # Mask the actual secret in the finding
                            masked_line = re.sub(
                                r'(["\'])[^"\']{8,}(["\'])',
                                r'\1***REDACTED***\2',
                                line
                            )

                            finding = Finding(
                                vuln_type=VulnerabilityType.HARDCODED_SECRETS,
                                title=f"Hardcoded secret: {description}",
                                description=f"Found potential hardcoded secret in source code",
                                severity=FindingSeverity.HIGH,
                                target=self.target,
                                file_path=self._relative_path(file_path),
                                line_number=line_num,
                                evidence=Evidence(notes=masked_line.strip()),
                                tags=["sast", "secrets"],
                            )
                            await self.add_finding(finding)

            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")

            # Update progress
            if i % 10 == 0:
                progress = 10 + (i / len(files)) * 20
                await self.update_progress(
                    f"Scanning for secrets ({i}/{len(files)})",
                    progress
                )

    async def _scan_for_injections(self, files: list[str]) -> None:
        """Scan files for injection vulnerabilities."""
        for i, file_path in enumerate(files):
            self.check_cancelled()

            try:
                language = self._detect_language(file_path)
                if not language or language not in SECURITY_RULES:
                    continue

                content = await self._read_file(file_path)
                if not content:
                    continue

                rules = SECURITY_RULES[language]

                for category, patterns in rules.items():
                    if category == "secrets":
                        continue  # Already scanned

                    for pattern, description in patterns:
                        for line_num, line in enumerate(content.split("\n"), 1):
                            if re.search(pattern, line):
                                vuln_type = self._map_category_to_vuln_type(category)
                                severity = self._assess_injection_severity(category)

                                finding = Finding(
                                    vuln_type=vuln_type,
                                    title=f"{category.replace('_', ' ').title()}: {description}",
                                    description=f"Potential {category.replace('_', ' ')} vulnerability detected",
                                    severity=severity,
                                    target=self.target,
                                    file_path=self._relative_path(file_path),
                                    line_number=line_num,
                                    evidence=Evidence(notes=line.strip()[:200]),
                                    tags=["sast", category],
                                )
                                await self.add_finding(finding)

            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")

            # Update progress
            if i % 10 == 0:
                progress = 30 + (i / len(files)) * 20
                await self.update_progress(
                    f"Scanning for injections ({i}/{len(files)})",
                    progress
                )

    async def _scan_dependencies(self) -> None:
        """Scan for vulnerable dependencies."""
        # Check for package files
        package_files = {
            "requirements.txt": "python",
            "Pipfile": "python",
            "Pipfile.lock": "python",
            "pyproject.toml": "python",
            "package.json": "javascript",
            "package-lock.json": "javascript",
            "yarn.lock": "javascript",
            "pom.xml": "java",
            "build.gradle": "java",
            "go.mod": "go",
            "go.sum": "go",
        }

        for filename, lang in package_files.items():
            file_path = os.path.join(self.source_path, filename)
            if os.path.exists(file_path):
                await self._analyze_dependency_file(file_path, lang)

    async def _analyze_dependency_file(self, file_path: str, language: str) -> None:
        """Analyze a dependency file for known vulnerabilities."""
        try:
            # Try to use safety for Python
            if language == "python" and file_path.endswith("requirements.txt"):
                from aipt_v2.execution.tool_registry import get_registry
                registry = get_registry()

                if await registry.is_tool_available("safety"):
                    result = await self._run_tool("safety", [
                        "check", "-r", file_path, "--json"
                    ])
                    if result.get("output"):
                        await self._parse_safety_output(result["output"])

            # Try npm audit for JavaScript
            elif language == "javascript" and file_path.endswith("package.json"):
                dir_path = os.path.dirname(file_path)
                from aipt_v2.execution.tool_registry import get_registry
                registry = get_registry()

                if await registry.is_tool_available("npm"):
                    result = await self._run_tool("npm", [
                        "audit", "--json"
                    ], cwd=dir_path)
                    if result.get("output"):
                        await self._parse_npm_audit(result["output"])

        except Exception as e:
            logger.warning(f"Error analyzing dependencies in {file_path}: {e}")

    async def _run_external_tools(self) -> None:
        """Run external SAST tools like Semgrep, Bandit."""
        try:
            from aipt_v2.execution.tool_registry import get_registry
            registry = get_registry()

            # Try Semgrep
            if await registry.is_tool_available("semgrep"):
                result = await self._run_tool("semgrep", [
                    "--config", "auto",
                    "--json",
                    self.source_path
                ], timeout=300)
                if result.get("output"):
                    await self._parse_semgrep_output(result["output"])

            # Try Bandit for Python
            python_files = [f for f in await self._discover_files() if f.endswith(".py")]
            if python_files and await registry.is_tool_available("bandit"):
                result = await self._run_tool("bandit", [
                    "-r", self.source_path,
                    "-f", "json"
                ], timeout=180)
                if result.get("output"):
                    await self._parse_bandit_output(result["output"])

        except Exception as e:
            logger.warning(f"Error running external SAST tools: {e}")

    async def _parse_safety_output(self, output: str) -> None:
        """Parse safety check output."""
        import json
        try:
            data = json.loads(output)
            for vuln in data:
                finding = Finding(
                    vuln_type=VulnerabilityType.MISCONFIGURATION,
                    title=f"Vulnerable dependency: {vuln.get('package_name', 'unknown')}",
                    description=vuln.get("vulnerability_id", ""),
                    severity=FindingSeverity.MEDIUM,
                    target=self.target,
                    cve_id=vuln.get("cve"),
                    component=vuln.get("package_name"),
                    tags=["sast", "dependency", "python"],
                )
                await self.add_finding(finding)
        except json.JSONDecodeError:
            pass

    async def _parse_npm_audit(self, output: str) -> None:
        """Parse npm audit output."""
        import json
        try:
            data = json.loads(output)
            for vuln_id, vuln in data.get("vulnerabilities", {}).items():
                severity_map = {"critical": FindingSeverity.CRITICAL,
                               "high": FindingSeverity.HIGH,
                               "moderate": FindingSeverity.MEDIUM,
                               "low": FindingSeverity.LOW}
                finding = Finding(
                    vuln_type=VulnerabilityType.MISCONFIGURATION,
                    title=f"Vulnerable dependency: {vuln_id}",
                    description=vuln.get("title", ""),
                    severity=severity_map.get(vuln.get("severity", "low"), FindingSeverity.LOW),
                    target=self.target,
                    component=vuln_id,
                    tags=["sast", "dependency", "javascript"],
                )
                await self.add_finding(finding)
        except json.JSONDecodeError:
            pass

    async def _parse_semgrep_output(self, output: str) -> None:
        """Parse Semgrep output."""
        import json
        try:
            data = json.loads(output)
            for result in data.get("results", []):
                severity_map = {"ERROR": FindingSeverity.HIGH,
                               "WARNING": FindingSeverity.MEDIUM,
                               "INFO": FindingSeverity.LOW}
                finding = Finding(
                    vuln_type=VulnerabilityType.OTHER,
                    title=result.get("check_id", "Unknown rule"),
                    description=result.get("extra", {}).get("message", ""),
                    severity=severity_map.get(
                        result.get("extra", {}).get("severity", "INFO"),
                        FindingSeverity.INFO
                    ),
                    target=self.target,
                    file_path=result.get("path"),
                    line_number=result.get("start", {}).get("line"),
                    tags=["sast", "semgrep"],
                )
                await self.add_finding(finding)
        except json.JSONDecodeError:
            pass

    async def _parse_bandit_output(self, output: str) -> None:
        """Parse Bandit output."""
        import json
        try:
            data = json.loads(output)
            for result in data.get("results", []):
                severity_map = {"HIGH": FindingSeverity.HIGH,
                               "MEDIUM": FindingSeverity.MEDIUM,
                               "LOW": FindingSeverity.LOW}
                finding = Finding(
                    vuln_type=VulnerabilityType.OTHER,
                    title=result.get("test_name", "Unknown"),
                    description=result.get("issue_text", ""),
                    severity=severity_map.get(
                        result.get("issue_severity", "LOW"),
                        FindingSeverity.LOW
                    ),
                    target=self.target,
                    file_path=result.get("filename"),
                    line_number=result.get("line_number"),
                    cwe_id=result.get("issue_cwe", {}).get("id"),
                    tags=["sast", "bandit", "python"],
                )
                await self.add_finding(finding)
        except json.JSONDecodeError:
            pass

    async def _read_file(self, file_path: str) -> Optional[str]:
        """Read file content asynchronously."""
        try:
            import aiofiles
            async with aiofiles.open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return await f.read()
        except Exception:
            return None

    async def _run_tool(
        self,
        tool_name: str,
        args: list[str],
        timeout: int = 60,
        cwd: Optional[str] = None,
    ) -> dict:
        """Run a SAST tool."""
        try:
            from aipt_v2.execution.tool_runner import ToolRunner
            runner = ToolRunner()
            return await runner.run(
                tool_name=tool_name,
                args=args,
                timeout=timeout,
                cwd=cwd or self.source_path,
            )
        except Exception as e:
            logger.warning(f"Tool {tool_name} failed: {e}")
            return {"output": "", "error": str(e)}

    def _detect_language(self, file_path: str) -> Optional[str]:
        """Detect programming language from file extension."""
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if any(file_path.endswith(ext) for ext in exts):
                return lang
        return None

    def _relative_path(self, file_path: str) -> str:
        """Convert to relative path."""
        if self.source_path and file_path.startswith(self.source_path):
            return file_path[len(self.source_path):].lstrip("/")
        return file_path

    def _map_category_to_vuln_type(self, category: str) -> VulnerabilityType:
        """Map SAST category to vulnerability type."""
        mapping = {
            "sql_injection": VulnerabilityType.SQLI,
            "command_injection": VulnerabilityType.COMMAND_INJECTION,
            "xss": VulnerabilityType.XSS,
            "deserialization": VulnerabilityType.DESERIALIZATION,
            "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
            "xxe": VulnerabilityType.XXE,
            "prototype_pollution": VulnerabilityType.OTHER,
        }
        return mapping.get(category, VulnerabilityType.OTHER)

    def _assess_injection_severity(self, category: str) -> FindingSeverity:
        """Assess severity based on vulnerability category."""
        high_severity = ["sql_injection", "command_injection", "deserialization", "xxe"]
        medium_severity = ["xss", "path_traversal", "prototype_pollution"]

        if category in high_severity:
            return FindingSeverity.HIGH
        if category in medium_severity:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW
