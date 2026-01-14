"""
Code Review Agent - AI-powered source code security review.

Performs comprehensive security analysis of source code to identify:
- Injection vulnerabilities (SQLi, XSS, Command Injection)
- Authentication/Authorization flaws
- Cryptographic issues
- Hardcoded secrets
- Insecure dependencies
- OWASP Top 10 vulnerabilities
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from aipt_v2.skills.agents.base import (
    AgentConfig,
    AgentResult,
    BaseSecurityAgent,
    Finding,
    Severity,
    VulnCategory,
    register_tool,
)

logger = structlog.get_logger()


# Register code review tools
@register_tool(
    name="read_file",
    description="Read the contents of a source code file",
    parameters={
        "file_path": {"type": "string", "description": "Path to the file to read"}
    },
    category="code_review"
)
async def read_file(file_path: str) -> str:
    """Read a source code file."""
    try:
        path = Path(file_path)
        if not path.exists():
            return f"Error: File not found: {file_path}"
        if not path.is_file():
            return f"Error: Not a file: {file_path}"

        # Limit file size to prevent memory issues
        if path.stat().st_size > 1_000_000:  # 1MB limit
            return f"Error: File too large (>1MB): {file_path}"

        content = path.read_text(encoding='utf-8', errors='replace')
        return f"File: {file_path}\n\n{content}"

    except Exception as e:
        return f"Error reading file: {str(e)}"


@register_tool(
    name="list_files",
    description="List files in a directory with optional filtering by extension",
    parameters={
        "directory": {"type": "string", "description": "Directory path to list"},
        "extension": {"type": "string", "description": "Optional file extension filter (e.g., '.py', '.js')"}
    },
    category="code_review"
)
async def list_files(directory: str, extension: Optional[str] = None) -> str:
    """List files in a directory."""
    try:
        path = Path(directory)
        if not path.exists():
            return f"Error: Directory not found: {directory}"
        if not path.is_dir():
            return f"Error: Not a directory: {directory}"

        files = []
        for item in path.rglob("*"):
            if item.is_file():
                if extension is None or item.suffix == extension:
                    files.append(str(item.relative_to(path)))

        if not files:
            return f"No files found in {directory}" + (f" with extension {extension}" if extension else "")

        return f"Files in {directory}:\n" + "\n".join(sorted(files)[:200])  # Limit to 200 files

    except Exception as e:
        return f"Error listing files: {str(e)}"


@register_tool(
    name="search_code",
    description="Search for a pattern in code files",
    parameters={
        "directory": {"type": "string", "description": "Directory to search in"},
        "pattern": {"type": "string", "description": "Regex pattern to search for"},
        "file_extension": {"type": "string", "description": "Optional file extension filter"}
    },
    category="code_review"
)
async def search_code(directory: str, pattern: str, file_extension: Optional[str] = None) -> str:
    """Search for a pattern in code files."""
    try:
        path = Path(directory)
        if not path.exists():
            return f"Error: Directory not found: {directory}"

        regex = re.compile(pattern, re.IGNORECASE)
        matches = []

        for item in path.rglob("*"):
            if not item.is_file():
                continue
            if file_extension and item.suffix != file_extension:
                continue

            try:
                content = item.read_text(encoding='utf-8', errors='replace')
                for i, line in enumerate(content.split('\n'), 1):
                    if regex.search(line):
                        matches.append(f"{item}:{i}: {line.strip()[:100]}")

                        if len(matches) >= 100:  # Limit results
                            matches.append("... (truncated, more matches exist)")
                            return "\n".join(matches)

            except Exception:
                continue

        if not matches:
            return f"No matches found for pattern: {pattern}"

        return f"Matches for '{pattern}':\n" + "\n".join(matches)

    except Exception as e:
        return f"Error searching: {str(e)}"


@register_tool(
    name="analyze_dependencies",
    description="Analyze project dependencies for known vulnerabilities",
    parameters={
        "directory": {"type": "string", "description": "Project directory"}
    },
    category="code_review"
)
async def analyze_dependencies(directory: str) -> str:
    """Analyze project dependencies."""
    try:
        path = Path(directory)
        results = []

        # Check for various dependency files
        dep_files = {
            "package.json": "Node.js",
            "requirements.txt": "Python",
            "Pipfile": "Python (Pipenv)",
            "pyproject.toml": "Python (Poetry/PEP)",
            "Gemfile": "Ruby",
            "composer.json": "PHP",
            "pom.xml": "Java (Maven)",
            "build.gradle": "Java (Gradle)",
            "go.mod": "Go",
            "Cargo.toml": "Rust",
        }

        for dep_file, lang in dep_files.items():
            dep_path = path / dep_file
            if dep_path.exists():
                content = dep_path.read_text(encoding='utf-8', errors='replace')
                results.append(f"\n=== {dep_file} ({lang}) ===\n{content[:2000]}")

        if not results:
            return "No dependency files found in the project."

        return "Dependency Analysis:\n" + "\n".join(results)

    except Exception as e:
        return f"Error analyzing dependencies: {str(e)}"


@register_tool(
    name="report_finding",
    description="Report a security vulnerability finding",
    parameters={
        "title": {"type": "string", "description": "Title of the vulnerability"},
        "severity": {"type": "string", "description": "Severity: critical, high, medium, low, info"},
        "category": {"type": "string", "description": "Vulnerability category"},
        "description": {"type": "string", "description": "Detailed description"},
        "evidence": {"type": "string", "description": "Code snippet or evidence"},
        "location": {"type": "string", "description": "File path and line number"},
        "remediation": {"type": "string", "description": "How to fix"},
        "cwe_id": {"type": "string", "description": "CWE identifier (e.g., CWE-89)"}
    },
    category="code_review"
)
async def report_finding(
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    location: str,
    remediation: str,
    cwe_id: Optional[str] = None
) -> str:
    """Report a security finding."""
    return f"""Finding Recorded:
Title: {title}
Severity: {severity}
Category: {category}
Location: {location}
CWE: {cwe_id or 'N/A'}
Description: {description}
Evidence: {evidence[:500]}
Remediation: {remediation}
"""


CODE_REVIEW_SYSTEM_PROMPT = """You are an expert security code reviewer with deep knowledge of:
- OWASP Top 10 vulnerabilities
- Language-specific security issues (Python, JavaScript, Java, Go, PHP, etc.)
- Secure coding practices
- Common vulnerability patterns

Your mission is to perform a comprehensive security review of the provided source code.

## REVIEW CHECKLIST

### Injection Vulnerabilities
- SQL Injection (raw queries, string concatenation)
- Command Injection (os.system, subprocess, exec)
- XSS (unescaped output, innerHTML)
- LDAP Injection
- XPath Injection
- Template Injection

### Authentication & Session
- Hardcoded credentials
- Weak password requirements
- Insecure session management
- Missing authentication
- Broken authentication logic

### Cryptography
- Weak algorithms (MD5, SHA1 for passwords, DES)
- Hardcoded keys/secrets
- Insecure random number generation
- Missing encryption for sensitive data

### Data Exposure
- Sensitive data in logs
- Exposed API keys/secrets
- PII handling issues
- Insufficient data protection

### Access Control
- Missing authorization checks
- IDOR vulnerabilities
- Path traversal
- Privilege escalation

### Configuration & Dependencies
- Debug mode in production
- Exposed sensitive endpoints
- Outdated/vulnerable dependencies
- Insecure defaults

## METHODOLOGY

1. First, understand the codebase structure using list_files
2. Identify the technology stack and frameworks
3. Search for common vulnerability patterns
4. Read and analyze suspicious files
5. Report each finding using report_finding

## OUTPUT

For each vulnerability found, use the report_finding tool with:
- Clear, specific title
- Accurate severity assessment
- Vulnerable code location with line numbers
- Evidence (the actual vulnerable code)
- Specific remediation steps
- CWE identifier when applicable

Be thorough and systematic. Check ALL files. Don't stop until you've reviewed the entire codebase or exhausted the step limit.

Severity Guidelines:
- CRITICAL: Remote code execution, authentication bypass, hardcoded admin credentials
- HIGH: SQL injection, XSS, SSRF, path traversal with file read
- MEDIUM: Information disclosure, weak cryptography, missing security headers
- LOW: Best practice violations, minor information leaks
- INFO: Observations and recommendations"""


class CodeReviewAgent(BaseSecurityAgent):
    """
    AI-powered source code security reviewer.

    Performs comprehensive security analysis including:
    - Static analysis for vulnerability patterns
    - Dependency checking
    - Secret detection
    - Configuration review

    Usage:
        agent = CodeReviewAgent(target_path="/path/to/code")
        result = await agent.run()
        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
    """

    def __init__(
        self,
        target_path: str,
        config: Optional[AgentConfig] = None,
        focus_areas: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
    ):
        """
        Initialize the code review agent.

        Args:
            target_path: Path to the code directory to review
            config: Agent configuration
            focus_areas: Specific areas to focus on (e.g., ["authentication", "sql"])
            exclude_patterns: File patterns to exclude (e.g., ["*.test.js", "node_modules/*"])
        """
        super().__init__(config)
        self.target_path = Path(target_path).resolve()
        self.focus_areas = focus_areas or []
        self.exclude_patterns = exclude_patterns or [
            "node_modules/*", "venv/*", ".venv/*", "__pycache__/*",
            "*.min.js", "*.bundle.js", "dist/*", "build/*"
        ]

        if not self.target_path.exists():
            raise ValueError(f"Target path does not exist: {target_path}")

    def get_system_prompt(self) -> str:
        """Get the code review system prompt."""
        prompt = CODE_REVIEW_SYSTEM_PROMPT

        # Add focus areas if specified
        if self.focus_areas:
            prompt += f"\n\n## FOCUS AREAS\nPrioritize checking for: {', '.join(self.focus_areas)}"

        return prompt

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get tools available for code review."""
        return [
            {
                "name": "read_file",
                "description": "Read the contents of a source code file",
                "parameters": {
                    "file_path": {"type": "string", "description": "Path to the file to read"}
                },
                "required": ["file_path"]
            },
            {
                "name": "list_files",
                "description": "List files in a directory with optional filtering by extension",
                "parameters": {
                    "directory": {"type": "string", "description": "Directory path to list"},
                    "extension": {"type": "string", "description": "Optional file extension filter"}
                },
                "required": ["directory"]
            },
            {
                "name": "search_code",
                "description": "Search for a regex pattern in code files",
                "parameters": {
                    "directory": {"type": "string", "description": "Directory to search in"},
                    "pattern": {"type": "string", "description": "Regex pattern to search for"},
                    "file_extension": {"type": "string", "description": "Optional file extension filter"}
                },
                "required": ["directory", "pattern"]
            },
            {
                "name": "analyze_dependencies",
                "description": "Analyze project dependencies for known vulnerabilities",
                "parameters": {
                    "directory": {"type": "string", "description": "Project directory"}
                },
                "required": ["directory"]
            },
            {
                "name": "report_finding",
                "description": "Report a security vulnerability finding",
                "parameters": {
                    "title": {"type": "string", "description": "Title of the vulnerability"},
                    "severity": {"type": "string", "description": "Severity: critical, high, medium, low, info"},
                    "category": {"type": "string", "description": "Vulnerability category"},
                    "description": {"type": "string", "description": "Detailed description"},
                    "evidence": {"type": "string", "description": "Code snippet or evidence"},
                    "location": {"type": "string", "description": "File path and line number"},
                    "remediation": {"type": "string", "description": "How to fix"},
                    "cwe_id": {"type": "string", "description": "CWE identifier"}
                },
                "required": ["title", "severity", "category", "description", "evidence", "location", "remediation"]
            }
        ]

    async def run(self, initial_message: Optional[str] = None) -> AgentResult:
        """
        Run the code review.

        Args:
            initial_message: Optional additional instructions

        Returns:
            AgentResult with all security findings
        """
        # Build the initial message
        message = f"""Perform a comprehensive security code review of: {self.target_path}

Start by listing the files to understand the project structure, then systematically review each file for security vulnerabilities. Focus on:
1. Critical security issues first
2. Common vulnerability patterns
3. Secure coding best practices

{initial_message or ''}

Begin the review now."""

        return await super().run(message)

    async def quick_scan(self) -> AgentResult:
        """
        Perform a quick security scan focusing on high-priority patterns.

        Returns:
            AgentResult with findings from pattern-based scanning
        """
        # Use a reduced step limit for quick scan
        original_max_steps = self.config.max_steps
        self.config.max_steps = min(30, original_max_steps)

        try:
            message = f"""Perform a QUICK security scan of: {self.target_path}

Focus on HIGH PRIORITY patterns only:
1. Search for hardcoded secrets (passwords, API keys, tokens)
2. Search for SQL query construction
3. Search for command execution functions
4. Check dependency files for outdated packages

Do not read every file - use search_code to find suspicious patterns quickly.
Limit to finding the most critical issues."""

            return await super().run(message)
        finally:
            self.config.max_steps = original_max_steps
