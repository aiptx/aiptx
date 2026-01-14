"""
Security Agent - Main coordinator for AI-powered security testing.

This is the primary entry point for AI-driven security assessments.
It can coordinate multiple specialized agents or perform comprehensive
testing on its own.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional

import structlog

from aipt_v2.skills.agents.base import (
    AgentConfig,
    AgentResult,
    BaseSecurityAgent,
    Finding,
    Severity,
)
from aipt_v2.skills.prompts import SkillPrompts, VULNERABILITY_PROMPTS

logger = structlog.get_logger()


SECURITY_AGENT_SYSTEM_PROMPT = """You are an elite AI security testing agent with expertise across:
- Web application security (OWASP Top 10)
- API security (OWASP API Top 10)
- Source code security review
- Network security assessment
- Cloud security

Your mission is to perform comprehensive security testing and discover vulnerabilities.

## CAPABILITIES

1. **Web Testing**: XSS, SQLi, SSRF, RCE, authentication bypass
2. **API Testing**: BOLA, BFLA, injection, mass assignment
3. **Code Review**: Static analysis, secret detection, dependency scanning
4. **Configuration**: Security headers, TLS, misconfigurations

## TESTING PHILOSOPHY

- Be thorough and systematic
- Test ALL inputs and endpoints
- Use multiple payloads and techniques
- Document everything with evidence
- Prioritize critical vulnerabilities

## SEVERITY GUIDELINES

- **CRITICAL**: Remote code execution, authentication bypass, admin access
- **HIGH**: SQL injection, XSS (stored), sensitive data exposure
- **MEDIUM**: XSS (reflected), CSRF, information disclosure
- **LOW**: Missing headers, verbose errors, minor issues
- **INFO**: Best practice recommendations

## OUTPUT FORMAT

For each finding, provide:
- Clear title describing the issue
- Accurate severity rating
- Detailed description with impact
- Steps to reproduce with payloads
- Evidence (requests/responses/code)
- Specific remediation steps

Continue testing until exhausted or stopped."""


class SecurityAgent(BaseSecurityAgent):
    """
    Main AI security agent that coordinates comprehensive testing.

    This is the primary interface for AI-powered security assessments.
    It can:
    - Perform standalone security testing
    - Coordinate multiple specialized agents
    - Combine results from different testing approaches

    Usage:
        # Standalone testing
        agent = SecurityAgent(target="https://example.com")
        result = await agent.run()

        # Coordinated testing
        agent = SecurityAgent(target="https://example.com")
        result = await agent.run_full_assessment()
    """

    def __init__(
        self,
        target: str,
        config: Optional[AgentConfig] = None,
        test_types: Optional[List[str]] = None,
        credentials: Optional[Dict[str, str]] = None
    ):
        """
        Initialize the security agent.

        Args:
            target: Target URL, path, or identifier to test
            config: Agent configuration
            test_types: List of test types to perform (web, api, code)
            credentials: Authentication credentials
        """
        super().__init__(config)
        self.target = target
        self.test_types = test_types or ["web"]
        self.credentials = credentials or {}

    def get_system_prompt(self) -> str:
        """Get the security agent system prompt."""
        # Build combined prompt from selected vulnerability types
        prompts = SkillPrompts()

        # Get vulnerability-specific prompts based on test types
        vuln_prompts = []
        if "web" in self.test_types:
            for vid in ["sqli", "xss", "ssrf", "rce"]:
                if vid in VULNERABILITY_PROMPTS:
                    vuln_prompts.append(VULNERABILITY_PROMPTS[vid].system_prompt[:500])

        combined = SECURITY_AGENT_SYSTEM_PROMPT

        if vuln_prompts:
            combined += "\n\n## VULNERABILITY EXPERTISE\n\n"
            combined += "\n---\n".join(vuln_prompts)

        return combined

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get tools for security testing."""
        # Import tools from specialized agents
        from aipt_v2.skills.agents.base import get_all_tools

        tools = []

        # Add appropriate tools based on test types
        if "web" in self.test_types:
            tools.extend([
                {
                    "name": "fetch_page",
                    "description": "Fetch a web page and analyze its content",
                    "parameters": {
                        "url": {"type": "string", "description": "URL to fetch"},
                        "headers": {"type": "object", "description": "Optional headers"},
                        "method": {"type": "string", "description": "HTTP method"}
                    },
                    "required": ["url"]
                },
                {
                    "name": "test_xss",
                    "description": "Test for XSS vulnerabilities",
                    "parameters": {
                        "url": {"type": "string"},
                        "param": {"type": "string"},
                        "method": {"type": "string"}
                    },
                    "required": ["url", "param"]
                },
                {
                    "name": "test_sqli",
                    "description": "Test for SQL injection",
                    "parameters": {
                        "url": {"type": "string"},
                        "param": {"type": "string"},
                        "method": {"type": "string"}
                    },
                    "required": ["url", "param"]
                },
            ])

        if "api" in self.test_types:
            tools.extend([
                {
                    "name": "http_request",
                    "description": "Send an HTTP request to test an API endpoint",
                    "parameters": {
                        "method": {"type": "string"},
                        "url": {"type": "string"},
                        "headers": {"type": "object"},
                        "body": {"type": "string"},
                        "params": {"type": "object"}
                    },
                    "required": ["method", "url"]
                },
            ])

        if "code" in self.test_types:
            tools.extend([
                {
                    "name": "read_file",
                    "description": "Read a source code file",
                    "parameters": {
                        "file_path": {"type": "string"}
                    },
                    "required": ["file_path"]
                },
                {
                    "name": "search_code",
                    "description": "Search for patterns in code",
                    "parameters": {
                        "directory": {"type": "string"},
                        "pattern": {"type": "string"},
                        "file_extension": {"type": "string"}
                    },
                    "required": ["directory", "pattern"]
                },
            ])

        # Always include reporting tool
        tools.append({
            "name": "report_finding",
            "description": "Report a security vulnerability finding",
            "parameters": {
                "title": {"type": "string"},
                "severity": {"type": "string"},
                "category": {"type": "string"},
                "description": {"type": "string"},
                "evidence": {"type": "string"},
                "location": {"type": "string"},
                "remediation": {"type": "string"},
                "cwe_id": {"type": "string"}
            },
            "required": ["title", "severity", "category", "description", "evidence", "location", "remediation"]
        })

        return tools

    async def run(self, initial_message: Optional[str] = None) -> AgentResult:
        """
        Run security testing.

        Args:
            initial_message: Optional additional instructions

        Returns:
            AgentResult with findings
        """
        message = f"""Perform comprehensive security testing on: {self.target}

Test Types: {', '.join(self.test_types)}

{f'Authentication available: {list(self.credentials.keys())}' if self.credentials else 'No authentication provided'}

Begin testing now. Be thorough and systematic.

{initial_message or ''}"""

        return await super().run(message)

    async def run_full_assessment(self) -> Dict[str, AgentResult]:
        """
        Run a full security assessment using specialized agents.

        This coordinates multiple specialized agents for comprehensive testing.

        Returns:
            Dictionary of results from each agent type
        """
        results = {}

        # Run tests in parallel where possible
        tasks = []

        if "web" in self.test_types:
            from aipt_v2.skills.agents.web_pentest import WebPentestAgent
            web_agent = WebPentestAgent(target=self.target, config=self.config)
            tasks.append(("web", web_agent.run()))

        if "api" in self.test_types:
            from aipt_v2.skills.agents.api_tester import APITestAgent
            api_agent = APITestAgent(base_url=self.target, config=self.config)
            tasks.append(("api", api_agent.run()))

        if "code" in self.test_types:
            from aipt_v2.skills.agents.code_review import CodeReviewAgent
            code_agent = CodeReviewAgent(target_path=self.target, config=self.config)
            tasks.append(("code", code_agent.run()))

        # Execute all agents
        for name, task in tasks:
            try:
                result = await task
                results[name] = result
                logger.info(f"{name} testing complete", findings=len(result.findings))
            except Exception as e:
                logger.error(f"{name} testing failed", error=str(e))
                results[name] = AgentResult(success=False, errors=[str(e)])

        return results

    def combine_results(self, results: Dict[str, AgentResult]) -> AgentResult:
        """
        Combine results from multiple agents into a single result.

        Args:
            results: Dictionary of results from run_full_assessment

        Returns:
            Combined AgentResult
        """
        all_findings = []
        all_errors = []
        total_time = 0
        total_steps = 0
        total_tokens = 0

        for name, result in results.items():
            all_findings.extend(result.findings)
            all_errors.extend([f"[{name}] {e}" for e in result.errors])
            total_time += result.execution_time
            total_steps += result.total_steps
            total_tokens += result.tokens_used

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return AgentResult(
            success=len(all_errors) == 0,
            findings=all_findings,
            errors=all_errors,
            execution_time=total_time,
            total_steps=total_steps,
            tokens_used=total_tokens,
            model_used=self.config.model
        )
