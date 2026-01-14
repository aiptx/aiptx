"""
Base Security Agent - Foundation for all AI-powered security testing agents.

Architecture inspired by multi-agent security testing systems with:
- LiteLLM integration for multi-provider LLM support (Claude, GPT, DeepSeek, etc.)
- Tool registry with XML schema for structured tool calls
- Async execution for concurrent testing
- Structured vulnerability findings output
"""

import asyncio
import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type
from pathlib import Path

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class Severity(str, Enum):
    """Vulnerability severity levels following CVSS-like classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(str, Enum):
    """OWASP Top 10 2021 aligned vulnerability categories."""
    INJECTION = "A03:2021-Injection"
    BROKEN_AUTH = "A07:2021-Auth-Failures"
    SENSITIVE_DATA = "A02:2021-Crypto-Failures"
    XXE = "A05:2021-Security-Misconfiguration"
    BROKEN_ACCESS = "A01:2021-Broken-Access-Control"
    SECURITY_MISCONFIG = "A05:2021-Security-Misconfiguration"
    XSS = "A03:2021-Injection"
    INSECURE_DESER = "A08:2021-Software-Data-Integrity"
    VULN_COMPONENTS = "A06:2021-Vulnerable-Components"
    INSUFFICIENT_LOGGING = "A09:2021-Security-Logging-Failures"
    SSRF = "A10:2021-SSRF"


@dataclass
class Finding:
    """Represents a security finding/vulnerability discovered by an agent."""
    title: str
    severity: Severity
    category: VulnCategory
    description: str
    evidence: str
    location: str  # File path, URL, or endpoint
    line_number: Optional[int] = None
    remediation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "line_number": self.line_number,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "references": self.references,
        }


@dataclass
class AgentResult:
    """Result of an agent's security testing run."""
    success: bool
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    total_steps: int = 0
    tokens_used: int = 0
    model_used: str = ""
    raw_transcript: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "execution_time": self.execution_time,
            "total_steps": self.total_steps,
            "tokens_used": self.tokens_used,
            "model_used": self.model_used,
            "summary": {
                "total": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
            }
        }


class AgentConfig(BaseModel):
    """Configuration for AI security agents."""
    # LLM Settings
    model: str = Field(default="claude-sonnet-4-20250514", description="LLM model to use")
    temperature: float = Field(default=0.7, ge=0, le=2)
    max_tokens: int = Field(default=4096, ge=1)

    # Agent Behavior
    max_steps: int = Field(default=100, description="Maximum agent steps before stopping")
    timeout: int = Field(default=600, description="Timeout in seconds")
    aggressive_mode: bool = Field(default=False, description="Enable aggressive testing")

    # Tool Settings
    enable_terminal: bool = Field(default=True)
    enable_browser: bool = Field(default=False)
    enable_http_client: bool = Field(default=True)

    # Output Settings
    verbose: bool = Field(default=False)
    save_transcript: bool = Field(default=True)


# Tool Registry for Agent Tools
_tool_registry: Dict[str, Dict[str, Any]] = {}


def register_tool(
    name: str,
    description: str,
    parameters: Dict[str, Any],
    category: str = "general"
) -> Callable:
    """Decorator to register a tool for use by agents.

    Example:
        @register_tool(
            name="run_command",
            description="Execute a shell command",
            parameters={"command": {"type": "string", "required": True}}
        )
        async def run_command(command: str) -> str:
            ...
    """
    def decorator(func: Callable) -> Callable:
        _tool_registry[name] = {
            "name": name,
            "description": description,
            "parameters": parameters,
            "category": category,
            "function": func,
        }
        return func
    return decorator


def get_tool(name: str) -> Optional[Dict[str, Any]]:
    """Get a registered tool by name."""
    return _tool_registry.get(name)


def get_all_tools(category: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Get all registered tools, optionally filtered by category."""
    if category:
        return {k: v for k, v in _tool_registry.items() if v["category"] == category}
    return _tool_registry.copy()


class BaseSecurityAgent(ABC):
    """
    Base class for all AI-powered security testing agents.

    Provides:
    - LiteLLM integration for multi-provider LLM support
    - Tool execution framework
    - Message history management
    - Structured finding extraction
    - Async execution support

    Subclasses must implement:
    - get_system_prompt(): Return the agent's system prompt
    - get_tools(): Return list of tools available to the agent
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.messages: List[Dict[str, str]] = []
        self.findings: List[Finding] = []
        self.step_count = 0
        self.tokens_used = 0
        self._start_time = 0.0
        self._stop_requested = False

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for this agent."""
        pass

    @abstractmethod
    def get_tools(self) -> List[Dict[str, Any]]:
        """Return the list of tools available to this agent."""
        pass

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Convert tools to LLM-compatible format (OpenAI function calling schema)."""
        tools = self.get_tools()
        definitions = []

        for tool in tools:
            definitions.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": {
                        "type": "object",
                        "properties": tool.get("parameters", {}),
                        "required": tool.get("required", []),
                    }
                }
            })

        return definitions

    async def _call_llm(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Call the LLM via LiteLLM."""
        import litellm

        try:
            response = await litellm.acompletion(
                model=self.config.model,
                messages=messages,
                tools=self.get_tool_definitions() if self.get_tools() else None,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )

            # Track token usage
            if hasattr(response, 'usage') and response.usage:
                self.tokens_used += response.usage.total_tokens

            return response

        except Exception as e:
            logger.error("LLM call failed", error=str(e), model=self.config.model)
            raise

    async def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute a tool and return the result."""
        tool = get_tool(tool_name)

        if not tool:
            return f"Error: Unknown tool '{tool_name}'"

        try:
            func = tool["function"]
            if asyncio.iscoroutinefunction(func):
                result = await func(**arguments)
            else:
                result = func(**arguments)
            return str(result)
        except Exception as e:
            logger.error("Tool execution failed", tool=tool_name, error=str(e))
            return f"Error executing {tool_name}: {str(e)}"

    def _extract_findings_from_response(self, content: str) -> List[Finding]:
        """Extract structured findings from LLM response."""
        findings = []

        # Look for XML-style finding blocks
        finding_pattern = r'<finding>(.*?)</finding>'
        matches = re.findall(finding_pattern, content, re.DOTALL)

        for match in matches:
            try:
                finding = self._parse_finding_xml(match)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse finding", error=str(e))

        # Also look for JSON-style findings
        json_pattern = r'```json\s*(\{[^`]*"severity"[^`]*\})\s*```'
        json_matches = re.findall(json_pattern, content, re.DOTALL)

        for match in json_matches:
            try:
                data = json.loads(match)
                if "title" in data and "severity" in data:
                    finding = Finding(
                        title=data.get("title", "Unknown"),
                        severity=Severity(data.get("severity", "info").lower()),
                        category=VulnCategory(data.get("category", VulnCategory.SECURITY_MISCONFIG.value)),
                        description=data.get("description", ""),
                        evidence=data.get("evidence", ""),
                        location=data.get("location", "Unknown"),
                        line_number=data.get("line_number"),
                        remediation=data.get("remediation", ""),
                        cwe_id=data.get("cwe_id"),
                    )
                    findings.append(finding)
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning("Failed to parse JSON finding", error=str(e))

        return findings

    def _parse_finding_xml(self, xml_content: str) -> Optional[Finding]:
        """Parse an XML-formatted finding."""
        def extract_tag(tag: str, content: str) -> str:
            pattern = f'<{tag}>(.*?)</{tag}>'
            match = re.search(pattern, content, re.DOTALL)
            return match.group(1).strip() if match else ""

        title = extract_tag("title", xml_content)
        if not title:
            return None

        severity_str = extract_tag("severity", xml_content).lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        return Finding(
            title=title,
            severity=severity,
            category=VulnCategory.SECURITY_MISCONFIG,  # Default, agent should specify
            description=extract_tag("description", xml_content),
            evidence=extract_tag("evidence", xml_content),
            location=extract_tag("location", xml_content) or "Unknown",
            remediation=extract_tag("remediation", xml_content),
            cwe_id=extract_tag("cwe", xml_content) or None,
        )

    def stop(self):
        """Request the agent to stop execution."""
        self._stop_requested = True

    async def run(self, initial_message: Optional[str] = None) -> AgentResult:
        """
        Execute the agent's security testing workflow.

        Args:
            initial_message: Optional initial user message to start the conversation

        Returns:
            AgentResult with findings and execution metadata
        """
        self._start_time = time.time()
        self._stop_requested = False
        self.messages = []
        self.findings = []
        self.step_count = 0
        self.tokens_used = 0
        errors = []

        # Initialize with system prompt
        self.messages.append({
            "role": "system",
            "content": self.get_system_prompt()
        })

        # Add initial user message if provided
        if initial_message:
            self.messages.append({
                "role": "user",
                "content": initial_message
            })

        try:
            while self.step_count < self.config.max_steps and not self._stop_requested:
                # Check timeout
                elapsed = time.time() - self._start_time
                if elapsed > self.config.timeout:
                    logger.warning("Agent timeout reached", timeout=self.config.timeout)
                    errors.append(f"Timeout after {elapsed:.1f}s")
                    break

                self.step_count += 1

                # Call LLM
                response = await self._call_llm(self.messages)
                message = response.choices[0].message

                # Extract text content
                content = message.content or ""

                # Check for findings in response
                new_findings = self._extract_findings_from_response(content)
                self.findings.extend(new_findings)

                # Add assistant response to history
                self.messages.append({
                    "role": "assistant",
                    "content": content,
                })

                # Check for tool calls
                tool_calls = getattr(message, 'tool_calls', None)

                if not tool_calls:
                    # No tool calls - check if agent is done
                    if self._is_completion_message(content):
                        logger.info("Agent completed", steps=self.step_count)
                        break
                    # Continue with next iteration if needed
                    continue

                # Execute tool calls
                for tool_call in tool_calls:
                    tool_name = tool_call.function.name
                    try:
                        arguments = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError:
                        arguments = {}

                    if self.config.verbose:
                        logger.info("Executing tool", tool=tool_name, args=arguments)

                    result = await self._execute_tool(tool_name, arguments)

                    # Add tool result to messages
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result,
                    })

        except Exception as e:
            logger.error("Agent execution failed", error=str(e))
            errors.append(str(e))

        execution_time = time.time() - self._start_time

        return AgentResult(
            success=len(errors) == 0,
            findings=self.findings,
            errors=errors,
            execution_time=execution_time,
            total_steps=self.step_count,
            tokens_used=self.tokens_used,
            model_used=self.config.model,
            raw_transcript=self.messages if self.config.save_transcript else [],
        )

    def _is_completion_message(self, content: str) -> bool:
        """Check if the message indicates the agent has completed its task."""
        completion_indicators = [
            "testing complete",
            "analysis complete",
            "scan complete",
            "review complete",
            "no more vulnerabilities",
            "all tests completed",
            "finished testing",
            "security assessment complete",
        ]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in completion_indicators)
