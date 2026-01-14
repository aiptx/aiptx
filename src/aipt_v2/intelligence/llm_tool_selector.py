"""
AIPT LLM-Powered Tool Selection

Uses LLM intelligence to dynamically select the most appropriate security tools
based on:
- Current scan phase
- Findings discovered so far
- Target characteristics (tech stack, WAF, etc.)
- Time/resource constraints

This replaces static tool lists with intelligent, context-aware selection.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from aipt_v2.models.findings import Finding, VulnerabilityType

logger = logging.getLogger(__name__)


# Available tools by category
AVAILABLE_TOOLS = {
    "recon": {
        "subfinder": {
            "description": "Fast subdomain discovery using passive sources",
            "best_for": ["subdomain_enumeration", "asset_discovery"],
            "speed": "fast",
            "noise": "low",
        },
        "amass": {
            "description": "Comprehensive subdomain enumeration with active/passive modes",
            "best_for": ["deep_subdomain_enum", "asset_discovery"],
            "speed": "slow",
            "noise": "medium",
        },
        "httpx": {
            "description": "HTTP probing to find live hosts and tech fingerprinting",
            "best_for": ["live_host_detection", "tech_detection"],
            "speed": "fast",
            "noise": "low",
        },
        "nmap": {
            "description": "Port scanning and service detection",
            "best_for": ["port_scan", "service_detection", "os_detection"],
            "speed": "medium",
            "noise": "high",
        },
        "whatweb": {
            "description": "Web technology fingerprinting",
            "best_for": ["tech_detection", "cms_detection"],
            "speed": "fast",
            "noise": "low",
        },
        "wafw00f": {
            "description": "Web application firewall detection",
            "best_for": ["waf_detection", "security_posture"],
            "speed": "fast",
            "noise": "low",
        },
        "waybackurls": {
            "description": "Fetch URLs from Wayback Machine archives",
            "best_for": ["url_discovery", "historical_endpoints"],
            "speed": "fast",
            "noise": "none",
        },
        "gau": {
            "description": "Fetch known URLs from AlienVault, Wayback, Common Crawl",
            "best_for": ["url_discovery", "parameter_discovery"],
            "speed": "fast",
            "noise": "none",
        },
    },
    "scan": {
        "nuclei": {
            "description": "Template-based vulnerability scanner",
            "best_for": ["known_vulns", "cve_detection", "misconfigs"],
            "speed": "fast",
            "noise": "medium",
        },
        "nikto": {
            "description": "Web server scanner for dangerous files/CGIs",
            "best_for": ["web_server_vulns", "misconfigs", "default_files"],
            "speed": "slow",
            "noise": "high",
        },
        "wpscan": {
            "description": "WordPress vulnerability scanner",
            "best_for": ["wordpress_vulns", "plugin_vulns", "theme_vulns"],
            "speed": "medium",
            "noise": "medium",
            "requires": ["wordpress"],
        },
        "sqlmap": {
            "description": "Automatic SQL injection detection and exploitation",
            "best_for": ["sqli_detection", "sqli_exploitation", "db_dump"],
            "speed": "slow",
            "noise": "high",
        },
        "ffuf": {
            "description": "Fast web fuzzer for content discovery",
            "best_for": ["dir_bruteforce", "parameter_fuzzing", "vhost_discovery"],
            "speed": "fast",
            "noise": "high",
        },
        "gobuster": {
            "description": "Directory/file & DNS busting tool",
            "best_for": ["dir_bruteforce", "dns_bruteforce"],
            "speed": "fast",
            "noise": "high",
        },
        "dirsearch": {
            "description": "Web path scanner",
            "best_for": ["dir_bruteforce", "backup_files"],
            "speed": "medium",
            "noise": "high",
        },
        "sslscan": {
            "description": "SSL/TLS configuration scanner",
            "best_for": ["ssl_vulns", "cipher_analysis", "cert_issues"],
            "speed": "fast",
            "noise": "low",
        },
        "testssl": {
            "description": "Comprehensive SSL/TLS testing",
            "best_for": ["ssl_vulns", "protocol_analysis"],
            "speed": "medium",
            "noise": "low",
        },
    },
    "exploit": {
        "sqlmap": {
            "description": "SQL injection exploitation and data extraction",
            "best_for": ["sqli_exploitation", "db_dump", "os_shell"],
            "speed": "slow",
            "noise": "high",
        },
        "commix": {
            "description": "Command injection exploitation",
            "best_for": ["command_injection", "os_shell"],
            "speed": "medium",
            "noise": "high",
        },
        "xsstrike": {
            "description": "Advanced XSS detection and exploitation",
            "best_for": ["xss_detection", "xss_exploitation", "waf_bypass"],
            "speed": "medium",
            "noise": "medium",
        },
    },
}


TOOL_SELECTION_PROMPT = """You are an expert penetration tester selecting tools for the next phase of testing.

## Current Scan State
- **Target**: {target}
- **Phase**: {phase}
- **Time Budget**: {time_budget} minutes remaining
- **Stealth Mode**: {stealth_mode}

## Findings So Far
{findings_summary}

## Detected Technologies
{tech_stack}

## WAF/Security Controls
{security_controls}

## Tools Already Run
{tools_run}

## Available Tools for {phase} Phase
{available_tools}

## Your Task
Select the 3-5 most valuable tools to run next. Consider:

1. **Gap Analysis**: What information are we missing?
2. **Finding Follow-up**: Which findings need deeper investigation?
3. **Attack Surface**: What haven't we explored yet?
4. **Efficiency**: Prioritize fast tools if time-limited
5. **Stealth**: Avoid noisy tools if stealth_mode is True
6. **Tech-Specific**: Use specialized tools for detected technologies

## Output Format (JSON)
```json
{{
    "selected_tools": [
        {{
            "name": "tool_name",
            "priority": 1,
            "reasoning": "Why this tool now",
            "expected_findings": "What we hope to discover",
            "custom_args": "Any specific arguments or targets"
        }}
    ],
    "skip_tools": [
        {{
            "name": "tool_name",
            "reason": "Why skip this tool"
        }}
    ],
    "overall_strategy": "Brief description of testing strategy"
}}
```"""


@dataclass
class ToolSelection:
    """Result of LLM tool selection."""
    name: str
    priority: int
    reasoning: str
    expected_findings: str
    custom_args: Optional[str] = None


@dataclass
class ToolSelectionResult:
    """Complete tool selection result."""
    selected_tools: list[ToolSelection]
    skip_tools: list[dict[str, str]]
    overall_strategy: str
    confidence: float = 0.9
    selected_at: datetime = field(default_factory=datetime.utcnow)

    def get_tool_names(self) -> list[str]:
        """Get just the tool names in priority order."""
        return [t.name for t in sorted(self.selected_tools, key=lambda x: x.priority)]


class LLMToolSelector:
    """
    LLM-powered intelligent tool selection.

    Uses an LLM to analyze the current scan state and select the most
    appropriate tools for the next phase of testing.

    Example:
        selector = LLMToolSelector()
        result = await selector.select_tools(
            target="https://example.com",
            phase="scan",
            findings=[...],
            tech_stack=["WordPress", "PHP", "MySQL"]
        )
        for tool in result.get_tool_names():
            print(f"Run: {tool}")
    """

    def __init__(
        self,
        llm_provider: str = "anthropic",
        llm_model: str = "claude-3-haiku-20240307",
    ):
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self._llm = None

    async def _get_llm(self):
        """Get or create LLM client."""
        if self._llm is None:
            try:
                import litellm
                self._llm = litellm
            except ImportError:
                logger.warning("litellm not installed, falling back to heuristics")
                return None
        return self._llm

    async def select_tools(
        self,
        target: str,
        phase: str,
        findings: list[Finding],
        tech_stack: list[str] = None,
        waf_detected: str = None,
        tools_already_run: list[str] = None,
        time_budget_minutes: int = 60,
        stealth_mode: bool = False,
    ) -> ToolSelectionResult:
        """
        Select the best tools for the current phase.

        Args:
            target: Target URL or domain
            phase: Current phase (recon, scan, exploit)
            findings: Findings discovered so far
            tech_stack: Detected technologies
            waf_detected: Detected WAF name
            tools_already_run: Tools that have already been executed
            time_budget_minutes: Remaining time budget
            stealth_mode: Whether to prioritize stealth over thoroughness

        Returns:
            ToolSelectionResult with prioritized tool list
        """
        llm = await self._get_llm()

        if llm is None or not self._has_api_key():
            # Fall back to heuristic selection
            return self._heuristic_selection(
                target, phase, findings, tech_stack,
                waf_detected, tools_already_run, stealth_mode
            )

        # Prepare context for LLM
        findings_summary = self._summarize_findings(findings)
        available = AVAILABLE_TOOLS.get(phase, {})
        available_str = json.dumps(available, indent=2)

        prompt = TOOL_SELECTION_PROMPT.format(
            target=target,
            phase=phase,
            time_budget=time_budget_minutes,
            stealth_mode=stealth_mode,
            findings_summary=findings_summary,
            tech_stack=", ".join(tech_stack) if tech_stack else "Not yet determined",
            security_controls=waf_detected or "None detected",
            tools_run=", ".join(tools_already_run) if tools_already_run else "None yet",
            available_tools=available_str,
        )

        try:
            response = await self._call_llm(prompt)
            return self._parse_llm_response(response)
        except Exception as e:
            logger.warning(f"LLM tool selection failed: {e}, falling back to heuristics")
            return self._heuristic_selection(
                target, phase, findings, tech_stack,
                waf_detected, tools_already_run, stealth_mode
            )

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM and get response."""
        llm = await self._get_llm()

        model_str = f"{self.llm_provider}/{self.llm_model}"
        if self.llm_provider == "anthropic" and not self.llm_model.startswith("anthropic/"):
            model_str = f"anthropic/{self.llm_model}"
        elif self.llm_provider == "openai" and not self.llm_model.startswith("openai/"):
            model_str = f"openai/{self.llm_model}"

        response = await llm.acompletion(
            model=model_str,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,
            temperature=0.3,
        )

        return response.choices[0].message.content

    def _parse_llm_response(self, response: str) -> ToolSelectionResult:
        """Parse LLM response into ToolSelectionResult."""
        try:
            # Extract JSON from response
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
            else:
                raise ValueError("No JSON found in response")

            selected = []
            for tool_data in data.get("selected_tools", []):
                selected.append(ToolSelection(
                    name=tool_data["name"],
                    priority=tool_data.get("priority", 1),
                    reasoning=tool_data.get("reasoning", ""),
                    expected_findings=tool_data.get("expected_findings", ""),
                    custom_args=tool_data.get("custom_args"),
                ))

            return ToolSelectionResult(
                selected_tools=selected,
                skip_tools=data.get("skip_tools", []),
                overall_strategy=data.get("overall_strategy", ""),
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            # Return empty result, will fall back to heuristics
            raise

    def _heuristic_selection(
        self,
        target: str,
        phase: str,
        findings: list[Finding],
        tech_stack: list[str] = None,
        waf_detected: str = None,
        tools_already_run: list[str] = None,
        stealth_mode: bool = False,
    ) -> ToolSelectionResult:
        """
        Heuristic-based tool selection when LLM is unavailable.

        Uses predefined rules based on phase and context.
        """
        tools_already_run = tools_already_run or []
        tech_stack = tech_stack or []
        selected = []

        available = AVAILABLE_TOOLS.get(phase, {})

        if phase == "recon":
            # Standard recon order
            priority_order = ["subfinder", "httpx", "whatweb", "wafw00f", "waybackurls"]
            if not stealth_mode:
                priority_order.extend(["nmap", "amass"])

        elif phase == "scan":
            priority_order = ["nuclei", "ffuf"]

            # Add tech-specific tools
            if any("wordpress" in t.lower() for t in tech_stack):
                priority_order.insert(0, "wpscan")

            # Add SQLi tools if we found potential injection points
            sqli_findings = [f for f in findings if f.vuln_type == VulnerabilityType.SQL_INJECTION]
            if sqli_findings:
                priority_order.insert(0, "sqlmap")

            if not stealth_mode:
                priority_order.extend(["nikto", "gobuster", "sslscan"])

        elif phase == "exploit":
            priority_order = []

            # Select exploit tools based on findings
            for finding in findings:
                if finding.vuln_type == VulnerabilityType.SQL_INJECTION:
                    if "sqlmap" not in priority_order:
                        priority_order.append("sqlmap")
                elif finding.vuln_type == VulnerabilityType.COMMAND_INJECTION:
                    if "commix" not in priority_order:
                        priority_order.append("commix")
                elif finding.vuln_type in [VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED]:
                    if "xsstrike" not in priority_order:
                        priority_order.append("xsstrike")

        else:
            priority_order = list(available.keys())[:5]

        # Build selection result
        priority = 1
        for tool_name in priority_order:
            if tool_name in tools_already_run:
                continue
            if tool_name not in available:
                continue

            tool_info = available[tool_name]
            selected.append(ToolSelection(
                name=tool_name,
                priority=priority,
                reasoning=f"Standard {phase} phase tool: {tool_info['description']}",
                expected_findings=f"Discover {', '.join(tool_info['best_for'][:2])}",
            ))
            priority += 1

            if len(selected) >= 5:
                break

        return ToolSelectionResult(
            selected_tools=selected,
            skip_tools=[],
            overall_strategy=f"Heuristic {phase} phase tool selection",
            confidence=0.7,
        )

    def _summarize_findings(self, findings: list[Finding]) -> str:
        """Summarize findings for LLM context."""
        if not findings:
            return "No findings discovered yet."

        # Count by severity
        by_severity = {}
        for f in findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # Count by type
        by_type = {}
        for f in findings:
            vtype = f.vuln_type.value
            by_type[vtype] = by_type.get(vtype, 0) + 1

        lines = [
            f"Total findings: {len(findings)}",
            f"By severity: {by_severity}",
            f"By type: {by_type}",
            "",
            "Notable findings:",
        ]

        # Add top 5 most severe
        sorted_findings = sorted(findings, key=lambda f: f.severity, reverse=True)
        for f in sorted_findings[:5]:
            lines.append(f"- [{f.severity.value}] {f.vuln_type.value}: {f.title} at {f.url}")

        return "\n".join(lines)

    def _has_api_key(self) -> bool:
        """Check if API key is available."""
        if self.llm_provider == "anthropic":
            return bool(os.getenv("ANTHROPIC_API_KEY"))
        if self.llm_provider == "openai":
            return bool(os.getenv("OPENAI_API_KEY"))
        return False
