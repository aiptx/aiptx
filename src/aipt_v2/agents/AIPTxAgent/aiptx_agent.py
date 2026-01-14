"""
AIPT AIPTxAgent - Main penetration testing agent

This is the primary agent that orchestrates penetration testing activities.
It uses the BaseAgent infrastructure with security-focused tools and prompts.
"""

import asyncio
import logging
from typing import Any, Optional, Dict

from aipt_v2.agents.base import BaseAgent
from aipt_v2.agents.ptt import PTT, TaskStatus
from aipt_v2.llm.config import LLMConfig


logger = logging.getLogger(__name__)


class AIPTxAgent(BaseAgent):
    """
    AIPTxAgent - AI-powered penetration testing agent.

    This agent performs autonomous security testing using a Think-Select-Execute-Learn loop:
    1. THINK: Analyze current state and decide next action
    2. SELECT: Choose appropriate security tools via RAG
    3. EXECUTE: Run tools and capture output
    4. LEARN: Extract findings, update PTT, decide next phase

    Features:
    - Multi-phase pentest tracking (recon, enum, exploit, post, report)
    - RAG-based tool selection with 50+ security tools
    - CVE intelligence with CVSS+EPSS+POC scoring
    - Docker sandbox for isolated tool execution
    - Browser automation for web application testing
    - Proxy interception for traffic analysis
    """

    agent_name = "AIPTxAgent"
    max_iterations = 300

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize AIPTxAgent.

        Args:
            config: Agent configuration with:
                - llm_config: LLMConfig instance
                - max_iterations: Maximum agent loop iterations
                - non_interactive: Run without user interaction
                - local_sources: Local source directories to mount
        """
        # Ensure llm_config is provided
        if "llm_config" not in config:
            config["llm_config"] = LLMConfig()

        super().__init__(config)

        # Initialize PTT for tracking pentest progress
        self.ptt = PTT()

        # Store scan configuration
        self.scan_config: Optional[Dict[str, Any]] = None
        self.targets_info: list[Dict[str, Any]] = []

        # Results storage
        self.findings: list[Dict[str, Any]] = []
        self.vulnerabilities: list[Dict[str, Any]] = []

    async def execute_scan(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a penetration test scan.

        Args:
            scan_config: Scan configuration with:
                - scan_id: Unique scan identifier
                - targets: List of target info dicts
                - user_instructions: Optional user instructions
                - run_name: Name for this run

        Returns:
            Dict with scan results including findings and vulnerabilities
        """
        self.scan_config = scan_config
        self.targets_info = scan_config.get("targets", [])

        # Build the task prompt
        task = self._build_task_prompt(scan_config)

        # Initialize PTT for first target
        if self.targets_info:
            first_target = self.targets_info[0].get("original", "unknown")
            self.ptt.initialize(first_target)

        logger.info(f"Starting penetration test scan: {scan_config.get('scan_id', 'unknown')}")

        try:
            # Run the agent loop
            result = await self.agent_loop(task)

            # Compile final results
            final_result = {
                "success": True,
                "scan_id": scan_config.get("scan_id"),
                "findings": self.findings,
                "vulnerabilities": self.vulnerabilities,
                "ptt_summary": self.ptt.get_summary() if self.ptt.target else {},
                "agent_summary": self.state.get_execution_summary(),
            }

            return final_result

        except asyncio.CancelledError:
            logger.warning("Scan was cancelled")
            return {
                "success": False,
                "error": "Scan was cancelled",
                "scan_id": scan_config.get("scan_id"),
            }
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_id": scan_config.get("scan_id"),
            }

    def _build_task_prompt(self, scan_config: Dict[str, Any]) -> str:
        """Build the initial task prompt for the agent."""
        targets = scan_config.get("targets", [])
        user_instructions = scan_config.get("user_instructions", "")

        # Build target description
        if len(targets) == 1:
            target_desc = targets[0].get("original", "unknown target")
            target_type = targets[0].get("type", "unknown")
        else:
            target_desc = f"{len(targets)} targets"
            target_type = "multiple"

        task = f"""You are an AI penetration testing agent. Your mission is to perform a comprehensive security assessment on: {target_desc}

Target Type: {target_type}
"""

        if len(targets) == 1:
            details = targets[0].get("details", {})
            if details:
                task += f"Target Details: {details}\n"

        if user_instructions:
            task += f"\nUser Instructions: {user_instructions}\n"

        task += """
Your objectives:
1. RECONNAISSANCE: Gather information about the target (ports, services, technologies)
2. ENUMERATION: Identify potential attack vectors and vulnerabilities
3. EXPLOITATION: Safely test identified vulnerabilities (do not cause damage)
4. DOCUMENTATION: Record all findings with severity and remediation advice

Guidelines:
- Follow responsible disclosure practices
- Document all findings clearly
- Prioritize high-impact vulnerabilities
- Stay within authorized scope
- Use appropriate tools for each phase

Begin your security assessment now. Start with reconnaissance to understand the target.
"""

        return task

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the scan results."""
        self.findings.append(finding)

        # Also track in PTT
        if self.ptt.target:
            phase = finding.get("phase", self.ptt.current_phase)
            self.ptt.add_findings(phase, [finding])

    def add_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Add a vulnerability to the scan results."""
        self.vulnerabilities.append(vulnerability)

        # Also add as finding
        self.add_finding({
            **vulnerability,
            "type": "vulnerability",
        })

        # Notify tracer if available
        from aipt_v2.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer and hasattr(tracer, "report_vulnerability"):
            tracer.report_vulnerability(
                report_id=vulnerability.get("id", "VULN"),
                title=vulnerability.get("title", "Unknown Vulnerability"),
                content=vulnerability.get("description", ""),
                severity=vulnerability.get("severity", "info"),
            )

    def get_ptt_summary(self) -> str:
        """Get PTT progress summary for the LLM."""
        if self.ptt.target:
            return self.ptt.to_prompt()
        return "No PTT initialized"


# Backwards compatibility alias
StrixAgent = AIPTxAgent
