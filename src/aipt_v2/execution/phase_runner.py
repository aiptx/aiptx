"""
AIPTX Phase Runner
==================

Orchestrates the complete penetration testing pipeline:
RECON -> AI Checkpoint -> SCAN -> AI Checkpoint -> EXPLOIT -> AI Checkpoint -> REPORT

Integrates:
- Local tool execution
- Result collection and aggregation
- AI checkpoint analysis (Ollama)
- Phase transition decisions
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from .tool_registry import ToolRegistry, ToolConfig, ToolPhase, ToolCapability, get_registry
from .local_tool_executor import LocalToolExecutor, ExecutionBatch, ToolExecution, ProgressCallback
from .result_collector import ResultCollector, NormalizedFinding, AttackPath, FindingSeverity

logger = logging.getLogger(__name__)


class PipelineState(str, Enum):
    """State of the pipeline execution."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PhaseConfig:
    """Configuration for a single phase."""
    phase: ToolPhase
    enabled: bool = True
    tools: Optional[List[str]] = None  # Specific tools to run (None = all available)
    capabilities: Optional[Set[ToolCapability]] = None  # Required capabilities
    timeout: int = 600  # Phase timeout
    stop_on_critical: bool = False  # Stop if critical finding found
    ai_checkpoint: bool = True  # Run AI analysis after phase


@dataclass
class PipelineConfig:
    """Configuration for the complete pipeline."""
    phases: List[PhaseConfig] = field(default_factory=lambda: [
        PhaseConfig(phase=ToolPhase.RECON),
        PhaseConfig(phase=ToolPhase.SCAN),
        PhaseConfig(phase=ToolPhase.EXPLOIT, enabled=False),  # Disabled by default
    ])
    max_parallel_tools: int = 5
    ai_checkpoints_enabled: bool = True
    ollama_model: str = "mistral:7b"
    ollama_url: str = "http://localhost:11434"
    stop_on_critical: bool = False
    verbose: bool = True


@dataclass
class PhaseReport:
    """Report from a completed phase."""
    phase: ToolPhase
    state: str
    tools_run: int
    tools_failed: int
    findings_count: int
    critical_count: int
    high_count: int
    duration_seconds: float
    ai_analysis: Optional[str] = None
    recommended_actions: List[str] = field(default_factory=list)


@dataclass
class PipelineReport:
    """Final report from the complete pipeline."""
    target: str
    state: PipelineState
    start_time: datetime
    end_time: Optional[datetime]
    phases: List[PhaseReport] = field(default_factory=list)
    total_findings: int = 0
    attack_paths: List[AttackPath] = field(default_factory=list)
    summary: str = ""


class AICheckpointClient:
    """
    Client for AI checkpoint analysis using Ollama.

    Provides post-phase analysis and recommendations.
    """

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mistral:7b"):
        self.base_url = base_url
        self.model = model
        self._available: Optional[bool] = None

    async def is_available(self) -> bool:
        """Check if Ollama is available."""
        if self._available is not None:
            return self._available

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/api/version", timeout=5) as resp:
                    self._available = resp.status == 200
        except Exception:
            self._available = False

        return self._available

    async def analyze_phase(
        self,
        phase: ToolPhase,
        findings_summary: str,
        target: str,
    ) -> Dict[str, Any]:
        """
        Analyze phase results and provide recommendations.

        Args:
            phase: The completed phase
            findings_summary: Compact summary of findings
            target: Target URL/domain

        Returns:
            Dict with analysis and recommendations
        """
        if not await self.is_available():
            return self._fallback_analysis(phase, findings_summary)

        prompts = {
            ToolPhase.RECON: self._recon_prompt(findings_summary, target),
            ToolPhase.SCAN: self._scan_prompt(findings_summary, target),
            ToolPhase.EXPLOIT: self._exploit_prompt(findings_summary, target),
        }

        prompt = prompts.get(phase, "Analyze these security findings and provide recommendations.")

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                    timeout=60,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_response(data.get("response", ""))
        except Exception as e:
            logger.warning(f"AI checkpoint failed: {e}")

        return self._fallback_analysis(phase, findings_summary)

    def _recon_prompt(self, findings: str, target: str) -> str:
        return f"""You are a cybersecurity assistant helping with an AUTHORIZED penetration test. The target organization has contracted this security assessment and provided written permission.

Your role: Analyze reconnaissance findings and recommend next steps for the security assessment.

TARGET: {target} (Authorized test target)

RECONNAISSANCE FINDINGS:
{findings}

Based on these findings, provide a professional security assessment:
1. PRIORITY_TARGETS: List 3-5 highest priority areas for vulnerability assessment
2. RECOMMENDED_SCANS: Which security scan types to prioritize (e.g., web app testing, service enumeration)
3. ATTACK_SURFACE: Brief assessment of the attack surface discovered
4. NEXT_PHASE_FOCUS: What the next assessment phase should focus on

Be concise and professional. Format as key:value pairs."""

    def _scan_prompt(self, findings: str, target: str) -> str:
        return f"""You are a cybersecurity assistant helping with an AUTHORIZED penetration test. The target organization has contracted this security assessment and provided written permission.

Your role: Analyze vulnerability scan results and recommend remediation priorities and testing focus areas.

TARGET: {target} (Authorized test target)

VULNERABILITY SCAN FINDINGS:
{findings}

Based on these findings, provide a professional security assessment:
1. CRITICAL_VULNS: Most critical vulnerabilities requiring immediate attention
2. ATTACK_CHAINS: Potential attack chains that should be validated (e.g., SQLi -> Data Access -> Privilege Escalation)
3. TESTING_PRIORITY: Recommended order for further security validation
4. RISK_ASSESSMENT: Brief risk assessment for the organization

This helps the security team understand the real-world risk. Be concise. Format as key:value pairs."""

    def _exploit_prompt(self, findings: str, target: str) -> str:
        return f"""You are a cybersecurity assistant helping with an AUTHORIZED penetration test. The target organization has contracted this security assessment and provided written permission.

Your role: Analyze proof-of-concept validation results and recommend remediation actions.

TARGET: {target} (Authorized test target)

VALIDATION FINDINGS:
{findings}

Based on these findings, provide a professional security assessment:
1. VALIDATED_ISSUES: Summary of confirmed security issues
2. ACCESS_ACHIEVED: What level of access was demonstrated
3. LATERAL_MOVEMENT_RISK: Potential for lateral movement (helps prioritize remediation)
4. REMEDIATION_PRIORITY: Recommended remediation actions in order of priority
5. CLEANUP_NOTES: Any cleanup required after testing

Be concise and professional. Format as key:value pairs."""

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured format."""
        result = {
            "analysis": response,
            "recommendations": [],
            "priority_targets": [],
        }

        # Extract key sections
        lines = response.split("\n")
        current_key = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check for key:value pattern
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip().upper().replace(" ", "_")
                value = parts[1].strip()

                if key in ["PRIORITY_TARGETS", "RECOMMENDED_SCANS", "CRITICAL_VULNS"]:
                    result["priority_targets"].extend(
                        [v.strip() for v in value.split(",")]
                    )
                elif key in ["ATTACK_CHAINS", "EXPLOITATION_ORDER", "PIVOT_OPTIONS"]:
                    result["recommendations"].append(value)

        return result

    def _fallback_analysis(self, phase: ToolPhase, findings: str) -> Dict[str, Any]:
        """Rule-based fallback when AI is not available."""
        recommendations = []

        # Count severity mentions
        critical_count = findings.lower().count("critical")
        high_count = findings.lower().count("high")

        if phase == ToolPhase.RECON:
            recommendations = [
                "Run nuclei with default templates",
                "Perform directory enumeration with ffuf",
                "Check for common vulnerabilities",
            ]
            if "port" in findings.lower():
                recommendations.append("Service-specific vulnerability scanning")

        elif phase == ToolPhase.SCAN:
            if critical_count > 0 or high_count > 0:
                recommendations = [
                    f"Found {critical_count} critical, {high_count} high vulns",
                    "Prioritize critical vulnerabilities for exploitation",
                    "Verify findings before exploitation",
                ]
            else:
                recommendations = [
                    "No critical vulnerabilities found",
                    "Consider deeper scanning with custom templates",
                    "Review configuration issues",
                ]

        elif phase == ToolPhase.EXPLOIT:
            recommendations = [
                "Document successful exploitation",
                "Assess impact and access level",
                "Plan cleanup and remediation",
            ]

        return {
            "analysis": f"[Fallback Analysis] {phase.value} phase complete",
            "recommendations": recommendations,
            "priority_targets": [],
        }


class PhaseRunner:
    """
    Orchestrates the complete penetration testing pipeline.

    Manages:
    - Phase execution sequence
    - Tool selection and execution
    - AI checkpoint integration
    - Result aggregation
    - Progress reporting

    Example:
        runner = PhaseRunner(target="example.com")
        await runner.initialize()

        # Run complete pipeline
        report = await runner.run_pipeline()

        # Or run individual phases
        await runner.run_phase(ToolPhase.RECON)
        await runner.run_ai_checkpoint(ToolPhase.RECON)
        await runner.run_phase(ToolPhase.SCAN)

        # Get results
        collector = runner.get_results()
        print(collector.to_markdown())
    """

    def __init__(
        self,
        target: str,
        config: Optional[PipelineConfig] = None,
        registry: Optional[ToolRegistry] = None,
    ):
        self.target = target
        self.config = config or PipelineConfig()
        self.registry = registry or get_registry()

        self.executor = LocalToolExecutor(
            registry=self.registry,
            max_parallel=self.config.max_parallel_tools,
        )
        self.collector = ResultCollector(target)
        self.ai_client = AICheckpointClient(
            base_url=self.config.ollama_url,
            model=self.config.ollama_model,
        )

        self.state = PipelineState.IDLE
        self.current_phase: Optional[ToolPhase] = None
        self._phase_reports: Dict[ToolPhase, PhaseReport] = {}
        self._start_time: Optional[datetime] = None
        self._callbacks: List[Callable] = []

    async def initialize(self) -> None:
        """Initialize the runner and discover tools."""
        await self.executor.initialize()

        # Check AI availability
        if self.config.ai_checkpoints_enabled:
            ai_available = await self.ai_client.is_available()
            if not ai_available:
                logger.warning("Ollama not available - AI checkpoints will use fallback analysis")

    def add_progress_callback(self, callback: ProgressCallback) -> None:
        """Add a progress callback."""
        self.executor.add_callback(callback)

    # =========================================================================
    # Phase Execution
    # =========================================================================

    async def run_phase(
        self,
        phase: ToolPhase,
        config: Optional[PhaseConfig] = None,
    ) -> PhaseReport:
        """
        Run a single phase of the pipeline.

        Args:
            phase: Phase to run
            config: Optional phase-specific configuration

        Returns:
            PhaseReport with results
        """
        phase_config = config
        if not phase_config:
            phase_config = next(
                (p for p in self.config.phases if p.phase == phase),
                PhaseConfig(phase=phase)
            )

        logger.info(f"Starting phase: {phase.value}")
        self.current_phase = phase
        start_time = datetime.utcnow()

        # Select tools to run
        if phase_config.tools:
            tools = [
                self.registry.get_tool(t)
                for t in phase_config.tools
                if self.registry.is_available(t)
            ]
        elif phase_config.capabilities:
            tools = []
            for cap in phase_config.capabilities:
                tools.extend(self.registry.get_tools_by_capability(cap))
            tools = list(set(tools))  # Deduplicate
        else:
            tools = self.registry.get_tools_by_phase(phase)

        if not tools:
            logger.warning(f"No tools available for phase {phase.value}")
            return PhaseReport(
                phase=phase,
                state="skipped",
                tools_run=0,
                tools_failed=0,
                findings_count=0,
                critical_count=0,
                high_count=0,
                duration_seconds=0,
            )

        # Execute tools
        batch = await self.executor.run_phase(phase, self.target)

        # Collect results
        phase_results = self.collector.add_phase_results(phase, batch)

        # Build report
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        critical = len(phase_results.get_by_severity(FindingSeverity.CRITICAL))
        high = len(phase_results.get_by_severity(FindingSeverity.HIGH))

        report = PhaseReport(
            phase=phase,
            state="completed",
            tools_run=len(phase_results.tools_run),
            tools_failed=len(phase_results.tools_failed),
            findings_count=len(phase_results.findings),
            critical_count=critical,
            high_count=high,
            duration_seconds=duration,
        )

        # Run AI checkpoint if enabled
        if phase_config.ai_checkpoint and self.config.ai_checkpoints_enabled:
            ai_result = await self.run_ai_checkpoint(phase)
            report.ai_analysis = ai_result.get("analysis", "")
            report.recommended_actions = ai_result.get("recommendations", [])

        self._phase_reports[phase] = report

        logger.info(
            f"Phase {phase.value} complete: "
            f"{report.findings_count} findings ({critical} critical, {high} high)"
        )

        return report

    async def run_ai_checkpoint(self, phase: ToolPhase) -> Dict[str, Any]:
        """
        Run AI checkpoint analysis after a phase.

        Args:
            phase: The phase that just completed

        Returns:
            AI analysis results
        """
        # Get compact summary for LLM
        findings_summary = self.collector.to_compact_format(max_findings=30)

        result = await self.ai_client.analyze_phase(
            phase=phase,
            findings_summary=findings_summary,
            target=self.target,
        )

        logger.info(f"AI checkpoint for {phase.value}: {len(result.get('recommendations', []))} recommendations")

        return result

    # =========================================================================
    # Pipeline Execution
    # =========================================================================

    async def run_pipeline(self) -> PipelineReport:
        """
        Run the complete penetration testing pipeline.

        Returns:
            PipelineReport with all results
        """
        self.state = PipelineState.RUNNING
        self._start_time = datetime.utcnow()

        report = PipelineReport(
            target=self.target,
            state=PipelineState.RUNNING,
            start_time=self._start_time,
            end_time=None,
        )

        try:
            for phase_config in self.config.phases:
                if not phase_config.enabled:
                    logger.info(f"Skipping disabled phase: {phase_config.phase.value}")
                    continue

                phase_report = await self.run_phase(phase_config.phase, phase_config)
                report.phases.append(phase_report)

                # Check for stop conditions
                if self.config.stop_on_critical and phase_report.critical_count > 0:
                    logger.info("Critical finding detected - stopping pipeline")
                    break

            # Finalize
            report.state = PipelineState.COMPLETED
            report.end_time = datetime.utcnow()
            report.total_findings = len(self.collector.get_all_findings())
            report.attack_paths = self.collector.detect_attack_paths()
            report.summary = self._generate_summary(report)

            self.state = PipelineState.COMPLETED

        except asyncio.CancelledError:
            report.state = PipelineState.CANCELLED
            self.state = PipelineState.CANCELLED
            raise
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            report.state = PipelineState.FAILED
            self.state = PipelineState.FAILED
            raise

        return report

    def _generate_summary(self, report: PipelineReport) -> str:
        """Generate executive summary."""
        lines = [
            f"Pipeline completed for {self.target}",
            "",
            f"Phases Run: {len(report.phases)}",
            f"Total Findings: {report.total_findings}",
        ]

        # Severity breakdown
        stats = self.collector.get_statistics()
        severity_dist = stats.get("severity_distribution", {})
        lines.append(f"Critical: {severity_dist.get('critical', 0)}")
        lines.append(f"High: {severity_dist.get('high', 0)}")
        lines.append(f"Medium: {severity_dist.get('medium', 0)}")

        # Attack paths
        if report.attack_paths:
            lines.append("")
            lines.append(f"Attack Paths Identified: {len(report.attack_paths)}")
            for path in report.attack_paths[:3]:
                lines.append(f"  - {path.name} ({path.impact} impact)")

        return "\n".join(lines)

    # =========================================================================
    # Results Access
    # =========================================================================

    def get_results(self) -> ResultCollector:
        """Get the result collector with all findings."""
        return self.collector

    def get_phase_report(self, phase: ToolPhase) -> Optional[PhaseReport]:
        """Get report for a specific phase."""
        return self._phase_reports.get(phase)

    def get_all_findings(self) -> List[NormalizedFinding]:
        """Get all findings across all phases."""
        return self.collector.get_all_findings()

    def get_critical_findings(self) -> List[NormalizedFinding]:
        """Get critical and high severity findings."""
        return self.collector.get_critical_findings()

    def export_json(self) -> str:
        """Export results to JSON."""
        return self.collector.to_json()

    def export_markdown(self) -> str:
        """Export results to markdown."""
        return self.collector.to_markdown()

    # =========================================================================
    # Control
    # =========================================================================

    async def cancel(self) -> None:
        """Cancel the running pipeline."""
        self.state = PipelineState.CANCELLED
        await self.executor.cancel_all()


# ============================================================================
# Convenience Functions
# ============================================================================

async def run_quick_scan(target: str) -> PipelineReport:
    """
    Run a quick scan with default settings.

    Args:
        target: Target URL or domain

    Returns:
        PipelineReport with results
    """
    config = PipelineConfig(
        phases=[
            PhaseConfig(phase=ToolPhase.RECON, timeout=180),
            PhaseConfig(phase=ToolPhase.SCAN, timeout=300),
        ],
        max_parallel_tools=3,
    )

    runner = PhaseRunner(target, config)
    await runner.initialize()
    return await runner.run_pipeline()


async def run_full_scan(target: str, include_exploit: bool = False) -> PipelineReport:
    """
    Run a comprehensive scan.

    Args:
        target: Target URL or domain
        include_exploit: Whether to include exploitation phase

    Returns:
        PipelineReport with results
    """
    config = PipelineConfig(
        phases=[
            PhaseConfig(phase=ToolPhase.RECON, timeout=300),
            PhaseConfig(phase=ToolPhase.SCAN, timeout=600),
            PhaseConfig(phase=ToolPhase.EXPLOIT, enabled=include_exploit, timeout=600),
        ],
        max_parallel_tools=5,
        ai_checkpoints_enabled=True,
    )

    runner = PhaseRunner(target, config)
    await runner.initialize()
    return await runner.run_pipeline()
