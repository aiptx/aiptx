"""
AIPTX Coordinator Agent - Multi-Agent Orchestration

The Coordinator agent:
- Analyzes targets to determine scan strategy
- Spawns specialized agents based on target profile
- Coordinates findings and validation
- Aggregates results into unified report

This is the "brain" of the multi-agent architecture.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

from aipt_v2.agents.shared.message_bus import (
    MessageBus,
    AgentMessage,
    MessageType,
    MessagePriority,
    get_message_bus,
)
from aipt_v2.agents.shared.finding_repository import (
    FindingRepository,
    Finding,
    FindingSeverity,
    FindingStatus,
    get_finding_repository,
)
from aipt_v2.agents.shared.agent_pool import AgentPool, AgentResult
from aipt_v2.validation import (
    PoCValidator,
    ValidatorConfig,
    ValidationResult,
    ValidationStatus,
)

logger = logging.getLogger(__name__)


class TargetType(str, Enum):
    """Types of targets that can be scanned."""
    WEB_APP = "web_app"         # Traditional web application
    API = "api"                 # REST/GraphQL API
    SPA = "spa"                 # Single-page application
    GITHUB_REPO = "github_repo" # Source code repository
    LOCAL_DIR = "local_dir"     # Local source directory
    WEBSOCKET = "websocket"     # WebSocket application
    GRAPHQL = "graphql"         # GraphQL API


@dataclass
class TargetProfile:
    """Profile of a scan target after analysis."""
    url: str
    target_type: TargetType
    technologies: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    has_websocket: bool = False
    has_graphql: bool = False
    has_api: bool = False
    has_forms: bool = False
    auth_required: bool = False
    source_path: Optional[str] = None
    endpoints: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanStrategy:
    """Scan strategy generated for a target."""
    agents_to_spawn: list[str]
    priority_order: list[str]
    max_concurrent: int = 5
    timeout: int = 3600
    enable_poc_validation: bool = True
    custom_config: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    """Final scan result from the coordinator."""
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: list[Finding] = field(default_factory=list)
    validated_findings: list[Finding] = field(default_factory=list)
    false_positives: list[Finding] = field(default_factory=list)
    agent_results: list[AgentResult] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)
    validation_statistics: dict = field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None

    @property
    def confirmation_rate(self) -> float:
        """Calculate the PoC confirmation rate."""
        total = len(self.validated_findings) + len(self.false_positives)
        if total == 0:
            return 0.0
        return len(self.validated_findings) / total

    @property
    def critical_findings(self) -> list[Finding]:
        """Get validated critical findings."""
        return [
            f for f in self.validated_findings
            if f.severity == FindingSeverity.CRITICAL
        ]

    @property
    def high_findings(self) -> list[Finding]:
        """Get validated high severity findings."""
        return [
            f for f in self.validated_findings
            if f.severity == FindingSeverity.HIGH
        ]


class CoordinatorAgent:
    """
    Main orchestration agent for multi-agent collaboration.

    The Coordinator:
    1. Analyzes target to determine type and features
    2. Creates scan strategy
    3. Spawns specialized agents
    4. Coordinates findings and validation
    5. Produces unified report

    Usage:
        coordinator = CoordinatorAgent(target="https://example.com")
        result = await coordinator.run()
    """

    def __init__(
        self,
        target: str,
        source_path: Optional[str] = None,
        config: Optional[dict] = None,
        message_bus: Optional[MessageBus] = None,
        finding_repository: Optional[FindingRepository] = None,
    ):
        """
        Initialize coordinator.

        Args:
            target: Target URL or path
            source_path: Optional source code path for SAST
            config: Optional configuration overrides
            message_bus: Message bus (uses global if None)
            finding_repository: Finding repository (uses global if None)
        """
        self.target = target
        self.source_path = source_path
        self.config = config or {}
        self._message_bus = message_bus or get_message_bus()
        self._finding_repository = finding_repository or get_finding_repository()
        self._agent_pool = AgentPool(
            max_concurrent=self.config.get("max_concurrent", 5),
            timeout=self.config.get("timeout", 3600),
        )
        self._target_profile: Optional[TargetProfile] = None
        self._scan_strategy: Optional[ScanStrategy] = None
        self._started_at: Optional[datetime] = None
        self._subscriptions: list[str] = []

    async def run(self) -> ScanResult:
        """
        Execute the coordinated multi-agent scan.

        Returns:
            ScanResult with all findings and statistics
        """
        self._started_at = datetime.now()
        result = ScanResult(
            target=self.target,
            started_at=self._started_at,
        )

        try:
            # Start message bus
            await self._message_bus.start()
            await self._subscribe_to_messages()

            # Phase 1: Analyze target
            logger.info(f"[Coordinator] Analyzing target: {self.target}")
            self._target_profile = await self.analyze_target()

            # Phase 2: Generate strategy
            logger.info(f"[Coordinator] Generating scan strategy")
            self._scan_strategy = await self.generate_strategy(self._target_profile)

            # Phase 3: Spawn and run agents
            logger.info(f"[Coordinator] Spawning {len(self._scan_strategy.agents_to_spawn)} agents")
            agents = await self.spawn_agents(self._scan_strategy)

            # Phase 4: Run agents
            async def on_progress(status):
                logger.info(
                    f"[Coordinator] Progress: {status['completed']}/{status['total_agents']} "
                    f"agents complete, {status['running']} running"
                )

            agent_results = await self._agent_pool.run_all(
                progress_callback=on_progress
            )
            result.agent_results = agent_results

            # Phase 5: Collect findings
            result.findings = await self._finding_repository.get_all()

            # Phase 6: Validate findings (PoC)
            if self._scan_strategy.enable_poc_validation:
                logger.info(f"[Coordinator] Validating findings with PoC")
                validated, false_pos, val_stats = await self._validate_findings_with_stats(
                    result.findings
                )
                result.validated_findings = validated
                result.false_positives = false_pos
                result.validation_statistics = val_stats
            else:
                result.validated_findings = result.findings

            # Phase 7: Detect attack chains
            result.attack_chains = await self._detect_attack_chains(result.findings)

            # Phase 8: Generate statistics
            result.statistics = await self._generate_statistics(result)

            result.completed_at = datetime.now()
            result.success = True

            logger.info(
                f"[Coordinator] Scan complete: {len(result.validated_findings)} validated findings"
            )

        except asyncio.CancelledError:
            result.success = False
            result.error = "Scan cancelled"
            await self._agent_pool.cancel_all()
        except Exception as e:
            logger.error(f"[Coordinator] Error: {e}", exc_info=True)
            result.success = False
            result.error = str(e)
        finally:
            await self._cleanup()

        return result

    async def analyze_target(self) -> TargetProfile:
        """
        Analyze target to determine type and features.

        Returns:
            TargetProfile with detected features
        """
        profile = TargetProfile(
            url=self.target,
            target_type=TargetType.WEB_APP,
        )

        # Check if it's a local path
        import os
        if os.path.exists(self.target):
            profile.target_type = TargetType.LOCAL_DIR
            profile.source_path = self.target
            return profile

        # Check if it's a GitHub URL
        if "github.com" in self.target:
            profile.target_type = TargetType.GITHUB_REPO
            return profile

        # Analyze web target
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(self.target, timeout=15) as resp:
                    html = await resp.text()
                    headers = dict(resp.headers)

                    # Detect technologies
                    profile.technologies = self._detect_technologies(html, headers)
                    profile.frameworks = self._detect_frameworks(html, headers)

                    # Detect features
                    profile.has_websocket = self._detect_websocket(html)
                    profile.has_graphql = self._detect_graphql(html)
                    profile.has_api = self._detect_api(html)
                    profile.has_forms = self._detect_forms(html)

                    # Determine target type
                    if profile.has_graphql:
                        profile.target_type = TargetType.GRAPHQL
                    elif profile.has_websocket:
                        profile.target_type = TargetType.WEBSOCKET
                    elif self._is_spa(html):
                        profile.target_type = TargetType.SPA
                    elif profile.has_api:
                        profile.target_type = TargetType.API

        except Exception as e:
            logger.warning(f"Error analyzing target: {e}")

        # Add source path if provided
        if self.source_path:
            profile.source_path = self.source_path

        return profile

    def _detect_technologies(self, html: str, headers: dict) -> list[str]:
        """Detect technologies from HTML and headers."""
        technologies = []

        # Header detection
        if "X-Powered-By" in headers:
            technologies.append(headers["X-Powered-By"])
        if "Server" in headers:
            technologies.append(headers["Server"])

        # HTML detection
        tech_patterns = {
            "React": ["react", "__NEXT_DATA__", "data-reactroot"],
            "Vue": ["vue", "__VUE__", "v-app"],
            "Angular": ["ng-app", "ng-version", "angular"],
            "jQuery": ["jquery", "jQuery"],
            "Bootstrap": ["bootstrap"],
            "WordPress": ["wp-content", "wp-includes"],
            "Laravel": ["laravel_session"],
            "Django": ["csrfmiddlewaretoken"],
            "Express": ["express"],
        }

        html_lower = html.lower()
        for tech, patterns in tech_patterns.items():
            if any(p.lower() in html_lower for p in patterns):
                technologies.append(tech)

        return list(set(technologies))

    def _detect_frameworks(self, html: str, headers: dict) -> list[str]:
        """Detect frameworks."""
        frameworks = []

        # Check for SPA frameworks
        if "react" in html.lower() or "__NEXT_DATA__" in html:
            frameworks.append("React")
        if "vue" in html.lower() or "__VUE__" in html:
            frameworks.append("Vue")
        if "ng-app" in html or "ng-version" in html:
            frameworks.append("Angular")

        return frameworks

    def _detect_websocket(self, html: str) -> bool:
        """Detect if target uses WebSockets."""
        ws_indicators = ["websocket", "socket.io", "sockjs", "ws://", "wss://"]
        return any(ind in html.lower() for ind in ws_indicators)

    def _detect_graphql(self, html: str) -> bool:
        """Detect if target uses GraphQL."""
        gql_indicators = ["graphql", "__schema", "query {", "mutation {"]
        return any(ind in html.lower() for ind in gql_indicators)

    def _detect_api(self, html: str) -> bool:
        """Detect if target is API-focused."""
        api_indicators = ["/api/", "swagger", "openapi", "rest"]
        return any(ind in html.lower() for ind in api_indicators)

    def _detect_forms(self, html: str) -> bool:
        """Detect if target has forms."""
        return "<form" in html.lower()

    def _is_spa(self, html: str) -> bool:
        """Check if target is a Single-Page Application."""
        # SPA indicators: minimal HTML, JS-heavy, specific frameworks
        spa_indicators = [
            "__NEXT_DATA__",
            "root" in html and len(html) < 5000,  # Minimal HTML with root div
            "bundle.js",
            "app.js",
            "main.js",
        ]
        return any(
            (ind in html if isinstance(ind, str) else ind)
            for ind in spa_indicators
        )

    async def generate_strategy(self, profile: TargetProfile) -> ScanStrategy:
        """
        Generate scan strategy based on target profile.

        Args:
            profile: Target profile from analysis

        Returns:
            ScanStrategy with agents to spawn
        """
        agents = []
        priority = []

        # Always start with recon for web targets
        if profile.target_type not in [TargetType.LOCAL_DIR, TargetType.GITHUB_REPO]:
            agents.append("ReconAgent")
            priority.append("ReconAgent")

        # Add SAST if we have source code
        if profile.source_path or profile.target_type in [
            TargetType.LOCAL_DIR, TargetType.GITHUB_REPO
        ]:
            agents.append("SASTAgent")
            priority.append("SASTAgent")

        # Add DAST for web targets
        if profile.target_type in [
            TargetType.WEB_APP, TargetType.API, TargetType.SPA, TargetType.GRAPHQL
        ]:
            agents.append("DASTAgent")

        # Add WebSocket agent if needed
        if profile.has_websocket or profile.target_type == TargetType.WEBSOCKET:
            agents.append("WebSocketAgent")

        # Add business logic agent for ecommerce/forms
        if profile.has_forms or profile.has_api:
            agents.append("BusinessLogicAgent")

        # Determine concurrency
        max_concurrent = min(len(agents), self.config.get("max_concurrent", 5))

        return ScanStrategy(
            agents_to_spawn=agents,
            priority_order=priority + [a for a in agents if a not in priority],
            max_concurrent=max_concurrent,
            enable_poc_validation=self.config.get("enable_poc_validation", True),
        )

    async def spawn_agents(self, strategy: ScanStrategy) -> list[Any]:
        """
        Spawn specialized agents based on strategy.

        Args:
            strategy: Scan strategy

        Returns:
            List of spawned agents
        """
        from aipt_v2.agents.specialized import (
            ReconAgent,
            SASTAgent,
            DASTAgent,
            BusinessLogicAgent,
            WebSocketAgent,
        )
        from aipt_v2.agents.specialized.base_specialized import AgentConfig

        agent_classes = {
            "ReconAgent": ReconAgent,
            "SASTAgent": SASTAgent,
            "DASTAgent": DASTAgent,
            "BusinessLogicAgent": BusinessLogicAgent,
            "WebSocketAgent": WebSocketAgent,
        }

        agents = []

        for agent_name in strategy.agents_to_spawn:
            if agent_name not in agent_classes:
                logger.warning(f"Unknown agent: {agent_name}")
                continue

            agent_class = agent_classes[agent_name]

            config = AgentConfig(
                target=self.target,
                timeout=strategy.timeout // len(strategy.agents_to_spawn),
                custom_config={
                    "source_path": self._target_profile.source_path,
                }
            )

            agent = agent_class(
                config=config,
                message_bus=self._message_bus,
                finding_repository=self._finding_repository,
            )

            self._agent_pool.add_agent(agent)
            agents.append(agent)

            logger.info(f"[Coordinator] Spawned {agent_name}")

        return agents

    async def _validate_findings_with_stats(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding], dict]:
        """
        Validate findings with PoC execution using the PoCValidator.

        The PoCValidator attempts actual exploitation to confirm vulnerabilities,
        generating working PoC code and collecting evidence (screenshots, responses).
        Only validated findings with working exploits are marked as confirmed.

        Args:
            findings: Findings to validate

        Returns:
            Tuple of (validated_findings, false_positives, validation_statistics)
        """
        if not findings:
            return [], [], {}

        # Configure the validator based on coordinator settings
        validator_config = ValidatorConfig(
            max_concurrent=self.config.get("poc_max_concurrent", 3),
            timeout_per_finding=self.config.get("poc_timeout", 60.0),
            min_severity=self.config.get("poc_min_severity", FindingSeverity.LOW),
            skip_info=self.config.get("poc_skip_info", True),
            max_attempts=self.config.get("poc_max_attempts", 5),
            enable_browser=self.config.get("poc_enable_browser", False),
            sandbox_mode=self.config.get("poc_sandbox_mode", False),
            callback_server=self.config.get("poc_callback_server"),
        )

        # Create validator
        poc_validator = PoCValidator(config=validator_config)

        try:
            # Set status to pending validation for findings that need it
            for finding in findings:
                if finding.status == FindingStatus.NEW:
                    finding.status = FindingStatus.PENDING_VALIDATION

            # Progress callback to log validation status
            async def on_validation_progress(progress: dict):
                logger.info(
                    f"[Coordinator] PoC Validation: {progress['confirmed']}/{progress['total_validated']} "
                    f"confirmed, {progress['false_positives']} false positives"
                )

            # Run batch validation
            validation_results = await poc_validator.validate_findings(
                findings,
                progress_callback=on_validation_progress,
            )

            # Map results back to findings
            result_map = {r.finding_id: r for r in validation_results}

            validated_findings = []
            false_positives = []

            for finding in findings:
                result = result_map.get(finding.id)

                if result:
                    # Update finding with validation results
                    finding.poc = result.to_poc_info()

                    if result.validated:
                        finding.status = FindingStatus.VALIDATED
                        validated_findings.append(finding)
                        logger.info(
                            f"[Coordinator] CONFIRMED: {finding.title} "
                            f"(confidence: {result.confidence:.0%})"
                        )
                    elif result.status == ValidationStatus.FALSE_POSITIVE:
                        finding.status = FindingStatus.FALSE_POSITIVE
                        false_positives.append(finding)
                        logger.info(f"[Coordinator] FALSE POSITIVE: {finding.title}")
                    elif result.status == ValidationStatus.NEEDS_MANUAL:
                        finding.status = FindingStatus.NEEDS_MANUAL
                        validated_findings.append(finding)
                    elif result.status == ValidationStatus.SKIPPED:
                        # Keep original status for skipped findings
                        validated_findings.append(finding)
                    elif result.status == ValidationStatus.ERROR:
                        # Include findings with validation errors for manual review
                        finding.status = FindingStatus.NEEDS_MANUAL
                        validated_findings.append(finding)
                else:
                    # Finding wasn't in validation batch (e.g., already validated)
                    validated_findings.append(finding)

            # Get final statistics
            stats = poc_validator.get_statistics()
            logger.info(
                f"[Coordinator] PoC Validation Complete: "
                f"{stats['validated_findings']} confirmed, "
                f"{stats['false_positives']} false positives, "
                f"confirmation rate: {stats['confirmation_rate']:.0%}"
            )

            # Update repository with validation results
            for finding in findings:
                await self._finding_repository.mark_validated(
                    finding_id=finding.id,
                    validated=finding.poc.validated if finding.poc else False,
                    poc_info=finding.poc,
                )

            return validated_findings, false_positives, stats

        except Exception as e:
            logger.error(f"[Coordinator] PoC validation error: {e}", exc_info=True)
            # Return all findings on error (better to have unvalidated than none)
            return findings, [], {"error": str(e)}

        finally:
            await poc_validator.cleanup()

    async def _validate_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Validate findings with PoC execution (simplified interface).

        Args:
            findings: Findings to validate

        Returns:
            List of validated findings
        """
        validated, _, _ = await self._validate_findings_with_stats(findings)
        return validated

    async def _detect_attack_chains(self, findings: list[Finding]) -> list[dict]:
        """
        Detect attack chains from findings.

        Args:
            findings: All findings

        Returns:
            List of detected attack chains
        """
        chains = []

        # Group findings by target/component
        by_component = {}
        for finding in findings:
            component = finding.component or finding.url or finding.target
            if component not in by_component:
                by_component[component] = []
            by_component[component].append(finding)

        # Look for chain patterns
        for component, component_findings in by_component.items():
            # SSRF + RCE chain
            ssrf_findings = [f for f in component_findings if "ssrf" in f.vuln_type.value]
            rce_findings = [f for f in component_findings if "rce" in f.vuln_type.value]

            if ssrf_findings and rce_findings:
                chains.append({
                    "type": "ssrf_to_rce",
                    "description": "SSRF could be chained with internal service for RCE",
                    "findings": [ssrf_findings[0].id, rce_findings[0].id],
                    "severity": "critical",
                })

            # SQLi + Auth Bypass chain
            sqli_findings = [f for f in component_findings if "sqli" in f.vuln_type.value]
            auth_findings = [f for f in component_findings if "auth" in f.vuln_type.value]

            if sqli_findings and auth_findings:
                chains.append({
                    "type": "sqli_auth_bypass",
                    "description": "SQL injection could bypass authentication",
                    "findings": [sqli_findings[0].id, auth_findings[0].id],
                    "severity": "critical",
                })

        return chains

    async def _generate_statistics(self, result: ScanResult) -> dict:
        """Generate comprehensive scan statistics."""
        stats = {
            "duration_seconds": 0,
            "total_findings": len(result.findings),
            "validated_findings": len(result.validated_findings),
            "false_positives": len(result.false_positives),
            "confirmation_rate": result.confirmation_rate,
            "by_severity": {},
            "validated_by_severity": {},
            "by_type": {},
            "agents_run": len(result.agent_results),
            "agents_completed": 0,
            "agents_failed": 0,
            "attack_chains": len(result.attack_chains),
        }

        if result.completed_at and result.started_at:
            stats["duration_seconds"] = (
                result.completed_at - result.started_at
            ).total_seconds()

        # Count all findings by severity
        for finding in result.findings:
            severity = finding.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

        # Count validated findings by severity
        for finding in result.validated_findings:
            severity = finding.severity.value
            stats["validated_by_severity"][severity] = (
                stats["validated_by_severity"].get(severity, 0) + 1
            )

        # Count by type
        for finding in result.findings:
            vuln_type = finding.vuln_type.value
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1

        # Agent statistics
        for agent_result in result.agent_results:
            if agent_result.status.value == "completed":
                stats["agents_completed"] += 1
            elif agent_result.status.value == "failed":
                stats["agents_failed"] += 1

        # Add PoC validation statistics if available
        if result.validation_statistics:
            stats["poc_validation"] = result.validation_statistics

        return stats

    async def _subscribe_to_messages(self) -> None:
        """Subscribe to relevant message bus topics."""
        # Subscribe to coordination requests
        sub_id = await self._message_bus.subscribe(
            topic="coordination.request",
            callback=self._handle_coordination_request,
            subscriber_id="coordinator",
        )
        self._subscriptions.append(sub_id)

        # Subscribe to agent status updates
        sub_id = await self._message_bus.subscribe(
            topic="agent.status.*",
            callback=self._handle_agent_status,
            subscriber_id="coordinator",
        )
        self._subscriptions.append(sub_id)

    async def _handle_coordination_request(self, message: AgentMessage) -> None:
        """Handle coordination request from agents."""
        logger.debug(f"[Coordinator] Received coordination request: {message.content}")

        # Process request and respond
        request_type = message.content.get("request_type")
        response_content = {"status": "acknowledged", "request_type": request_type}

        if request_type == "recon_complete":
            # Recon is done, data is now available for other agents
            response_content["action"] = "proceed"

        # Publish response
        response = AgentMessage(
            topic=message.reply_to or f"coordination.response.{message.sender_id}",
            message_type=MessageType.COORD_RESPONSE,
            sender_id="coordinator",
            sender_name="Coordinator",
            content=response_content,
            correlation_id=message.correlation_id,
        )
        await self._message_bus.publish(response)

    async def _handle_agent_status(self, message: AgentMessage) -> None:
        """Handle agent status updates."""
        logger.debug(
            f"[Coordinator] Agent {message.sender_name}: {message.content.get('status')}"
        )

    async def _cleanup(self) -> None:
        """Cleanup coordinator resources."""
        # Unsubscribe from topics
        for sub_id in self._subscriptions:
            await self._message_bus.unsubscribe(sub_id)

        await self._message_bus.stop()


# Convenience function for simple scanning
async def scan(
    target: str,
    source_path: Optional[str] = None,
    **config,
) -> ScanResult:
    """
    Convenience function to run a coordinated scan.

    Args:
        target: Target URL or path
        source_path: Optional source code path
        **config: Additional configuration

    Returns:
        ScanResult

    Usage:
        result = await scan("https://example.com")
        for finding in result.validated_findings:
            print(finding.title)
    """
    coordinator = CoordinatorAgent(
        target=target,
        source_path=source_path,
        config=config,
    )
    return await coordinator.run()
