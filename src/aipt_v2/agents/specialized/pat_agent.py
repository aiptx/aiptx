"""
AIPTX Distributed PAT Agent

Specialized agent for distributed vulnerability scanning using PayloadsAllTheThings.

Features:
- Distributes vuln types across multiple workers
- Integrates with AgentPool for parallel execution
- Publishes findings to message bus for deduplication
- Supports coordinated scanning with other agents

Usage:
    from aipt_v2.agents.specialized.pat_agent import DistributedPATAgent, PATCoordinator

    # Single agent
    agent = DistributedPATAgent(config)
    result = await agent.run()

    # Coordinated scanning
    coordinator = PATCoordinator(max_workers=5)
    findings = await coordinator.scan_distributed(
        target_url="https://example.com/api",
        vuln_types=[VulnerabilityType.SQL_INJECTION, VulnerabilityType.XSS],
        parameters=["id", "user"],
    )
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingRepository,
    FindingSeverity,
)
from aipt_v2.agents.shared.finding_repository import VulnerabilityType as RepoVulnType
from aipt_v2.agents.shared.finding_repository import (
    get_finding_repository,
)
from aipt_v2.agents.shared.message_bus import (
    AgentMessage,
    MessageBus,
    MessagePriority,
    MessageType,
    get_message_bus,
)

from .base_specialized import (
    AgentCapability,
    AgentConfig,
    AgentProgress,
    SpecializedAgent,
)

logger = logging.getLogger(__name__)


@dataclass
class PATAgentConfig(AgentConfig):
    """Configuration specific to PAT agent."""

    # PAT-specific settings
    vuln_types: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    max_payloads_per_type: int = 100

    # Mutation settings
    enable_mutations: bool = True
    max_mutations_per_payload: int = 10

    # Validation
    auto_validate: bool = True
    collect_evidence: bool = True

    # Distributed execution
    worker_id: Optional[str] = None
    chunk_index: Optional[int] = None
    total_chunks: Optional[int] = None


class DistributedPATAgent(SpecializedAgent):
    """
    PAT scanning agent for distributed execution.

    This agent can run independently or as part of a coordinated
    distributed scan. It handles a subset of vulnerability types
    or parameters based on the worker assignment.

    Features:
    - Full PAT scanner integration
    - WAF-aware execution
    - PoC validation
    - Exploit chain building
    - Finding deduplication via message bus
    """

    name = "DistributedPATAgent"

    def __init__(
        self,
        config: PATAgentConfig,
        message_bus: Optional[MessageBus] = None,
        finding_repository: Optional[FindingRepository] = None,
    ):
        """
        Initialize distributed PAT agent.

        Args:
            config: PAT agent configuration
            message_bus: Message bus for communication
            finding_repository: Finding repository
        """
        super().__init__(config, message_bus, finding_repository)
        self.pat_config = config
        self._scanner = None
        self._findings_published = 0

    def get_capabilities(self) -> list[AgentCapability]:
        """Return supported capabilities."""
        return [
            AgentCapability.INJECTION_TESTING,
            AgentCapability.XSS_TESTING,
            AgentCapability.FUZZING,
            AgentCapability.API_TESTING,
        ]

    async def run(self) -> dict:
        """
        Execute PAT scan on assigned target/vuln_types.

        Returns:
            Dict with scan results
        """
        logger.info(f"[{self.name}] Starting distributed PAT scan")
        self._update_progress("initializing", 0)

        try:
            # Import PAT scanner (lazy to avoid circular imports)
            from aipt_v2.scanners.pat import (
                ChainEscalatingPATScanner,
                EnhancedPATScanConfig,
                VulnerabilityType,
            )

            # Convert string vuln types to enum
            vuln_types = []
            for vt_str in self.pat_config.vuln_types:
                try:
                    vuln_types.append(VulnerabilityType(vt_str))
                except ValueError:
                    logger.warning(f"Unknown vuln type: {vt_str}")

            if not vuln_types:
                # Default to common types
                vuln_types = [
                    VulnerabilityType.SQL_INJECTION,
                    VulnerabilityType.XSS,
                    VulnerabilityType.COMMAND_INJECTION,
                ]

            # Create scanner config
            scan_config = EnhancedPATScanConfig(
                target_url=self.config.target,
                parameters=self.pat_config.parameters,
                vuln_types=vuln_types,
                authorized=True,  # Authorized by coordinator
                enable_mutations=self.pat_config.enable_mutations,
                max_mutations_per_payload=self.pat_config.max_mutations_per_payload,
                auto_validate=self.pat_config.auto_validate,
                collect_evidence=self.pat_config.collect_evidence,
            )

            # Configure from auth/scope
            if self.config.auth_config:
                if "headers" in self.config.auth_config:
                    scan_config.headers = self.config.auth_config["headers"]
                if "cookies" in self.config.auth_config:
                    scan_config.cookies = self.config.auth_config["cookies"]

            if self.config.scope_config:
                scan_config.scope_patterns = self.config.scope_config.get("patterns", [])

            # Create scanner
            self._scanner = ChainEscalatingPATScanner(scan_config)

            self._update_progress("scanning", 10)

            # Execute scan with progress callback
            async def on_finding(finding):
                await self._publish_finding(finding)
                self._findings_published += 1

            result = await self._scanner.scan(on_finding=on_finding)

            self._update_progress("completed", 100)

            # Build result
            return {
                "status": "success",
                "target": self.config.target,
                "vuln_types_scanned": [vt.value for vt in vuln_types],
                "findings_count": len(result.findings),
                "findings_published": self._findings_published,
                "requests_made": result.requests_made,
                "duration_seconds": result.duration_seconds,
                "worker_id": self.pat_config.worker_id,
                "chunk_index": self.pat_config.chunk_index,
            }

        except Exception as e:
            logger.error(f"[{self.name}] Scan failed: {e}", exc_info=True)
            self._update_progress("failed", 0)
            return {
                "status": "error",
                "error": str(e),
                "worker_id": self.pat_config.worker_id,
            }

    async def _publish_finding(self, scan_finding) -> None:
        """Publish finding to message bus and repository."""
        try:
            # Convert ScanFinding to Finding for repository
            finding = Finding(
                title=scan_finding.title,
                description=scan_finding.description,
                severity=FindingSeverity(scan_finding.severity.value),
                url=scan_finding.url,
                evidence=scan_finding.evidence,
                request=scan_finding.request,
                response=scan_finding.response,
                vuln_type=self._map_vuln_type(scan_finding.template),
                tags=scan_finding.tags,
            )

            # Add to repository (handles dedup)
            await self.add_finding(finding)

            # Publish to message bus for other agents
            if self.message_bus:
                await self.message_bus.publish(
                    topic="findings.new",
                    message=AgentMessage(
                        message_type=MessageType.FINDING,
                        priority=self._severity_to_priority(scan_finding.severity.value),
                        sender=self.agent_id,
                        payload={
                            "finding_id": finding.id,
                            "title": finding.title,
                            "severity": finding.severity.value,
                            "url": finding.url,
                            "vuln_type": scan_finding.template,
                        },
                    ),
                )

            logger.debug(f"[{self.name}] Published finding: {finding.title}")

        except Exception as e:
            logger.warning(f"Failed to publish finding: {e}")

    def _map_vuln_type(self, template: str) -> Optional[RepoVulnType]:
        """Map PAT vuln type to repository vuln type."""
        mapping = {
            "sql_injection": RepoVulnType.SQLI,
            "xss": RepoVulnType.XSS,
            "command_injection": RepoVulnType.COMMAND_INJECTION,
            "ssrf": RepoVulnType.SSRF,
            "xxe": RepoVulnType.XXE,
            "lfi": RepoVulnType.LFI,
            "rfi": RepoVulnType.RFI,
            "ssti": RepoVulnType.SSTI,
            "nosql_injection": RepoVulnType.NOSQL_INJECTION,
            "path_traversal": RepoVulnType.PATH_TRAVERSAL,
            "idor": RepoVulnType.IDOR,
            "open_redirect": RepoVulnType.OPEN_REDIRECT,
            "file_upload": RepoVulnType.FILE_UPLOAD,
        }
        return mapping.get(template)

    def _severity_to_priority(self, severity: str) -> MessagePriority:
        """Map severity to message priority."""
        mapping = {
            "critical": MessagePriority.CRITICAL,
            "high": MessagePriority.HIGH,
            "medium": MessagePriority.NORMAL,
            "low": MessagePriority.LOW,
            "info": MessagePriority.LOW,
        }
        return mapping.get(severity.lower(), MessagePriority.NORMAL)

    def _update_progress(self, status: str, percent: float) -> None:
        """Update progress tracking."""
        self.progress = AgentProgress(
            agent_id=self.agent_id,
            agent_name=self.name,
            status=status,
            current_task=f"PAT scan - {status}",
            progress_percent=percent,
            findings_count=self._findings_published,
            metadata={
                "worker_id": self.pat_config.worker_id,
                "chunk_index": self.pat_config.chunk_index,
            },
        )


class PATCoordinator:
    """
    Coordinates distributed PAT scanning across multiple workers.

    Distributes vulnerability types or parameters across workers
    for parallel execution, then aggregates results.

    Usage:
        coordinator = PATCoordinator(max_workers=5)
        findings = await coordinator.scan_distributed(
            target_url="https://example.com/api",
            vuln_types=["sql_injection", "xss", "csrf", "idor"],
            parameters=["id", "user", "search"],
        )
    """

    def __init__(
        self,
        max_workers: int = 5,
        message_bus: Optional[MessageBus] = None,
        finding_repository: Optional[FindingRepository] = None,
    ):
        """
        Initialize PAT coordinator.

        Args:
            max_workers: Maximum concurrent workers
            message_bus: Message bus for communication
            finding_repository: Finding repository
        """
        self.max_workers = max_workers
        self.message_bus = message_bus or get_message_bus()
        self.finding_repository = finding_repository or get_finding_repository()
        self._workers: list[DistributedPATAgent] = []
        self._results: list[dict] = []

    async def scan_distributed(
        self,
        target_url: str,
        vuln_types: list[str],
        parameters: list[str],
        auth_config: Optional[dict] = None,
        scope_config: Optional[dict] = None,
        enable_mutations: bool = True,
        auto_validate: bool = True,
        progress_callback: Optional[Callable[[dict], None]] = None,
    ) -> list[Finding]:
        """
        Distribute PAT scanning across workers.

        Args:
            target_url: Target URL to scan
            vuln_types: Vulnerability types to test
            parameters: Parameters to test
            auth_config: Authentication configuration
            scope_config: Scope configuration
            enable_mutations: Enable payload mutations
            auto_validate: Enable PoC validation
            progress_callback: Called with progress updates

        Returns:
            List of findings (deduplicated)
        """
        logger.info(
            f"[PATCoordinator] Starting distributed scan: "
            f"{len(vuln_types)} vuln types, {self.max_workers} workers"
        )

        # Split vuln types across workers
        chunks = self._chunk_vuln_types(vuln_types)

        # Create worker configs
        worker_configs = []
        for i, chunk in enumerate(chunks):
            config = PATAgentConfig(
                target=target_url,
                vuln_types=chunk,
                parameters=parameters,
                enable_mutations=enable_mutations,
                auto_validate=auto_validate,
                auth_config=auth_config,
                scope_config=scope_config,
                worker_id=f"pat-worker-{i}",
                chunk_index=i,
                total_chunks=len(chunks),
            )
            worker_configs.append(config)

        # Execute workers in parallel
        self._workers = [
            DistributedPATAgent(
                config,
                message_bus=self.message_bus,
                finding_repository=self.finding_repository,
            )
            for config in worker_configs
        ]

        # Run with semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_workers)

        async def run_with_semaphore(worker: DistributedPATAgent):
            async with semaphore:
                result = await worker.run()
                if progress_callback:
                    progress_callback(
                        {
                            "worker_id": worker.pat_config.worker_id,
                            "status": result.get("status"),
                            "findings_count": result.get("findings_count", 0),
                        }
                    )
                return result

        tasks = [run_with_semaphore(w) for w in self._workers]
        self._results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate findings from repository (already deduplicated)
        all_findings = await self.finding_repository.get_by_url(target_url)

        # Log summary
        total_findings = len(all_findings)
        successful_workers = sum(
            1 for r in self._results if isinstance(r, dict) and r.get("status") == "success"
        )

        logger.info(
            f"[PATCoordinator] Distributed scan complete: "
            f"{successful_workers}/{len(self._workers)} workers, "
            f"{total_findings} total findings"
        )

        return all_findings

    def _chunk_vuln_types(self, vuln_types: list[str]) -> list[list[str]]:
        """Split vuln types into chunks for workers."""
        if len(vuln_types) <= self.max_workers:
            # One vuln type per worker
            return [[vt] for vt in vuln_types]

        # Distribute evenly
        chunk_size = len(vuln_types) // self.max_workers
        remainder = len(vuln_types) % self.max_workers

        chunks = []
        idx = 0
        for i in range(self.max_workers):
            size = chunk_size + (1 if i < remainder else 0)
            chunks.append(vuln_types[idx : idx + size])
            idx += size

        return [c for c in chunks if c]  # Filter empty

    def get_worker_results(self) -> list[dict]:
        """Get results from all workers."""
        return [r for r in self._results if isinstance(r, dict)]

    def get_statistics(self) -> dict:
        """Get distributed scan statistics."""
        successful = [
            r for r in self._results if isinstance(r, dict) and r.get("status") == "success"
        ]

        total_findings = sum(r.get("findings_count", 0) for r in successful)
        total_requests = sum(r.get("requests_made", 0) for r in successful)
        total_duration = sum(r.get("duration_seconds", 0) for r in successful)

        return {
            "workers_total": len(self._workers),
            "workers_successful": len(successful),
            "workers_failed": len(self._results) - len(successful),
            "total_findings": total_findings,
            "total_requests": total_requests,
            "total_duration_seconds": total_duration,
            "avg_findings_per_worker": total_findings / len(successful) if successful else 0,
        }


# Factory function for easy agent creation
def create_pat_agent(
    target: str,
    vuln_types: Optional[list[str]] = None,
    parameters: Optional[list[str]] = None,
    **kwargs,
) -> DistributedPATAgent:
    """
    Create a PAT agent with common defaults.

    Args:
        target: Target URL
        vuln_types: Vulnerability types to test
        parameters: Parameters to test
        **kwargs: Additional config options

    Returns:
        Configured DistributedPATAgent
    """
    config = PATAgentConfig(
        target=target,
        vuln_types=vuln_types
        or [
            "sql_injection",
            "xss",
            "command_injection",
            "ssrf",
        ],
        parameters=parameters or [],
        **kwargs,
    )
    return DistributedPATAgent(config)
