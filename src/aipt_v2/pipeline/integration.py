"""
AIPTX Pipeline Integration - Connect new pipeline to orchestrator

This module provides integration between the existing orchestrator and
the new findings pipeline. It can be called after orchestrator phases
to process findings through the new pipeline.

Usage:
    from aipt_v2.pipeline.integration import PipelineIntegration

    # After orchestrator run
    integration = PipelineIntegration(orchestrator)
    canonical = await integration.run_pipeline()

    # Generate reports from canonical
    report_paths = await integration.generate_reports()

Benefits:
- Preserves existing orchestrator functionality
- Adds new pipeline capabilities (normalization, dedup, verification)
- Generates canonical_findings.json for accurate analytics
- Creates reports with Confirmed/Needs Review/Suppressed sections
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

from .normalizer import FindingsNormalizer, NormalizerResult
from .deduplicator import Deduplicator, DeduplicationStats
from .verification_engine import VerificationEngine
from .persistence import (
    CanonicalFindings,
    PipelinePersistence,
    save_findings_raw,
    save_canonical_findings,
)

if TYPE_CHECKING:
    from ..orchestrator import Orchestrator

logger = logging.getLogger(__name__)


class PipelineIntegration:
    """
    Integrates the new findings pipeline with the existing orchestrator.

    This class processes orchestrator findings through:
    1. Normalization - Convert to FindingV2 format
    2. Deduplication - Remove duplicates via fingerprinting
    3. Verification - Apply category-specific verification policies
    4. Persistence - Save canonical findings to disk
    5. Reporting - Generate reports from canonical data
    """

    def __init__(
        self,
        orchestrator: "Orchestrator",
        enable_verification: bool = True,
        max_concurrent_verifications: int = 10,
    ):
        """
        Initialize pipeline integration.

        Args:
            orchestrator: The orchestrator instance with findings
            enable_verification: Whether to run verification policies
            max_concurrent_verifications: Max concurrent verification requests
        """
        self.orchestrator = orchestrator
        self.enable_verification = enable_verification
        self.max_concurrent_verifications = max_concurrent_verifications

        # Pipeline components
        self.normalizer = FindingsNormalizer()
        self.deduplicator = Deduplicator()
        self.verification_engine = VerificationEngine(
            max_concurrent=max_concurrent_verifications
        )

        # Results
        self.normalizer_result: Optional[NormalizerResult] = None
        self.dedup_stats: Optional[DeduplicationStats] = None
        self.canonical: Optional[CanonicalFindings] = None
        self.report_paths: dict[str, Path] = {}

    async def run_pipeline(self) -> CanonicalFindings:
        """
        Run the full pipeline on orchestrator findings.

        Pipeline stages:
        1. Normalize all findings to FindingV2 format
        2. Deduplicate by fingerprint
        3. Run verification policies
        4. Save canonical findings

        Returns:
            CanonicalFindings with processed findings
        """
        output_dir = Path(self.orchestrator.output_dir)
        scan_id = self.orchestrator.timestamp
        target = self.orchestrator.domain

        logger.info(f"Starting pipeline for {target} ({len(self.orchestrator.findings)} raw findings)")

        # Stage 1: Normalize findings
        logger.info("Stage 1: Normalizing findings...")
        self.normalizer_result = self.normalizer.normalize_all(
            phase_results=self.orchestrator.phase_results,
            output_dir=output_dir,
            scan_id=scan_id,
            target=target,
        )
        total_raw = len(self.normalizer_result.findings)
        logger.info(f"Normalized {total_raw} findings")

        # Stage 2: Deduplicate
        logger.info("Stage 2: Deduplicating findings...")
        deduped_findings = self.deduplicator.deduplicate(self.normalizer_result.findings)
        self.dedup_stats = self.deduplicator.get_stats()
        after_dedup = len(deduped_findings)
        logger.info(f"After deduplication: {after_dedup} findings ({total_raw - after_dedup} duplicates merged)")

        # Stage 3: Verify (if enabled)
        if self.enable_verification:
            logger.info("Stage 3: Running verification policies...")
            verified_findings = await self.verification_engine.verify_all(deduped_findings)
            verification_stats = self.verification_engine.get_stats()
            logger.info(f"Verification complete: {verification_stats.get('by_status', {})}")
        else:
            verified_findings = deduped_findings
            logger.info("Stage 3: Skipping verification (disabled)")

        # Stage 4: Save canonical findings
        logger.info("Stage 4: Saving canonical findings...")
        canonical_path = save_canonical_findings(
            findings=verified_findings,
            output_dir=output_dir,
            scan_id=scan_id,
            target=target,
            total_raw=total_raw,
            after_dedup=after_dedup,
            tool_stats={
                name: stats.__dict__ if hasattr(stats, '__dict__') else stats
                for name, stats in self.normalizer_result.tool_stats.items()
            },
            scan_started_at=datetime.fromisoformat(
                self.orchestrator.phase_results.get(
                    list(self.orchestrator.phase_results.keys())[0]
                ).started_at
            ) if self.orchestrator.phase_results else None,
            scan_completed_at=datetime.utcnow(),
        )

        # Load and store canonical
        persistence = PipelinePersistence(output_dir)
        self.canonical = persistence.load_canonical_findings()

        logger.info(f"Pipeline complete. Canonical findings saved to {canonical_path}")
        logger.info(f"Summary: {self.canonical.summary.to_dict()}")

        return self.canonical

    async def generate_reports(self) -> dict[str, Path]:
        """
        Generate reports from canonical findings.

        Returns:
            Dictionary of format -> file path
        """
        if not self.canonical:
            raise RuntimeError("Run run_pipeline() first")

        from ..reports.generator import ReportGenerator, ReportConfig

        config = ReportConfig(
            client_name=getattr(self.orchestrator.config, 'client_name', 'Client'),
            project_name=getattr(self.orchestrator.config, 'project_name', 'Security Assessment'),
            output_dir=Path(self.orchestrator.output_dir) / "reports",
            formats=["html", "json", "markdown"],
            include_evidence=True,
            include_remediation=True,
        )

        generator = ReportGenerator(config)
        self.report_paths = await generator.generate_from_canonical(self.canonical)

        logger.info(f"Generated reports: {list(self.report_paths.keys())}")
        return self.report_paths

    def get_summary(self) -> dict[str, Any]:
        """Get pipeline execution summary"""
        return {
            "target": self.orchestrator.domain,
            "scan_id": self.orchestrator.timestamp,
            "pipeline": {
                "total_raw": self.normalizer_result.total_raw_findings if self.normalizer_result else 0,
                "after_dedup": self.dedup_stats.total_output if self.dedup_stats else 0,
                "duplicates_merged": self.dedup_stats.duplicates_merged if self.dedup_stats else 0,
            },
            "canonical": self.canonical.summary.to_dict() if self.canonical else {},
            "tool_stats": {
                name: {
                    "status": stats.status.value if hasattr(stats.status, 'value') else str(stats.status),
                    "findings": stats.finding_count,
                    "error": stats.error,
                }
                for name, stats in (self.normalizer_result.tool_stats.items() if self.normalizer_result else {})
            },
            "reports": {fmt: str(path) for fmt, path in self.report_paths.items()},
        }


async def run_pipeline_standalone(
    output_dir: Path,
    target: str,
    scan_id: str,
) -> CanonicalFindings:
    """
    Run pipeline standalone on existing JSON files.

    Useful for reprocessing scan results without rerunning the scan.

    Args:
        output_dir: Directory containing scan output files
        target: Target domain
        scan_id: Scan identifier

    Returns:
        CanonicalFindings with processed findings
    """
    normalizer = FindingsNormalizer()
    deduplicator = Deduplicator()
    verification_engine = VerificationEngine()

    # Normalize from JSON files
    normalizer_result = normalizer.normalize_from_json_files(
        output_dir=output_dir,
        scan_id=scan_id,
        target=target,
    )

    # Deduplicate
    deduped = deduplicator.deduplicate(normalizer_result.findings)

    # Verify
    verified = await verification_engine.verify_all(deduped)

    # Save canonical
    canonical_path = save_canonical_findings(
        findings=verified,
        output_dir=output_dir,
        scan_id=scan_id,
        target=target,
        total_raw=normalizer_result.total_raw_findings,
        after_dedup=len(deduped),
        tool_stats={
            name: stats.__dict__ if hasattr(stats, '__dict__') else stats
            for name, stats in normalizer_result.tool_stats.items()
        },
    )

    # Load and return
    persistence = PipelinePersistence(output_dir)
    return persistence.load_canonical_findings()
