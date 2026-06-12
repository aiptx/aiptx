"""
AIPTX Pipeline Module - Canonical Findings Processing Pipeline

This module implements the new findings pipeline:
Scanner -> Normalizer -> findings_raw.json -> Dedupe -> Verifier -> canonical_findings.json -> Reports

Components:
- FindingsNormalizer: Converts tool outputs to FindingV2 format
- Deduplicator: Smart fingerprint-based deduplication with merge
- VerificationEngine: Category-specific verification policies
- PipelinePersistence: Saves normalized and canonical findings to disk

Usage:
    from aipt_v2.pipeline import FindingsNormalizer, Deduplicator, VerificationEngine

    normalizer = FindingsNormalizer()
    raw_findings = normalizer.normalize_all(phase_results, output_dir)

    deduplicator = Deduplicator()
    deduped_findings = deduplicator.deduplicate(raw_findings)

    engine = VerificationEngine()
    verified_findings = await engine.verify_all(deduped_findings)
"""

from .deduplicator import (
    CrossTargetDeduplicator,
    DeduplicationStats,
    Deduplicator,
    generate_fingerprint,
)
from .integration import (
    PipelineIntegration,
    run_pipeline_standalone,
)
from .normalizer import (
    FindingsNormalizer,
    NormalizerResult,
    ToolNormalizer,
    ToolStatus,
)
from .persistence import (
    CanonicalFindings,
    CanonicalSummary,
    PipelinePersistence,
    ToolStatusEntry,
    load_canonical_findings,
    save_canonical_findings,
    save_findings_raw,
)
from .verification_engine import (
    VERIFICATION_POLICIES,
    CVEVersionVerificationPolicy,
    DefaultVerificationPolicy,
    ExposureVerificationPolicy,
    HostHeaderVerificationPolicy,
    SQLiVerificationPolicy,
    SSRFVerificationPolicy,
    SSTIVerificationPolicy,
    TLSVerificationPolicy,
    VerificationConfidence,
    VerificationEngine,
    VerificationPolicy,
    VerificationResult,
    XSSVerificationPolicy,
)

__all__ = [
    # Normalizer
    "FindingsNormalizer",
    "ToolNormalizer",
    "NormalizerResult",
    "ToolStatus",
    # Deduplicator
    "Deduplicator",
    "CrossTargetDeduplicator",
    "DeduplicationStats",
    "generate_fingerprint",
    # Verification Engine
    "VerificationEngine",
    "VerificationPolicy",
    "VerificationResult",
    "VerificationConfidence",
    "TLSVerificationPolicy",
    "ExposureVerificationPolicy",
    "CVEVersionVerificationPolicy",
    "SSTIVerificationPolicy",
    "HostHeaderVerificationPolicy",
    "SSRFVerificationPolicy",
    "SQLiVerificationPolicy",
    "XSSVerificationPolicy",
    "DefaultVerificationPolicy",
    "VERIFICATION_POLICIES",
    # Persistence
    "PipelinePersistence",
    "CanonicalFindings",
    "CanonicalSummary",
    "ToolStatusEntry",
    "save_findings_raw",
    "save_canonical_findings",
    "load_canonical_findings",
    # Integration
    "PipelineIntegration",
    "run_pipeline_standalone",
]
