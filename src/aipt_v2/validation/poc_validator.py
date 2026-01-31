"""
AIPTX PoC Validator - Core Validation Engine

The PoC Validator ensures zero false positives by:
1. Attempting actual exploitation
2. Verifying success with evidence
3. Generating working PoC code

Every validated finding includes:
- Working exploit code (curl/python)
- Evidence (screenshots, responses)
- Confidence score
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    FindingStatus,
    VulnerabilityType,
    PoCInfo,
)
from aipt_v2.validation.evidence import Evidence, EvidenceCollector
from aipt_v2.validation.executor import ExploitExecutor, SandboxConfig
from aipt_v2.validation.strategies import (
    ValidationStrategy,
    StrategyResult,
    get_strategy_for_vuln_type,
)

logger = logging.getLogger(__name__)


class ValidationStatus(str, Enum):
    """Status of validation attempt."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MANUAL = "needs_manual"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ValidationResult:
    """Result from validating a single finding."""
    finding_id: str
    status: ValidationStatus = ValidationStatus.PENDING
    validated: bool = False
    confidence: float = 0.0
    poc_code: str = ""
    poc_type: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    attempts: int = 0
    error: Optional[str] = None
    notes: str = ""
    validated_at: Optional[datetime] = None
    duration_ms: float = 0.0

    def to_poc_info(self) -> PoCInfo:
        """Convert to PoCInfo for Finding."""
        return PoCInfo(
            validated=self.validated,
            validation_time=self.validated_at,
            poc_code=self.poc_code,
            poc_type=self.poc_type,
            confidence=self.confidence,
            validator_notes=self.notes,
            attempts=self.attempts,
            last_attempt=self.validated_at,
        )


@dataclass
class ValidatedFinding:
    """
    A finding that has been through PoC validation.

    Contains the original finding plus validation results.
    """
    finding: Finding
    validation: ValidationResult

    @property
    def is_confirmed(self) -> bool:
        """Check if finding is confirmed exploitable."""
        return self.validation.validated and self.validation.confidence >= 0.7

    @property
    def poc_code(self) -> str:
        """Get the PoC code."""
        return self.validation.poc_code

    @property
    def evidence(self) -> list[Evidence]:
        """Get collected evidence."""
        return self.validation.evidence


@dataclass
class ValidatorConfig:
    """Configuration for PoC validator."""
    max_concurrent: int = 3                # Max concurrent validations
    timeout_per_finding: float = 60.0      # Timeout per finding (seconds)
    min_severity: FindingSeverity = FindingSeverity.LOW
    skip_info: bool = True                 # Skip INFO severity
    max_attempts: int = 5                  # Max attempts per finding
    enable_browser: bool = False           # Enable browser for XSS validation
    sandbox_mode: bool = False             # Use Docker sandbox
    callback_server: Optional[str] = None  # Callback server URL


class PoCValidator:
    """
    PoC Validation engine for zero false positives.

    Validates findings by attempting actual exploitation and
    collecting evidence. Only validated findings are reported
    as confirmed vulnerabilities.

    Usage:
        validator = PoCValidator()

        # Validate a single finding
        result = await validator.validate_finding(finding)

        # Validate multiple findings
        results = await validator.validate_findings(findings)

        # Get validated finding
        if result.validated:
            print(f"Confirmed: {finding.title}")
            print(f"PoC: {result.poc_code}")
    """

    def __init__(self, config: Optional[ValidatorConfig] = None):
        """
        Initialize PoC validator.

        Args:
            config: Validator configuration
        """
        self.config = config or ValidatorConfig()
        self.executor = ExploitExecutor(
            config=SandboxConfig(
                timeout=self.config.timeout_per_finding,
            )
        )
        self._validation_count = 0
        self._validated_count = 0
        self._false_positive_count = 0

    async def validate_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate a single finding with PoC.

        Args:
            finding: Finding to validate

        Returns:
            ValidationResult with outcome
        """
        start_time = asyncio.get_event_loop().time()
        self._validation_count += 1

        result = ValidationResult(
            finding_id=finding.id,
            status=ValidationStatus.IN_PROGRESS,
        )

        # Skip based on severity
        if self.config.skip_info and finding.severity == FindingSeverity.INFO:
            result.status = ValidationStatus.SKIPPED
            result.notes = "Skipped: INFO severity"
            return result

        if finding.severity.value < self.config.min_severity.value:
            result.status = ValidationStatus.SKIPPED
            result.notes = f"Skipped: Below minimum severity ({self.config.min_severity.value})"
            return result

        try:
            # Get validation strategy
            strategy = get_strategy_for_vuln_type(finding.vuln_type)

            if not strategy:
                result.status = ValidationStatus.NEEDS_MANUAL
                result.notes = f"No validation strategy for {finding.vuln_type.value}"
                return result

            # Create evidence collector
            collector = EvidenceCollector(finding_id=finding.id)

            try:
                # Run validation with timeout
                strategy_result = await asyncio.wait_for(
                    strategy.validate(finding, collector),
                    timeout=self.config.timeout_per_finding,
                )

                # Process results
                result.validated = strategy_result.validated
                result.confidence = strategy_result.confidence
                result.poc_code = strategy_result.poc_code
                result.poc_type = strategy_result.poc_type
                result.evidence = strategy_result.evidence
                result.attempts = len(strategy_result.attempts)
                result.notes = strategy_result.notes

                if result.validated:
                    result.status = ValidationStatus.VALIDATED
                    self._validated_count += 1
                    logger.info(
                        f"[PoC] VALIDATED: {finding.title} "
                        f"(confidence: {result.confidence:.0%})"
                    )
                else:
                    result.status = ValidationStatus.FALSE_POSITIVE
                    self._false_positive_count += 1
                    logger.info(f"[PoC] FALSE POSITIVE: {finding.title}")

            except asyncio.TimeoutError:
                result.status = ValidationStatus.ERROR
                result.error = "Validation timed out"
                logger.warning(f"[PoC] Timeout validating: {finding.title}")

            finally:
                await collector.cleanup()

        except Exception as e:
            result.status = ValidationStatus.ERROR
            result.error = str(e)
            logger.error(f"[PoC] Error validating {finding.title}: {e}", exc_info=True)

        result.validated_at = datetime.now()
        result.duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000

        return result

    async def validate_findings(
        self,
        findings: list[Finding],
        progress_callback: Optional[callable] = None,
    ) -> list[ValidationResult]:
        """
        Validate multiple findings concurrently.

        Args:
            findings: Findings to validate
            progress_callback: Called with progress updates

        Returns:
            List of validation results
        """
        # Filter findings that need validation
        to_validate = [
            f for f in findings
            if f.status in [FindingStatus.NEW, FindingStatus.PENDING_VALIDATION]
        ]

        if not to_validate:
            return []

        logger.info(f"[PoC] Validating {len(to_validate)} findings")

        # Use semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def validate_with_semaphore(finding: Finding) -> ValidationResult:
            async with semaphore:
                result = await self.validate_finding(finding)

                if progress_callback:
                    try:
                        if asyncio.iscoroutinefunction(progress_callback):
                            await progress_callback(self.get_progress())
                        else:
                            progress_callback(self.get_progress())
                    except Exception as e:
                        logger.warning(f"Progress callback error: {e}")

                return result

        # Run validations
        tasks = [validate_with_semaphore(f) for f in to_validate]
        results = await asyncio.gather(*tasks)

        # Log summary
        validated = sum(1 for r in results if r.validated)
        false_positives = sum(1 for r in results if r.status == ValidationStatus.FALSE_POSITIVE)
        logger.info(
            f"[PoC] Validation complete: {validated} validated, "
            f"{false_positives} false positives"
        )

        return results

    async def validate_and_update_finding(
        self,
        finding: Finding,
    ) -> ValidatedFinding:
        """
        Validate finding and update its PoC info.

        Args:
            finding: Finding to validate

        Returns:
            ValidatedFinding with updated finding
        """
        result = await self.validate_finding(finding)

        # Update finding's PoC info
        finding.poc = result.to_poc_info()

        if result.validated:
            finding.status = FindingStatus.VALIDATED
        elif result.status == ValidationStatus.FALSE_POSITIVE:
            finding.status = FindingStatus.FALSE_POSITIVE
        elif result.status == ValidationStatus.NEEDS_MANUAL:
            finding.status = FindingStatus.NEEDS_MANUAL

        return ValidatedFinding(finding=finding, validation=result)

    def get_progress(self) -> dict:
        """Get current validation progress."""
        return {
            "total_validated": self._validation_count,
            "confirmed": self._validated_count,
            "false_positives": self._false_positive_count,
            "confirmation_rate": (
                self._validated_count / self._validation_count
                if self._validation_count > 0 else 0
            ),
        }

    def get_statistics(self) -> dict:
        """Get validation statistics."""
        return {
            "total_findings_processed": self._validation_count,
            "validated_findings": self._validated_count,
            "false_positives": self._false_positive_count,
            "confirmation_rate": (
                self._validated_count / self._validation_count
                if self._validation_count > 0 else 0
            ),
            "false_positive_rate": (
                self._false_positive_count / self._validation_count
                if self._validation_count > 0 else 0
            ),
        }

    async def cleanup(self) -> None:
        """Cleanup resources."""
        await self.executor.cleanup()


# Convenience functions
async def validate_finding(finding: Finding) -> ValidationResult:
    """
    Convenience function to validate a single finding.

    Args:
        finding: Finding to validate

    Returns:
        ValidationResult
    """
    validator = PoCValidator()
    return await validator.validate_finding(finding)


async def validate_findings(
    findings: list[Finding],
    **config_kwargs,
) -> list[ValidationResult]:
    """
    Convenience function to validate multiple findings.

    Args:
        findings: Findings to validate
        **config_kwargs: ValidatorConfig parameters

    Returns:
        List of ValidationResults
    """
    config = ValidatorConfig(**config_kwargs)
    validator = PoCValidator(config)
    return await validator.validate_findings(findings)


# Integration with finding repository
async def validate_repository_findings(
    min_severity: FindingSeverity = FindingSeverity.LOW,
    max_concurrent: int = 3,
) -> dict:
    """
    Validate all pending findings in the repository.

    Args:
        min_severity: Minimum severity to validate
        max_concurrent: Max concurrent validations

    Returns:
        Validation statistics
    """
    from aipt_v2.agents.shared.finding_repository import (
        get_finding_repository,
        FindingStatus,
    )

    repo = get_finding_repository()
    pending = await repo.get_pending_validation()

    config = ValidatorConfig(
        min_severity=min_severity,
        max_concurrent=max_concurrent,
    )
    validator = PoCValidator(config)

    results = await validator.validate_findings(pending)

    # Update repository
    for result in results:
        if result.validated:
            await repo.mark_validated(
                finding_id=result.finding_id,
                validated=True,
                poc_info=result.to_poc_info(),
            )
        elif result.status == ValidationStatus.FALSE_POSITIVE:
            await repo.mark_validated(
                finding_id=result.finding_id,
                validated=False,
                poc_info=result.to_poc_info(),
            )

    return validator.get_statistics()
