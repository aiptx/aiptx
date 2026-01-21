"""
AIPTX Reporting Module
======================

Provides vulnerability reporting tools with CVSS 3.1 scoring and PoC validation.
Ensures zero false positives through structured validation.

Integrated from Strix's reporting system.

Usage:
    from aipt_v2.tools.reporting import (
        calculate_cvss_score,
        validate_poc,
        create_vulnerability_report,
    )

    # Calculate CVSS score
    score, severity, vector = calculate_cvss_score(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
    )

    # Validate PoC
    is_valid, errors = validate_poc(poc_data)

    # Create vulnerability report
    result = create_vulnerability_report(
        title="SQL Injection in Login",
        description="...",
        poc=poc_data,
        cvss_components={...},
    )
"""

from .cvss import (
    calculate_cvss_score,
    validate_cvss_parameters,
    CVSSVector,
    CVSS_VALID_VALUES,
)
from .poc_validator import (
    validate_poc,
    PoCValidationError,
    PoCRequirements,
)
from .reporting_actions import (
    create_vulnerability_report,
    submit_vulnerability,
    validate_required_fields,
)

__all__ = [
    # CVSS
    "calculate_cvss_score",
    "validate_cvss_parameters",
    "CVSSVector",
    "CVSS_VALID_VALUES",
    # PoC Validation
    "validate_poc",
    "PoCValidationError",
    "PoCRequirements",
    # Reporting Actions
    "create_vulnerability_report",
    "submit_vulnerability",
    "validate_required_fields",
]
