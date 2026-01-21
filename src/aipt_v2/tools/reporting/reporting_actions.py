"""
Reporting Actions
=================

Tool actions for creating and managing vulnerability reports.
Used by agents to submit validated vulnerabilities.

Integrated from Strix's reporting system.

Example:
    result = await create_vulnerability_report(
        title="SQL Injection in Login",
        description="The login form is vulnerable to SQL injection...",
        impact="Authentication bypass and potential data breach",
        target="https://example.com/api/login",
        technical_analysis="The username parameter is concatenated...",
        poc_description="Inject a SQL payload in the username field...",
        poc_script_code="curl -X POST https://example.com/api/login -d 'user=admin\\' OR \\'1\\'=\\'1'",
        remediation_steps="Use parameterized queries...",
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="L",
    )
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


def validate_required_fields(**kwargs: str | None) -> list[str]:
    """
    Validate that all required fields are present and non-empty.

    Returns:
        List of validation error messages.
    """
    errors: list[str] = []

    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "impact": "Impact cannot be empty",
        "target": "Target cannot be empty",
        "technical_analysis": "Technical analysis cannot be empty",
        "poc_description": "PoC description cannot be empty",
        "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
        "remediation_steps": "Remediation steps cannot be empty",
    }

    for field_name, error_msg in required_fields.items():
        value = kwargs.get(field_name)
        if not value or not str(value).strip():
            errors.append(error_msg)

    return errors


def create_vulnerability_report(
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    # CVSS Components
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
    # Optional fields
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    code_file: str | None = None,
    code_before: str | None = None,
    code_after: str | None = None,
    code_diff: str | None = None,
) -> dict[str, Any]:
    """
    Create a validated vulnerability report with CVSS scoring.

    This is the main entry point for agents to submit vulnerabilities.
    It validates the PoC, calculates CVSS score, and stores the report.

    Args:
        title: Vulnerability title.
        description: Detailed description.
        impact: Business/security impact.
        target: Target URL/endpoint.
        technical_analysis: Technical explanation.
        poc_description: PoC explanation.
        poc_script_code: Actual exploit code/commands.
        remediation_steps: How to fix.
        attack_vector: N (Network), A (Adjacent), L (Local), P (Physical).
        attack_complexity: L (Low), H (High).
        privileges_required: N (None), L (Low), H (High).
        user_interaction: N (None), R (Required).
        scope: U (Unchanged), C (Changed).
        confidentiality: N (None), L (Low), H (High).
        integrity: N (None), L (Low), H (High).
        availability: N (None), L (Low), H (High).
        endpoint: Optional specific endpoint.
        method: Optional HTTP method.
        cve: Optional CVE identifier.
        code_file: Optional vulnerable code file path.
        code_before: Optional code before fix.
        code_after: Optional code after fix.
        code_diff: Optional code diff.

    Returns:
        Dict with:
        - success: Whether the report was created.
        - message: Status message.
        - report_id: ID of created report (if successful).
        - severity: Calculated severity.
        - cvss_score: Calculated CVSS score.
        - errors: List of validation errors (if failed).
    """
    from .cvss import calculate_cvss_score, validate_cvss_parameters
    from .poc_validator import validate_poc

    # Validate required fields
    validation_errors = validate_required_fields(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
    )

    # Validate CVSS parameters
    validation_errors.extend(
        validate_cvss_parameters(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )
    )

    # Validate PoC
    poc_data = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
    }
    is_poc_valid, poc_errors = validate_poc(poc_data)
    validation_errors.extend(poc_errors)

    if validation_errors:
        return {
            "success": False,
            "message": "Validation failed",
            "errors": validation_errors,
        }

    # Calculate CVSS score
    try:
        cvss_score, severity, cvss_vector = calculate_cvss_score(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )
    except ValueError as e:
        return {
            "success": False,
            "message": f"CVSS calculation failed: {e}",
            "errors": [str(e)],
        }

    # Store the report via tracer if available
    try:
        from aipt_v2.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer and hasattr(tracer, "add_vulnerability_report"):
            cvss_breakdown = {
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
                "scope": scope,
                "confidentiality": confidentiality,
                "integrity": integrity,
                "availability": availability,
            }

            report_id = tracer.add_vulnerability_report(
                title=title,
                description=description,
                severity=severity,
                impact=impact,
                target=target,
                technical_analysis=technical_analysis,
                poc_description=poc_description,
                poc_script_code=poc_script_code,
                remediation_steps=remediation_steps,
                cvss=cvss_score,
                cvss_breakdown=cvss_breakdown,
                endpoint=endpoint,
                method=method,
                cve=cve,
                code_file=code_file,
                code_before=code_before,
                code_after=code_after,
                code_diff=code_diff,
            )

            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created successfully",
                "report_id": report_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
            }

    except (ImportError, AttributeError) as e:
        logger.debug(f"Tracer not available: {e}")

    # Return success even without tracer persistence
    import uuid

    return {
        "success": True,
        "message": f"Vulnerability report '{title}' created (local only)",
        "report_id": str(uuid.uuid4()),
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "warning": "Report not persisted - tracer unavailable",
    }


def submit_vulnerability(
    poc: dict[str, Any],
    cvss_components: dict[str, str],
) -> dict[str, Any]:
    """
    Submit a vulnerability with PoC and CVSS components.

    Convenience function that unpacks dictionaries for create_vulnerability_report.

    Args:
        poc: Dictionary with PoC fields (title, description, etc.)
        cvss_components: Dictionary with CVSS fields (attack_vector, etc.)

    Returns:
        Result from create_vulnerability_report.
    """
    return create_vulnerability_report(
        title=poc.get("title", ""),
        description=poc.get("description", ""),
        impact=poc.get("impact", ""),
        target=poc.get("target", ""),
        technical_analysis=poc.get("technical_analysis", ""),
        poc_description=poc.get("poc_description", ""),
        poc_script_code=poc.get("poc_script_code", ""),
        remediation_steps=poc.get("remediation_steps", ""),
        attack_vector=cvss_components.get("attack_vector", "N"),
        attack_complexity=cvss_components.get("attack_complexity", "L"),
        privileges_required=cvss_components.get("privileges_required", "N"),
        user_interaction=cvss_components.get("user_interaction", "N"),
        scope=cvss_components.get("scope", "U"),
        confidentiality=cvss_components.get("confidentiality", "N"),
        integrity=cvss_components.get("integrity", "N"),
        availability=cvss_components.get("availability", "N"),
        endpoint=poc.get("endpoint"),
        method=poc.get("method"),
        cve=poc.get("cve"),
        code_file=poc.get("code_file"),
        code_before=poc.get("code_before"),
        code_after=poc.get("code_after"),
        code_diff=poc.get("code_diff"),
    )
