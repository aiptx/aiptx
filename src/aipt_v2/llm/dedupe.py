"""
AIPTX Vulnerability Deduplication - LLM-Based Duplicate Detection

Uses LLM semantic analysis to determine if a candidate vulnerability report
describes the same issue as any existing report. Prevents false duplicates
while catching real duplicates with different wording.

Key Logic:
- Same root cause = duplicate (even if different wording)
- Same vuln type + different endpoint = NOT duplicate
- Same endpoint + different parameter = NOT duplicate
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

import litellm

logger = logging.getLogger(__name__)

DEDUPE_SYSTEM_PROMPT = """You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

YOU MUST RESPOND WITH EXACTLY THIS XML FORMAT AND NOTHING ELSE:

<dedupe_result>
<is_duplicate>true</is_duplicate>
<duplicate_id>vuln-0001</duplicate_id>
<confidence>0.95</confidence>
<reason>Both reports describe SQL injection in /api/login via the username parameter</reason>
</dedupe_result>

OR if not a duplicate:

<dedupe_result>
<is_duplicate>false</is_duplicate>
<duplicate_id></duplicate_id>
<confidence>0.90</confidence>
<reason>Different endpoints: candidate is /api/search, existing is /api/login</reason>
</dedupe_result>

RULES:
- is_duplicate MUST be exactly "true" or "false" (lowercase)
- duplicate_id MUST be the exact ID from existing reports or empty if not duplicate
- confidence MUST be a decimal (your confidence level in the decision)
- reason MUST be a specific explanation mentioning endpoint/parameter/root cause
- DO NOT include any text outside the <dedupe_result> tags"""

# Fields relevant for deduplication comparison
DEDUPE_FIELDS = [
    "id",
    "title",
    "description",
    "impact",
    "target",
    "technical_analysis",
    "poc_description",
    "endpoint",
    "method",
    "vulnerability_type",
    "cvss_score",
    "parameter",
    "url",
]


def _prepare_report_for_comparison(report: dict[str, Any]) -> dict[str, Any]:
    """
    Extract and truncate relevant fields for comparison.

    Args:
        report: Full vulnerability report

    Returns:
        Cleaned report with only relevant fields
    """
    cleaned = {}
    for field in DEDUPE_FIELDS:
        if report.get(field):
            value = report[field]
            # Truncate long fields to save tokens
            if isinstance(value, str) and len(value) > 8000:
                value = value[:8000] + "...[truncated]"
            cleaned[field] = value

    return cleaned


def _extract_xml_field(content: str, field: str) -> str:
    """Extract a field value from XML response."""
    pattern = rf"<{field}>(.*?)</{field}>"
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    """
    Parse LLM response in XML format.

    Args:
        content: Raw LLM response

    Returns:
        Parsed deduplication result
    """
    result_match = re.search(
        r"<dedupe_result>(.*?)</dedupe_result>",
        content,
        re.DOTALL | re.IGNORECASE,
    )

    if not result_match:
        logger.warning(f"No <dedupe_result> block found in response: {content[:500]}")
        raise ValueError("No <dedupe_result> block found in response")

    result_content = result_match.group(1)

    is_duplicate_str = _extract_xml_field(result_content, "is_duplicate")
    duplicate_id = _extract_xml_field(result_content, "duplicate_id")
    confidence_str = _extract_xml_field(result_content, "confidence")
    reason = _extract_xml_field(result_content, "reason")

    is_duplicate = is_duplicate_str.lower() == "true"

    try:
        confidence = float(confidence_str) if confidence_str else 0.0
        confidence = min(1.0, max(0.0, confidence))  # Clamp to [0, 1]
    except ValueError:
        confidence = 0.0

    return {
        "is_duplicate": is_duplicate,
        "duplicate_id": duplicate_id[:64] if duplicate_id else "",
        "confidence": confidence,
        "reason": reason[:500] if reason else "",
    }


def check_duplicate(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
) -> dict[str, Any]:
    """
    Check if a candidate vulnerability report is a duplicate of existing reports.

    Uses LLM semantic analysis to compare the technical root cause, affected
    components, and exploitation methods to determine if reports describe
    the same vulnerability.

    Args:
        candidate: The new vulnerability report to check
        existing_reports: List of existing vulnerability reports to compare against
        model: LLM model to use (default: claude-3-haiku-20240307 for speed)
        api_key: Optional API key override
        api_base: Optional API base URL override

    Returns:
        dict with keys:
            - is_duplicate: bool
            - duplicate_id: str (ID of duplicate if found, empty otherwise)
            - confidence: float (0.0 to 1.0)
            - reason: str (explanation of decision)
            - error: str (if an error occurred)
    """
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    try:
        # Clean and truncate reports for comparison
        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in existing_reports]

        comparison_data = {
            "candidate": candidate_cleaned,
            "existing_reports": existing_cleaned,
        }

        # Use fast model by default for deduplication
        model_name = model or "claude-3-haiku-20240307"

        messages = [
            {"role": "system", "content": DEDUPE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Compare this candidate vulnerability against existing reports:\n\n"
                    f"{json.dumps(comparison_data, indent=2)}\n\n"
                    f"Respond with ONLY the <dedupe_result> XML block."
                ),
            },
        ]

        # Build completion kwargs
        completion_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "timeout": 120,
            "temperature": 0,  # Deterministic for consistency
        }

        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        logger.info(f"Running deduplication check against {len(existing_reports)} reports")

        response = litellm.completion(**completion_kwargs)

        content = response.choices[0].message.content
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            f"Deduplication result: is_duplicate={result['is_duplicate']}, "
            f"confidence={result['confidence']:.2f}, reason={result['reason'][:100]}"
        )

        return result

    except Exception as e:
        logger.exception("Error during vulnerability deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Deduplication check failed: {e}",
            "error": str(e),
        }


async def check_duplicate_async(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
) -> dict[str, Any]:
    """
    Async version of check_duplicate for use in async agent loops.

    Args:
        candidate: The new vulnerability report to check
        existing_reports: List of existing reports to compare against
        model: LLM model to use
        api_key: Optional API key override
        api_base: Optional API base URL override

    Returns:
        Same as check_duplicate()
    """
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    try:
        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in existing_reports]

        comparison_data = {
            "candidate": candidate_cleaned,
            "existing_reports": existing_cleaned,
        }

        model_name = model or "claude-3-haiku-20240307"

        messages = [
            {"role": "system", "content": DEDUPE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Compare this candidate vulnerability against existing reports:\n\n"
                    f"{json.dumps(comparison_data, indent=2)}\n\n"
                    f"Respond with ONLY the <dedupe_result> XML block."
                ),
            },
        ]

        completion_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "timeout": 120,
            "temperature": 0,
        }

        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        # Use async completion
        response = await litellm.acompletion(**completion_kwargs)

        content = response.choices[0].message.content
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        return _parse_dedupe_response(content)

    except Exception as e:
        logger.exception("Error during async deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Async deduplication check failed: {e}",
            "error": str(e),
        }


def quick_hash_check(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Quick pre-check using hash comparison before expensive LLM call.

    Returns early match if exact duplicate found, None otherwise.
    This is a performance optimization for obvious duplicates.

    Args:
        candidate: The new vulnerability report
        existing_reports: List of existing reports

    Returns:
        Match result if exact duplicate found, None to proceed with LLM check
    """
    # Create a signature from key fields
    def create_signature(report: dict[str, Any]) -> str:
        parts = [
            str(report.get("endpoint", "")).lower(),
            str(report.get("parameter", "")).lower(),
            str(report.get("vulnerability_type", "")).lower(),
            str(report.get("method", "")).lower(),
        ]
        return "|".join(parts)

    candidate_sig = create_signature(candidate)

    for existing in existing_reports:
        if create_signature(existing) == candidate_sig:
            return {
                "is_duplicate": True,
                "duplicate_id": existing.get("id", ""),
                "confidence": 1.0,
                "reason": f"Exact match: same endpoint, parameter, and vulnerability type",
            }

    return None  # No quick match, proceed with LLM check


def deduplicate_with_optimization(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Optimized deduplication that uses quick hash check before LLM.

    Args:
        candidate: The new vulnerability report
        existing_reports: List of existing reports
        **kwargs: Passed to check_duplicate()

    Returns:
        Deduplication result
    """
    # Try quick hash check first
    quick_result = quick_hash_check(candidate, existing_reports)
    if quick_result:
        logger.info("Quick hash check found exact duplicate")
        return quick_result

    # Fall back to LLM-based check
    return check_duplicate(candidate, existing_reports, **kwargs)


__all__ = [
    "check_duplicate",
    "check_duplicate_async",
    "quick_hash_check",
    "deduplicate_with_optimization",
]
