"""
AIPTX Checkpoint Prompts
========================

Security-focused prompts for AI checkpoints.
Optimized for local LLMs with limited context windows.
"""

# System prompt used for all checkpoints
SYSTEM_PROMPT = """You are an expert penetration tester with deep knowledge of:
- Web application security (OWASP Top 10)
- Network security and infrastructure attacks
- Exploitation techniques and attack chains
- Security tools (nmap, nuclei, sqlmap, burp, etc.)

You analyze security findings methodically and provide actionable recommendations.
Always respond in the specified JSON format. Be concise but thorough."""


# Post-RECON checkpoint prompt
POST_RECON_PROMPT = """## RECONNAISSANCE RESULTS
{recon_summary}

## YOUR TASK
Analyze these reconnaissance results and recommend a scanning strategy.

Consider:
1. Which vulnerability scanners should be prioritized? (nuclei, nikto, wpscan, etc.)
2. What specific scan profiles/templates should be used?
3. Which hosts/endpoints are highest priority targets?
4. Are there any attack paths suggested by the recon data?
5. Any services that need special attention? (old versions, exposed APIs)

## OUTPUT FORMAT (JSON)
{{
    "scan_priority": ["scanner_name", ...],
    "high_value_targets": [
        {{"url": "https://...", "reason": "...", "suggested_tests": ["sqli", "xss", ...]}}
    ],
    "skip_recommendations": ["target_or_tool to skip"],
    "custom_templates": ["nuclei template tags to focus on"],
    "authentication_targets": ["login endpoints to test"],
    "estimated_scan_time": "X-Y minutes",
    "reasoning": "Brief explanation of strategy (2-3 sentences)"
}}"""


# Post-SCAN checkpoint prompt
POST_SCAN_PROMPT = """## VULNERABILITY FINDINGS
{vuln_summary}

## DISCOVERED ATTACK SURFACE
{attack_surface}

## YOUR TASK
Create an exploitation plan based on discovered vulnerabilities.

Consider:
1. Which vulnerabilities should be exploited first? (consider severity, exploitability)
2. Can any vulnerabilities be chained for greater impact?
3. What exploitation tools and techniques are appropriate?
4. What safety measures should be observed?
5. What data/access could each exploit yield?

## OUTPUT FORMAT (JSON)
{{
    "exploitation_order": [
        {{
            "finding_id": "F001",
            "vulnerability": "SQL Injection",
            "target": "https://...",
            "tool": "sqlmap",
            "parameters": "--level=3 --risk=2",
            "expected_outcome": "Database access",
            "chain_potential": ["Can chain with IDOR for full data access"]
        }}
    ],
    "attack_chains": [
        {{
            "name": "Auth Bypass to Admin",
            "steps": ["sqli_auth_bypass", "admin_panel_access", "rce_via_plugin"],
            "impact": "Full system compromise",
            "confidence": 0.8
        }}
    ],
    "skip_exploits": [
        {{"finding_id": "F002", "reason": "Low impact, high noise"}}
    ],
    "safety_notes": ["Avoid DoS conditions", "Rate limit requests"],
    "reasoning": "Strategic explanation (2-3 sentences)"
}}"""


# Post-EXPLOIT checkpoint prompt
POST_EXPLOIT_PROMPT = """## EXPLOIT ATTEMPTED
Target: {target}
Vulnerability: {vuln_type}
Tool: {tool}
Command: {command}

## RESULT
Exit Code: {exit_code}
Output (truncated):
```
{output_truncated}
```

## CONTEXT
Previous attempts on this target: {previous_attempts}
Overall progress: {findings_exploited}/{total_findings} findings tested

## YOUR TASK
Evaluate this exploitation attempt and recommend next action.

Consider:
1. Was the exploit successful? (look for indicators of success)
2. Should we retry with different parameters?
3. Should we pivot to a different approach?
4. What information was gained?
5. Are there post-exploitation opportunities?

## OUTPUT FORMAT (JSON)
{{
    "success": true/false,
    "confidence": 0.0-1.0,
    "evidence_of_success": ["indicators found in output"],
    "next_action": "retry|pivot|escalate|skip|post_exploit",
    "retry_parameters": {{
        "tool": "sqlmap",
        "new_params": "--technique=U --union-cols=5"
    }},
    "pivot_target": {{
        "finding_id": "alternative vulnerability ID",
        "reason": "Why pivot to this"
    }},
    "extracted_data": ["credentials found", "tokens", "info discovered"],
    "post_exploit_suggestions": ["privesc check", "lateral movement", "data exfil"],
    "reasoning": "Analysis explanation (2-3 sentences)"
}}"""


# Compact prompts for smaller context windows (4K)
COMPACT_POST_RECON_PROMPT = """## RECON RESULTS
{recon_summary}

Recommend scan strategy. Output JSON:
{{
    "priority_scanners": ["nuclei", "nikto"],
    "top_targets": [{{"url": "...", "tests": ["sqli"]}}],
    "reasoning": "Brief explanation"
}}"""


COMPACT_POST_SCAN_PROMPT = """## VULNS FOUND
{vuln_summary}

Plan exploitation. Output JSON:
{{
    "exploit_order": [{{"id": "F001", "tool": "sqlmap", "target": "..."}}],
    "chains": [{{"steps": ["sqli", "rce"], "impact": "critical"}}],
    "reasoning": "Brief explanation"
}}"""


COMPACT_POST_EXPLOIT_PROMPT = """## EXPLOIT RESULT
Target: {target} | Tool: {tool} | Exit: {exit_code}
Output: {output_truncated}

Evaluate. Output JSON:
{{
    "success": true/false,
    "confidence": 0.8,
    "next": "retry|pivot|skip",
    "reasoning": "Brief"
}}"""


def get_prompt(
    checkpoint_type: str,
    context_size: int = 8192,
) -> tuple[str, str]:
    """
    Get appropriate prompt for checkpoint type and context size.

    Args:
        checkpoint_type: "post_recon", "post_scan", or "post_exploit"
        context_size: Model context window size

    Returns:
        Tuple of (system_prompt, user_prompt_template)
    """
    # Use compact prompts for small context windows
    use_compact = context_size < 6000

    prompts = {
        "post_recon": (
            COMPACT_POST_RECON_PROMPT if use_compact else POST_RECON_PROMPT
        ),
        "post_scan": (
            COMPACT_POST_SCAN_PROMPT if use_compact else POST_SCAN_PROMPT
        ),
        "post_exploit": (
            COMPACT_POST_EXPLOIT_PROMPT if use_compact else POST_EXPLOIT_PROMPT
        ),
    }

    if checkpoint_type not in prompts:
        raise ValueError(f"Unknown checkpoint type: {checkpoint_type}")

    return SYSTEM_PROMPT, prompts[checkpoint_type]
