"""
AIPTX Web Search Actions - Perplexity AI Integration

Provides intelligent web search for cybersecurity research during assessments.
Uses Perplexity AI's sonar-reasoning model for comprehensive security intelligence.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Cybersecurity-focused system prompt for Perplexity AI
SECURITY_RESEARCH_PROMPT = """You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux. When responding to search queries:

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
   - Penetration testing approaches
   - Web application security findings

2. Provide technical depth appropriate for security professionals
3. Include specific versions, configurations, and technical details when available
4. Focus on actionable intelligence for security assessment
5. Cite reliable security sources (NIST, OWASP, CVE databases, security vendors)
6. When providing commands or installation instructions, prioritize Kali Linux compatibility
   and use apt package manager or tools pre-installed in Kali
7. Be detailed and specific - avoid general answers. Always include concrete code examples,
   command-line instructions, configuration snippets, or practical implementation steps
   when applicable

Structure your response to be comprehensive yet concise, emphasizing the most critical
security implications and details."""

# Perplexity API configuration
PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
DEFAULT_MODEL = "sonar-reasoning"
DEFAULT_TIMEOUT = 300


def web_search(
    query: str,
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Search for cybersecurity information using Perplexity AI.

    Args:
        query: The search query (e.g., "CVE-2024-1234 exploit details")
        model: Perplexity model to use (default: sonar-reasoning)
        timeout: Request timeout in seconds

    Returns:
        dict with keys:
            - success: bool
            - query: str (original query)
            - content: str (search results)
            - message: str (status message)
            - model: str (model used)
    """
    try:
        api_key = os.getenv("PERPLEXITY_API_KEY")
        if not api_key:
            logger.warning("PERPLEXITY_API_KEY not set - web search disabled")
            return {
                "success": False,
                "query": query,
                "content": "",
                "message": "PERPLEXITY_API_KEY environment variable not set. "
                "Set it to enable web search functionality.",
                "model": model,
            }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": SECURITY_RESEARCH_PROMPT},
                {"role": "user", "content": query},
            ],
        }

        logger.info(f"Web search: '{query}' using {model}")

        # Use httpx for async-compatible HTTP requests
        with httpx.Client(timeout=timeout) as client:
            response = client.post(PERPLEXITY_API_URL, headers=headers, json=payload)
            response.raise_for_status()

        response_data = response.json()
        content = response_data["choices"][0]["message"]["content"]

        logger.info(f"Web search completed: {len(content)} chars")

        return {
            "success": True,
            "query": query,
            "content": content,
            "message": "Web search completed successfully",
            "model": model,
        }

    except httpx.TimeoutException:
        logger.error(f"Web search timed out after {timeout}s")
        return {
            "success": False,
            "query": query,
            "content": "",
            "message": f"Request timed out after {timeout} seconds",
            "model": model,
        }

    except httpx.HTTPStatusError as e:
        logger.error(f"Web search HTTP error: {e.response.status_code}")
        return {
            "success": False,
            "query": query,
            "content": "",
            "message": f"HTTP error {e.response.status_code}: {e.response.text[:200]}",
            "model": model,
        }

    except httpx.RequestError as e:
        logger.error(f"Web search request error: {e}")
        return {
            "success": False,
            "query": query,
            "content": "",
            "message": f"Request failed: {str(e)}",
            "model": model,
        }

    except KeyError as e:
        logger.error(f"Unexpected API response format: {e}")
        return {
            "success": False,
            "query": query,
            "content": "",
            "message": f"Unexpected API response format: missing {str(e)}",
            "model": model,
        }

    except Exception as e:
        logger.error(f"Web search failed: {e}")
        return {
            "success": False,
            "query": query,
            "content": "",
            "message": f"Web search failed: {str(e)}",
            "model": model,
        }


async def web_search_async(
    query: str,
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Async version of web_search for use in async agent loops.

    Args:
        query: The search query
        model: Perplexity model to use
        timeout: Request timeout in seconds

    Returns:
        Same as web_search()
    """
    try:
        api_key = os.getenv("PERPLEXITY_API_KEY")
        if not api_key:
            return {
                "success": False,
                "query": query,
                "content": "",
                "message": "PERPLEXITY_API_KEY environment variable not set",
                "model": model,
            }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": SECURITY_RESEARCH_PROMPT},
                {"role": "user", "content": query},
            ],
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(PERPLEXITY_API_URL, headers=headers, json=payload)
            response.raise_for_status()

        response_data = response.json()
        content = response_data["choices"][0]["message"]["content"]

        return {
            "success": True,
            "query": query,
            "content": content,
            "message": "Web search completed successfully",
            "model": model,
        }

    except Exception as e:
        return {
            "success": False,
            "query": query,
            "content": "",
            "message": f"Async web search failed: {str(e)}",
            "model": model,
        }


def search_cve(cve_id: str) -> dict[str, Any]:
    """
    Search for specific CVE information.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")

    Returns:
        Structured CVE information including CVSS, affected products, and exploits
    """
    query = f"""Provide detailed information about {cve_id}:
1. CVSS score and severity rating
2. Affected products and versions
3. Vulnerability description and root cause
4. Exploitation techniques and proof-of-concept availability
5. Remediation and mitigation steps
6. Public exploits or Metasploit modules available"""

    return web_search(query)


def search_exploit(
    technology: str,
    vulnerability_type: str | None = None,
) -> dict[str, Any]:
    """
    Search for exploits targeting specific technology.

    Args:
        technology: Target technology (e.g., "Apache Struts 2.5.20")
        vulnerability_type: Optional vulnerability class (e.g., "RCE", "SQLi")

    Returns:
        Exploit information and attack techniques
    """
    vuln_filter = f" {vulnerability_type}" if vulnerability_type else ""
    query = f"""Find{vuln_filter} exploits and vulnerabilities for {technology}:
1. Known CVEs and their severity
2. Public exploits (Exploit-DB, GitHub, Metasploit)
3. Attack techniques and payloads
4. Detection and exploitation indicators
5. Recommended testing approach"""

    return web_search(query)


def search_security_tool(tool_name: str, use_case: str | None = None) -> dict[str, Any]:
    """
    Search for security tool usage and examples.

    Args:
        tool_name: Name of security tool (e.g., "sqlmap", "nmap")
        use_case: Specific use case (e.g., "blind SQL injection testing")

    Returns:
        Tool documentation, examples, and best practices
    """
    context = f" for {use_case}" if use_case else ""
    query = f"""Provide detailed usage guide for {tool_name}{context}:
1. Installation on Kali Linux
2. Common command-line options
3. Practical examples with real syntax
4. Best practices and tips
5. Output interpretation"""

    return web_search(query)


__all__ = [
    "web_search",
    "web_search_async",
    "search_cve",
    "search_exploit",
    "search_security_tool",
]
