"""
AIPTX Beast Mode - Chain Discoverer
===================================

Discover novel attack chains that humans might miss.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class NovelChain:
    """A discovered novel attack chain."""
    name: str
    description: str
    steps: list[dict[str, str]]
    initial_vuln: str
    final_impact: str
    confidence: float
    novelty_score: float  # How unusual this chain is
    prerequisites: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "steps": self.steps,
            "initial_vuln": self.initial_vuln,
            "final_impact": self.final_impact,
            "confidence": self.confidence,
            "novelty_score": self.novelty_score,
            "prerequisites": self.prerequisites,
            "metadata": self.metadata,
        }


# Known chain patterns for discovery
CHAIN_PATTERNS = {
    "ssrf_to_internal": {
        "trigger": "ssrf",
        "enables": ["internal_access", "cloud_metadata", "admin_panel"],
        "description": "SSRF allowing access to internal resources",
    },
    "sqli_to_rce": {
        "trigger": "sqli",
        "enables": ["file_write", "outfile", "into_dumpfile"],
        "description": "SQL injection leading to remote code execution",
    },
    "lfi_to_rce": {
        "trigger": "lfi",
        "enables": ["log_poisoning", "session_inclusion", "php_filter"],
        "description": "Local file inclusion to code execution",
    },
    "upload_to_shell": {
        "trigger": "file_upload",
        "enables": ["webshell", "reverse_shell"],
        "description": "File upload leading to shell access",
    },
    "xxe_to_ssrf": {
        "trigger": "xxe",
        "enables": ["ssrf", "file_read", "internal_scan"],
        "description": "XXE used to perform SSRF",
    },
    "idor_to_takeover": {
        "trigger": "idor",
        "enables": ["account_takeover", "privilege_escalation"],
        "description": "IDOR leading to account compromise",
    },
    "xss_to_admin": {
        "trigger": "xss",
        "enables": ["session_hijack", "csrf", "admin_action"],
        "description": "XSS used to compromise admin",
    },
    "deserialization_to_rce": {
        "trigger": "insecure_deserialization",
        "enables": ["rce", "arbitrary_code"],
        "description": "Unsafe deserialization to code execution",
    },
}

# Uncommon chain combinations for novelty scoring
UNCOMMON_CHAINS = [
    ("race_condition", "privilege_escalation"),
    ("cache_poisoning", "xss"),
    ("cors_misconfiguration", "data_theft"),
    ("jwt_confusion", "authentication_bypass"),
    ("graphql_introspection", "information_disclosure"),
    ("websocket_hijacking", "session_takeover"),
    ("pdf_ssrf", "internal_network_access"),
    ("prototype_pollution", "rce"),
]


class ChainDiscoverer:
    """
    Discover novel and non-obvious attack chains.

    Uses pattern matching and LLM reasoning to find
    attack paths that might be missed by humans.
    """

    def __init__(self):
        """Initialize chain discoverer."""
        self._discovered_chains: list[NovelChain] = []
        self._vulns: list[dict[str, Any]] = []

    def add_vulnerability(self, vuln: dict[str, Any]):
        """Add a vulnerability for chain analysis."""
        self._vulns.append(vuln)

    def discover_chains(
        self,
        vulns: list[dict[str, Any]] | None = None,
    ) -> list[NovelChain]:
        """
        Discover potential attack chains from vulnerabilities.

        Args:
            vulns: List of vulnerabilities to analyze

        Returns:
            List of discovered chains
        """
        if vulns:
            self._vulns.extend(vulns)

        chains = []

        # Look for known patterns
        chains.extend(self._find_pattern_chains())

        # Look for novel combinations
        chains.extend(self._find_novel_combinations())

        # Look for chained privilege escalation
        chains.extend(self._find_privesc_chains())

        # Score chains by novelty
        for chain in chains:
            chain.novelty_score = self._calculate_novelty(chain)

        # Sort by confidence * novelty
        chains.sort(
            key=lambda c: c.confidence * c.novelty_score,
            reverse=True,
        )

        self._discovered_chains.extend(chains)
        return chains

    def _find_pattern_chains(self) -> list[NovelChain]:
        """Find chains matching known patterns."""
        chains = []

        vuln_types = {v.get("type", "").lower() for v in self._vulns}

        for pattern_name, pattern in CHAIN_PATTERNS.items():
            trigger = pattern["trigger"]
            if trigger in vuln_types:
                # Found a potential chain start
                for enabled in pattern["enables"]:
                    chains.append(NovelChain(
                        name=f"{trigger}_to_{enabled}",
                        description=pattern["description"],
                        steps=[
                            {"step": 1, "action": f"Exploit {trigger}"},
                            {"step": 2, "action": f"Achieve {enabled}"},
                        ],
                        initial_vuln=trigger,
                        final_impact=enabled,
                        confidence=0.7,
                        novelty_score=0.3,  # Known pattern
                    ))

        return chains

    def _find_novel_combinations(self) -> list[NovelChain]:
        """Find novel vulnerability combinations."""
        chains = []

        vuln_types = [v.get("type", "").lower() for v in self._vulns]

        # Check for uncommon combinations
        for combo in UNCOMMON_CHAINS:
            if all(t in vuln_types for t in combo):
                chains.append(NovelChain(
                    name=f"novel_{combo[0]}_chain",
                    description=f"Novel chain combining {combo[0]} with {combo[1]}",
                    steps=[
                        {"step": i + 1, "action": f"Exploit {t}"}
                        for i, t in enumerate(combo)
                    ],
                    initial_vuln=combo[0],
                    final_impact=combo[-1],
                    confidence=0.5,  # Lower confidence for novel
                    novelty_score=0.9,  # High novelty
                ))

        return chains

    def _find_privesc_chains(self) -> list[NovelChain]:
        """Find privilege escalation chains."""
        chains = []

        # Look for chains that lead to elevated access
        privesc_triggers = ["misconfiguration", "writable_path", "suid", "sudo"]
        vuln_types = [v.get("type", "").lower() for v in self._vulns]

        for trigger in privesc_triggers:
            if any(trigger in vt for vt in vuln_types):
                chains.append(NovelChain(
                    name=f"{trigger}_to_root",
                    description=f"Privilege escalation via {trigger}",
                    steps=[
                        {"step": 1, "action": f"Identify {trigger}"},
                        {"step": 2, "action": "Exploit for elevated privileges"},
                        {"step": 3, "action": "Verify root/admin access"},
                    ],
                    initial_vuln=trigger,
                    final_impact="root_access",
                    confidence=0.6,
                    novelty_score=0.4,
                ))

        return chains

    def _calculate_novelty(self, chain: NovelChain) -> float:
        """Calculate novelty score for a chain."""
        score = 0.5  # Base score

        # Increase for uncommon chains
        if chain.initial_vuln in [c[0] for c in UNCOMMON_CHAINS]:
            score += 0.3

        # Increase for multi-step chains
        if len(chain.steps) > 2:
            score += 0.1 * (len(chain.steps) - 2)

        # Decrease for well-known patterns
        if chain.name in CHAIN_PATTERNS:
            score -= 0.2

        return min(1.0, max(0.0, score))

    def get_chain_recommendations(
        self,
        vulns: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Get chain recommendations for vulnerabilities.

        Args:
            vulns: Vulnerabilities to analyze

        Returns:
            List of chain recommendations
        """
        recommendations = []

        for vuln in vulns:
            vuln_type = vuln.get("type", "").lower()

            # Check if this vuln can be chained
            for pattern_name, pattern in CHAIN_PATTERNS.items():
                if pattern["trigger"] == vuln_type:
                    for outcome in pattern["enables"]:
                        recommendations.append({
                            "vulnerability": vuln.get("name", vuln_type),
                            "potential_chain": pattern_name,
                            "possible_outcome": outcome,
                            "confidence": 0.6,
                            "next_steps": self._get_chain_steps(vuln_type, outcome),
                        })

        return recommendations

    def _get_chain_steps(self, vuln_type: str, outcome: str) -> list[str]:
        """Get steps to achieve a chain outcome."""
        step_templates = {
            ("ssrf", "cloud_metadata"): [
                "Use SSRF to access 169.254.169.254",
                "Retrieve IAM credentials",
                "Use credentials to access cloud resources",
            ],
            ("ssrf", "internal_access"): [
                "Enumerate internal network ranges",
                "Port scan internal hosts through SSRF",
                "Access internal services",
            ],
            ("sqli", "file_write"): [
                "Determine writable directory",
                "Use INTO OUTFILE or DUMPFILE",
                "Write webshell or config file",
            ],
            ("lfi", "log_poisoning"): [
                "Inject PHP code into access logs",
                "Include log file via LFI",
                "Achieve code execution",
            ],
            ("xss", "session_hijack"): [
                "Craft XSS payload to steal cookies",
                "Host payload receiver",
                "Hijack admin session",
            ],
        }

        return step_templates.get(
            (vuln_type, outcome),
            [f"Exploit {vuln_type}", f"Chain to {outcome}"],
        )

    def get_llm_analysis_prompt(
        self,
        vulns: list[dict[str, Any]],
        target_context: str,
    ) -> str:
        """
        Generate prompt for LLM chain analysis.

        Args:
            vulns: Vulnerabilities to analyze
            target_context: Context about the target

        Returns:
            LLM prompt
        """
        vuln_list = "\n".join(
            f"- {v.get('type', 'Unknown')}: {v.get('description', 'No description')}"
            for v in vulns
        )

        return f"""As a security researcher, analyze these vulnerabilities for potential attack chains:

Vulnerabilities:
{vuln_list}

Target Context: {target_context}

Find non-obvious ways to chain these vulnerabilities together to achieve:
1. Remote code execution
2. Privilege escalation
3. Data exfiltration
4. Account takeover

For each chain, provide:
- Steps to execute
- Prerequisites
- Confidence level
- Why this chain might be missed by automated tools

Think creatively - consider business logic flaws, timing issues, and uncommon combinations."""

    def get_discovered_chains(self) -> list[NovelChain]:
        """Get all discovered chains."""
        return self._discovered_chains.copy()


def discover_attack_chains(
    vulns: list[dict[str, Any]],
) -> list[NovelChain]:
    """Convenience function for chain discovery."""
    discoverer = ChainDiscoverer()
    return discoverer.discover_chains(vulns)


__all__ = [
    "NovelChain",
    "ChainDiscoverer",
    "CHAIN_PATTERNS",
    "discover_attack_chains",
]
