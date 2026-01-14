"""
AIPT Vulnerability Chaining Engine

Analyzes findings to identify attack chains - sequences of vulnerabilities
that can be combined for greater impact.

Example Chains:
- SSRF → Internal Service Access → Sensitive Data Exposure
- SQL Injection → Authentication Bypass → Privilege Escalation
- XSS → Session Hijacking → Account Takeover
- File Upload → RCE → Full Server Compromise

This module helps pentesters demonstrate real-world attack impact
by showing how multiple "medium" findings can combine into "critical" risks.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import hashlib

# Works with dict-based findings, not typed Finding class


logger = logging.getLogger(__name__)


# ============================================================================
# Vulnerability Types (for chain rules)
# ============================================================================

class VulnerabilityType(Enum):
    """Types of vulnerabilities for chain detection"""
    # Injection
    SQL_INJECTION = "sql_injection"
    XSS_STORED = "xss_stored"
    XSS_REFLECTED = "xss_reflected"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"

    # Authentication/Authorization
    AUTH_BYPASS = "auth_bypass"
    BROKEN_AUTH = "broken_authentication"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    IDOR = "idor"

    # Information Disclosure
    INFORMATION_DISCLOSURE = "information_disclosure"
    PATH_TRAVERSAL = "path_traversal"
    SOURCE_CODE_DISCLOSURE = "source_code_disclosure"

    # Server-Side
    SSRF = "ssrf"
    RCE = "rce"
    FILE_UPLOAD = "file_upload"
    FILE_INCLUSION = "file_inclusion"
    LFI = "lfi"
    RFI = "rfi"
    DESERIALIZATION = "deserialization"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    XXE = "xxe"

    # Client-Side
    CSRF = "csrf"
    CLICKJACKING = "clickjacking"
    OPEN_REDIRECT = "open_redirect"

    # Cryptographic
    WEAK_CRYPTO = "weak_cryptography"
    HARDCODED_SECRETS = "hardcoded_secrets"

    # Configuration
    MISCONFIGURATION = "misconfiguration"
    DEFAULT_CREDENTIALS = "default_credentials"
    EXPOSED_ADMIN = "exposed_admin_panel"

    # Other
    DOS = "denial_of_service"
    BUSINESS_LOGIC = "business_logic"
    UNKNOWN = "unknown"


class ChainType(Enum):
    """Types of vulnerability chains"""
    DATA_EXFILTRATION = "data_exfiltration"
    ACCOUNT_TAKEOVER = "account_takeover"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    INTERNAL_NETWORK_ACCESS = "internal_network_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    LATERAL_MOVEMENT = "lateral_movement"


class ChainImpact(Enum):
    """Business impact levels"""
    CATASTROPHIC = "catastrophic"  # Full compromise, data breach
    SEVERE = "severe"              # Significant access, major data exposure
    SIGNIFICANT = "significant"    # Limited access, some data exposure
    MODERATE = "moderate"          # Potential for escalation
    MINIMAL = "minimal"            # Low impact chain


@dataclass
class ChainLink:
    """A single step in an attack chain"""
    finding: Finding
    step_number: int
    action: str  # What the attacker does at this step
    outcome: str  # What they achieve
    prerequisites: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "vulnerability": self.finding.title,
            "severity": self.finding.severity.value,
            "url": self.finding.url,
            "action": self.action,
            "outcome": self.outcome,
            "prerequisites": self.prerequisites,
        }


@dataclass
class AttackChain:
    """A complete attack chain combining multiple vulnerabilities"""
    chain_id: str
    name: str
    chain_type: ChainType
    links: list[ChainLink]

    # Impact assessment
    combined_severity: Severity
    impact: ChainImpact
    business_impact: str

    # Metadata
    confidence: float  # 0.0 to 1.0
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Narrative
    attack_narrative: str = ""
    remediation_priority: str = ""

    @property
    def length(self) -> int:
        return len(self.links)

    @property
    def entry_point(self) -> Finding:
        return self.links[0].finding if self.links else None

    @property
    def final_outcome(self) -> str:
        return self.links[-1].outcome if self.links else ""

    def get_cvss_amplification(self) -> float:
        """
        Calculate how much the chain amplifies individual CVSS scores.
        Chains often have impact greater than sum of parts.
        """
        if not self.links:
            return 1.0

        individual_max = max(
            (l.finding.cvss_score or 0) for l in self.links
        )

        # Chain severity bonus based on type
        chain_bonus = {
            ChainType.REMOTE_CODE_EXECUTION: 2.0,
            ChainType.DATA_EXFILTRATION: 1.8,
            ChainType.ACCOUNT_TAKEOVER: 1.7,
            ChainType.PRIVILEGE_ESCALATION: 1.6,
            ChainType.INTERNAL_NETWORK_ACCESS: 1.5,
            ChainType.LATERAL_MOVEMENT: 1.4,
            ChainType.SUPPLY_CHAIN: 1.9,
            ChainType.DENIAL_OF_SERVICE: 1.2,
        }

        return chain_bonus.get(self.chain_type, 1.3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "chain_type": self.chain_type.value,
            "length": self.length,
            "combined_severity": self.combined_severity.value,
            "impact": self.impact.value,
            "business_impact": self.business_impact,
            "confidence": self.confidence,
            "cvss_amplification": self.get_cvss_amplification(),
            "links": [link.to_dict() for link in self.links],
            "attack_narrative": self.attack_narrative,
            "remediation_priority": self.remediation_priority,
        }


# ============================================================================
# Chain Detection Rules
# ============================================================================

# Define which vulnerability types can lead to others
CHAIN_RULES: dict[VulnerabilityType, list[tuple[VulnerabilityType, str, str]]] = {
    # SSRF can lead to...
    VulnerabilityType.SSRF: [
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Use SSRF to access internal endpoints",
         "Read internal service data"),
        (VulnerabilityType.RCE,
         "SSRF to internal admin panel with RCE",
         "Execute commands on internal systems"),
        (VulnerabilityType.SQL_INJECTION,
         "SSRF to internal database interface",
         "Query internal databases"),
    ],

    # SQL Injection can lead to...
    VulnerabilityType.SQL_INJECTION: [
        (VulnerabilityType.AUTH_BYPASS,
         "Extract credentials from database",
         "Authenticate as any user"),
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Dump database tables",
         "Access all stored data"),
        (VulnerabilityType.RCE,
         "SQL injection to xp_cmdshell or file write",
         "Execute system commands"),
        (VulnerabilityType.PRIVILEGE_ESCALATION,
         "Modify user roles in database",
         "Elevate to admin privileges"),
    ],

    # XSS can lead to...
    VulnerabilityType.XSS_STORED: [
        (VulnerabilityType.AUTH_BYPASS,
         "Steal session cookies via XSS",
         "Hijack user sessions"),
        (VulnerabilityType.CSRF,
         "Use XSS to perform actions as victim",
         "Execute privileged actions"),
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Exfiltrate page data via XSS",
         "Steal sensitive displayed information"),
    ],
    VulnerabilityType.XSS_REFLECTED: [
        (VulnerabilityType.AUTH_BYPASS,
         "Phish credentials via reflected XSS",
         "Capture user credentials"),
    ],

    # File Upload can lead to...
    VulnerabilityType.FILE_UPLOAD: [
        (VulnerabilityType.RCE,
         "Upload web shell",
         "Execute arbitrary code"),
        (VulnerabilityType.FILE_INCLUSION,
         "Upload malicious include file",
         "Include and execute uploaded code"),
    ],

    # File Inclusion can lead to...
    VulnerabilityType.FILE_INCLUSION: [
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Read sensitive configuration files",
         "Access credentials and secrets"),
        (VulnerabilityType.RCE,
         "Include remote file or log poisoning",
         "Execute arbitrary code"),
    ],

    # Auth Bypass can lead to...
    VulnerabilityType.AUTH_BYPASS: [
        (VulnerabilityType.PRIVILEGE_ESCALATION,
         "Access admin functionality",
         "Perform administrative actions"),
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Access protected user data",
         "View all user information"),
        (VulnerabilityType.IDOR,
         "Access other users' resources",
         "Modify or steal user data"),
    ],

    # IDOR can lead to...
    VulnerabilityType.IDOR: [
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Enumerate and access all records",
         "Mass data extraction"),
        (VulnerabilityType.PRIVILEGE_ESCALATION,
         "Modify own role/permissions",
         "Elevate account privileges"),
    ],

    # Open Redirect can lead to...
    VulnerabilityType.OPEN_REDIRECT: [
        (VulnerabilityType.AUTH_BYPASS,
         "Redirect OAuth flow to attacker",
         "Steal authentication tokens"),
        (VulnerabilityType.XSS_REFLECTED,
         "Chain with XSS via redirect",
         "Execute JavaScript in context"),
    ],

    # XXE can lead to...
    VulnerabilityType.XXE: [
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Read local files via XXE",
         "Access server files"),
        (VulnerabilityType.SSRF,
         "XXE to make server-side requests",
         "Access internal network"),
        (VulnerabilityType.RCE,
         "XXE with expect:// wrapper",
         "Execute system commands"),
    ],

    # Command Injection leads to RCE
    VulnerabilityType.COMMAND_INJECTION: [
        (VulnerabilityType.RCE,
         "Execute arbitrary commands",
         "Full system compromise"),
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Read files and environment",
         "Access secrets and configuration"),
    ],

    # Weak Crypto can lead to...
    VulnerabilityType.WEAK_CRYPTO: [
        (VulnerabilityType.AUTH_BYPASS,
         "Crack or forge authentication tokens",
         "Authenticate as any user"),
        (VulnerabilityType.INFORMATION_DISCLOSURE,
         "Decrypt sensitive data",
         "Access protected information"),
    ],

    # Insecure Deserialization
    VulnerabilityType.INSECURE_DESERIALIZATION: [
        (VulnerabilityType.RCE,
         "Craft malicious serialized object",
         "Execute arbitrary code"),
    ],
}


class VulnerabilityChainer:
    """
    Analyzes findings to identify attack chains.

    This class takes a list of individual findings and identifies
    how they can be combined into more impactful attack scenarios.

    Example:
        chainer = VulnerabilityChainer()
        chains = chainer.find_chains(findings)
        for chain in chains:
            print(f"Attack Chain: {chain.name}")
            print(f"Impact: {chain.impact.value}")
            for link in chain.links:
                print(f"  Step {link.step_number}: {link.action}")
    """

    def __init__(self, max_chain_length: int = 5):
        self.max_chain_length = max_chain_length
        self._chain_counter = 0

    def find_chains(
        self,
        findings: list[Finding],
        min_confidence: float = 0.5,
    ) -> list[AttackChain]:
        """
        Find all possible attack chains in the findings.

        Args:
            findings: List of vulnerability findings
            min_confidence: Minimum confidence threshold for chains

        Returns:
            List of identified attack chains, sorted by impact
        """
        if not findings:
            return []

        chains = []

        # Group findings by vulnerability type
        by_type: dict[VulnerabilityType, list[Finding]] = {}
        for f in findings:
            if f.vuln_type not in by_type:
                by_type[f.vuln_type] = []
            by_type[f.vuln_type].append(f)

        # Find chains starting from each finding
        for finding in findings:
            found_chains = self._find_chains_from(finding, by_type, [])
            chains.extend(found_chains)

        # Deduplicate and filter
        unique_chains = self._deduplicate_chains(chains)
        filtered_chains = [c for c in unique_chains if c.confidence >= min_confidence]

        # Sort by impact (most severe first)
        impact_order = [
            ChainImpact.CATASTROPHIC,
            ChainImpact.SEVERE,
            ChainImpact.SIGNIFICANT,
            ChainImpact.MODERATE,
            ChainImpact.MINIMAL,
        ]
        filtered_chains.sort(key=lambda c: impact_order.index(c.impact))

        logger.info(f"Found {len(filtered_chains)} attack chains")
        return filtered_chains

    def _find_chains_from(
        self,
        start: Finding,
        by_type: dict[VulnerabilityType, list[Finding]],
        current_path: list[Finding],
    ) -> list[AttackChain]:
        """Recursively find chains starting from a finding"""
        chains = []

        # Prevent cycles and limit depth
        if start in current_path or len(current_path) >= self.max_chain_length:
            return chains

        current_path = current_path + [start]

        # Get possible next steps from chain rules
        next_types = CHAIN_RULES.get(start.vuln_type, [])

        for next_type, action, outcome in next_types:
            # Find findings that match the next type
            matching = by_type.get(next_type, [])

            for next_finding in matching:
                # Check if findings are related (same host/path)
                if self._findings_related(start, next_finding):
                    # Recurse to find longer chains
                    deeper_chains = self._find_chains_from(
                        next_finding, by_type, current_path
                    )
                    chains.extend(deeper_chains)

            # Even without a matching finding, if we have 2+ steps, record the chain
            if len(current_path) >= 2:
                chain = self._build_chain(current_path)
                if chain:
                    chains.append(chain)

        return chains

    def _findings_related(self, f1: Finding, f2: Finding) -> bool:
        """Check if two findings are related (could be chained)"""
        # Same host
        try:
            from urllib.parse import urlparse
            host1 = urlparse(f1.url).netloc
            host2 = urlparse(f2.url).netloc
            if host1 and host2 and host1 == host2:
                return True
        except Exception:
            pass

        # Same parameter
        if f1.parameter and f2.parameter and f1.parameter == f2.parameter:
            return True

        # If same source scanner found both, likely related
        if f1.source == f2.source:
            return True

        return False

    def _build_chain(self, findings: list[Finding]) -> AttackChain | None:
        """Build an AttackChain from a list of findings"""
        if len(findings) < 2:
            return None

        self._chain_counter += 1
        chain_id = f"chain_{self._chain_counter:04d}"

        # Build links
        links = []
        for i, finding in enumerate(findings):
            # Get action/outcome from chain rules
            action, outcome = self._get_step_details(
                finding,
                findings[i + 1] if i + 1 < len(findings) else None
            )

            link = ChainLink(
                finding=finding,
                step_number=i + 1,
                action=action,
                outcome=outcome,
                prerequisites=[f"Step {j+1} completed" for j in range(i)],
            )
            links.append(link)

        # Determine chain type and impact
        chain_type = self._classify_chain_type(findings)
        impact = self._assess_impact(findings, chain_type)
        combined_severity = self._calculate_combined_severity(findings, chain_type)

        # Generate narrative
        narrative = self._generate_narrative(links, chain_type)

        # Calculate confidence
        confidence = self._calculate_confidence(findings)

        return AttackChain(
            chain_id=chain_id,
            name=self._generate_chain_name(chain_type, findings),
            chain_type=chain_type,
            links=links,
            combined_severity=combined_severity,
            impact=impact,
            business_impact=self._describe_business_impact(chain_type, impact),
            confidence=confidence,
            attack_narrative=narrative,
            remediation_priority=self._suggest_remediation(links),
        )

    def _get_step_details(
        self,
        current: Finding,
        next_finding: Finding | None,
    ) -> tuple[str, str]:
        """Get action and outcome for a chain step"""
        rules = CHAIN_RULES.get(current.vuln_type, [])

        if next_finding:
            for next_type, action, outcome in rules:
                if next_finding.vuln_type == next_type:
                    return action, outcome

        # Default based on vulnerability type
        defaults = {
            VulnerabilityType.SQL_INJECTION: ("Execute SQL injection", "Access database"),
            VulnerabilityType.XSS_STORED: ("Inject stored XSS payload", "Execute JavaScript in user browsers"),
            VulnerabilityType.SSRF: ("Exploit SSRF vulnerability", "Make server-side requests"),
            VulnerabilityType.RCE: ("Execute remote code", "Full system access"),
            VulnerabilityType.AUTH_BYPASS: ("Bypass authentication", "Access as authenticated user"),
            VulnerabilityType.IDOR: ("Access unauthorized resources", "View/modify other users' data"),
        }

        return defaults.get(
            current.vuln_type,
            (f"Exploit {current.vuln_type.value}", "Advance attack")
        )

    def _classify_chain_type(self, findings: list[Finding]) -> ChainType:
        """Determine the type of attack chain"""
        types = {f.vuln_type for f in findings}

        # Check for RCE chain
        if VulnerabilityType.RCE in types or VulnerabilityType.COMMAND_INJECTION in types:
            return ChainType.REMOTE_CODE_EXECUTION

        # Check for data exfiltration
        if VulnerabilityType.SQL_INJECTION in types and VulnerabilityType.INFORMATION_DISCLOSURE in types:
            return ChainType.DATA_EXFILTRATION

        # Check for account takeover
        if VulnerabilityType.AUTH_BYPASS in types or (
            VulnerabilityType.XSS_STORED in types and VulnerabilityType.CSRF in types
        ):
            return ChainType.ACCOUNT_TAKEOVER

        # Check for privilege escalation
        if VulnerabilityType.PRIVILEGE_ESCALATION in types or (
            VulnerabilityType.IDOR in types and VulnerabilityType.AUTH_BYPASS in types
        ):
            return ChainType.PRIVILEGE_ESCALATION

        # Check for internal network access
        if VulnerabilityType.SSRF in types:
            return ChainType.INTERNAL_NETWORK_ACCESS

        # Default based on most severe finding
        return ChainType.DATA_EXFILTRATION

    def _assess_impact(
        self,
        findings: list[Finding],
        chain_type: ChainType,
    ) -> ChainImpact:
        """Assess the business impact of the chain"""
        severities = [f.severity for f in findings]

        # Catastrophic if RCE or multiple criticals
        if chain_type == ChainType.REMOTE_CODE_EXECUTION:
            return ChainImpact.CATASTROPHIC
        if severities.count(Severity.CRITICAL) >= 2:
            return ChainImpact.CATASTROPHIC

        # Severe if data exfil or account takeover with high severity
        if chain_type in [ChainType.DATA_EXFILTRATION, ChainType.ACCOUNT_TAKEOVER]:
            if Severity.HIGH in severities or Severity.CRITICAL in severities:
                return ChainImpact.SEVERE

        # Significant if privilege escalation
        if chain_type == ChainType.PRIVILEGE_ESCALATION:
            return ChainImpact.SIGNIFICANT

        # Based on highest severity in chain
        if Severity.CRITICAL in severities:
            return ChainImpact.SEVERE
        if Severity.HIGH in severities:
            return ChainImpact.SIGNIFICANT
        if Severity.MEDIUM in severities:
            return ChainImpact.MODERATE

        return ChainImpact.MINIMAL

    def _calculate_combined_severity(
        self,
        findings: list[Finding],
        chain_type: ChainType,
    ) -> Severity:
        """Calculate the combined severity of the chain"""
        # Chain severity is often higher than individual findings
        max_severity = max(f.severity for f in findings)

        # Escalate severity for high-impact chain types
        escalation_types = [
            ChainType.REMOTE_CODE_EXECUTION,
            ChainType.DATA_EXFILTRATION,
            ChainType.ACCOUNT_TAKEOVER,
        ]

        if chain_type in escalation_types:
            severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            current_idx = severity_order.index(max_severity)
            escalated_idx = min(current_idx + 1, len(severity_order) - 1)
            return severity_order[escalated_idx]

        return max_severity

    def _calculate_confidence(self, findings: list[Finding]) -> float:
        """Calculate confidence in the chain validity"""
        # Base confidence on finding confirmations
        confirmed_count = sum(1 for f in findings if f.confirmed)
        base_confidence = confirmed_count / len(findings)

        # Boost for AI-validated findings
        ai_findings = [f for f in findings if f.ai_confidence]
        if ai_findings:
            ai_boost = sum(f.ai_confidence for f in ai_findings) / len(ai_findings)
            base_confidence = (base_confidence + ai_boost) / 2

        # Reduce confidence for longer chains (more assumptions)
        length_penalty = max(0, (len(findings) - 2) * 0.1)

        return max(0.3, min(1.0, base_confidence - length_penalty))

    def _generate_chain_name(
        self,
        chain_type: ChainType,
        findings: list[Finding],
    ) -> str:
        """Generate a descriptive name for the chain"""
        type_names = {
            ChainType.REMOTE_CODE_EXECUTION: "Remote Code Execution Chain",
            ChainType.DATA_EXFILTRATION: "Data Exfiltration Chain",
            ChainType.ACCOUNT_TAKEOVER: "Account Takeover Chain",
            ChainType.PRIVILEGE_ESCALATION: "Privilege Escalation Chain",
            ChainType.INTERNAL_NETWORK_ACCESS: "Internal Network Access Chain",
            ChainType.LATERAL_MOVEMENT: "Lateral Movement Chain",
            ChainType.DENIAL_OF_SERVICE: "Denial of Service Chain",
            ChainType.SUPPLY_CHAIN: "Supply Chain Attack",
        }

        base_name = type_names.get(chain_type, "Attack Chain")
        entry = findings[0].vuln_type.value.replace("_", " ").title()

        return f"{base_name} via {entry}"

    def _generate_narrative(
        self,
        links: list[ChainLink],
        chain_type: ChainType,
    ) -> str:
        """Generate a human-readable attack narrative"""
        lines = [
            "## Attack Narrative\n",
            "An attacker could exploit this chain of vulnerabilities as follows:\n",
        ]

        for link in links:
            lines.append(
                f"**Step {link.step_number}:** {link.action}\n"
                f"- Vulnerability: {link.finding.title}\n"
                f"- URL: `{link.finding.url}`\n"
                f"- Outcome: {link.outcome}\n"
            )

        lines.append(f"\n**Final Impact:** {links[-1].outcome}")

        return "\n".join(lines)

    def _describe_business_impact(
        self,
        chain_type: ChainType,
        impact: ChainImpact,
    ) -> str:
        """Describe the business impact of the chain"""
        descriptions = {
            (ChainType.REMOTE_CODE_EXECUTION, ChainImpact.CATASTROPHIC):
                "Complete server compromise. Attacker can access all data, install backdoors, "
                "pivot to internal networks, and cause widespread damage.",

            (ChainType.DATA_EXFILTRATION, ChainImpact.SEVERE):
                "Mass data breach potential. Sensitive customer data, credentials, and "
                "proprietary information could be extracted.",

            (ChainType.ACCOUNT_TAKEOVER, ChainImpact.SEVERE):
                "Any user account can be compromised. Attackers could access admin accounts, "
                "steal user data, or perform actions as victims.",

            (ChainType.PRIVILEGE_ESCALATION, ChainImpact.SIGNIFICANT):
                "Unauthorized access to privileged functionality. Attackers could modify "
                "configurations, access restricted data, or compromise other users.",

            (ChainType.INTERNAL_NETWORK_ACCESS, ChainImpact.SEVERE):
                "Access to internal network services. Attackers could reach databases, "
                "admin panels, and other sensitive internal resources.",
        }

        return descriptions.get(
            (chain_type, impact),
            f"Potential for {impact.value} impact through {chain_type.value} attack."
        )

    def _suggest_remediation(self, links: list[ChainLink]) -> str:
        """Suggest remediation priority based on chain analysis"""
        # Breaking the first link breaks the chain
        first = links[0].finding

        return (
            f"**Priority:** Fix the entry point first.\n"
            f"Remediating '{first.title}' at {first.url} will break this entire attack chain.\n"
            f"This should be addressed with {first.severity.value.upper()} priority."
        )

    def _deduplicate_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Remove duplicate or subset chains"""
        if not chains:
            return []

        # Create fingerprint for each chain
        def chain_fingerprint(chain: AttackChain) -> str:
            finding_ids = sorted(f.finding.fingerprint for f in chain.links)
            return hashlib.md5("|".join(finding_ids).encode()).hexdigest()

        seen = set()
        unique = []

        for chain in chains:
            fp = chain_fingerprint(chain)
            if fp not in seen:
                seen.add(fp)
                unique.append(chain)

        return unique
