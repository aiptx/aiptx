"""
AIPTX Chain Exploit Analysis
=============================

Advanced attack chain detection and analysis engine that correlates
findings across phases to identify multi-step attack paths.

Features:
- Multi-hop attack path detection
- MITRE ATT&CK technique mapping
- Confidence scoring based on evidence strength
- Risk prioritization and impact assessment
- AI-ready chain descriptions for Ollama analysis
- Exploit prerequisite and dependency tracking

This module transforms isolated vulnerability findings into
actionable attack narratives for penetration testers.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


# ============================================================================
# MITRE ATT&CK Technique Mapping
# ============================================================================

class MitreTactic(str, Enum):
    """MITRE ATT&CK Tactics (Enterprise)."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEV = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESC = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class MitreTechnique:
    """MITRE ATT&CK Technique reference."""
    id: str  # e.g., "T1190"
    name: str
    tactic: MitreTactic
    description: str
    url: str = ""

    def __post_init__(self):
        if not self.url:
            self.url = f"https://attack.mitre.org/techniques/{self.id}/"


# Common technique mappings
TECHNIQUE_MAP = {
    # Initial Access
    "sqli": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                           "SQL injection to gain initial access"),
    "rce": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                          "Remote code execution vulnerability"),
    "default_creds": MitreTechnique("T1078", "Valid Accounts", MitreTactic.INITIAL_ACCESS,
                                    "Default or weak credentials"),
    "xss": MitreTechnique("T1189", "Drive-by Compromise", MitreTactic.INITIAL_ACCESS,
                          "Cross-site scripting for session hijacking"),

    # Credential Access
    "credential_dump": MitreTechnique("T1003", "OS Credential Dumping", MitreTactic.CREDENTIAL_ACCESS,
                                      "Dumping credentials from database or memory"),
    "brute_force": MitreTechnique("T1110", "Brute Force", MitreTactic.CREDENTIAL_ACCESS,
                                  "Password guessing or cracking"),
    "password_spray": MitreTechnique("T1110.003", "Password Spraying", MitreTactic.CREDENTIAL_ACCESS,
                                     "Single password against many accounts"),

    # Privilege Escalation
    "priv_esc": MitreTechnique("T1068", "Exploitation for Privilege Escalation", MitreTactic.PRIVILEGE_ESC,
                               "Escalating privileges through vulnerability"),
    "sudo_abuse": MitreTechnique("T1548.003", "Sudo and Sudo Caching", MitreTactic.PRIVILEGE_ESC,
                                 "Abusing sudo misconfigurations"),

    # Lateral Movement
    "lateral_ssh": MitreTechnique("T1021.004", "SSH", MitreTactic.LATERAL_MOVEMENT,
                                  "Using SSH for lateral movement"),
    "lateral_smb": MitreTechnique("T1021.002", "SMB/Windows Admin Shares", MitreTactic.LATERAL_MOVEMENT,
                                  "Using SMB for lateral movement"),
    "pass_the_hash": MitreTechnique("T1550.002", "Pass the Hash", MitreTactic.LATERAL_MOVEMENT,
                                    "Using password hashes for authentication"),

    # Exfiltration
    "data_exfil": MitreTechnique("T1567", "Exfiltration Over Web Service", MitreTactic.EXFILTRATION,
                                 "Exfiltrating data via web channels"),

    # Discovery
    "network_scan": MitreTechnique("T1046", "Network Service Discovery", MitreTactic.DISCOVERY,
                                   "Scanning for network services"),
    "subdomain_enum": MitreTechnique("T1596.001", "DNS/Passive DNS", MitreTactic.RECONNAISSANCE,
                                     "Subdomain enumeration"),
}


# ============================================================================
# Chain Analysis Data Structures
# ============================================================================

class ChainConfidence(str, Enum):
    """Confidence level in attack chain viability."""
    CONFIRMED = "confirmed"  # Verified through exploitation
    HIGH = "high"            # Strong evidence, likely exploitable
    MEDIUM = "medium"        # Moderate evidence, possible
    LOW = "low"              # Weak evidence, speculative
    THEORETICAL = "theoretical"  # Possible but no direct evidence


class ChainImpact(str, Enum):
    """Impact level of successful attack chain."""
    CRITICAL = "critical"    # Full system compromise, data breach
    HIGH = "high"            # Significant access or data exposure
    MEDIUM = "medium"        # Limited access or information disclosure
    LOW = "low"              # Minimal impact


@dataclass
class ChainNode:
    """
    A single node in an attack chain representing one step.
    """
    id: str
    finding_id: str
    technique: Optional[MitreTechnique]
    action: str  # What the attacker does
    result: str  # What they achieve
    prerequisites: List[str] = field(default_factory=list)  # Required prior steps
    evidence_strength: float = 0.5  # 0-1 confidence in this step


@dataclass
class AttackChain:
    """
    A complete attack chain from initial access to impact.
    """
    id: str
    name: str
    description: str
    nodes: List[ChainNode]
    confidence: ChainConfidence
    impact: ChainImpact
    mitre_tactics: List[MitreTactic]

    # Risk scoring
    risk_score: float = 0.0  # 0-100
    exploitability: float = 0.0  # 0-1
    business_impact: float = 0.0  # 0-1

    # Metadata
    target_assets: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.risk_score:
            self.risk_score = self._calculate_risk_score()

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score 0-100."""
        # Base on impact
        impact_weights = {
            ChainImpact.CRITICAL: 40,
            ChainImpact.HIGH: 30,
            ChainImpact.MEDIUM: 20,
            ChainImpact.LOW: 10,
        }
        base_score = impact_weights.get(self.impact, 10)

        # Confidence multiplier
        confidence_mult = {
            ChainConfidence.CONFIRMED: 1.0,
            ChainConfidence.HIGH: 0.85,
            ChainConfidence.MEDIUM: 0.6,
            ChainConfidence.LOW: 0.3,
            ChainConfidence.THEORETICAL: 0.1,
        }
        mult = confidence_mult.get(self.confidence, 0.5)

        # Evidence from nodes
        avg_evidence = sum(n.evidence_strength for n in self.nodes) / len(self.nodes) if self.nodes else 0.5

        score = base_score * mult * (1 + avg_evidence)
        return min(100, max(0, score))

    def to_narrative(self) -> str:
        """Generate human-readable attack narrative."""
        lines = [f"## Attack Chain: {self.name}"]
        lines.append(f"**Risk Score:** {self.risk_score:.1f}/100")
        lines.append(f"**Confidence:** {self.confidence.value.title()}")
        lines.append(f"**Impact:** {self.impact.value.title()}")
        lines.append("")
        lines.append("### Attack Steps:")
        for i, node in enumerate(self.nodes, 1):
            lines.append(f"{i}. **{node.action}**")
            lines.append(f"   - Result: {node.result}")
            if node.technique:
                lines.append(f"   - MITRE: {node.technique.id} ({node.technique.name})")
        return "\n".join(lines)

    def to_compact(self) -> str:
        """Compact format for LLM context."""
        tactics = " → ".join(t.value for t in self.mitre_tactics)
        return f"[{self.impact.value[0].upper()}|{self.risk_score:.0f}] {self.name}: {tactics}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "risk_score": self.risk_score,
            "confidence": self.confidence.value,
            "impact": self.impact.value,
            "mitre_tactics": [t.value for t in self.mitre_tactics],
            "nodes": [
                {
                    "id": n.id,
                    "finding_id": n.finding_id,
                    "action": n.action,
                    "result": n.result,
                    "technique": n.technique.id if n.technique else None,
                    "evidence_strength": n.evidence_strength,
                }
                for n in self.nodes
            ],
            "target_assets": self.target_assets,
            "recommended_tools": self.recommended_tools,
        }


# ============================================================================
# Chain Patterns - Attack Path Templates
# ============================================================================

@dataclass
class ChainPattern:
    """
    A template for detecting attack chains.
    """
    id: str
    name: str
    description: str
    entry_types: Set[str]  # Finding types that can start this chain
    intermediate_types: Set[str]  # Types that can be in the middle
    exit_types: Set[str]  # Types that complete the chain
    tactics: List[MitreTactic]
    base_impact: ChainImpact
    keywords: Set[str]  # Keywords in findings that match this pattern


# Pre-defined attack chain patterns
CHAIN_PATTERNS = [
    ChainPattern(
        id="sqli_to_rce",
        name="SQL Injection to Remote Code Execution",
        description="Exploit SQL injection to achieve code execution on the database server",
        entry_types={"sqli", "vuln"},
        intermediate_types={"database", "credential"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"sql", "injection", "database", "xp_cmdshell", "into outfile"},
    ),
    ChainPattern(
        id="sqli_data_breach",
        name="SQL Injection Data Breach",
        description="Exploit SQL injection to exfiltrate sensitive data",
        entry_types={"sqli", "vuln"},
        intermediate_types={"database"},
        exit_types={"data_exfil", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION, MitreTactic.EXFILTRATION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"sql", "injection", "union", "select", "dump"},
    ),
    ChainPattern(
        id="xss_session_hijack",
        name="XSS to Session Hijacking",
        description="Use XSS to steal session cookies and impersonate users",
        entry_types={"xss", "vuln"},
        intermediate_types={"cookie", "session"},
        exit_types={"session_hijack", "account_takeover"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"xss", "script", "cookie", "document.cookie", "reflected", "stored"},
    ),
    ChainPattern(
        id="ssrf_internal_pivot",
        name="SSRF Internal Network Pivot",
        description="Use SSRF to scan and attack internal network services",
        entry_types={"ssrf", "vuln"},
        intermediate_types={"port", "service"},
        exit_types={"internal_access", "lateral_move"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.DISCOVERY, MitreTactic.LATERAL_MOVEMENT],
        base_impact=ChainImpact.HIGH,
        keywords={"ssrf", "localhost", "127.0.0.1", "internal", "metadata"},
    ),
    ChainPattern(
        id="cred_reuse_lateral",
        name="Credential Reuse Lateral Movement",
        description="Use discovered credentials to access other systems",
        entry_types={"credential", "password"},
        intermediate_types={"ssh", "rdp", "smb"},
        exit_types={"lateral_move", "shell"},
        tactics=[MitreTactic.CREDENTIAL_ACCESS, MitreTactic.LATERAL_MOVEMENT],
        base_impact=ChainImpact.CRITICAL,
        keywords={"password", "credential", "username", "hash", "login"},
    ),
    ChainPattern(
        id="subdomain_takeover",
        name="Subdomain Takeover",
        description="Take over unclaimed subdomains pointing to external services",
        entry_types={"subdomain", "dns"},
        intermediate_types={"dangling", "cname"},
        exit_types={"takeover", "phishing"},
        tactics=[MitreTactic.RECONNAISSANCE, MitreTactic.INITIAL_ACCESS],
        base_impact=ChainImpact.MEDIUM,
        keywords={"subdomain", "cname", "dangling", "unclaimed", "takeover"},
    ),
    ChainPattern(
        id="lfi_to_rce",
        name="LFI to Remote Code Execution",
        description="Escalate Local File Inclusion to code execution",
        entry_types={"lfi", "vuln"},
        intermediate_types={"log", "session", "upload"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"lfi", "local file", "include", "..%2f", "log poison"},
    ),
    ChainPattern(
        id="exposed_admin_rce",
        name="Exposed Admin Panel Exploitation",
        description="Access exposed admin panel and achieve code execution",
        entry_types={"admin", "panel", "path"},
        intermediate_types={"upload", "config"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.HIGH,
        keywords={"admin", "panel", "dashboard", "upload", "webshell"},
    ),
    ChainPattern(
        id="weak_ssl_mitm",
        name="Weak SSL/TLS Man-in-the-Middle",
        description="Exploit weak SSL configuration for traffic interception",
        entry_types={"ssl", "tls", "vuln"},
        intermediate_types={"cipher", "protocol"},
        exit_types={"mitm", "credential"},
        tactics=[MitreTactic.CREDENTIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.MEDIUM,
        keywords={"ssl", "tls", "weak", "poodle", "beast", "heartbleed"},
    ),
    ChainPattern(
        id="service_exploit_privesc",
        name="Service Exploitation to Privilege Escalation",
        description="Exploit vulnerable service and escalate to root/admin",
        entry_types={"port", "service", "vuln"},
        intermediate_types={"shell", "access"},
        exit_types={"priv_esc", "root"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"service", "exploit", "cve", "rce", "root", "privilege"},
    ),
]


# ============================================================================
# Chain Analysis Engine
# ============================================================================

class ChainAnalyzer:
    """
    Analyzes findings to detect attack chains and prioritize exploitation paths.

    The analyzer uses:
    1. Pattern matching against known attack chain templates (60+ patterns)
    2. Finding correlation based on targets and relationships
    3. Evidence strength calculation for confidence scoring
    4. MITRE ATT&CK technique mapping
    5. Extended patterns for modern attack vectors (SSRF, XXE, SSTI, Cloud, K8s)

    Example:
        analyzer = ChainAnalyzer()

        # Add findings from scan
        for finding in scan_results:
            analyzer.add_finding(finding)

        # Detect chains
        chains = analyzer.analyze()

        # Get prioritized exploitation plan
        plan = analyzer.get_exploitation_plan()

        # Export for AI analysis
        llm_context = analyzer.to_llm_context()

        # Use extended patterns for more comprehensive analysis
        analyzer_extended = ChainAnalyzer(use_extended_patterns=True)
    """

    def __init__(self, use_extended_patterns: bool = True):
        """
        Initialize the ChainAnalyzer.

        Args:
            use_extended_patterns: If True, include 50+ additional attack patterns
                covering OWASP Top 10, API Security, Cloud, Containers, and more.
        """
        self.findings: Dict[str, Any] = {}
        self.findings_by_type: Dict[str, List[str]] = defaultdict(list)
        self.findings_by_host: Dict[str, List[str]] = defaultdict(list)
        self.findings_by_severity: Dict[str, List[str]] = defaultdict(list)
        self.use_extended_patterns = use_extended_patterns

        # Load patterns - optionally include extended patterns
        if use_extended_patterns:
            try:
                from .attack_patterns import EXTENDED_CHAIN_PATTERNS, EXTENDED_TECHNIQUE_MAP, ATTACK_TOOL_RECOMMENDATIONS
                self.patterns = CHAIN_PATTERNS + EXTENDED_CHAIN_PATTERNS
                self._extended_techniques = EXTENDED_TECHNIQUE_MAP
                self._extended_tools = ATTACK_TOOL_RECOMMENDATIONS
                logger.info(f"Loaded {len(self.patterns)} attack chain patterns (including extended)")
            except ImportError:
                logger.warning("Extended patterns not available, using base patterns only")
                self.patterns = CHAIN_PATTERNS
                self._extended_techniques = {}
                self._extended_tools = {}
        else:
            self.patterns = CHAIN_PATTERNS
            self._extended_techniques = {}
            self._extended_tools = {}

        self.detected_chains: List[AttackChain] = []

    def add_finding(self, finding: Any) -> None:
        """
        Add a finding for chain analysis.

        Args:
            finding: A finding object with id, type, value, severity, metadata
        """
        fid = getattr(finding, "id", str(id(finding)))
        self.findings[fid] = finding

        # Index by type
        ftype = getattr(finding, "type", "unknown").lower()
        self.findings_by_type[ftype].append(fid)

        # Index by host
        host = getattr(finding, "host", None) or finding.metadata.get("host", "")
        if host:
            self.findings_by_host[host].append(fid)

        # Index by severity
        severity = getattr(finding, "severity", "info")
        if hasattr(severity, "value"):
            severity = severity.value
        self.findings_by_severity[severity.lower()].append(fid)

    def add_findings(self, findings: List[Any]) -> None:
        """Add multiple findings."""
        for finding in findings:
            self.add_finding(finding)

    def analyze(self) -> List[AttackChain]:
        """
        Perform chain analysis on all findings.

        Returns:
            List of detected attack chains, sorted by risk score
        """
        self.detected_chains = []

        # Pattern-based detection
        for pattern in self.patterns:
            chains = self._match_pattern(pattern)
            self.detected_chains.extend(chains)

        # Cross-host correlation
        cross_host_chains = self._analyze_cross_host()
        self.detected_chains.extend(cross_host_chains)

        # Vulnerability chaining
        vuln_chains = self._chain_vulnerabilities()
        self.detected_chains.extend(vuln_chains)

        # Deduplicate and sort by risk
        self._deduplicate_chains()
        self.detected_chains.sort(key=lambda c: -c.risk_score)

        logger.info(f"Detected {len(self.detected_chains)} attack chains")
        return self.detected_chains

    def _match_pattern(self, pattern: ChainPattern) -> List[AttackChain]:
        """Match a specific attack pattern against findings."""
        chains = []

        # Find entry point findings
        entry_findings = []
        for ftype in pattern.entry_types:
            entry_findings.extend(self.findings_by_type.get(ftype, []))

        # Also check by keyword
        for fid, finding in self.findings.items():
            value = getattr(finding, "value", "").lower()
            desc = getattr(finding, "description", "").lower()
            if any(kw in value or kw in desc for kw in pattern.keywords):
                if fid not in entry_findings:
                    entry_findings.append(fid)

        if not entry_findings:
            return chains

        # For each entry point, build potential chain
        for entry_id in entry_findings:
            entry = self.findings[entry_id]

            # Calculate evidence strength
            evidence = self._calculate_evidence(entry, pattern)

            if evidence < 0.2:
                continue

            # Determine confidence
            if evidence >= 0.8:
                confidence = ChainConfidence.HIGH
            elif evidence >= 0.5:
                confidence = ChainConfidence.MEDIUM
            else:
                confidence = ChainConfidence.LOW

            # Build chain nodes
            nodes = [
                ChainNode(
                    id=f"node_{pattern.id}_1",
                    finding_id=entry_id,
                    technique=self._get_technique(pattern.id),
                    action=f"Exploit {getattr(entry, 'type', 'vulnerability')}",
                    result=f"Initial access via {getattr(entry, 'value', 'unknown')[:50]}",
                    evidence_strength=evidence,
                )
            ]

            # Add intermediate nodes based on related findings
            related = self._find_related_findings(entry_id, pattern.intermediate_types)
            for i, rel_id in enumerate(related[:2]):
                rel = self.findings[rel_id]
                nodes.append(ChainNode(
                    id=f"node_{pattern.id}_{i+2}",
                    finding_id=rel_id,
                    technique=None,
                    action=f"Leverage {getattr(rel, 'type', 'finding')}",
                    result=getattr(rel, 'value', '')[:50],
                    prerequisites=[nodes[-1].id],
                    evidence_strength=evidence * 0.8,
                ))

            # Add exit node
            nodes.append(ChainNode(
                id=f"node_{pattern.id}_exit",
                finding_id=entry_id,
                technique=self._get_technique_for_exit(pattern.exit_types),
                action=f"Achieve {list(pattern.exit_types)[0]}",
                result=pattern.description,
                prerequisites=[nodes[-1].id],
                evidence_strength=evidence * 0.7,
            ))

            # Create chain
            chain = AttackChain(
                id=f"chain_{pattern.id}_{entry_id[:8]}",
                name=pattern.name,
                description=f"{pattern.description} via {getattr(entry, 'value', 'unknown')[:30]}",
                nodes=nodes,
                confidence=confidence,
                impact=pattern.base_impact,
                mitre_tactics=pattern.tactics,
                target_assets=[getattr(entry, "host", "") or getattr(entry, "target", "")],
                recommended_tools=self._get_recommended_tools(pattern.id),
            )

            chains.append(chain)

        return chains

    def _calculate_evidence(self, finding: Any, pattern: ChainPattern) -> float:
        """Calculate evidence strength for a pattern match."""
        score = 0.0

        value = getattr(finding, "value", "").lower()
        desc = getattr(finding, "description", "").lower()

        # Keyword matches
        keyword_matches = sum(1 for kw in pattern.keywords if kw in value or kw in desc)
        score += min(0.4, keyword_matches * 0.1)

        # Severity bonus
        severity = getattr(finding, "severity", "info")
        if hasattr(severity, "value"):
            severity = severity.value
        severity_scores = {"critical": 0.3, "high": 0.2, "medium": 0.1, "low": 0.05}
        score += severity_scores.get(severity.lower(), 0)

        # CVE presence
        if hasattr(finding, "cve") and finding.cve:
            score += 0.2

        # Related findings bonus
        related = self._find_related_findings(
            getattr(finding, "id", str(id(finding))),
            pattern.intermediate_types
        )
        score += min(0.2, len(related) * 0.05)

        return min(1.0, score)

    def _find_related_findings(
        self,
        finding_id: str,
        types: Set[str],
    ) -> List[str]:
        """Find findings related by type or host."""
        related = []

        finding = self.findings.get(finding_id)
        if not finding:
            return related

        host = getattr(finding, "host", None) or finding.metadata.get("host", "")

        # Same host, different type
        for ftype in types:
            for fid in self.findings_by_type.get(ftype, []):
                if fid == finding_id:
                    continue
                other = self.findings[fid]
                other_host = getattr(other, "host", None) or other.metadata.get("host", "")
                if host and other_host == host:
                    related.append(fid)

        return related

    def _get_technique(self, pattern_id: str) -> Optional[MitreTechnique]:
        """Get MITRE technique for pattern."""
        # Base mapping for original patterns
        mapping = {
            "sqli_to_rce": "sqli",
            "sqli_data_breach": "sqli",
            "xss_session_hijack": "xss",
            "cred_reuse_lateral": "credential_dump",
            "service_exploit_privesc": "rce",
        }

        # Extended mapping for new patterns
        extended_mapping = {
            # SQLi variants
            "sqli_union_exfil": "sqli",
            "sqli_blind_boolean": "sqli",
            "sqli_time_based": "sqli",
            "sqli_stacked_rce": "sqli",
            "nosql_injection": "sqli",
            # Access Control
            "idor_horizontal": "idor",
            "idor_vertical": "idor",
            "bola_api": "idor",
            "bfla_api": "idor",
            "path_traversal_lfi": "path_traversal",
            "lfi_log_poison_rce": "path_traversal",
            "lfi_php_wrapper_rce": "path_traversal",
            # XSS
            "xss_stored_admin": "xss_stored",
            "xss_dom_based": "xss_reflected",
            "xss_to_csrf": "xss",
            "xss_keylogger": "xss_stored",
            # SSRF
            "ssrf_cloud_metadata": "ssrf",
            "ssrf_internal_scan": "ssrf",
            "ssrf_internal_exploit": "ssrf",
            "ssrf_file_read": "ssrf",
            # XXE
            "xxe_file_read": "xxe",
            "xxe_ssrf": "xxe",
            "xxe_blind_oob": "xxe",
            "xxe_rce": "xxe",
            # SSTI
            "ssti_jinja2_rce": "ssti",
            "ssti_twig_rce": "ssti",
            "ssti_freemarker_rce": "ssti",
            # Deserialization
            "java_deserial_rce": "deserialization",
            "php_deserial_rce": "deserialization",
            "python_pickle_rce": "deserialization",
            "dotnet_deserial_rce": "deserialization",
            # Auth
            "jwt_none_alg": "jwt_attack",
            "jwt_key_confusion": "jwt_attack",
            "jwt_secret_bruteforce": "jwt_attack",
            "oauth_redirect_theft": "oauth_flaw",
            "mfa_bypass_backup": "mfa_bypass",
            "password_reset_token": "brute_force",
            "session_fixation": "session_hijack",
            # API
            "graphql_introspection_enum": "graphql_introspection",
            "graphql_batching_dos": "dos",
            "api_mass_assignment": "idor",
            "api_rate_limit_bypass": "brute_force",
            # Cloud
            "aws_metadata_to_s3": "ssrf",
            "s3_bucket_takeover": "ssrf",
            "azure_metadata_to_keyvault": "ssrf",
            "gcp_metadata_to_storage": "ssrf",
            # Container/K8s
            "container_escape_privileged": "container_escape",
            "k8s_api_unauth": "container_discovery",
            "k8s_etcd_secret_dump": "credential_dump",
            "k8s_serviceaccount_abuse": "token_impersonation",
            # File Upload
            "file_upload_webshell": "file_upload",
            "file_upload_xxe": "xxe",
            "file_upload_polyglot": "file_upload",
            # Lateral Movement
            "kerberoasting_crack": "kerberoasting",
            "asreproast_crack": "asreproasting",
            "dcsync_ntds": "credential_dump",
            # PrivEsc
            "linux_sudo_privesc": "sudo_abuse",
            "linux_suid_privesc": "suid_abuse",
            "windows_token_impersonation": "token_impersonation",
            "windows_unquoted_service": "dll_hijack",
            # Command Injection
            "command_injection_rce": "command_injection",
            "ldap_injection": "sqli",
            "xpath_injection": "sqli",
        }

        key = mapping.get(pattern_id) or extended_mapping.get(pattern_id)

        # First check extended techniques, then fall back to base
        if key and hasattr(self, '_extended_techniques') and key in self._extended_techniques:
            return self._extended_techniques[key]
        return TECHNIQUE_MAP.get(key)

    def _get_technique_for_exit(self, exit_types: Set[str]) -> Optional[MitreTechnique]:
        """Get technique for exit type."""
        for exit_type in exit_types:
            if exit_type in TECHNIQUE_MAP:
                return TECHNIQUE_MAP[exit_type]
        return None

    def _get_recommended_tools(self, pattern_id: str) -> List[str]:
        """Get recommended tools for a pattern."""
        # Base tools for original patterns
        base_tools = {
            "sqli_to_rce": ["sqlmap", "burp"],
            "sqli_data_breach": ["sqlmap"],
            "xss_session_hijack": ["dalfox", "xsstrike"],
            "ssrf_internal_pivot": ["burp", "ffuf"],
            "cred_reuse_lateral": ["hydra", "crackmapexec"],
            "lfi_to_rce": ["burp", "ffuf"],
            "weak_ssl_mitm": ["testssl", "sslyze"],
            "service_exploit_privesc": ["metasploit", "searchsploit"],
        }

        # Extended tools for new patterns
        extended_tools = {
            # SQLi variants
            "sqli_union_exfil": ["sqlmap", "burp", "ghauri"],
            "sqli_blind_boolean": ["sqlmap", "burp"],
            "sqli_time_based": ["sqlmap", "burp"],
            "sqli_stacked_rce": ["sqlmap", "burp", "mssqlclient"],
            "nosql_injection": ["nosqlmap", "burp"],
            "ldap_injection": ["burp"],
            "xpath_injection": ["burp"],
            "command_injection_rce": ["commix", "burp"],
            # Access Control
            "idor_horizontal": ["burp", "autorize", "ffuf"],
            "idor_vertical": ["burp", "autorize"],
            "bola_api": ["burp", "autorize"],
            "bfla_api": ["burp"],
            "path_traversal_lfi": ["dotdotpwn", "burp", "ffuf"],
            "lfi_log_poison_rce": ["burp", "ffuf", "lfimap"],
            "lfi_php_wrapper_rce": ["burp", "lfimap"],
            # XSS
            "xss_stored_admin": ["dalfox", "xsstrike", "burp"],
            "xss_dom_based": ["dalfox", "burp"],
            "xss_to_csrf": ["burp", "xsstrike"],
            "xss_keylogger": ["beef", "burp"],
            # SSRF
            "ssrf_cloud_metadata": ["burp", "ssrfmap", "gopherus"],
            "ssrf_internal_scan": ["burp", "ffuf"],
            "ssrf_internal_exploit": ["burp", "ssrfmap", "gopherus"],
            "ssrf_file_read": ["burp", "ssrfmap"],
            # XXE
            "xxe_file_read": ["burp", "xxeinjector"],
            "xxe_ssrf": ["burp", "xxeinjector"],
            "xxe_blind_oob": ["burp", "xxeinjector", "oastify"],
            "xxe_rce": ["burp", "xxeinjector"],
            # SSTI
            "ssti_jinja2_rce": ["tplmap", "sstimap", "burp"],
            "ssti_twig_rce": ["tplmap", "burp"],
            "ssti_freemarker_rce": ["tplmap", "burp"],
            # Deserialization
            "java_deserial_rce": ["ysoserial", "burp", "jexboss"],
            "php_deserial_rce": ["phpggc", "burp"],
            "python_pickle_rce": ["burp"],
            "dotnet_deserial_rce": ["ysoserial.net", "burp"],
            # Auth
            "jwt_none_alg": ["jwt_tool", "burp"],
            "jwt_key_confusion": ["jwt_tool", "burp"],
            "jwt_secret_bruteforce": ["jwt_tool", "hashcat", "john"],
            "oauth_redirect_theft": ["burp"],
            "mfa_bypass_backup": ["burp"],
            "password_reset_token": ["burp", "ffuf"],
            "session_fixation": ["burp"],
            # API
            "graphql_introspection_enum": ["graphqlmap", "inql", "burp"],
            "graphql_batching_dos": ["graphqlmap", "burp"],
            "api_mass_assignment": ["burp", "postman"],
            "api_rate_limit_bypass": ["burp", "ffuf"],
            "api_version_exploit": ["burp", "ffuf"],
            # Cloud
            "aws_metadata_to_s3": ["pacu", "awscli", "cloudfox"],
            "s3_bucket_takeover": ["s3scanner", "bucket_finder"],
            "azure_metadata_to_keyvault": ["azurehound", "roadtools"],
            "gcp_metadata_to_storage": ["gcp_scanner"],
            # Container/K8s
            "container_escape_privileged": ["deepce", "cdkexec"],
            "k8s_api_unauth": ["kube-hunter", "kubectl"],
            "k8s_etcd_secret_dump": ["etcdctl"],
            "k8s_serviceaccount_abuse": ["kubectl", "kube-hunter"],
            # File Upload
            "file_upload_webshell": ["burp", "fuxploider"],
            "file_upload_xxe": ["burp", "xxeinjector"],
            "file_upload_polyglot": ["burp", "exiftool"],
            # Lateral Movement / AD
            "kerberoasting_crack": ["impacket", "rubeus", "hashcat"],
            "asreproast_crack": ["impacket", "rubeus", "hashcat"],
            "dcsync_ntds": ["mimikatz", "impacket"],
            # PrivEsc
            "linux_sudo_privesc": ["linpeas", "gtfobins"],
            "linux_suid_privesc": ["linpeas", "gtfobins"],
            "windows_token_impersonation": ["winpeas", "incognito", "potato"],
            "windows_unquoted_service": ["winpeas", "powerup"],
        }

        # Check base tools first, then extended
        if pattern_id in base_tools:
            return base_tools[pattern_id]
        if pattern_id in extended_tools:
            return extended_tools[pattern_id]

        # Try to get from extended tool recommendations by pattern type
        if hasattr(self, '_extended_tools'):
            for key in ["sqli", "xss", "ssrf", "xxe", "ssti", "jwt", "api", "container", "kubernetes"]:
                if key in pattern_id.lower():
                    return self._extended_tools.get(key, [])

        return ["burp", "manual"]

    def _analyze_cross_host(self) -> List[AttackChain]:
        """Analyze attack chains that span multiple hosts."""
        chains = []

        # Find credentials that could enable lateral movement
        cred_findings = self.findings_by_type.get("credential", [])
        port_findings = self.findings_by_type.get("port", [])

        if cred_findings and port_findings:
            # Look for SSH/RDP ports that could be accessed with found creds
            ssh_ports = [
                fid for fid in port_findings
                if self.findings[fid].metadata.get("port") in [22, 2222]
            ]
            rdp_ports = [
                fid for fid in port_findings
                if self.findings[fid].metadata.get("port") == 3389
            ]

            if ssh_ports:
                chains.append(self._build_lateral_chain(
                    cred_findings[0], ssh_ports[0], "SSH"
                ))

            if rdp_ports:
                chains.append(self._build_lateral_chain(
                    cred_findings[0], rdp_ports[0], "RDP"
                ))

        return chains

    def _build_lateral_chain(
        self,
        cred_id: str,
        port_id: str,
        service: str,
    ) -> AttackChain:
        """Build a lateral movement chain."""
        cred = self.findings[cred_id]
        port = self.findings[port_id]

        return AttackChain(
            id=f"chain_lateral_{service.lower()}_{cred_id[:8]}",
            name=f"Lateral Movement via {service}",
            description=f"Use discovered credentials for {service} access",
            nodes=[
                ChainNode(
                    id="node_cred",
                    finding_id=cred_id,
                    technique=TECHNIQUE_MAP.get("credential_dump"),
                    action="Obtain credentials",
                    result=f"Credentials: {getattr(cred, 'value', 'unknown')[:30]}",
                    evidence_strength=0.8,
                ),
                ChainNode(
                    id=f"node_{service.lower()}",
                    finding_id=port_id,
                    technique=TECHNIQUE_MAP.get(f"lateral_{service.lower()}"),
                    action=f"Connect via {service}",
                    result=f"Access to {port.metadata.get('host', 'target')}",
                    prerequisites=["node_cred"],
                    evidence_strength=0.6,
                ),
            ],
            confidence=ChainConfidence.MEDIUM,
            impact=ChainImpact.HIGH,
            mitre_tactics=[MitreTactic.CREDENTIAL_ACCESS, MitreTactic.LATERAL_MOVEMENT],
            target_assets=[port.metadata.get("host", "")],
            recommended_tools=["hydra", "crackmapexec", "sshpass"],
        )

    def _chain_vulnerabilities(self) -> List[AttackChain]:
        """Chain multiple vulnerabilities for maximum impact."""
        chains = []

        vulns = self.findings_by_type.get("vuln", [])
        critical_vulns = [
            fid for fid in vulns
            if self.findings[fid].severity in ["critical", "CRITICAL"]
            or (hasattr(self.findings[fid].severity, "value")
                and self.findings[fid].severity.value == "critical")
        ]

        # Chain critical vulns on same host
        by_host = defaultdict(list)
        for fid in critical_vulns:
            host = self.findings[fid].metadata.get("host", "unknown")
            by_host[host].append(fid)

        for host, fids in by_host.items():
            if len(fids) >= 2:
                chains.append(self._build_multi_vuln_chain(host, fids))

        return chains

    def _build_multi_vuln_chain(
        self,
        host: str,
        finding_ids: List[str],
    ) -> AttackChain:
        """Build chain from multiple vulnerabilities."""
        nodes = []
        for i, fid in enumerate(finding_ids[:4]):
            finding = self.findings[fid]
            nodes.append(ChainNode(
                id=f"node_vuln_{i}",
                finding_id=fid,
                technique=TECHNIQUE_MAP.get("rce"),
                action=f"Exploit {getattr(finding, 'type', 'vuln')}",
                result=getattr(finding, "value", "")[:50],
                prerequisites=[f"node_vuln_{i-1}"] if i > 0 else [],
                evidence_strength=0.9,
            ))

        return AttackChain(
            id=f"chain_multi_vuln_{host[:8]}",
            name=f"Multi-Vulnerability Exploitation ({host})",
            description=f"Chain {len(finding_ids)} critical vulnerabilities on {host}",
            nodes=nodes,
            confidence=ChainConfidence.HIGH,
            impact=ChainImpact.CRITICAL,
            mitre_tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION, MitreTactic.PRIVILEGE_ESC],
            target_assets=[host],
            recommended_tools=["metasploit", "burp"],
        )

    def _deduplicate_chains(self) -> None:
        """Remove duplicate chains."""
        seen = set()
        unique = []

        for chain in self.detected_chains:
            # Key based on name and primary finding
            key = f"{chain.name}_{chain.nodes[0].finding_id if chain.nodes else ''}"
            if key not in seen:
                seen.add(key)
                unique.append(chain)

        self.detected_chains = unique

    # =========================================================================
    # Output Methods
    # =========================================================================

    def get_exploitation_plan(self, max_chains: int = 5) -> Dict[str, Any]:
        """
        Generate a prioritized exploitation plan.

        Returns:
            Dictionary with prioritized attack chains and recommendations
        """
        if not self.detected_chains:
            self.analyze()

        top_chains = self.detected_chains[:max_chains]

        return {
            "target_count": len(set(
                asset for chain in top_chains for asset in chain.target_assets
            )),
            "total_chains": len(self.detected_chains),
            "prioritized_chains": [
                {
                    "priority": i + 1,
                    "name": chain.name,
                    "risk_score": chain.risk_score,
                    "confidence": chain.confidence.value,
                    "impact": chain.impact.value,
                    "steps": len(chain.nodes),
                    "recommended_tools": chain.recommended_tools,
                }
                for i, chain in enumerate(top_chains)
            ],
            "immediate_actions": [
                chain.nodes[0].action for chain in top_chains if chain.nodes
            ],
        }

    def to_llm_context(self, max_chains: int = 10, max_tokens: int = 2000) -> str:
        """
        Export analysis for LLM consumption.

        Args:
            max_chains: Maximum chains to include
            max_tokens: Approximate token budget

        Returns:
            Compact string for LLM context
        """
        if not self.detected_chains:
            self.analyze()

        lines = ["## Attack Chain Analysis"]
        lines.append(f"Total Chains: {len(self.detected_chains)}")
        lines.append("")

        # Summary by impact
        by_impact = defaultdict(list)
        for chain in self.detected_chains:
            by_impact[chain.impact.value].append(chain)

        lines.append("### By Impact")
        for impact in ["critical", "high", "medium", "low"]:
            count = len(by_impact.get(impact, []))
            if count:
                lines.append(f"- {impact.upper()}: {count}")

        lines.append("")
        lines.append("### Top Attack Chains")

        for chain in self.detected_chains[:max_chains]:
            lines.append(f"\n{chain.to_compact()}")
            lines.append(f"  Tactics: {' → '.join(t.value for t in chain.mitre_tactics)}")
            if chain.recommended_tools:
                lines.append(f"  Tools: {', '.join(chain.recommended_tools)}")

        result = "\n".join(lines)

        # Truncate if needed
        if len(result) > max_tokens * 4:  # Rough char to token estimate
            result = result[:max_tokens * 4] + "\n... (truncated)"

        return result

    def to_json(self, indent: int = 2) -> str:
        """Export all chains to JSON."""
        if not self.detected_chains:
            self.analyze()

        return json.dumps({
            "analysis_summary": {
                "total_findings": len(self.findings),
                "total_chains": len(self.detected_chains),
                "by_impact": {
                    impact.value: len([c for c in self.detected_chains if c.impact == impact])
                    for impact in ChainImpact
                },
            },
            "chains": [chain.to_dict() for chain in self.detected_chains],
        }, indent=indent, default=str)


# ============================================================================
# Convenience Functions
# ============================================================================

def analyze_findings(findings: List[Any]) -> List[AttackChain]:
    """
    Quick chain analysis on a list of findings.

    Args:
        findings: List of finding objects

    Returns:
        List of detected attack chains
    """
    analyzer = ChainAnalyzer()
    analyzer.add_findings(findings)
    return analyzer.analyze()


def get_top_attack_paths(
    findings: List[Any],
    max_paths: int = 5,
) -> List[Dict[str, Any]]:
    """
    Get top attack paths from findings.

    Args:
        findings: List of finding objects
        max_paths: Maximum paths to return

    Returns:
        List of attack path dictionaries
    """
    chains = analyze_findings(findings)
    return [chain.to_dict() for chain in chains[:max_paths]]
