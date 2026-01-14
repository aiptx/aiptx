"""
AIPT Finding Model - Unified vulnerability representation

This model represents vulnerabilities discovered by ANY tool in the pipeline:
- Traditional scanners (Acunetix, Burp, Nuclei, ZAP)
- AI-autonomous agents (Strix)
- Manual exploitation attempts
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import hashlib
import json


class Severity(Enum):
    """CVSS-aligned severity levels"""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # CVSS 0.0 / Informational

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.INFO

    def __lt__(self, other: "Severity") -> bool:
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)


class VulnerabilityType(Enum):
    """OWASP Top 10 aligned vulnerability categories"""
    # A01:2021 - Broken Access Control
    IDOR = "idor"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # A02:2021 - Cryptographic Failures
    WEAK_CRYPTO = "weak_crypto"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"

    # A03:2021 - Injection
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    NOSQL_INJECTION = "nosql_injection"

    # A04:2021 - Insecure Design
    BUSINESS_LOGIC_FLAW = "business_logic_flaw"

    # A05:2021 - Security Misconfiguration
    MISCONFIGURATION = "misconfiguration"
    DEFAULT_CREDENTIALS = "default_credentials"
    DIRECTORY_LISTING = "directory_listing"

    # A06:2021 - Vulnerable Components
    OUTDATED_COMPONENT = "outdated_component"
    KNOWN_CVE = "known_cve"

    # A07:2021 - Authentication Failures
    AUTH_BYPASS = "auth_bypass"
    WEAK_PASSWORD = "weak_password"
    SESSION_FIXATION = "session_fixation"

    # A08:2021 - Software Integrity Failures
    INSECURE_DESERIALIZATION = "insecure_deserialization"

    # A09:2021 - Logging & Monitoring Failures
    INSUFFICIENT_LOGGING = "insufficient_logging"

    # A10:2021 - SSRF
    SSRF = "ssrf"

    # Cross-Site Scripting (separate category)
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"

    # Other
    OPEN_REDIRECT = "open_redirect"
    FILE_INCLUSION = "file_inclusion"
    FILE_UPLOAD = "file_upload"
    XXE = "xxe"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    CSRF = "csrf"
    INFORMATION_DISCLOSURE = "information_disclosure"
    RCE = "rce"

    # Catch-all
    OTHER = "other"


@dataclass
class Finding:
    """
    Unified vulnerability finding from any source

    This is the core data structure that normalizes findings from:
    - Acunetix (JSON API responses)
    - Burp Suite (XML/JSON exports)
    - Nuclei (JSON output)
    - ZAP (JSON API responses)
    - Strix (AI agent reports)
    """

    # Core identification
    title: str
    severity: Severity
    vuln_type: VulnerabilityType

    # Location
    url: str
    parameter: str | None = None
    method: str = "GET"

    # Evidence
    description: str = ""
    evidence: str = ""
    request: str | None = None
    response: str | None = None

    # Source tracking
    source: str = "unknown"  # acunetix, burp, nuclei, zap, aipt, manual
    source_id: str | None = None  # Original ID from source scanner

    # Validation
    confirmed: bool = False
    exploited: bool = False
    poc_command: str | None = None

    # Metadata
    cvss_score: float | None = None
    cwe_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # Remediation
    remediation: str = ""

    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    # AI-specific fields (for Strix findings)
    ai_reasoning: str | None = None
    ai_confidence: float | None = None  # 0.0 to 1.0

    def __post_init__(self):
        """Generate unique fingerprint for deduplication"""
        self._fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """
        Generate a unique fingerprint for finding deduplication.

        Two findings are considered duplicates if they have the same:
        - URL (normalized)
        - Parameter
        - Vulnerability type
        """
        normalized_url = self.url.rstrip("/").lower()
        data = f"{normalized_url}:{self.parameter}:{self.vuln_type.value}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def is_duplicate_of(self, other: "Finding") -> bool:
        """Check if this finding is a duplicate of another"""
        return self.fingerprint == other.fingerprint

    def merge_with(self, other: "Finding") -> "Finding":
        """
        Merge two duplicate findings, keeping the best evidence from both.
        Prefers confirmed/exploited findings, higher confidence, more details.
        """
        # Prefer the confirmed/exploited finding
        if other.confirmed and not self.confirmed:
            base, supplement = other, self
        elif other.exploited and not self.exploited:
            base, supplement = other, self
        else:
            base, supplement = self, other

        # Merge evidence
        merged_evidence = base.evidence
        if supplement.evidence and supplement.evidence not in merged_evidence:
            merged_evidence = f"{merged_evidence}\n\n--- Additional Evidence ---\n{supplement.evidence}"

        # Merge sources
        sources = set([base.source, supplement.source])
        merged_source = ", ".join(sorted(sources))

        # Take highest confidence
        confidence = max(
            base.ai_confidence or 0,
            supplement.ai_confidence or 0
        ) or None

        return Finding(
            title=base.title,
            severity=max(base.severity, other.severity),  # Take highest severity
            vuln_type=base.vuln_type,
            url=base.url,
            parameter=base.parameter,
            method=base.method,
            description=base.description or supplement.description,
            evidence=merged_evidence,
            request=base.request or supplement.request,
            response=base.response or supplement.response,
            source=merged_source,
            confirmed=base.confirmed or supplement.confirmed,
            exploited=base.exploited or supplement.exploited,
            poc_command=base.poc_command or supplement.poc_command,
            cvss_score=base.cvss_score or supplement.cvss_score,
            cwe_id=base.cwe_id or supplement.cwe_id,
            cve_ids=list(set(base.cve_ids + supplement.cve_ids)),
            references=list(set(base.references + supplement.references)),
            remediation=base.remediation or supplement.remediation,
            ai_reasoning=base.ai_reasoning or supplement.ai_reasoning,
            ai_confidence=confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity.value,
            "vuln_type": self.vuln_type.value,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "source": self.source,
            "source_id": self.source_id,
            "confirmed": self.confirmed,
            "exploited": self.exploited,
            "poc_command": self.poc_command,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "cve_ids": self.cve_ids,
            "references": self.references,
            "remediation": self.remediation,
            "discovered_at": self.discovered_at.isoformat(),
            "ai_reasoning": self.ai_reasoning,
            "ai_confidence": self.ai_confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create Finding from dictionary"""
        return cls(
            title=data["title"],
            severity=Severity(data["severity"]),
            vuln_type=VulnerabilityType(data.get("vuln_type", "other")),
            url=data["url"],
            parameter=data.get("parameter"),
            method=data.get("method", "GET"),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            request=data.get("request"),
            response=data.get("response"),
            source=data.get("source", "unknown"),
            source_id=data.get("source_id"),
            confirmed=data.get("confirmed", False),
            exploited=data.get("exploited", False),
            poc_command=data.get("poc_command"),
            cvss_score=data.get("cvss_score"),
            cwe_id=data.get("cwe_id"),
            cve_ids=data.get("cve_ids", []),
            references=data.get("references", []),
            remediation=data.get("remediation", ""),
            discovered_at=datetime.fromisoformat(data["discovered_at"]) if "discovered_at" in data else datetime.utcnow(),
            ai_reasoning=data.get("ai_reasoning"),
            ai_confidence=data.get("ai_confidence"),
        )
