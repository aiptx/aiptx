"""
AIPT Finding Model - Unified vulnerability representation

This model represents vulnerabilities discovered by ANY tool in the pipeline:
- Traditional scanners (Acunetix, Burp, Nuclei, ZAP)
- AI-autonomous agents (Strix)
- Manual exploitation attempts
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class VerificationStatus(Enum):
    """
    Verification status for findings - determines reportability.

    This is the core mechanism for eliminating false positives:
    - Critical/High findings MUST be CONFIRMED to be reported
    - Medium findings can be CONFIRMED or LIKELY
    - Low/Info can be POTENTIAL but not UNVERIFIED
    """

    UNVERIFIED = "unverified"  # Initial state, no validation attempted
    PENDING = "pending"  # Queued for validation
    IN_PROGRESS = "in_progress"  # Currently being validated
    CONFIRMED = "confirmed"  # Verified with evidence (callback, content, etc.)
    LIKELY = "likely"  # High confidence but no definitive proof
    POTENTIAL = "potential"  # Low confidence, needs manual review
    FALSE_POSITIVE = "false_positive"  # Proven not exploitable
    MANUAL_REVIEW = "manual_review"  # Cannot be auto-verified, needs human review


class Severity(Enum):
    """CVSS-aligned severity levels"""

    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"  # CVSS 7.0-8.9
    MEDIUM = "medium"  # CVSS 4.0-6.9
    LOW = "low"  # CVSS 0.1-3.9
    INFO = "info"  # CVSS 0.0 / Informational

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
    """
    OWASP Top 10 aligned vulnerability categories.

    This is the canonical VulnerabilityType enum used throughout AIPTX.
    All modules should import from here to prevent enum mismatch errors.

    Includes additional types for vulnerability chaining analysis.
    """

    # A01:2021 - Broken Access Control
    IDOR = "idor"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PATH_TRAVERSAL = "path_traversal"

    # A02:2021 - Cryptographic Failures
    WEAK_CRYPTO = "weak_crypto"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    HARDCODED_SECRETS = "hardcoded_secrets"

    # A03:2021 - Injection
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    NOSQL_INJECTION = "nosql_injection"

    # A04:2021 - Insecure Design
    BUSINESS_LOGIC_FLAW = "business_logic_flaw"
    BUSINESS_LOGIC = "business_logic"  # Alias for chaining compatibility

    # A05:2021 - Security Misconfiguration
    MISCONFIGURATION = "misconfiguration"
    DEFAULT_CREDENTIALS = "default_credentials"
    DIRECTORY_LISTING = "directory_listing"
    EXPOSED_ADMIN = "exposed_admin_panel"

    # A06:2021 - Vulnerable Components
    OUTDATED_COMPONENT = "outdated_component"
    KNOWN_CVE = "known_cve"

    # A07:2021 - Authentication Failures
    AUTH_BYPASS = "auth_bypass"
    BROKEN_AUTH = "broken_authentication"  # Alias for chaining compatibility
    WEAK_PASSWORD = "weak_password"
    SESSION_FIXATION = "session_fixation"

    # A08:2021 - Software Integrity Failures
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    DESERIALIZATION = "deserialization"  # Alias for chaining compatibility

    # A09:2021 - Logging & Monitoring Failures
    INSUFFICIENT_LOGGING = "insufficient_logging"

    # A10:2021 - SSRF
    SSRF = "ssrf"

    # Cross-Site Scripting (separate category)
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"

    # File Inclusion (LFI/RFI)
    FILE_INCLUSION = "file_inclusion"
    LFI = "lfi"  # Local File Inclusion
    RFI = "rfi"  # Remote File Inclusion

    # Other Common Vulnerabilities
    OPEN_REDIRECT = "open_redirect"
    FILE_UPLOAD = "file_upload"
    XXE = "xxe"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    CSRF = "csrf"
    CLICKJACKING = "clickjacking"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SOURCE_CODE_DISCLOSURE = "source_code_disclosure"
    RCE = "rce"
    DOS = "denial_of_service"

    # Catch-all
    OTHER = "other"
    UNKNOWN = "unknown"  # For unclassified vulnerabilities


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

    # Verification state machine (for false positive elimination)
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    verification_attempts: int = 0
    last_verification_at: datetime | None = None

    # Callback verification for blind/OOB vulnerabilities (SSRF, XXE, Blind SQLi)
    callback_id: str | None = None
    callback_received: bool = False
    callback_data: dict[str, Any] = field(default_factory=dict)

    # Evidence tracking for verification
    verification_evidence: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Generate unique fingerprint for deduplication"""
        self._fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """
        Generate a unique fingerprint for finding deduplication.

        Enhanced fingerprinting to prevent over-aggressive deduplication.
        Two findings are considered duplicates ONLY if they have the same:
        - URL path (not query params, to avoid false dedup)
        - HTTP method
        - Parameter name
        - Vulnerability type
        - Root cause signature (extracted from evidence)

        This ensures different endpoints are NOT incorrectly merged.
        """
        from urllib.parse import urlparse

        # Parse URL and use only the path (not query params or fragments)
        parsed = urlparse(self.url)
        normalized_path = parsed.path.rstrip("/").lower()

        # Include host to differentiate internal vs external targets
        host = parsed.netloc.lower()

        # Create compound key with all distinguishing factors
        components = [
            host,
            normalized_path,
            self.method.upper(),
            self.parameter or "_no_param_",
            self.vuln_type.value,
            self._get_root_cause_signature(),
        ]

        data = "|".join(str(c) for c in components)
        return hashlib.sha256(data.encode()).hexdigest()[:24]

    def _get_root_cause_signature(self) -> str:
        """
        Extract root cause signature from evidence for better deduplication.

        Findings with the same root cause (e.g., same SQL error message)
        can be deduplicated, but different root causes should remain separate.
        """
        evidence_lower = (self.evidence or "").lower()

        # SQL Injection signatures
        if "sql syntax" in evidence_lower or "mysql" in evidence_lower:
            return "sqli_mysql"
        if "postgresql" in evidence_lower or "pg_" in evidence_lower:
            return "sqli_postgres"
        if "sqlite" in evidence_lower:
            return "sqli_sqlite"
        if "ora-" in evidence_lower:
            return "sqli_oracle"

        # XSS signatures
        if "<script" in evidence_lower:
            return "xss_script"
        if "onerror" in evidence_lower or "onload" in evidence_lower:
            return "xss_event"

        # SSRF signatures - differentiate by target
        if "169.254.169.254" in evidence_lower:
            return "ssrf_aws_metadata"
        if "metadata.google" in evidence_lower:
            return "ssrf_gcp_metadata"
        if "localhost" in evidence_lower or "127.0.0.1" in evidence_lower:
            return "ssrf_localhost"

        # Default: use vuln type as signature
        return self.vuln_type.value

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def is_duplicate_of(self, other: "Finding") -> bool:
        """Check if this finding is a duplicate of another"""
        return self.fingerprint == other.fingerprint

    def is_reportable(self) -> bool:
        """
        Check if finding meets reporting criteria based on severity and verification status.

        Reporting rules (to eliminate false positives):
        - CRITICAL/HIGH: MUST be CONFIRMED (verified with evidence)
        - MEDIUM: Can be CONFIRMED or LIKELY (high confidence)
        - LOW/INFO: Can be POTENTIAL but not UNVERIFIED or FALSE_POSITIVE

        This ensures only validated findings reach the final report.
        """
        # Never report false positives
        if self.verification_status == VerificationStatus.FALSE_POSITIVE:
            return False

        # Critical and High severity require confirmed status
        if self.severity in [Severity.CRITICAL, Severity.HIGH]:
            return self.verification_status == VerificationStatus.CONFIRMED

        # Medium severity can be confirmed or likely
        if self.severity == Severity.MEDIUM:
            return self.verification_status in [
                VerificationStatus.CONFIRMED,
                VerificationStatus.LIKELY,
            ]

        # Low and Info can be potential (for informational purposes)
        # but not unverified or pending
        return self.verification_status not in [
            VerificationStatus.UNVERIFIED,
            VerificationStatus.PENDING,
            VerificationStatus.FALSE_POSITIVE,
        ]

    def needs_verification(self) -> bool:
        """
        Check if finding requires verification before reporting.

        Returns True if:
        - Status is UNVERIFIED or PENDING
        - Severity is CRITICAL, HIGH, or MEDIUM (important enough to verify)
        """
        return self.verification_status in [
            VerificationStatus.UNVERIFIED,
            VerificationStatus.PENDING,
        ] and self.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]

    def mark_verified(
        self,
        status: VerificationStatus,
        evidence: str | None = None,
        confidence: float | None = None,
    ) -> None:
        """
        Mark finding as verified with given status.

        Args:
            status: The verification result status
            evidence: Optional evidence string from verification
            confidence: Optional confidence score (0.0-1.0)
        """
        self.verification_status = status
        self.verification_attempts += 1
        self.last_verification_at = datetime.utcnow()

        if evidence:
            self.verification_evidence.append(evidence)
            self.evidence = (
                f"{self.evidence}\n\n--- Verification Evidence ---\n{evidence}"
                if self.evidence
                else evidence
            )

        if confidence is not None:
            self.ai_confidence = confidence

        # Update confirmed/exploited flags based on status
        if status == VerificationStatus.CONFIRMED:
            self.confirmed = True
            self.exploited = True
        elif status == VerificationStatus.FALSE_POSITIVE:
            self.confirmed = False
            self.exploited = False

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
            merged_evidence = (
                f"{merged_evidence}\n\n--- Additional Evidence ---\n{supplement.evidence}"
            )

        # Merge sources
        sources = set([base.source, supplement.source])
        merged_source = ", ".join(sorted(sources))

        # Take highest confidence
        confidence = max(base.ai_confidence or 0, supplement.ai_confidence or 0) or None

        # Determine best verification status (prefer CONFIRMED over others)
        verification_priority = [
            VerificationStatus.CONFIRMED,
            VerificationStatus.LIKELY,
            VerificationStatus.POTENTIAL,
            VerificationStatus.MANUAL_REVIEW,
            VerificationStatus.IN_PROGRESS,
            VerificationStatus.PENDING,
            VerificationStatus.UNVERIFIED,
            VerificationStatus.FALSE_POSITIVE,
        ]
        base_priority = (
            verification_priority.index(base.verification_status)
            if base.verification_status in verification_priority
            else 99
        )
        supp_priority = (
            verification_priority.index(supplement.verification_status)
            if supplement.verification_status in verification_priority
            else 99
        )
        best_verification = (
            base.verification_status
            if base_priority <= supp_priority
            else supplement.verification_status
        )

        # Merge verification evidence
        merged_verification_evidence = list(
            set(base.verification_evidence + supplement.verification_evidence)
        )

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
            # Verification fields - preserve the best status
            verification_status=best_verification,
            verification_attempts=max(base.verification_attempts, supplement.verification_attempts),
            last_verification_at=base.last_verification_at or supplement.last_verification_at,
            callback_id=base.callback_id or supplement.callback_id,
            callback_received=base.callback_received or supplement.callback_received,
            callback_data={**supplement.callback_data, **base.callback_data},
            verification_evidence=merged_verification_evidence,
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
            # Verification fields
            "verification_status": self.verification_status.value,
            "verification_attempts": self.verification_attempts,
            "last_verification_at": (
                self.last_verification_at.isoformat() if self.last_verification_at else None
            ),
            "callback_id": self.callback_id,
            "callback_received": self.callback_received,
            "callback_data": self.callback_data,
            "verification_evidence": self.verification_evidence,
            "is_reportable": self.is_reportable(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create Finding from dictionary"""
        # Parse verification status
        verification_status = VerificationStatus.UNVERIFIED
        if "verification_status" in data:
            try:
                verification_status = VerificationStatus(data["verification_status"])
            except ValueError:
                verification_status = VerificationStatus.UNVERIFIED

        # Parse last_verification_at
        last_verification_at = None
        if data.get("last_verification_at"):
            try:
                last_verification_at = datetime.fromisoformat(data["last_verification_at"])
            except (ValueError, TypeError):
                pass

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
            discovered_at=(
                datetime.fromisoformat(data["discovered_at"])
                if "discovered_at" in data
                else datetime.utcnow()
            ),
            ai_reasoning=data.get("ai_reasoning"),
            ai_confidence=data.get("ai_confidence"),
            # Verification fields
            verification_status=verification_status,
            verification_attempts=data.get("verification_attempts", 0),
            last_verification_at=last_verification_at,
            callback_id=data.get("callback_id"),
            callback_received=data.get("callback_received", False),
            callback_data=data.get("callback_data", {}),
            verification_evidence=data.get("verification_evidence", []),
        )
