"""
AIPT FindingV2 - Canonical Finding Schema for Normalized Pipeline

This is the canonical finding format used throughout the new findings pipeline:
Scanner -> Normalizer -> findings_raw.json -> Dedupe -> Verifier -> canonical_findings.json -> Reports

Key differences from legacy Finding:
- Default verification_status is NEEDS_REVIEW (not UNVERIFIED)
- FindingCategory routes findings to appropriate verification policy
- ScannerType tracks execution context (local/VPS/enterprise API)
- Proper URL normalization (no double slashes)
- All severities are enum-only (no numeric)

Backward compatible with legacy Finding class via converters.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse, urljoin


class FindingCategory(Enum):
    """
    Categories for routing findings to appropriate verification policies.

    Each category has specific verification rules:
    - TLS_SSL: Auto-confirm from authoritative scanners
    - EXPOSURE: Verify content exists and is meaningful
    - CVE_VERSION: Verify version matches CVE requirements
    - INJECTION_SSTI: Requires canary+flip test
    - HOST_HEADER: Requires demonstrable impact
    - SSRF: Requires OOB callback or content verification
    """
    TLS_SSL = "tls_ssl"                    # SSL/TLS issues (auto-confirm from sslscan/testssl)
    EXPOSURE = "exposure"                  # Info disclosure, sensitive files, phpinfo
    CVE_VERSION = "cve_version"            # Version-based CVEs (requires version match)
    INJECTION_SSTI = "injection_ssti"      # SSTI (requires canary+flip verification)
    INJECTION_SQLI = "injection_sqli"      # SQL Injection
    INJECTION_XSS = "injection_xss"        # Cross-Site Scripting
    INJECTION_CMDI = "injection_cmdi"      # Command Injection
    INJECTION_XXE = "injection_xxe"        # XML External Entity
    HOST_HEADER = "host_header"            # Host Header Injection (impact-only)
    SSRF = "ssrf"                          # Server-Side Request Forgery
    CONFIG = "config"                      # Misconfigurations
    AUTH = "auth"                          # Authentication issues
    ACCESS_CONTROL = "access_control"      # Authorization/IDOR issues
    CRYPTO = "crypto"                      # Cryptographic weaknesses
    SECRETS = "secrets"                    # Hardcoded secrets/credentials
    CSRF = "csrf"                          # Cross-Site Request Forgery
    OPEN_REDIRECT = "open_redirect"        # Open Redirect
    FILE_UPLOAD = "file_upload"            # File Upload vulnerabilities
    DESERIALIZATION = "deserialization"    # Insecure Deserialization
    OTHER = "other"                        # Uncategorized


class VerificationStatusV2(Enum):
    """
    Verification status for the new pipeline.

    Key change: Default is NEEDS_REVIEW (not UNVERIFIED)

    State machine:
    NEEDS_REVIEW -> PENDING -> IN_PROGRESS -> CONFIRMED/LIKELY/SUPPRESSED_FP/MANUAL_REVIEW
    """
    NEEDS_REVIEW = "needs_review"          # Default state - requires verification
    PENDING = "pending"                    # Queued for verification
    IN_PROGRESS = "in_progress"            # Currently being verified
    CONFIRMED = "confirmed"                # Verified with evidence
    LIKELY = "likely"                      # High confidence, no definitive proof
    SUPPRESSED_FP = "suppressed_fp"        # Confirmed false positive (suppressed)
    MANUAL_REVIEW = "manual_review"        # Cannot auto-verify, needs human review


class ScannerType(Enum):
    """
    Scanner execution context for tracking tool origin.

    Used to properly attribute findings and handle failures.
    """
    LOCAL = "local"                        # Local tool execution (subprocess)
    VPS = "vps"                            # Remote VPS execution (SSH)
    API_ENTERPRISE = "api_enterprise"      # Enterprise scanner API (Acunetix, Burp, Nessus, ZAP)
    FAILED = "failed"                      # Tool failed to execute


class SeverityV2(Enum):
    """
    CVSS-aligned severity levels (enum only, no numeric).

    Maps to CVSS score ranges but stored as enum strings.
    """
    CRITICAL = "critical"                  # CVSS 9.0-10.0
    HIGH = "high"                          # CVSS 7.0-8.9
    MEDIUM = "medium"                      # CVSS 4.0-6.9
    LOW = "low"                            # CVSS 0.1-3.9
    INFO = "info"                          # CVSS 0.0 / Informational

    @classmethod
    def from_cvss(cls, score: float) -> "SeverityV2":
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

    @classmethod
    def from_string(cls, s: str) -> "SeverityV2":
        """Convert string to severity enum"""
        s_lower = s.lower().strip()
        mapping = {
            "critical": cls.CRITICAL, "crit": cls.CRITICAL, "4": cls.CRITICAL,
            "high": cls.HIGH, "3": cls.HIGH,
            "medium": cls.MEDIUM, "med": cls.MEDIUM, "2": cls.MEDIUM,
            "low": cls.LOW, "1": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO, "0": cls.INFO,
        }
        return mapping.get(s_lower, cls.INFO)

    @classmethod
    def from_numeric(cls, n: int) -> "SeverityV2":
        """Convert numeric severity (0-4) to enum"""
        mapping = {4: cls.CRITICAL, 3: cls.HIGH, 2: cls.MEDIUM, 1: cls.LOW, 0: cls.INFO}
        return mapping.get(n, cls.INFO)

    def __lt__(self, other: "SeverityV2") -> bool:
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class FindingV2:
    """
    Canonical finding schema for the normalized pipeline.

    This is the authoritative format for all findings after normalization.
    Reports ONLY read from canonical_findings.json which contains FindingV2 objects.

    Key fields:
    - id: UUID for tracking
    - fingerprint: SHA256 for deduplication
    - category: Routes to verification policy
    - verification_status: Default NEEDS_REVIEW
    - source_scanner_type: LOCAL/VPS/API_ENTERPRISE/FAILED
    """

    # Identity (generated on creation)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str = ""  # Generated in __post_init__

    # Classification
    title: str = ""
    severity: SeverityV2 = SeverityV2.INFO
    category: FindingCategory = FindingCategory.OTHER
    vuln_type: str = "other"  # String for flexibility with legacy types

    # Location
    target: str = ""                       # Base target (domain/IP)
    url: str = ""                          # Full URL (properly joined, no //)
    parameter: Optional[str] = None
    method: str = "GET"

    # Evidence
    description: str = ""
    evidence: str = ""
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None

    # Verification State Machine
    verification_status: VerificationStatusV2 = VerificationStatusV2.NEEDS_REVIEW
    verification_evidence: list[str] = field(default_factory=list)
    verification_attempts: int = 0
    verified_at: Optional[datetime] = None

    # Source Tracking
    source_tool: str = "unknown"           # Original scanner name
    source_scanner_type: ScannerType = ScannerType.LOCAL
    source_raw_id: Optional[str] = None    # Original finding ID from scanner
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    # Metadata
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str = ""

    # AI fields
    ai_reasoning: Optional[str] = None
    ai_confidence: Optional[float] = None

    # Merge tracking
    merged_from: list[str] = field(default_factory=list)  # IDs of merged findings
    duplicate_count: int = 1

    # Legacy compatibility
    confirmed: bool = False
    exploited: bool = False
    poc_command: Optional[str] = None

    def __post_init__(self):
        """Generate fingerprint and normalize URL"""
        # Normalize URL (fix double slashes)
        if self.url:
            self.url = normalize_url(self.url, self.target)
        # Generate fingerprint for deduplication
        if not self.fingerprint:
            self.fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """
        Generate SHA256 fingerprint for deduplication.

        Components:
        - Normalized host (lowercase, no port)
        - URL path (no query, no fragment, no trailing slash)
        - HTTP method (uppercase)
        - Parameter name (if any)
        - Vulnerability type
        - Category
        - Root cause signature
        """
        parsed = urlparse(self.url)
        host = parsed.netloc.lower().split(":")[0]  # Remove port
        path = parsed.path.rstrip("/").lower()

        components = [
            host,
            path,
            self.method.upper(),
            self.parameter or "_no_param_",
            self.vuln_type,
            self.category.value,
            self._get_root_cause_signature(),
        ]

        data = "|".join(str(c) for c in components)
        return hashlib.sha256(data.encode()).hexdigest()[:32]

    def _get_root_cause_signature(self) -> str:
        """Extract root cause signature from evidence for better deduplication"""
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

        # SSRF signatures
        if "169.254.169.254" in evidence_lower:
            return "ssrf_aws_metadata"
        if "metadata.google" in evidence_lower:
            return "ssrf_gcp_metadata"
        if "localhost" in evidence_lower or "127.0.0.1" in evidence_lower:
            return "ssrf_localhost"

        # SSTI signatures
        if "49" in evidence_lower and ("{{7*7}}" in evidence_lower or "7*7" in evidence_lower):
            return "ssti_jinja"

        return self.vuln_type

    def is_reportable(self) -> bool:
        """
        Check if finding should be included in final report.

        Rules:
        - SUPPRESSED_FP: Never reportable
        - CRITICAL/HIGH: Must be CONFIRMED
        - MEDIUM: Can be CONFIRMED or LIKELY
        - LOW/INFO: Can be CONFIRMED, LIKELY, or in MANUAL_REVIEW
        """
        if self.verification_status == VerificationStatusV2.SUPPRESSED_FP:
            return False

        if self.severity in [SeverityV2.CRITICAL, SeverityV2.HIGH]:
            return self.verification_status == VerificationStatusV2.CONFIRMED

        if self.severity == SeverityV2.MEDIUM:
            return self.verification_status in [
                VerificationStatusV2.CONFIRMED,
                VerificationStatusV2.LIKELY
            ]

        # Low and Info - more lenient
        return self.verification_status not in [
            VerificationStatusV2.NEEDS_REVIEW,
            VerificationStatusV2.PENDING,
            VerificationStatusV2.SUPPRESSED_FP
        ]

    def needs_verification(self) -> bool:
        """Check if finding requires verification"""
        return self.verification_status in [
            VerificationStatusV2.NEEDS_REVIEW,
            VerificationStatusV2.PENDING
        ]

    def mark_verified(
        self,
        status: VerificationStatusV2,
        evidence: Optional[str] = None,
        confidence: Optional[float] = None
    ) -> None:
        """Mark finding with verification result"""
        self.verification_status = status
        self.verification_attempts += 1
        self.verified_at = datetime.utcnow()

        if evidence:
            self.verification_evidence.append(evidence)
            separator = "\n\n--- Verification Evidence ---\n"
            self.evidence = f"{self.evidence}{separator}{evidence}" if self.evidence else evidence

        if confidence is not None:
            self.ai_confidence = confidence

        if status == VerificationStatusV2.CONFIRMED:
            self.confirmed = True
            self.exploited = True
        elif status == VerificationStatusV2.SUPPRESSED_FP:
            self.confirmed = False
            self.exploited = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "vuln_type": self.vuln_type,
            "target": self.target,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "verification_status": self.verification_status.value,
            "verification_evidence": self.verification_evidence,
            "verification_attempts": self.verification_attempts,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "source_tool": self.source_tool,
            "source_scanner_type": self.source_scanner_type.value,
            "source_raw_id": self.source_raw_id,
            "discovered_at": self.discovered_at.isoformat(),
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "cve_ids": self.cve_ids,
            "references": self.references,
            "remediation": self.remediation,
            "ai_reasoning": self.ai_reasoning,
            "ai_confidence": self.ai_confidence,
            "merged_from": self.merged_from,
            "duplicate_count": self.duplicate_count,
            "confirmed": self.confirmed,
            "exploited": self.exploited,
            "poc_command": self.poc_command,
            "is_reportable": self.is_reportable(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FindingV2":
        """Create FindingV2 from dictionary"""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            fingerprint=data.get("fingerprint", ""),
            title=data.get("title", ""),
            severity=SeverityV2(data.get("severity", "info")),
            category=FindingCategory(data.get("category", "other")),
            vuln_type=data.get("vuln_type", "other"),
            target=data.get("target", ""),
            url=data.get("url", ""),
            parameter=data.get("parameter"),
            method=data.get("method", "GET"),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            raw_request=data.get("raw_request"),
            raw_response=data.get("raw_response"),
            verification_status=VerificationStatusV2(data.get("verification_status", "needs_review")),
            verification_evidence=data.get("verification_evidence", []),
            verification_attempts=data.get("verification_attempts", 0),
            verified_at=datetime.fromisoformat(data["verified_at"]) if data.get("verified_at") else None,
            source_tool=data.get("source_tool", "unknown"),
            source_scanner_type=ScannerType(data.get("source_scanner_type", "local")),
            source_raw_id=data.get("source_raw_id"),
            discovered_at=datetime.fromisoformat(data["discovered_at"]) if data.get("discovered_at") else datetime.utcnow(),
            cvss_score=data.get("cvss_score"),
            cwe_id=data.get("cwe_id"),
            cve_ids=data.get("cve_ids", []),
            references=data.get("references", []),
            remediation=data.get("remediation", ""),
            ai_reasoning=data.get("ai_reasoning"),
            ai_confidence=data.get("ai_confidence"),
            merged_from=data.get("merged_from", []),
            duplicate_count=data.get("duplicate_count", 1),
            confirmed=data.get("confirmed", False),
            exploited=data.get("exploited", False),
            poc_command=data.get("poc_command"),
        )

    @classmethod
    def from_legacy(cls, finding: Any) -> "FindingV2":
        """
        Convert legacy Finding to FindingV2.

        Maps:
        - VerificationStatus.UNVERIFIED -> NEEDS_REVIEW
        - VerificationStatus.FALSE_POSITIVE -> SUPPRESSED_FP
        - Auto-categorizes based on vuln_type
        """
        from aipt_v2.models.findings import Finding, VerificationStatus, Severity

        # Map legacy verification status
        status_mapping = {
            VerificationStatus.UNVERIFIED: VerificationStatusV2.NEEDS_REVIEW,
            VerificationStatus.PENDING: VerificationStatusV2.PENDING,
            VerificationStatus.IN_PROGRESS: VerificationStatusV2.IN_PROGRESS,
            VerificationStatus.CONFIRMED: VerificationStatusV2.CONFIRMED,
            VerificationStatus.LIKELY: VerificationStatusV2.LIKELY,
            VerificationStatus.POTENTIAL: VerificationStatusV2.LIKELY,  # Map POTENTIAL to LIKELY
            VerificationStatus.FALSE_POSITIVE: VerificationStatusV2.SUPPRESSED_FP,
            VerificationStatus.MANUAL_REVIEW: VerificationStatusV2.MANUAL_REVIEW,
        }

        # Map severity
        severity_mapping = {
            Severity.CRITICAL: SeverityV2.CRITICAL,
            Severity.HIGH: SeverityV2.HIGH,
            Severity.MEDIUM: SeverityV2.MEDIUM,
            Severity.LOW: SeverityV2.LOW,
            Severity.INFO: SeverityV2.INFO,
        }

        # Determine category from vuln_type
        category = categorize_vuln_type(finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else str(finding.vuln_type))

        # Determine scanner type from source
        scanner_type = determine_scanner_type(finding.source)

        return cls(
            id=str(uuid.uuid4()),
            title=finding.title,
            severity=severity_mapping.get(finding.severity, SeverityV2.INFO),
            category=category,
            vuln_type=finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else str(finding.vuln_type),
            target=urlparse(finding.url).netloc,
            url=finding.url,
            parameter=finding.parameter,
            method=finding.method,
            description=finding.description,
            evidence=finding.evidence,
            raw_request=finding.request,
            raw_response=finding.response,
            verification_status=status_mapping.get(finding.verification_status, VerificationStatusV2.NEEDS_REVIEW),
            verification_evidence=finding.verification_evidence if hasattr(finding, 'verification_evidence') else [],
            verification_attempts=finding.verification_attempts if hasattr(finding, 'verification_attempts') else 0,
            verified_at=finding.last_verification_at if hasattr(finding, 'last_verification_at') else None,
            source_tool=finding.source,
            source_scanner_type=scanner_type,
            source_raw_id=finding.source_id if hasattr(finding, 'source_id') else None,
            discovered_at=finding.discovered_at,
            cvss_score=finding.cvss_score,
            cwe_id=finding.cwe_id,
            cve_ids=finding.cve_ids if hasattr(finding, 'cve_ids') else [],
            references=finding.references if hasattr(finding, 'references') else [],
            remediation=finding.remediation if hasattr(finding, 'remediation') else "",
            ai_reasoning=finding.ai_reasoning if hasattr(finding, 'ai_reasoning') else None,
            ai_confidence=finding.ai_confidence if hasattr(finding, 'ai_confidence') else None,
            confirmed=finding.confirmed if hasattr(finding, 'confirmed') else False,
            exploited=finding.exploited if hasattr(finding, 'exploited') else False,
            poc_command=finding.poc_command if hasattr(finding, 'poc_command') else None,
        )

    def to_legacy(self) -> Any:
        """Convert FindingV2 back to legacy Finding for backward compatibility"""
        from aipt_v2.models.findings import Finding, VerificationStatus, Severity, VulnerabilityType

        # Reverse map verification status
        status_mapping = {
            VerificationStatusV2.NEEDS_REVIEW: VerificationStatus.UNVERIFIED,
            VerificationStatusV2.PENDING: VerificationStatus.PENDING,
            VerificationStatusV2.IN_PROGRESS: VerificationStatus.IN_PROGRESS,
            VerificationStatusV2.CONFIRMED: VerificationStatus.CONFIRMED,
            VerificationStatusV2.LIKELY: VerificationStatus.LIKELY,
            VerificationStatusV2.SUPPRESSED_FP: VerificationStatus.FALSE_POSITIVE,
            VerificationStatusV2.MANUAL_REVIEW: VerificationStatus.MANUAL_REVIEW,
        }

        # Reverse map severity
        severity_mapping = {
            SeverityV2.CRITICAL: Severity.CRITICAL,
            SeverityV2.HIGH: Severity.HIGH,
            SeverityV2.MEDIUM: Severity.MEDIUM,
            SeverityV2.LOW: Severity.LOW,
            SeverityV2.INFO: Severity.INFO,
        }

        # Try to map vuln_type to VulnerabilityType enum
        try:
            vuln_type = VulnerabilityType(self.vuln_type)
        except ValueError:
            vuln_type = VulnerabilityType.OTHER

        return Finding(
            title=self.title,
            severity=severity_mapping.get(self.severity, Severity.INFO),
            vuln_type=vuln_type,
            url=self.url,
            parameter=self.parameter,
            method=self.method,
            description=self.description,
            evidence=self.evidence,
            request=self.raw_request,
            response=self.raw_response,
            source=self.source_tool,
            source_id=self.source_raw_id,
            confirmed=self.confirmed,
            exploited=self.exploited,
            poc_command=self.poc_command,
            cvss_score=self.cvss_score,
            cwe_id=self.cwe_id,
            cve_ids=self.cve_ids,
            references=self.references,
            remediation=self.remediation,
            discovered_at=self.discovered_at,
            ai_reasoning=self.ai_reasoning,
            ai_confidence=self.ai_confidence,
            verification_status=status_mapping.get(self.verification_status, VerificationStatus.UNVERIFIED),
            verification_attempts=self.verification_attempts,
            last_verification_at=self.verified_at,
            verification_evidence=self.verification_evidence,
        )


def normalize_url(url: str, base_target: str = "") -> str:
    """
    Normalize URL to fix common issues like double slashes.

    Fixes:
    - //path -> /path
    - https://domain//path -> https://domain/path
    - Ensures proper URL joining
    """
    if not url:
        return url

    # Parse URL
    parsed = urlparse(url)

    # Fix double slashes in path
    path = parsed.path
    while "//" in path:
        path = path.replace("//", "/")

    # Reconstruct URL
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"

    return normalized


def categorize_vuln_type(vuln_type: str) -> FindingCategory:
    """
    Map vulnerability type string to FindingCategory.

    Used for routing findings to appropriate verification policy.
    """
    vuln_lower = vuln_type.lower()

    # TLS/SSL
    if any(x in vuln_lower for x in ["ssl", "tls", "certificate", "heartbleed", "poodle", "beast"]):
        return FindingCategory.TLS_SSL

    # Exposures
    if any(x in vuln_lower for x in ["exposure", "disclosure", "phpinfo", "directory_listing", "backup"]):
        return FindingCategory.EXPOSURE

    # CVE/Version
    if any(x in vuln_lower for x in ["cve", "outdated", "component", "version"]):
        return FindingCategory.CVE_VERSION

    # SSTI
    if any(x in vuln_lower for x in ["ssti", "template"]):
        return FindingCategory.INJECTION_SSTI

    # SQL Injection
    if any(x in vuln_lower for x in ["sql", "sqli"]):
        return FindingCategory.INJECTION_SQLI

    # XSS
    if any(x in vuln_lower for x in ["xss", "cross-site scripting", "script"]):
        return FindingCategory.INJECTION_XSS

    # Command Injection
    if any(x in vuln_lower for x in ["command", "cmd", "rce", "os_command"]):
        return FindingCategory.INJECTION_CMDI

    # XXE
    if "xxe" in vuln_lower:
        return FindingCategory.INJECTION_XXE

    # Host Header
    if "host" in vuln_lower and "header" in vuln_lower:
        return FindingCategory.HOST_HEADER

    # SSRF
    if "ssrf" in vuln_lower:
        return FindingCategory.SSRF

    # Config
    if any(x in vuln_lower for x in ["config", "misconfiguration", "default"]):
        return FindingCategory.CONFIG

    # Auth
    if any(x in vuln_lower for x in ["auth", "authentication", "login", "password", "session"]):
        return FindingCategory.AUTH

    # Access Control
    if any(x in vuln_lower for x in ["idor", "access_control", "privilege", "authorization"]):
        return FindingCategory.ACCESS_CONTROL

    # Crypto
    if any(x in vuln_lower for x in ["crypto", "cipher", "weak_crypto"]):
        return FindingCategory.CRYPTO

    # Secrets
    if any(x in vuln_lower for x in ["secret", "credential", "hardcoded", "api_key"]):
        return FindingCategory.SECRETS

    # CSRF
    if "csrf" in vuln_lower:
        return FindingCategory.CSRF

    # Open Redirect
    if "redirect" in vuln_lower:
        return FindingCategory.OPEN_REDIRECT

    # File Upload
    if "upload" in vuln_lower:
        return FindingCategory.FILE_UPLOAD

    # Deserialization
    if "deserializ" in vuln_lower:
        return FindingCategory.DESERIALIZATION

    return FindingCategory.OTHER


def determine_scanner_type(source: str) -> ScannerType:
    """
    Determine scanner type from source string.

    Enterprise scanners are identified by name, others default to LOCAL.
    """
    source_lower = source.lower()

    enterprise_scanners = ["acunetix", "burp", "nessus", "zap", "owasp zap", "qualys", "rapid7"]
    if any(scanner in source_lower for scanner in enterprise_scanners):
        return ScannerType.API_ENTERPRISE

    if "vps" in source_lower or "remote" in source_lower:
        return ScannerType.VPS

    return ScannerType.LOCAL


def merge_findings_v2(primary: FindingV2, duplicate: FindingV2) -> FindingV2:
    """
    Merge two duplicate findings into one.

    Strategy:
    - Keep highest severity
    - Prefer CONFIRMED verification status
    - Combine evidence
    - Track merged IDs
    - Increment duplicate count
    """
    # Prefer the one with better verification status
    status_priority = [
        VerificationStatusV2.CONFIRMED,
        VerificationStatusV2.LIKELY,
        VerificationStatusV2.MANUAL_REVIEW,
        VerificationStatusV2.IN_PROGRESS,
        VerificationStatusV2.PENDING,
        VerificationStatusV2.NEEDS_REVIEW,
        VerificationStatusV2.SUPPRESSED_FP,
    ]

    primary_priority = status_priority.index(primary.verification_status) if primary.verification_status in status_priority else 99
    dup_priority = status_priority.index(duplicate.verification_status) if duplicate.verification_status in status_priority else 99

    if dup_priority < primary_priority:
        primary, duplicate = duplicate, primary

    # Merge evidence
    merged_evidence = primary.evidence
    if duplicate.evidence and duplicate.evidence not in merged_evidence:
        merged_evidence = f"{merged_evidence}\n\n--- Additional Evidence ---\n{duplicate.evidence}"

    # Combine verification evidence
    merged_verification_evidence = list(set(primary.verification_evidence + duplicate.verification_evidence))

    # Track merged IDs
    merged_from = list(set(primary.merged_from + duplicate.merged_from + [duplicate.id]))

    return FindingV2(
        id=primary.id,
        fingerprint=primary.fingerprint,
        title=primary.title,
        severity=max(primary.severity, duplicate.severity),
        category=primary.category,
        vuln_type=primary.vuln_type,
        target=primary.target,
        url=primary.url,
        parameter=primary.parameter,
        method=primary.method,
        description=primary.description or duplicate.description,
        evidence=merged_evidence,
        raw_request=primary.raw_request or duplicate.raw_request,
        raw_response=primary.raw_response or duplicate.raw_response,
        verification_status=primary.verification_status,
        verification_evidence=merged_verification_evidence,
        verification_attempts=max(primary.verification_attempts, duplicate.verification_attempts),
        verified_at=primary.verified_at or duplicate.verified_at,
        source_tool=f"{primary.source_tool}, {duplicate.source_tool}" if primary.source_tool != duplicate.source_tool else primary.source_tool,
        source_scanner_type=primary.source_scanner_type,
        source_raw_id=primary.source_raw_id,
        discovered_at=min(primary.discovered_at, duplicate.discovered_at),
        cvss_score=primary.cvss_score or duplicate.cvss_score,
        cwe_id=primary.cwe_id or duplicate.cwe_id,
        cve_ids=list(set(primary.cve_ids + duplicate.cve_ids)),
        references=list(set(primary.references + duplicate.references)),
        remediation=primary.remediation or duplicate.remediation,
        ai_reasoning=primary.ai_reasoning or duplicate.ai_reasoning,
        ai_confidence=max(primary.ai_confidence or 0, duplicate.ai_confidence or 0) or None,
        merged_from=merged_from,
        duplicate_count=primary.duplicate_count + duplicate.duplicate_count,
        confirmed=primary.confirmed or duplicate.confirmed,
        exploited=primary.exploited or duplicate.exploited,
        poc_command=primary.poc_command or duplicate.poc_command,
    )
