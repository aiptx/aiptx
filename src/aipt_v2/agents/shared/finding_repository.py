"""
AIPTX Finding Repository - Central Security Findings Storage

Thread-safe storage for security findings with:
- Real-time notifications via MessageBus
- Finding deduplication
- Severity-based filtering
- PoC validation status tracking
- Finding correlation and grouping

All agents push findings here, and the PoC validator
consumes them for validation.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger(__name__)


class FindingSeverity(str, Enum):
    """Severity levels aligned with CVSS."""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # Informational only


class FindingStatus(str, Enum):
    """Finding validation status."""
    NEW = "new"                    # Just discovered
    PENDING_VALIDATION = "pending" # Queued for PoC validation
    VALIDATING = "validating"      # Currently being validated
    VALIDATED = "validated"        # PoC confirmed exploitable
    FALSE_POSITIVE = "false_positive"  # PoC failed, not exploitable
    NEEDS_MANUAL = "needs_manual"  # Requires manual verification
    DUPLICATE = "duplicate"        # Duplicate of another finding


class VulnerabilityType(str, Enum):
    """Common vulnerability types for categorization."""
    # Injection
    SQLI = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    NOSQL_INJECTION = "nosql_injection"
    SSTI = "ssti"

    # File/Path
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"

    # Authentication/Authorization
    AUTH_BYPASS = "auth_bypass"
    BROKEN_AUTH = "broken_authentication"
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_FIXATION = "session_fixation"

    # Network/Protocol
    SSRF = "ssrf"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    WEBSOCKET = "websocket_vulnerability"

    # Code Execution
    RCE = "remote_code_execution"
    DESERIALIZATION = "insecure_deserialization"

    # Cryptography
    WEAK_CRYPTO = "weak_cryptography"
    HARDCODED_SECRETS = "hardcoded_secrets"

    # Configuration
    MISCONFIGURATION = "misconfiguration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SENSITIVE_DATA = "sensitive_data_exposure"

    # Business Logic
    BUSINESS_LOGIC = "business_logic"
    RACE_CONDITION = "race_condition"

    # Other
    OTHER = "other"


@dataclass
class Evidence:
    """Evidence collected during finding discovery or validation."""
    request: Optional[str] = None
    response: Optional[str] = None
    screenshot_path: Optional[str] = None
    extracted_data: Optional[str] = None
    timing_ms: Optional[float] = None
    stack_trace: Optional[str] = None
    notes: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class PoCInfo:
    """Proof-of-concept validation information."""
    validated: bool = False
    validation_time: Optional[datetime] = None
    poc_code: str = ""
    poc_type: str = ""  # curl, python, burp, etc.
    evidence: Optional[Evidence] = None
    confidence: float = 0.0  # 0.0-1.0
    validator_notes: str = ""
    attempts: int = 0
    last_attempt: Optional[datetime] = None


@dataclass
class Finding:
    """
    Security finding discovered by an agent.

    Contains all information about a vulnerability:
    - Basic info (type, severity, location)
    - Evidence (request/response, screenshots)
    - PoC validation status
    - Agent attribution
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Core identification
    vuln_type: VulnerabilityType = VulnerabilityType.OTHER
    title: str = ""
    description: str = ""

    # Severity
    severity: FindingSeverity = FindingSeverity.INFO
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None

    # Location
    target: str = ""
    url: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    file_path: Optional[str] = None  # For SAST findings
    line_number: Optional[int] = None  # For SAST findings
    component: Optional[str] = None

    # Evidence
    evidence: Evidence = field(default_factory=Evidence)
    payload: Optional[str] = None  # Payload that triggered the vuln

    # Validation
    status: FindingStatus = FindingStatus.NEW
    poc: PoCInfo = field(default_factory=PoCInfo)

    # Agent attribution
    discovered_by: str = ""  # Agent ID
    agent_name: str = ""     # Agent name
    discovered_at: datetime = field(default_factory=datetime.now)

    # Correlation
    correlation_id: Optional[str] = None  # Links related findings
    parent_finding_id: Optional[str] = None  # For chained exploits
    related_findings: list[str] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.8  # Discovery confidence (0.0-1.0)
    metadata: dict = field(default_factory=dict)

    def get_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication."""
        key = f"{self.vuln_type.value}:{self.target}:{self.url}:{self.parameter}:{self.endpoint}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "target": self.target,
            "url": self.url,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "component": self.component,
            "payload": self.payload,
            "status": self.status.value,
            "discovered_by": self.discovered_by,
            "agent_name": self.agent_name,
            "discovered_at": self.discovered_at.isoformat(),
            "confidence": self.confidence,
            "tags": self.tags,
            "poc_validated": self.poc.validated,
            "poc_confidence": self.poc.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Create finding from dictionary."""
        finding = cls(
            id=data.get("id", str(uuid.uuid4())),
            vuln_type=VulnerabilityType(data.get("vuln_type", "other")),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=FindingSeverity(data.get("severity", "info")),
            cvss_score=data.get("cvss_score"),
            cve_id=data.get("cve_id"),
            cwe_id=data.get("cwe_id"),
            target=data.get("target", ""),
            url=data.get("url"),
            endpoint=data.get("endpoint"),
            parameter=data.get("parameter"),
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
            component=data.get("component"),
            payload=data.get("payload"),
            status=FindingStatus(data.get("status", "new")),
            discovered_by=data.get("discovered_by", ""),
            agent_name=data.get("agent_name", ""),
            confidence=data.get("confidence", 0.8),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )
        if "discovered_at" in data:
            finding.discovered_at = datetime.fromisoformat(data["discovered_at"])
        return finding


FindingCallback = Callable[[Finding], Coroutine[Any, Any, None]]


class FindingRepository:
    """
    Central repository for all security findings.

    Thread-safe storage with:
    - Automatic deduplication
    - Real-time callbacks for new findings
    - Severity-based filtering
    - PoC validation tracking

    Usage:
        repo = FindingRepository()

        # Subscribe to new findings
        await repo.subscribe_new(my_callback)

        # Add a finding
        await repo.add(finding, source_agent="scanner1")

        # Get findings
        critical_findings = await repo.get_by_severity(FindingSeverity.CRITICAL)
    """

    def __init__(self):
        self._findings: dict[str, Finding] = {}
        self._fingerprints: set[str] = set()
        self._lock = asyncio.Lock()
        self._callbacks: list[FindingCallback] = []
        self._validation_callbacks: list[FindingCallback] = []

    async def add(
        self,
        finding: Finding,
        source_agent: str,
        deduplicate: bool = True,
    ) -> tuple[bool, Optional[str]]:
        """
        Add a finding to the repository.

        Args:
            finding: Finding to add
            source_agent: ID of the agent that discovered it
            deduplicate: Whether to check for duplicates

        Returns:
            Tuple of (was_added, finding_id or duplicate_id)
        """
        async with self._lock:
            # Check for duplicates
            if deduplicate:
                fingerprint = finding.get_fingerprint()
                if fingerprint in self._fingerprints:
                    # Find the original finding
                    for existing in self._findings.values():
                        if existing.get_fingerprint() == fingerprint:
                            finding.status = FindingStatus.DUPLICATE
                            finding.related_findings.append(existing.id)
                            logger.debug(
                                f"Duplicate finding detected: {finding.title} "
                                f"(original: {existing.id})"
                            )
                            return False, existing.id

                self._fingerprints.add(fingerprint)

            # Set source agent
            finding.discovered_by = source_agent

            # Store
            self._findings[finding.id] = finding
            logger.info(
                f"Added finding: {finding.title} ({finding.severity.value}) "
                f"from {finding.agent_name}"
            )

        # Notify callbacks (outside lock)
        for callback in self._callbacks:
            try:
                await callback(finding)
            except Exception as e:
                logger.error(f"Error in finding callback: {e}")

        # Publish to message bus if available
        await self._publish_finding(finding)

        return True, finding.id

    async def _publish_finding(self, finding: Finding) -> None:
        """Publish finding to message bus."""
        try:
            from aipt_v2.agents.shared.message_bus import (
                get_message_bus,
                AgentMessage,
                MessageType,
                MessagePriority,
            )

            bus = get_message_bus()
            priority = MessagePriority.HIGH if finding.severity in [
                FindingSeverity.CRITICAL, FindingSeverity.HIGH
            ] else MessagePriority.NORMAL

            message = AgentMessage(
                topic="findings.new",
                message_type=MessageType.FINDING_NEW,
                sender_id=finding.discovered_by,
                sender_name=finding.agent_name,
                content=finding.to_dict(),
                priority=priority,
            )
            await bus.publish(message)
        except ImportError:
            pass  # Message bus not available

    async def update(self, finding_id: str, updates: dict) -> bool:
        """
        Update an existing finding.

        Args:
            finding_id: ID of finding to update
            updates: Dictionary of fields to update

        Returns:
            True if finding was found and updated
        """
        async with self._lock:
            if finding_id not in self._findings:
                return False

            finding = self._findings[finding_id]
            for key, value in updates.items():
                if hasattr(finding, key):
                    setattr(finding, key, value)

            return True

    async def mark_validated(
        self,
        finding_id: str,
        validated: bool,
        poc_info: PoCInfo,
    ) -> bool:
        """
        Mark a finding as validated (or false positive).

        Args:
            finding_id: ID of finding
            validated: Whether PoC confirmed exploitability
            poc_info: Proof-of-concept information

        Returns:
            True if finding was found and updated
        """
        async with self._lock:
            if finding_id not in self._findings:
                return False

            finding = self._findings[finding_id]
            finding.poc = poc_info

            if validated:
                finding.status = FindingStatus.VALIDATED
                finding.poc.validated = True
            else:
                finding.status = FindingStatus.FALSE_POSITIVE
                finding.poc.validated = False

            finding.poc.validation_time = datetime.now()

        # Notify validation callbacks
        for callback in self._validation_callbacks:
            try:
                await callback(finding)
            except Exception as e:
                logger.error(f"Error in validation callback: {e}")

        # Publish validation result
        await self._publish_validation(finding)

        return True

    async def _publish_validation(self, finding: Finding) -> None:
        """Publish validation result to message bus."""
        try:
            from aipt_v2.agents.shared.message_bus import (
                get_message_bus,
                AgentMessage,
                MessageType,
                MessagePriority,
            )

            bus = get_message_bus()
            message_type = (
                MessageType.FINDING_VALIDATED
                if finding.poc.validated
                else MessageType.FINDING_REJECTED
            )

            message = AgentMessage(
                topic="findings.validated",
                message_type=message_type,
                sender_id="poc_validator",
                sender_name="PoC Validator",
                content=finding.to_dict(),
                priority=MessagePriority.HIGH,
            )
            await bus.publish(message)
        except ImportError:
            pass

    async def get(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID."""
        async with self._lock:
            return self._findings.get(finding_id)

    async def get_all(self) -> list[Finding]:
        """Get all findings."""
        async with self._lock:
            return list(self._findings.values())

    async def get_by_severity(
        self,
        severity: FindingSeverity,
        include_lower: bool = False,
    ) -> list[Finding]:
        """
        Get findings by severity level.

        Args:
            severity: Target severity
            include_lower: Include lower severities too

        Returns:
            List of matching findings
        """
        severity_order = [
            FindingSeverity.INFO,
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]

        target_index = severity_order.index(severity)

        async with self._lock:
            results = []
            for finding in self._findings.values():
                finding_index = severity_order.index(finding.severity)
                if include_lower:
                    if finding_index >= target_index:
                        results.append(finding)
                else:
                    if finding.severity == severity:
                        results.append(finding)
            return results

    async def get_by_type(self, vuln_type: VulnerabilityType) -> list[Finding]:
        """Get findings by vulnerability type."""
        async with self._lock:
            return [
                f for f in self._findings.values()
                if f.vuln_type == vuln_type
            ]

    async def get_by_status(self, status: FindingStatus) -> list[Finding]:
        """Get findings by validation status."""
        async with self._lock:
            return [
                f for f in self._findings.values()
                if f.status == status
            ]

    async def get_by_agent(self, agent_id: str) -> list[Finding]:
        """Get findings discovered by a specific agent."""
        async with self._lock:
            return [
                f for f in self._findings.values()
                if f.discovered_by == agent_id
            ]

    async def get_validated(self) -> list[Finding]:
        """Get only validated findings."""
        return await self.get_by_status(FindingStatus.VALIDATED)

    async def get_pending_validation(self) -> list[Finding]:
        """Get findings pending PoC validation."""
        async with self._lock:
            return [
                f for f in self._findings.values()
                if f.status in [FindingStatus.NEW, FindingStatus.PENDING_VALIDATION]
            ]

    async def subscribe_new(self, callback: FindingCallback) -> None:
        """Subscribe to new finding notifications."""
        self._callbacks.append(callback)

    async def subscribe_validation(self, callback: FindingCallback) -> None:
        """Subscribe to validation result notifications."""
        self._validation_callbacks.append(callback)

    async def get_statistics(self) -> dict:
        """Get repository statistics."""
        async with self._lock:
            findings = list(self._findings.values())

        stats = {
            "total": len(findings),
            "by_severity": {},
            "by_status": {},
            "by_type": {},
            "validated_count": 0,
            "false_positive_count": 0,
            "pending_validation": 0,
        }

        for severity in FindingSeverity:
            stats["by_severity"][severity.value] = sum(
                1 for f in findings if f.severity == severity
            )

        for status in FindingStatus:
            count = sum(1 for f in findings if f.status == status)
            stats["by_status"][status.value] = count

        for vuln_type in VulnerabilityType:
            count = sum(1 for f in findings if f.vuln_type == vuln_type)
            if count > 0:
                stats["by_type"][vuln_type.value] = count

        stats["validated_count"] = stats["by_status"].get("validated", 0)
        stats["false_positive_count"] = stats["by_status"].get("false_positive", 0)
        stats["pending_validation"] = (
            stats["by_status"].get("new", 0) +
            stats["by_status"].get("pending", 0)
        )

        return stats

    def clear(self) -> None:
        """Clear all findings (for testing)."""
        self._findings.clear()
        self._fingerprints.clear()


# Global singleton instance
_finding_repository: Optional[FindingRepository] = None


def get_finding_repository() -> FindingRepository:
    """Get the global finding repository instance."""
    global _finding_repository
    if _finding_repository is None:
        _finding_repository = FindingRepository()
    return _finding_repository


def reset_finding_repository() -> None:
    """Reset the global finding repository (for testing)."""
    global _finding_repository
    _finding_repository = FindingRepository()
