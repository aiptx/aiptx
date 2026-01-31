"""
AIPTX Result Collector
======================

Collects, aggregates, and structures scan results from multiple tools
across all phases. Provides unified access to findings for AI analysis.

Features:
- Cross-phase result aggregation
- Finding deduplication and correlation
- Priority scoring and attack path detection
- Export to multiple formats (JSON, compact, markdown)
"""

import json
import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .tool_registry import ToolPhase
from .local_tool_executor import ToolExecution, ExecutionBatch
from .parser import Finding

logger = logging.getLogger(__name__)


class FindingSeverity(str, Enum):
    """Normalized severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NormalizedFinding:
    """
    A normalized finding that can be compared across tools.
    """
    id: str
    type: str  # port, service, vuln, credential, host, path, info
    value: str
    description: str
    severity: FindingSeverity

    # Source tracking
    source_tool: str
    source_phase: ToolPhase
    raw_finding: Finding

    # Correlation
    target: str = ""
    related_findings: List[str] = field(default_factory=list)
    chain_potential: List[str] = field(default_factory=list)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0
    cve: Optional[str] = None
    cwe: Optional[str] = None

    def __hash__(self):
        return hash(self.id)

    @property
    def severity_score(self) -> int:
        """Numeric severity score for sorting."""
        scores = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
        }
        return scores.get(self.severity, 0)

    def to_compact(self) -> str:
        """Convert to compact format for LLM consumption."""
        sev_char = self.severity.value[0].upper()
        chain_str = ",".join(self.chain_potential[:3]) if self.chain_potential else ""
        chain_part = f" -> {chain_str}" if chain_str else ""
        return f"[{self.id}|{self.type}|{sev_char}] {self.value[:50]}{chain_part}"


@dataclass
class PhaseResults:
    """Results from a single phase."""
    phase: ToolPhase
    findings: List[NormalizedFinding] = field(default_factory=list)
    tools_run: List[str] = field(default_factory=list)
    tools_failed: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        total = len(self.tools_run)
        if total == 0:
            return 0.0
        failed = len(self.tools_failed)
        return (total - failed) / total

    def get_by_severity(self, severity: FindingSeverity) -> List[NormalizedFinding]:
        return [f for f in self.findings if f.severity == severity]

    def get_by_type(self, finding_type: str) -> List[NormalizedFinding]:
        return [f for f in self.findings if f.type == finding_type]


@dataclass
class AttackPath:
    """
    Represents a potential attack path through correlated findings.
    """
    id: str
    name: str
    description: str
    findings: List[NormalizedFinding]
    confidence: float
    impact: str  # low, medium, high, critical
    steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "finding_ids": [f.id for f in self.findings],
            "confidence": self.confidence,
            "impact": self.impact,
            "steps": self.steps,
        }


class ResultCollector:
    """
    Collects and aggregates results from all scan phases.

    Provides:
    - Unified finding storage across phases
    - Automatic deduplication
    - Cross-finding correlation
    - Attack path detection
    - Multiple export formats

    Example:
        collector = ResultCollector(target="example.com")

        # Add results from each phase
        collector.add_phase_results(ToolPhase.RECON, recon_batch)
        collector.add_phase_results(ToolPhase.SCAN, scan_batch)

        # Get aggregated findings
        critical = collector.get_findings_by_severity(FindingSeverity.CRITICAL)

        # Detect attack paths
        paths = collector.detect_attack_paths()

        # Export for LLM
        compact = collector.to_compact_format()
    """

    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.utcnow()

        self._phases: Dict[ToolPhase, PhaseResults] = {}
        self._all_findings: Dict[str, NormalizedFinding] = {}
        self._finding_counter = 0

        # Correlation indexes
        self._by_type: Dict[str, Set[str]] = defaultdict(set)
        self._by_severity: Dict[FindingSeverity, Set[str]] = defaultdict(set)
        self._by_host: Dict[str, Set[str]] = defaultdict(set)
        self._by_port: Dict[int, Set[str]] = defaultdict(set)

    def _next_finding_id(self) -> str:
        """Generate unique finding ID."""
        self._finding_counter += 1
        return f"F{self._finding_counter:04d}"

    def _compute_finding_hash(self, finding: Finding) -> str:
        """Compute hash for deduplication."""
        key = f"{finding.type}:{finding.value}:{finding.source_tool}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    # =========================================================================
    # Adding Results
    # =========================================================================

    def add_phase_results(
        self,
        phase: ToolPhase,
        batch: ExecutionBatch,
    ) -> PhaseResults:
        """
        Add results from a phase execution batch.

        Args:
            phase: The phase these results are from
            batch: ExecutionBatch containing tool executions

        Returns:
            PhaseResults for the phase
        """
        phase_results = PhaseResults(
            phase=phase,
            start_time=batch.start_time,
            end_time=batch.end_time,
        )

        if batch.start_time and batch.end_time:
            phase_results.duration_seconds = (
                batch.end_time - batch.start_time
            ).total_seconds()

        for execution in batch.executions:
            phase_results.tools_run.append(execution.tool.name)

            if not execution.is_success:
                phase_results.tools_failed.append(execution.tool.name)
                continue

            # Normalize and add findings
            for finding in execution.findings:
                normalized = self._normalize_finding(
                    finding, phase, execution.tool.name
                )
                if normalized:
                    phase_results.findings.append(normalized)

        self._phases[phase] = phase_results

        logger.info(
            f"Added {len(phase_results.findings)} findings from {phase.value} phase"
        )

        return phase_results

    def add_execution(
        self,
        execution: ToolExecution,
        phase: Optional[ToolPhase] = None,
    ) -> int:
        """
        Add results from a single tool execution.

        Args:
            execution: The tool execution to add
            phase: Override phase (uses tool's default if not specified)

        Returns:
            Number of findings added
        """
        actual_phase = phase or execution.tool.phase

        if actual_phase not in self._phases:
            self._phases[actual_phase] = PhaseResults(phase=actual_phase)

        phase_results = self._phases[actual_phase]
        phase_results.tools_run.append(execution.tool.name)

        if not execution.is_success:
            phase_results.tools_failed.append(execution.tool.name)
            return 0

        count = 0
        for finding in execution.findings:
            normalized = self._normalize_finding(
                finding, actual_phase, execution.tool.name
            )
            if normalized:
                phase_results.findings.append(normalized)
                count += 1

        return count

    def _normalize_finding(
        self,
        finding: Finding,
        phase: ToolPhase,
        tool_name: str,
    ) -> Optional[NormalizedFinding]:
        """Normalize a finding and check for duplicates."""
        # Check for duplicates
        finding_hash = self._compute_finding_hash(finding)
        if finding_hash in [f.id.split("_")[-1] for f in self._all_findings.values()]:
            return None

        # Map severity
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        severity = severity_map.get(
            finding.severity.lower() if finding.severity else "info",
            FindingSeverity.INFO
        )

        # Create normalized finding
        finding_id = f"{self._next_finding_id()}_{finding_hash}"

        normalized = NormalizedFinding(
            id=finding_id,
            type=finding.type,
            value=finding.value,
            description=finding.description,
            severity=severity,
            source_tool=tool_name,
            source_phase=phase,
            raw_finding=finding,
            target=self.target,
            chain_potential=self._detect_chain_potential(finding),
        )

        # Extract CVE/CWE if present
        if "cve" in finding.metadata:
            normalized.cve = finding.metadata["cve"]
        if "cwe" in finding.metadata:
            normalized.cwe = finding.metadata["cwe"]

        # Add to indexes
        self._all_findings[finding_id] = normalized
        self._by_type[finding.type].add(finding_id)
        self._by_severity[severity].add(finding_id)

        # Index by host/port if available
        if "host" in finding.metadata:
            self._by_host[finding.metadata["host"]].add(finding_id)
        if "port" in finding.metadata:
            self._by_port[finding.metadata["port"]].add(finding_id)

        return normalized

    def _detect_chain_potential(self, finding: Finding) -> List[str]:
        """Detect potential attack chains from finding type."""
        chains = []
        finding_type = finding.type.lower()
        value_lower = finding.value.lower() if finding.value else ""
        desc_lower = finding.description.lower() if finding.description else ""

        # SQL injection
        if "sqli" in finding_type or "sql" in value_lower:
            chains.extend(["data_exfil", "auth_bypass", "rce"])

        # XSS
        if "xss" in finding_type or "xss" in value_lower:
            chains.extend(["session_hijack", "phishing"])

        # Credentials
        if finding_type == "credential":
            chains.extend(["lateral_move", "priv_esc"])

        # Open ports
        if finding_type == "port":
            port = finding.metadata.get("port", 0)
            if port == 22:
                chains.append("ssh_brute")
            elif port == 3389:
                chains.append("rdp_brute")
            elif port in [80, 443, 8080]:
                chains.append("web_exploit")
            elif port == 445:
                chains.append("smb_exploit")

        # Vulnerabilities
        if finding_type == "vuln":
            if "rce" in desc_lower or "remote code" in desc_lower:
                chains.extend(["rce", "shell"])
            if "lfi" in desc_lower:
                chains.extend(["lfi", "config_leak"])
            if "ssrf" in desc_lower:
                chains.extend(["ssrf", "internal_scan"])

        return chains

    # =========================================================================
    # Querying Results
    # =========================================================================

    def get_all_findings(self) -> List[NormalizedFinding]:
        """Get all findings sorted by severity."""
        findings = list(self._all_findings.values())
        findings.sort(key=lambda f: (-f.severity_score, f.type))
        return findings

    def get_findings_by_phase(self, phase: ToolPhase) -> List[NormalizedFinding]:
        """Get findings for a specific phase."""
        if phase in self._phases:
            return self._phases[phase].findings
        return []

    def get_findings_by_severity(
        self,
        severity: FindingSeverity,
    ) -> List[NormalizedFinding]:
        """Get findings with a specific severity."""
        finding_ids = self._by_severity.get(severity, set())
        return [self._all_findings[fid] for fid in finding_ids]

    def get_findings_by_type(self, finding_type: str) -> List[NormalizedFinding]:
        """Get findings of a specific type."""
        finding_ids = self._by_type.get(finding_type, set())
        return [self._all_findings[fid] for fid in finding_ids]

    def get_critical_findings(self) -> List[NormalizedFinding]:
        """Get critical and high severity findings."""
        critical = self.get_findings_by_severity(FindingSeverity.CRITICAL)
        high = self.get_findings_by_severity(FindingSeverity.HIGH)
        return critical + high

    # =========================================================================
    # Attack Path Detection
    # =========================================================================

    def detect_attack_paths(self) -> List[AttackPath]:
        """
        Detect potential attack paths by correlating findings.

        Returns:
            List of potential attack paths
        """
        paths = []

        # Pattern 1: Open port -> Service vuln -> Exploit
        for port_id in self._by_type.get("port", set()):
            port_finding = self._all_findings[port_id]
            port_num = port_finding.raw_finding.metadata.get("port", 0)
            service = port_finding.raw_finding.metadata.get("service", "")

            # Look for vulns related to this service
            related_vulns = []
            for vuln_id in self._by_type.get("vuln", set()):
                vuln = self._all_findings[vuln_id]
                if service.lower() in vuln.description.lower():
                    related_vulns.append(vuln)

            if related_vulns:
                paths.append(AttackPath(
                    id=f"path_{len(paths)+1:03d}",
                    name=f"Service Exploit: {service}",
                    description=f"Exploit {service} on port {port_num}",
                    findings=[port_finding] + related_vulns,
                    confidence=0.7,
                    impact="high" if any(v.severity_score >= 4 for v in related_vulns) else "medium",
                    steps=[
                        f"Identify {service} on port {port_num}",
                        f"Exploit vulnerability: {related_vulns[0].value[:50]}",
                        "Gain access to system",
                    ],
                ))

        # Pattern 2: Credential findings -> Lateral movement
        creds = list(self._by_type.get("credential", set()))
        if creds:
            cred_findings = [self._all_findings[c] for c in creds]
            paths.append(AttackPath(
                id=f"path_{len(paths)+1:03d}",
                name="Credential Reuse",
                description="Use discovered credentials for lateral movement",
                findings=cred_findings,
                confidence=0.8,
                impact="critical",
                steps=[
                    f"Collect {len(creds)} credentials",
                    "Test credential reuse on other services",
                    "Achieve lateral movement",
                ],
            ))

        # Pattern 3: SQL injection -> Data exfiltration
        sqli_findings = [
            self._all_findings[fid]
            for fid in self._by_type.get("vuln", set())
            if "sql" in self._all_findings[fid].value.lower()
        ]
        if sqli_findings:
            paths.append(AttackPath(
                id=f"path_{len(paths)+1:03d}",
                name="SQL Injection Chain",
                description="Exploit SQL injection for data exfiltration",
                findings=sqli_findings,
                confidence=0.9,
                impact="critical",
                steps=[
                    f"Exploit {len(sqli_findings)} SQL injection points",
                    "Enumerate database structure",
                    "Extract sensitive data",
                    "Potentially escalate to RCE",
                ],
            ))

        return paths

    # =========================================================================
    # Export Formats
    # =========================================================================

    def to_compact_format(self, max_findings: int = 50) -> str:
        """
        Export to compact format for LLM consumption.

        Args:
            max_findings: Maximum findings to include

        Returns:
            Compact string representation
        """
        lines = [f"TARGET: {self.target}"]
        lines.append(f"FINDINGS: {len(self._all_findings)} total")
        lines.append("")

        # Group by severity
        for severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH,
                         FindingSeverity.MEDIUM, FindingSeverity.LOW]:
            findings = self.get_findings_by_severity(severity)
            if findings:
                lines.append(f"[{severity.value.upper()}] x{len(findings)}")
                for f in findings[:max_findings // 4]:
                    lines.append(f"  {f.to_compact()}")

        # Add attack paths
        paths = self.detect_attack_paths()
        if paths:
            lines.append("")
            lines.append("ATTACK PATHS:")
            for path in paths[:5]:
                lines.append(f"  [{path.impact.upper()}] {path.name} (conf: {path.confidence})")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export to dictionary format."""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "phases": {
                phase.value: {
                    "tools_run": results.tools_run,
                    "tools_failed": results.tools_failed,
                    "findings_count": len(results.findings),
                    "duration": results.duration_seconds,
                }
                for phase, results in self._phases.items()
            },
            "summary": {
                "total_findings": len(self._all_findings),
                "by_severity": {
                    sev.value: len(ids)
                    for sev, ids in self._by_severity.items()
                },
                "by_type": {
                    t: len(ids)
                    for t, ids in self._by_type.items()
                },
            },
            "findings": [
                {
                    "id": f.id,
                    "type": f.type,
                    "value": f.value,
                    "severity": f.severity.value,
                    "source_tool": f.source_tool,
                    "source_phase": f.source_phase.value,
                    "chain_potential": f.chain_potential,
                }
                for f in self.get_all_findings()
            ],
            "attack_paths": [
                path.to_dict()
                for path in self.detect_attack_paths()
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Export to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        """Export to markdown report format."""
        lines = [
            f"# Scan Results: {self.target}",
            "",
            f"**Scan Date:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Findings:** {len(self._all_findings)}",
            "",
            "## Summary by Severity",
            "",
        ]

        for severity in FindingSeverity:
            count = len(self._by_severity.get(severity, set()))
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            lines.append(f"- {emoji.get(severity.value, '')} **{severity.value.title()}:** {count}")

        lines.extend(["", "## Critical & High Findings", ""])

        for finding in self.get_critical_findings()[:20]:
            lines.append(f"### [{finding.severity.value.upper()}] {finding.value[:60]}")
            lines.append(f"- **Type:** {finding.type}")
            lines.append(f"- **Tool:** {finding.source_tool}")
            lines.append(f"- **Description:** {finding.description[:200]}")
            if finding.chain_potential:
                lines.append(f"- **Attack Potential:** {', '.join(finding.chain_potential)}")
            lines.append("")

        # Attack paths
        paths = self.detect_attack_paths()
        if paths:
            lines.extend(["## Potential Attack Paths", ""])
            for path in paths:
                lines.append(f"### {path.name}")
                lines.append(f"**Impact:** {path.impact.title()} | **Confidence:** {path.confidence:.0%}")
                lines.append("")
                lines.append("**Steps:**")
                for i, step in enumerate(path.steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

        return "\n".join(lines)

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        return {
            "target": self.target,
            "total_findings": len(self._all_findings),
            "phases_completed": len(self._phases),
            "severity_distribution": {
                sev.value: len(ids)
                for sev, ids in self._by_severity.items()
            },
            "type_distribution": {
                t: len(ids)
                for t, ids in self._by_type.items()
            },
            "tools_summary": {
                phase.value: {
                    "run": len(results.tools_run),
                    "failed": len(results.tools_failed),
                    "success_rate": results.success_rate,
                }
                for phase, results in self._phases.items()
            },
            "attack_paths": len(self.detect_attack_paths()),
        }
