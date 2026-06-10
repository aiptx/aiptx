"""
AIPTX End-to-End Pipeline Tests
================================

Comprehensive tests for the RECON → SCAN → EXPLOIT pipeline
with Ollama AI checkpoint integration.

These tests verify:
- Full pipeline execution flow
- AI checkpoint decision quality
- Phase context handoff
- Result aggregation and attack path detection
- Offline mode operation
"""

import asyncio
import json
import os
import pytest
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

# Import pipeline components
from aipt_v2.execution.phase_runner import (
    PhaseRunner,
    PhaseConfig,
    PipelineConfig,
    PipelineState,
    AICheckpointClient,
    run_quick_scan,
    run_full_scan,
)
from aipt_v2.execution.tool_registry import (
    ToolRegistry,
    ToolPhase,
    ToolCapability,
    TOOL_REGISTRY,
    get_registry,
)
from aipt_v2.execution.local_tool_executor import LocalToolExecutor
from aipt_v2.execution.result_collector import (
    ResultCollector,
    NormalizedFinding,
    AttackPath,
)
from aipt_v2.execution.parser import Finding
from aipt_v2.execution.local_tool_executor import (
    ToolExecution,
    ExecutionState,
    ExecutionBatch,
)
from aipt_v2.execution.tool_registry import TOOL_REGISTRY
from aipt_v2.scanners.base import ScanResult, ScanFinding, ScanSeverity


# ============================================================================
# Test helpers
# ============================================================================

# Map a phase name string to a ToolPhase enum value.
_PHASE_MAP = {
    "recon": ToolPhase.RECON,
    "scan": ToolPhase.SCAN,
    "exploit": ToolPhase.EXPLOIT,
    "test": ToolPhase.RECON,
}

# A representative tool per phase so executions carry a valid ToolConfig.
_PHASE_TOOL = {
    ToolPhase.RECON: TOOL_REGISTRY["subfinder"],
    ToolPhase.SCAN: TOOL_REGISTRY["nuclei"],
    ToolPhase.EXPLOIT: TOOL_REGISTRY["sqlmap"],
}


def _finding_type_for(scan_finding: ScanFinding) -> str:
    """Derive the parser Finding.type from a ScanFinding's tags/title."""
    tags = {t.lower() for t in (scan_finding.tags or [])}
    title = (scan_finding.title or "").lower()

    if "credential" in tags or "credentials" in title:
        return "credential"
    if {"sqli", "xss", "injection", "vuln", "exploitation"} & tags:
        return "vuln"
    if "sql injection" in title or "xss" in title:
        return "vuln"
    if "port" in tags or "open port" in title:
        return "port"
    if "directory" in tags or "subdomain" in tags or "path" in tags:
        return "path"
    return "info"


def _to_finding(scan_finding: ScanFinding, tool_name: str) -> Finding:
    """Convert a ScanFinding (scanner model) into a parser Finding."""
    metadata = {}
    if scan_finding.host:
        metadata["host"] = scan_finding.host
    if scan_finding.port:
        metadata["port"] = scan_finding.port
    if scan_finding.cve:
        metadata["cve"] = scan_finding.cve
    if scan_finding.cwe:
        metadata["cwe"] = scan_finding.cwe

    return Finding(
        type=_finding_type_for(scan_finding),
        value=scan_finding.title,
        description=scan_finding.description,
        severity=scan_finding.severity.value,
        metadata=metadata,
        source_tool=tool_name,
    )


def add_scan_finding(collector: ResultCollector, scan_finding: ScanFinding, phase: str):
    """
    Feed a single ScanFinding into a ResultCollector via the real public API.

    The collector ingests parser ``Finding`` objects through ``add_execution``,
    so we wrap the converted finding in a successful ToolExecution.
    """
    tool_phase = _PHASE_MAP.get(phase, ToolPhase.RECON)
    tool = _PHASE_TOOL[tool_phase]

    finding = _to_finding(scan_finding, tool.name)

    execution = ToolExecution(
        id=f"exec_{tool.name}",
        tool=tool,
        target=collector.target,
        command=f"{tool.binary} {collector.target}",
        state=ExecutionState.COMPLETED,
        return_code=0,
        findings=[finding],
    )

    return collector.add_execution(execution, phase=tool_phase)


def build_execution_batch(scan_findings, phase) -> ExecutionBatch:
    """
    Build a realistic ExecutionBatch (the thing executor.run_phase returns)
    carrying the given findings, so the real PhaseRunner.run_phase control
    flow (collector.add_phase_results -> PhaseReport) can be exercised.
    """
    tool = _PHASE_TOOL[phase]
    findings = [_to_finding(sf, tool.name) for sf in scan_findings]
    execution = ToolExecution(
        id=f"exec_{tool.name}",
        tool=tool,
        target="example.com",
        command=f"{tool.binary} example.com",
        state=ExecutionState.COMPLETED,
        return_code=0,
        findings=findings,
    )
    now = datetime.utcnow()
    return ExecutionBatch(
        id=f"batch_{phase.value}",
        phase=phase,
        executions=[execution],
        start_time=now,
        end_time=now,
    )


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_ollama_response():
    """Mock Ollama API response for AI checkpoints."""
    return {
        "model": "mistral:7b",
        "created_at": datetime.utcnow().isoformat(),
        "response": json.dumps({
            "recommendations": [
                {
                    "tool": "nuclei",
                    "priority": 1,
                    "reason": "Template-based scanning for known CVEs"
                },
                {
                    "tool": "sqlmap",
                    "priority": 2,
                    "reason": "SQL injection testing on discovered endpoints"
                }
            ],
            "attack_vectors": ["sqli", "xss", "ssrf"],
            "risk_assessment": "HIGH",
            "next_phase": "SCAN"
        }),
        "done": True,
    }


@pytest.fixture
def sample_recon_findings():
    """Sample findings from RECON phase."""
    return [
        ScanFinding(
            title="Subdomain: api.example.com",
            severity=ScanSeverity.INFO,
            description="Active subdomain with HTTP service",
            host="api.example.com",
            port=443,
            scanner="subfinder",
            tags=["subdomain", "recon"],
        ),
        ScanFinding(
            title="Subdomain: admin.example.com",
            severity=ScanSeverity.LOW,
            description="Admin panel detected",
            host="admin.example.com",
            port=443,
            scanner="subfinder",
            tags=["subdomain", "recon", "interesting"],
        ),
        ScanFinding(
            title="Open Port: 22/ssh",
            severity=ScanSeverity.INFO,
            description="SSH service on port 22",
            host="example.com",
            port=22,
            scanner="nmap",
            tags=["port", "ssh"],
        ),
        ScanFinding(
            title="Open Port: 3306/mysql",
            severity=ScanSeverity.MEDIUM,
            description="MySQL exposed to internet",
            host="example.com",
            port=3306,
            scanner="nmap",
            tags=["port", "database", "mysql"],
        ),
    ]


@pytest.fixture
def sample_scan_findings():
    """Sample findings from SCAN phase."""
    return [
        ScanFinding(
            title="SQL Injection in /api/users",
            severity=ScanSeverity.CRITICAL,
            description="Time-based blind SQL injection",
            host="api.example.com",
            port=443,
            url="https://api.example.com/api/users?id=1",
            scanner="nuclei",
            cve="CVE-2023-1234",
            cwe="CWE-89",
            tags=["sqli", "injection"],
        ),
        ScanFinding(
            title="XSS in /search",
            severity=ScanSeverity.HIGH,
            description="Reflected XSS via search parameter",
            host="example.com",
            port=443,
            url="https://example.com/search?q=test",
            scanner="dalfox",
            cwe="CWE-79",
            tags=["xss", "reflected"],
        ),
        ScanFinding(
            title="Directory listing enabled",
            severity=ScanSeverity.LOW,
            description="/backup/ directory listing",
            host="example.com",
            port=443,
            url="https://example.com/backup/",
            scanner="ffuf",
            tags=["directory", "information-disclosure"],
        ),
    ]


@pytest.fixture
def sample_exploit_findings():
    """Sample findings from EXPLOIT phase."""
    return [
        ScanFinding(
            title="SQLi Exploitation Success",
            severity=ScanSeverity.CRITICAL,
            description="Database dumped: users table with credentials",
            host="api.example.com",
            port=443,
            url="https://api.example.com/api/users?id=1",
            scanner="sqlmap",
            tags=["sqli", "exploitation", "data-breach"],
            evidence='{"tables": ["users", "sessions"], "dbms": "MySQL"}',
        ),
    ]


@pytest.fixture
def temp_output_dir():
    """Create temporary output directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def pipeline_config(temp_output_dir):
    """Create test pipeline configuration."""
    return PipelineConfig(
        phases=[
            PhaseConfig(
                phase=ToolPhase.RECON,
                tools=["subfinder", "httpx"],
                timeout=60,
            ),
            PhaseConfig(
                phase=ToolPhase.SCAN,
                tools=["nuclei", "ffuf"],
                timeout=120,
            ),
            PhaseConfig(
                phase=ToolPhase.EXPLOIT,
                tools=["sqlmap"],
                timeout=180,
            ),
        ],
        ai_checkpoints_enabled=True,
        ollama_model="mistral:7b",
        max_parallel_tools=2,
    )


# ============================================================================
# AI Checkpoint Tests
# ============================================================================

class TestAICheckpointClient:
    """Tests for Ollama AI checkpoint integration."""

    @pytest.mark.asyncio
    async def test_checkpoint_initialization(self):
        """Test AICheckpointClient initialization."""
        client = AICheckpointClient(
            base_url="http://localhost:11434",
            model="mistral:7b",
        )
        assert client.base_url == "http://localhost:11434"
        assert client.model == "mistral:7b"

    @pytest.mark.asyncio
    async def test_post_recon_checkpoint(self, mock_ollama_response, sample_recon_findings):
        """Test AI analysis after RECON phase."""
        client = AICheckpointClient()

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_ollama_response)
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await client.analyze_phase(
                phase=ToolPhase.RECON,
                findings_summary="Open Port: 22/ssh\nSubdomain: api.example.com",
                target="example.com",
            )

            assert result is not None
            assert "recommendations" in result or "next_phase" in result

    @pytest.mark.asyncio
    async def test_checkpoint_fallback_on_timeout(self, sample_recon_findings):
        """Test fallback to rule-based analysis on Ollama timeout."""
        client = AICheckpointClient()

        # Force the "Ollama unavailable" path so analyze_phase uses the
        # rule-based fallback instead of calling the model.
        with patch.object(client, "is_available", AsyncMock(return_value=False)):
            result = await client.analyze_phase(
                phase=ToolPhase.RECON,
                findings_summary="Open Port: 22/ssh\nSubdomain: api.example.com",
                target="example.com",
            )

            # Should return rule-based fallback analysis (not None, with
            # the fallback marker the collector produces).
            assert result is not None
            assert "Fallback Analysis" in result.get("analysis", "")
            assert len(result.get("recommendations", [])) > 0

    @pytest.mark.asyncio
    async def test_checkpoint_with_empty_findings(self):
        """Test checkpoint behavior with no findings."""
        client = AICheckpointClient()

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "response": json.dumps({"recommendations": [], "risk_assessment": "LOW"})
            })
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await client.analyze_phase(
                phase=ToolPhase.RECON,
                findings_summary="",
                target="example.com",
            )

            assert result is not None


# ============================================================================
# Phase Runner Tests
# ============================================================================

class TestPhaseRunner:
    """Tests for PhaseRunner pipeline execution."""

    @pytest.mark.asyncio
    async def test_runner_initialization(self, pipeline_config):
        """Test PhaseRunner initialization."""
        runner = PhaseRunner("example.com", pipeline_config)
        assert runner.state == PipelineState.IDLE
        assert runner.config == pipeline_config

    @pytest.mark.asyncio
    async def test_single_phase_execution(self, pipeline_config, sample_recon_findings):
        """Test execution of a single phase."""
        runner = PhaseRunner("example.com", pipeline_config)

        # The real run_phase calls executor.run_phase(...) -> ExecutionBatch,
        # then collector.add_phase_results(...) -> PhaseReport. Mock the
        # executor seam so findings flow through the real control path.
        batch = build_execution_batch(sample_recon_findings, ToolPhase.RECON)

        async def mock_run_phase(phase, target, *args, **kwargs):
            return batch

        with patch.object(runner.registry, "is_available", return_value=True):
            with patch.object(runner.executor, "run_phase", side_effect=mock_run_phase):
                # Keep AI checkpoint off the network: force fallback (offline) path.
                with patch.object(runner.ai_client, "is_available", AsyncMock(return_value=False)):
                    report = await runner.run_phase(ToolPhase.RECON)

        assert report.phase == ToolPhase.RECON
        assert report.state in ["completed", "success"]
        assert report.findings_count > 0

    @pytest.mark.asyncio
    async def test_full_pipeline_execution(
        self,
        pipeline_config,
        sample_recon_findings,
        sample_scan_findings,
        sample_exploit_findings,
    ):
        """Test full RECON → SCAN → EXPLOIT pipeline."""
        runner = PhaseRunner("example.com", pipeline_config)

        # Mock tool execution for each phase at the executor seam.
        batches = {
            ToolPhase.RECON: build_execution_batch(sample_recon_findings, ToolPhase.RECON),
            ToolPhase.SCAN: build_execution_batch(sample_scan_findings, ToolPhase.SCAN),
            ToolPhase.EXPLOIT: build_execution_batch(sample_exploit_findings, ToolPhase.EXPLOIT),
        }

        async def mock_run_phase(phase, target, *args, **kwargs):
            return batches[phase]

        with patch.object(runner.registry, "is_available", return_value=True):
            with patch.object(runner.executor, "run_phase", side_effect=mock_run_phase):
                with patch.object(runner.ai_client, "is_available", AsyncMock(return_value=False)):
                    report = await runner.run_pipeline()

        assert runner.state == PipelineState.COMPLETED
        assert report.total_findings > 0
        assert len(report.phases) == 3

    @pytest.mark.asyncio
    async def test_pipeline_with_ai_checkpoints(
        self,
        pipeline_config,
        sample_recon_findings,
        mock_ollama_response,
    ):
        """Test pipeline pauses for AI checkpoint analysis."""
        pipeline_config.ai_checkpoints_enabled = True
        runner = PhaseRunner("example.com", pipeline_config)

        checkpoint_called = False

        async def mock_checkpoint(phase, *args, **kwargs):
            nonlocal checkpoint_called
            checkpoint_called = True
            return {
                "analysis": "stub",
                "recommendations": [{"tool": "nuclei", "priority": 1}],
            }

        batch = build_execution_batch(sample_recon_findings, ToolPhase.RECON)

        async def mock_run_phase(phase, target, *args, **kwargs):
            return batch

        with patch.object(runner.registry, "is_available", return_value=True):
            with patch.object(runner.executor, "run_phase", side_effect=mock_run_phase):
                with patch.object(runner, "run_ai_checkpoint", side_effect=mock_checkpoint):
                    await runner.run_phase(ToolPhase.RECON)

        assert checkpoint_called, "AI checkpoint should be called after phase"

    @pytest.mark.asyncio
    async def test_pipeline_state_transitions(self, pipeline_config):
        """Test correct state transitions during pipeline."""
        runner = PhaseRunner("example.com", pipeline_config)
        states_seen = [runner.state]

        original_run = runner.run_phase

        async def tracking_run(*args, **kwargs):
            states_seen.append(runner.state)
            result = await original_run(*args, **kwargs)
            states_seen.append(runner.state)
            return result

        empty_batch = ExecutionBatch(id="empty", phase=ToolPhase.RECON, executions=[])

        async def mock_run_phase(phase, target, *args, **kwargs):
            return ExecutionBatch(id=f"empty_{phase.value}", phase=phase, executions=[])

        with patch.object(runner, "run_phase", side_effect=tracking_run):
            with patch.object(runner.executor, "run_phase", side_effect=mock_run_phase):
                with patch.object(runner.ai_client, "is_available", AsyncMock(return_value=False)):
                    await runner.run_pipeline()

        assert PipelineState.IDLE in states_seen
        assert PipelineState.RUNNING in states_seen or PipelineState.COMPLETED in states_seen
        assert runner.state == PipelineState.COMPLETED

    @pytest.mark.asyncio
    async def test_pipeline_cancellation(self, pipeline_config):
        """Test pipeline can be cancelled mid-execution."""
        runner = PhaseRunner("example.com", pipeline_config)

        async def slow_run_phase(phase, target, *args, **kwargs):
            await asyncio.sleep(10)
            return ExecutionBatch(id="slow", phase=phase, executions=[])

        with patch.object(runner.registry, "is_available", return_value=True):
            with patch.object(runner.executor, "run_phase", side_effect=slow_run_phase):
                task = asyncio.create_task(runner.run_pipeline())

                await asyncio.sleep(0.1)
                await runner.cancel()
                task.cancel()

                with pytest.raises(asyncio.CancelledError):
                    await task

                assert runner.state == PipelineState.CANCELLED


# ============================================================================
# Result Aggregation Tests
# ============================================================================

class TestResultCollector:
    """Tests for cross-phase result aggregation."""

    def test_finding_normalization(self, sample_recon_findings):
        """Test findings are normalized correctly."""
        collector = ResultCollector(target="example.com")

        for finding in sample_recon_findings:
            add_scan_finding(collector, finding, phase="recon")

        normalized = collector.get_all_findings()
        assert len(normalized) == len(sample_recon_findings)

        for nf in normalized:
            assert isinstance(nf, NormalizedFinding)
            assert nf.source_phase == ToolPhase.RECON

    def test_finding_deduplication(self, sample_recon_findings):
        """Test duplicate findings are merged."""
        collector = ResultCollector(target="example.com")

        # Add same finding twice
        for finding in sample_recon_findings:
            add_scan_finding(collector, finding, phase="recon")
            add_scan_finding(collector, finding, phase="recon")  # Duplicate

        normalized = collector.get_all_findings()
        assert len(normalized) == len(sample_recon_findings)

    def test_cross_phase_aggregation(
        self,
        sample_recon_findings,
        sample_scan_findings,
        sample_exploit_findings,
    ):
        """Test aggregation across multiple phases."""
        collector = ResultCollector(target="example.com")

        for finding in sample_recon_findings:
            add_scan_finding(collector, finding, phase="recon")
        for finding in sample_scan_findings:
            add_scan_finding(collector, finding, phase="scan")
        for finding in sample_exploit_findings:
            add_scan_finding(collector, finding, phase="exploit")

        stats = collector.get_statistics()
        assert stats["total_findings"] == (
            len(sample_recon_findings) +
            len(sample_scan_findings) +
            len(sample_exploit_findings)
        )
        assert "recon" in stats["tools_summary"]
        assert "scan" in stats["tools_summary"]
        assert "exploit" in stats["tools_summary"]


# ============================================================================
# Attack Path Detection Tests
# ============================================================================

class TestAttackPathDetection:
    """Tests for attack chain/path detection."""

    def test_sqli_to_data_breach_chain(
        self,
        sample_scan_findings,
        sample_exploit_findings,
    ):
        """Test detection of SQLi → Data Breach attack chain."""
        collector = ResultCollector(target="example.com")

        for finding in sample_scan_findings:
            add_scan_finding(collector, finding, phase="scan")
        for finding in sample_exploit_findings:
            add_scan_finding(collector, finding, phase="exploit")

        paths = collector.detect_attack_paths()

        # Should detect SQLi vulnerability leading to exploitation
        sqli_paths = [p for p in paths if "sql" in str(p.to_dict()).lower()]
        assert len(sqli_paths) > 0

    def test_recon_to_exploit_chain(
        self,
        sample_recon_findings,
        sample_scan_findings,
        sample_exploit_findings,
    ):
        """Test full chain from recon to exploitation."""
        collector = ResultCollector(target="example.com")

        for finding in sample_recon_findings:
            add_scan_finding(collector, finding, phase="recon")
        for finding in sample_scan_findings:
            add_scan_finding(collector, finding, phase="scan")
        for finding in sample_exploit_findings:
            add_scan_finding(collector, finding, phase="exploit")

        paths = collector.detect_attack_paths()

        # Should have at least one complete attack path
        assert len(paths) > 0

        # Verify path structure
        for path in paths:
            assert hasattr(path, "steps") or isinstance(path, (list, dict))

    def test_no_paths_for_info_only_findings(self, sample_recon_findings):
        """Test no attack paths for INFO-only findings."""
        collector = ResultCollector(target="example.com")

        # Add only INFO severity findings
        info_findings = [f for f in sample_recon_findings if f.severity == ScanSeverity.INFO]
        for finding in info_findings:
            add_scan_finding(collector, finding, phase="recon")

        paths = collector.detect_attack_paths()

        # INFO findings alone shouldn't create attack paths
        assert len(paths) == 0


# ============================================================================
# Tool Registry Integration Tests
# ============================================================================

class TestToolRegistryIntegration:
    """Tests for tool registry with pipeline."""

    @pytest.mark.asyncio
    async def test_discover_available_tools(self):
        """Test tool discovery on the system."""
        registry = ToolRegistry()
        status = await registry.discover_tools()

        assert isinstance(status, dict)
        # At minimum, some tools should be checked
        assert len(status) > 0

    def test_phase_tool_selection(self):
        """Test tools are correctly grouped by phase."""
        registry = ToolRegistry()

        recon_tools = [t for t in TOOL_REGISTRY.values() if t.phase == ToolPhase.RECON]
        scan_tools = [t for t in TOOL_REGISTRY.values() if t.phase == ToolPhase.SCAN]
        exploit_tools = [t for t in TOOL_REGISTRY.values() if t.phase == ToolPhase.EXPLOIT]

        assert len(recon_tools) > 0
        assert len(scan_tools) > 0
        assert len(exploit_tools) > 0

    def test_capability_based_selection(self):
        """Test selecting tools by capability."""
        registry = ToolRegistry()

        # Find tools with SQLI capability
        sqli_tools = [
            t for t in TOOL_REGISTRY.values()
            if ToolCapability.SQLI_SCAN in t.capabilities
            or ToolCapability.SQLI_EXPLOIT in t.capabilities
        ]

        assert len(sqli_tools) > 0
        assert any("sqlmap" in t.name for t in sqli_tools)


# ============================================================================
# Offline Mode Tests
# ============================================================================

class TestOfflineMode:
    """Tests for offline operation without internet."""

    @pytest.mark.asyncio
    async def test_pipeline_without_internet(self, pipeline_config):
        """Test pipeline runs with local tools only."""
        runner = PhaseRunner("example.com", pipeline_config)

        # Simulate no internet: local tools return empty batches and the
        # AI checkpoint client reports unavailable (rule-based fallback path).
        async def mock_run_phase(phase, target, *args, **kwargs):
            return ExecutionBatch(id=f"offline_{phase.value}", phase=phase, executions=[])

        with patch.object(runner.registry, "is_available", return_value=True):
            with patch.object(runner.executor, "run_phase", side_effect=mock_run_phase):
                with patch.object(runner.ai_client, "is_available", AsyncMock(return_value=False)):
                    report = await runner.run_pipeline()

                    assert report is not None
                    assert runner.state == PipelineState.COMPLETED

    @pytest.mark.asyncio
    async def test_ollama_local_only(self):
        """Test Ollama client uses local endpoint only."""
        client = AICheckpointClient(base_url="http://localhost:11434")

        # Should not make external requests
        assert "localhost" in client.base_url or "127.0.0.1" in client.base_url

    def test_wordlist_availability(self):
        """Test offline wordlists are available."""
        from aipt_v2.offline.readiness import OfflineReadinessChecker

        checker = OfflineReadinessChecker()
        # This checks if the readiness module exists and can be instantiated


# ============================================================================
# Export Format Tests
# ============================================================================

class TestExportFormats:
    """Tests for result export in various formats."""

    def test_json_export(
        self,
        sample_recon_findings,
        sample_scan_findings,
        temp_output_dir,
    ):
        """Test JSON export of findings."""
        collector = ResultCollector(target="example.com")

        for finding in sample_recon_findings + sample_scan_findings:
            add_scan_finding(collector, finding, phase="test")

        json_path = temp_output_dir / "findings.json"
        json_path.write_text(collector.to_json())

        assert json_path.exists()

        with open(json_path) as f:
            data = json.load(f)
            assert "findings" in data
            assert len(data["findings"]) > 0

    def test_markdown_export(
        self,
        sample_recon_findings,
        sample_scan_findings,
        temp_output_dir,
    ):
        """Test Markdown export of findings."""
        collector = ResultCollector(target="example.com")

        for finding in sample_recon_findings + sample_scan_findings:
            add_scan_finding(collector, finding, phase="test")

        md_path = temp_output_dir / "findings.md"
        md_path.write_text(collector.to_markdown())

        assert md_path.exists()

        content = md_path.read_text()
        assert "# " in content  # Has headers
        assert "CRITICAL" in content or "HIGH" in content or "MEDIUM" in content

    def test_compact_llm_export(self, sample_scan_findings):
        """Test compact format for LLM context."""
        collector = ResultCollector(target="example.com")

        for finding in sample_scan_findings:
            add_scan_finding(collector, finding, phase="scan")

        compact = collector.to_compact_format()

        # Should be concise
        assert len(compact) < 5000  # Under token limit
        # Should contain finding IDs
        assert "[" in compact and "]" in compact


# ============================================================================
# Performance Tests
# ============================================================================

class TestPerformance:
    """Performance and resource tests."""

    @pytest.mark.asyncio
    async def test_concurrent_tool_execution(self, pipeline_config):
        """Test tools run concurrently within limits."""
        pipeline_config.max_parallel_tools = 3
        runner = PhaseRunner("example.com", pipeline_config)

        # Two real recon tools so executor.run_phase fans out into multiple
        # run_tool coroutines that asyncio.gather runs concurrently.
        recon_tools = [TOOL_REGISTRY["subfinder"], TOOL_REGISTRY["httpx"]]

        running = 0
        max_concurrent = 0

        async def timed_tool(tool_name, target, *args, **kwargs):
            nonlocal running, max_concurrent
            running += 1
            max_concurrent = max(max_concurrent, running)
            await asyncio.sleep(0.1)
            running -= 1
            return ToolExecution(
                id=f"exec_{tool_name}",
                tool=TOOL_REGISTRY[tool_name],
                target=target,
                command=f"{tool_name} {target}",
                state=ExecutionState.COMPLETED,
                return_code=0,
                findings=[],
            )

        with patch.object(runner.registry, "is_available", return_value=True):
            with patch.object(runner.registry, "get_tools_by_phase", return_value=recon_tools):
                with patch.object(runner.executor, "run_tool", side_effect=timed_tool):
                    with patch.object(runner.ai_client, "is_available", AsyncMock(return_value=False)):
                        report = await runner.run_phase(ToolPhase.RECON)

        # Both tools ran, and they ran at the same time (concurrently).
        assert report.tools_run == 2
        assert max_concurrent == 2

    @pytest.mark.asyncio
    async def test_large_finding_set(self):
        """Test handling of many findings."""
        collector = ResultCollector(target="example.com")

        # Add 1000 findings
        for i in range(1000):
            finding = ScanFinding(
                title=f"Finding {i}",
                severity=ScanSeverity.INFO,
                description=f"Description {i}",
                host=f"host{i % 100}.example.com",
                scanner="test",
            )
            add_scan_finding(collector, finding, phase="test")

        stats = collector.get_statistics()
        assert stats["total_findings"] == 1000

        # Should still be fast
        compact = collector.to_compact_format()
        assert len(compact) > 0


# ============================================================================
# Integration Test - Full E2E
# ============================================================================

class TestFullE2EIntegration:
    """Full end-to-end integration tests."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_complete_pipeline_with_mock_tools(
        self,
        pipeline_config,
        sample_recon_findings,
        sample_scan_findings,
        sample_exploit_findings,
        temp_output_dir,
    ):
        """
        Complete E2E test simulating full pipeline execution.

        This test verifies:
        1. Pipeline initialization
        2. RECON phase execution
        3. AI checkpoint after RECON
        4. SCAN phase with checkpoint recommendations
        5. AI checkpoint after SCAN
        6. EXPLOIT phase execution
        7. Final report generation
        8. Attack path detection
        """
        runner = PhaseRunner("example.com", pipeline_config)

        # Phase execution mocks at the executor seam: each phase yields a
        # realistic ExecutionBatch that flows through the real collector.
        batches = {
            ToolPhase.RECON: build_execution_batch(sample_recon_findings, ToolPhase.RECON),
            ToolPhase.SCAN: build_execution_batch(sample_scan_findings, ToolPhase.SCAN),
            ToolPhase.EXPLOIT: build_execution_batch(sample_exploit_findings, ToolPhase.EXPLOIT),
        }

        async def mock_run_phase(phase, target, *args, **kwargs):
            return batches[phase]

        # AI checkpoint mock (wraps the real run_ai_checkpoint seam).
        checkpoint_calls = []

        async def mock_checkpoint(phase, *args, **kwargs):
            checkpoint_calls.append(phase)
            return {
                "analysis": "stub",
                "recommendations": [{"tool": "nuclei", "priority": 1}],
                "risk_assessment": "HIGH",
                "proceed": True,
            }

        with patch.object(runner.registry, "is_available", return_value=True):
            with patch.object(runner.executor, "run_phase", side_effect=mock_run_phase):
                with patch.object(runner, "run_ai_checkpoint", side_effect=mock_checkpoint):
                    # Execute full pipeline
                    report = await runner.run_pipeline()

        # Verify pipeline completed
        assert runner.state == PipelineState.COMPLETED
        assert report is not None

        # Verify all phases ran
        assert len(report.phases) == 3

        # Verify AI checkpoints were called
        assert len(checkpoint_calls) >= 2  # After RECON and SCAN

        # The pipeline aggregates findings in its own collector.
        collector = runner.get_results()
        stats = collector.get_statistics()
        assert stats["total_findings"] > 0

        # Verify attack paths detected (SQLi attack chain).
        paths = collector.detect_attack_paths()
        assert len(paths) > 0

        # Export results
        json_path = temp_output_dir / "full_report.json"
        json_path.write_text(collector.to_json())
        assert json_path.exists()

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.skipif(
        os.environ.get("SKIP_OLLAMA_TESTS", "1") == "1",
        reason="Ollama not available or SKIP_OLLAMA_TESTS=1"
    )
    async def test_real_ollama_checkpoint(self, sample_recon_findings):
        """
        Test with real Ollama instance (requires Ollama running).

        Run with: SKIP_OLLAMA_TESTS=0 pytest -k test_real_ollama
        """
        client = AICheckpointClient(
            base_url="http://localhost:11434",
            model="mistral:7b",
        )

        result = await client.analyze_phase(
            phase=ToolPhase.RECON,
            findings_summary="Open Port: 22/ssh\nSubdomain: api.example.com",
            target="example.com",
        )

        assert result is not None
        # Real Ollama should provide structured recommendations
        assert "recommendations" in result or "response" in result


# ============================================================================
# Convenience Function Tests
# ============================================================================

class TestConvenienceFunctions:
    """Tests for run_quick_scan and run_full_scan helpers."""

    @pytest.mark.asyncio
    async def test_quick_scan_function(self, temp_output_dir):
        """Test run_quick_scan convenience function."""
        with patch("aipt_v2.execution.phase_runner.PhaseRunner") as MockRunner:
            mock_instance = AsyncMock()
            mock_instance.run.return_value = MagicMock(
                total_findings=5,
                phase_reports=[],
            )
            MockRunner.return_value = mock_instance

            report = await run_quick_scan(
                target="example.com",
            )

            assert report is not None
            MockRunner.assert_called_once()

    @pytest.mark.asyncio
    async def test_full_scan_function(self, temp_output_dir):
        """Test run_full_scan convenience function."""
        with patch("aipt_v2.execution.phase_runner.PhaseRunner") as MockRunner:
            mock_instance = AsyncMock()
            mock_instance.run.return_value = MagicMock(
                total_findings=15,
                phase_reports=[],
            )
            MockRunner.return_value = mock_instance

            report = await run_full_scan(
                target="example.com",
                include_exploit=True,
            )

            assert report is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
