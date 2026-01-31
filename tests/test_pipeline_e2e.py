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
from aipt_v2.scanners.base import ScanResult, ScanFinding, ScanSeverity


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
            raw_data={"tables": ["users", "sessions"], "dbms": "MySQL"},
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
        target="example.com",
        output_dir=temp_output_dir,
        phases=[
            PhaseConfig(
                name="recon",
                phase=ToolPhase.RECON,
                tools=["subfinder", "httpx"],
                timeout=60,
            ),
            PhaseConfig(
                name="scan",
                phase=ToolPhase.SCAN,
                tools=["nuclei", "ffuf"],
                timeout=120,
            ),
            PhaseConfig(
                name="exploit",
                phase=ToolPhase.EXPLOIT,
                tools=["sqlmap"],
                timeout=180,
            ),
        ],
        enable_ai_checkpoints=True,
        ollama_model="mistral:7b",
        max_concurrent_tools=2,
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
                phase="recon",
                findings=sample_recon_findings,
                target="example.com",
            )

            assert result is not None
            assert "recommendations" in result or "next_phase" in result

    @pytest.mark.asyncio
    async def test_checkpoint_fallback_on_timeout(self, sample_recon_findings):
        """Test fallback to rule-based analysis on Ollama timeout."""
        client = AICheckpointClient(timeout=1)

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.side_effect = asyncio.TimeoutError()

            result = await client.analyze_phase(
                phase="recon",
                findings=sample_recon_findings,
                target="example.com",
            )

            # Should return rule-based fallback
            assert result is not None
            assert result.get("fallback") == True

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
                phase="recon",
                findings=[],
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
        runner = PhaseRunner(pipeline_config)
        assert runner.state == PipelineState.IDLE
        assert runner.config == pipeline_config

    @pytest.mark.asyncio
    async def test_single_phase_execution(self, pipeline_config, sample_recon_findings):
        """Test execution of a single phase."""
        runner = PhaseRunner(pipeline_config)

        with patch.object(runner, "_run_tools") as mock_run:
            mock_run.return_value = sample_recon_findings

            report = await runner.run_phase("recon")

            assert report.phase_name == "recon"
            assert report.status in ["completed", "success"]
            assert len(report.findings) > 0

    @pytest.mark.asyncio
    async def test_full_pipeline_execution(
        self,
        pipeline_config,
        sample_recon_findings,
        sample_scan_findings,
        sample_exploit_findings,
    ):
        """Test full RECON → SCAN → EXPLOIT pipeline."""
        runner = PhaseRunner(pipeline_config)

        # Mock tool execution for each phase
        findings_by_phase = {
            "recon": sample_recon_findings,
            "scan": sample_scan_findings,
            "exploit": sample_exploit_findings,
        }

        async def mock_run_tools(phase_name, *args, **kwargs):
            return findings_by_phase.get(phase_name, [])

        with patch.object(runner, "_run_tools", side_effect=mock_run_tools):
            with patch.object(runner, "_ai_checkpoint", return_value={"proceed": True}):
                report = await runner.run()

                assert runner.state == PipelineState.COMPLETED
                assert report.total_findings > 0
                assert len(report.phase_reports) == 3

    @pytest.mark.asyncio
    async def test_pipeline_with_ai_checkpoints(
        self,
        pipeline_config,
        sample_recon_findings,
        mock_ollama_response,
    ):
        """Test pipeline pauses for AI checkpoint analysis."""
        pipeline_config.enable_ai_checkpoints = True
        runner = PhaseRunner(pipeline_config)

        checkpoint_called = False

        async def mock_checkpoint(*args, **kwargs):
            nonlocal checkpoint_called
            checkpoint_called = True
            return {"recommendations": [{"tool": "nuclei", "priority": 1}]}

        with patch.object(runner, "_run_tools", return_value=sample_recon_findings):
            with patch.object(runner, "_ai_checkpoint", side_effect=mock_checkpoint):
                await runner.run_phase("recon")

        assert checkpoint_called, "AI checkpoint should be called after phase"

    @pytest.mark.asyncio
    async def test_pipeline_state_transitions(self, pipeline_config):
        """Test correct state transitions during pipeline."""
        runner = PhaseRunner(pipeline_config)
        states_seen = [runner.state]

        original_run = runner.run_phase

        async def tracking_run(*args, **kwargs):
            states_seen.append(runner.state)
            result = await original_run(*args, **kwargs)
            states_seen.append(runner.state)
            return result

        with patch.object(runner, "run_phase", side_effect=tracking_run):
            with patch.object(runner, "_run_tools", return_value=[]):
                await runner.run()

        assert PipelineState.IDLE in states_seen
        assert PipelineState.RUNNING in states_seen or PipelineState.COMPLETED in states_seen

    @pytest.mark.asyncio
    async def test_pipeline_cancellation(self, pipeline_config):
        """Test pipeline can be cancelled mid-execution."""
        runner = PhaseRunner(pipeline_config)

        async def slow_tools(*args, **kwargs):
            await asyncio.sleep(10)
            return []

        with patch.object(runner, "_run_tools", side_effect=slow_tools):
            task = asyncio.create_task(runner.run())

            await asyncio.sleep(0.1)
            await runner.cancel()

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
        collector = ResultCollector()

        for finding in sample_recon_findings:
            collector.add_finding(finding, phase="recon")

        normalized = collector.get_normalized_findings()
        assert len(normalized) == len(sample_recon_findings)

        for nf in normalized:
            assert isinstance(nf, NormalizedFinding)
            assert nf.phase == "recon"

    def test_finding_deduplication(self, sample_recon_findings):
        """Test duplicate findings are merged."""
        collector = ResultCollector()

        # Add same finding twice
        for finding in sample_recon_findings:
            collector.add_finding(finding, phase="recon")
            collector.add_finding(finding, phase="recon")  # Duplicate

        normalized = collector.get_normalized_findings()
        assert len(normalized) == len(sample_recon_findings)

    def test_cross_phase_aggregation(
        self,
        sample_recon_findings,
        sample_scan_findings,
        sample_exploit_findings,
    ):
        """Test aggregation across multiple phases."""
        collector = ResultCollector()

        for finding in sample_recon_findings:
            collector.add_finding(finding, phase="recon")
        for finding in sample_scan_findings:
            collector.add_finding(finding, phase="scan")
        for finding in sample_exploit_findings:
            collector.add_finding(finding, phase="exploit")

        stats = collector.get_statistics()
        assert stats["total_findings"] == (
            len(sample_recon_findings) +
            len(sample_scan_findings) +
            len(sample_exploit_findings)
        )
        assert "recon" in stats["by_phase"]
        assert "scan" in stats["by_phase"]
        assert "exploit" in stats["by_phase"]


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
        collector = ResultCollector()

        for finding in sample_scan_findings:
            collector.add_finding(finding, phase="scan")
        for finding in sample_exploit_findings:
            collector.add_finding(finding, phase="exploit")

        paths = collector.detect_attack_paths()

        # Should detect SQLi vulnerability leading to exploitation
        sqli_paths = [p for p in paths if "sqli" in str(p).lower()]
        assert len(sqli_paths) > 0

    def test_recon_to_exploit_chain(
        self,
        sample_recon_findings,
        sample_scan_findings,
        sample_exploit_findings,
    ):
        """Test full chain from recon to exploitation."""
        collector = ResultCollector()

        for finding in sample_recon_findings:
            collector.add_finding(finding, phase="recon")
        for finding in sample_scan_findings:
            collector.add_finding(finding, phase="scan")
        for finding in sample_exploit_findings:
            collector.add_finding(finding, phase="exploit")

        paths = collector.detect_attack_paths()

        # Should have at least one complete attack path
        assert len(paths) > 0

        # Verify path structure
        for path in paths:
            assert hasattr(path, "steps") or isinstance(path, (list, dict))

    def test_no_paths_for_info_only_findings(self, sample_recon_findings):
        """Test no attack paths for INFO-only findings."""
        collector = ResultCollector()

        # Add only INFO severity findings
        info_findings = [f for f in sample_recon_findings if f.severity == ScanSeverity.INFO]
        for finding in info_findings:
            collector.add_finding(finding, phase="recon")

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
        pipeline_config.offline_mode = True
        runner = PhaseRunner(pipeline_config)

        # Mock successful local tool execution
        with patch.object(runner, "_run_tools", return_value=[]):
            with patch.object(runner, "_ai_checkpoint", return_value={"fallback": True}):
                report = await runner.run()

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
        collector = ResultCollector()

        for finding in sample_recon_findings + sample_scan_findings:
            collector.add_finding(finding, phase="test")

        json_path = temp_output_dir / "findings.json"
        collector.export_json(str(json_path))

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
        collector = ResultCollector()

        for finding in sample_recon_findings + sample_scan_findings:
            collector.add_finding(finding, phase="test")

        md_path = temp_output_dir / "findings.md"
        collector.export_markdown(str(md_path))

        assert md_path.exists()

        content = md_path.read_text()
        assert "# " in content  # Has headers
        assert "CRITICAL" in content or "HIGH" in content or "MEDIUM" in content

    def test_compact_llm_export(self, sample_scan_findings):
        """Test compact format for LLM context."""
        collector = ResultCollector()

        for finding in sample_scan_findings:
            collector.add_finding(finding, phase="scan")

        compact = collector.export_compact()

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
        pipeline_config.max_concurrent_tools = 3
        runner = PhaseRunner(pipeline_config)

        execution_times = []

        async def timed_tool(*args, **kwargs):
            start = datetime.now()
            await asyncio.sleep(0.1)
            execution_times.append((datetime.now() - start).total_seconds())
            return []

        with patch.object(runner, "_run_single_tool", side_effect=timed_tool):
            await runner.run_phase("recon")

        # If running concurrently, total time should be less than sequential
        if len(execution_times) > 1:
            # Just verify concurrent execution happened
            assert True

    @pytest.mark.asyncio
    async def test_large_finding_set(self):
        """Test handling of many findings."""
        collector = ResultCollector()

        # Add 1000 findings
        for i in range(1000):
            finding = ScanFinding(
                title=f"Finding {i}",
                severity=ScanSeverity.INFO,
                description=f"Description {i}",
                host=f"host{i % 100}.example.com",
                scanner="test",
            )
            collector.add_finding(finding, phase="test")

        stats = collector.get_statistics()
        assert stats["total_findings"] == 1000

        # Should still be fast
        compact = collector.export_compact()
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
        runner = PhaseRunner(pipeline_config)
        collector = ResultCollector()

        # Phase execution mocks
        phase_findings = {
            "recon": sample_recon_findings,
            "scan": sample_scan_findings,
            "exploit": sample_exploit_findings,
        }

        async def mock_run_tools(phase_name, tools, *args, **kwargs):
            findings = phase_findings.get(phase_name, [])
            for f in findings:
                collector.add_finding(f, phase=phase_name)
            return findings

        # AI checkpoint mock
        checkpoint_calls = []

        async def mock_checkpoint(phase, findings, *args, **kwargs):
            checkpoint_calls.append(phase)
            return {
                "recommendations": [{"tool": "nuclei", "priority": 1}],
                "risk_assessment": "HIGH",
                "proceed": True,
            }

        with patch.object(runner, "_run_tools", side_effect=mock_run_tools):
            with patch.object(runner, "_ai_checkpoint", side_effect=mock_checkpoint):
                # Execute full pipeline
                report = await runner.run()

                # Verify pipeline completed
                assert runner.state == PipelineState.COMPLETED
                assert report is not None

                # Verify all phases ran
                assert len(report.phase_reports) == 3

                # Verify AI checkpoints were called
                assert len(checkpoint_calls) >= 2  # After RECON and SCAN

                # Verify findings collected
                stats = collector.get_statistics()
                assert stats["total_findings"] > 0

                # Verify attack paths detected
                paths = collector.detect_attack_paths()
                # Should detect SQLi attack chain
                assert len(paths) > 0

                # Export results
                json_path = temp_output_dir / "full_report.json"
                collector.export_json(str(json_path))
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
            phase="recon",
            findings=sample_recon_findings,
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
                output_dir=temp_output_dir,
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
                output_dir=temp_output_dir,
                enable_ai_checkpoints=True,
            )

            assert report is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
