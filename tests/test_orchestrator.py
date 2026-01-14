"""
Unit Tests for AIPT v2 Orchestrator Module
==========================================

Tests for orchestrator.py - Full penetration testing pipeline.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
from datetime import datetime


# ============== Dataclass Tests ==============

class TestFindingDataclass:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        from aipt_v2.orchestrator import Finding

        finding = Finding(
            type="vulnerability",
            value="SQL Injection",
            description="Found SQL injection in login form",
            severity="critical",
            phase="scan",
            tool="nuclei",
        )

        assert finding.type == "vulnerability"
        assert finding.value == "SQL Injection"
        assert finding.severity == "critical"
        assert finding.phase == "scan"
        assert finding.tool == "nuclei"

    def test_finding_defaults(self):
        """Test finding default values."""
        from aipt_v2.orchestrator import Finding

        finding = Finding(
            type="vuln",
            value="XSS",
            description="Reflected XSS",
            severity="high",
            phase="scan",
            tool="test",
        )

        assert finding.target == ""
        assert finding.evidence == ""
        assert finding.remediation == ""
        assert finding.metadata == {}
        assert finding.timestamp  # Should have default timestamp

    def test_finding_with_metadata(self):
        """Test finding with metadata."""
        from aipt_v2.orchestrator import Finding

        finding = Finding(
            type="vulnerability",
            value="CVE-2024-1234",
            description="Test vuln",
            severity="high",
            phase="exploit",
            tool="acunetix",
            target="https://example.com/api",
            metadata={
                "cvss": 8.5,
                "cwe": "CWE-89",
                "vuln_id": "vuln-123"
            }
        )

        assert finding.metadata["cvss"] == 8.5
        assert finding.metadata["cwe"] == "CWE-89"


class TestPhaseResultDataclass:
    """Tests for PhaseResult dataclass."""

    def test_phase_result_creation(self):
        """Test phase result creation."""
        from aipt_v2.orchestrator import PhaseResult, Phase

        result = PhaseResult(
            phase=Phase.RECON,
            status="completed",
            started_at="2024-01-01T00:00:00",
            finished_at="2024-01-01T00:05:00",
            duration=300.0,
            findings=[],
            tools_run=["subfinder", "httpx"],
        )

        assert result.phase == Phase.RECON
        assert result.status == "completed"
        assert result.duration == 300.0
        assert len(result.tools_run) == 2

    def test_phase_result_defaults(self):
        """Test phase result default values."""
        from aipt_v2.orchestrator import PhaseResult, Phase

        result = PhaseResult(
            phase=Phase.SCAN,
            status="completed",
            started_at="2024-01-01T00:00:00",
            finished_at="2024-01-01T00:10:00",
            duration=600.0,
            findings=[],
            tools_run=[],
        )

        assert result.errors == []
        assert result.metadata == {}


class TestOrchestratorConfigDataclass:
    """Tests for OrchestratorConfig dataclass."""

    def test_config_defaults(self):
        """Test config default values."""
        from aipt_v2.orchestrator import OrchestratorConfig

        config = OrchestratorConfig(target="example.com")

        assert config.target == "example.com"
        assert config.output_dir == "./scan_results"
        assert config.skip_recon is False
        assert config.skip_scan is False
        assert config.skip_exploit is False
        assert config.skip_report is False
        assert config.use_acunetix is True
        assert config.use_burp is False
        assert config.report_format == "html"

    def test_config_custom_values(self):
        """Test config with custom values."""
        from aipt_v2.orchestrator import OrchestratorConfig

        config = OrchestratorConfig(
            target="example.com",
            output_dir="/tmp/results",
            skip_recon=True,
            use_acunetix=False,
            use_burp=True,
            acunetix_profile="high_risk",
        )

        assert config.output_dir == "/tmp/results"
        assert config.skip_recon is True
        assert config.use_acunetix is False
        assert config.use_burp is True
        assert config.acunetix_profile == "high_risk"

    def test_config_recon_tools_default(self):
        """Test default recon tools."""
        from aipt_v2.orchestrator import OrchestratorConfig

        config = OrchestratorConfig(target="example.com")

        assert "subfinder" in config.recon_tools
        assert "httpx" in config.recon_tools
        assert "nmap" in config.recon_tools

    def test_config_scan_tools_default(self):
        """Test default scan tools."""
        from aipt_v2.orchestrator import OrchestratorConfig

        config = OrchestratorConfig(target="example.com")

        assert "nuclei" in config.scan_tools
        assert "ffuf" in config.scan_tools
        assert "sslscan" in config.scan_tools


# ============== Enums Tests ==============

class TestEnums:
    """Tests for Phase and Severity enums."""

    def test_phase_values(self):
        """Test Phase enum values."""
        from aipt_v2.orchestrator import Phase

        assert Phase.RECON.value == "recon"
        assert Phase.SCAN.value == "scan"
        assert Phase.EXPLOIT.value == "exploit"
        assert Phase.REPORT.value == "report"

    def test_severity_values(self):
        """Test Severity enum values."""
        from aipt_v2.orchestrator import Severity

        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


# ============== Orchestrator Class Tests ==============

class TestOrchestratorInitialization:
    """Tests for Orchestrator initialization."""

    @pytest.fixture
    def temp_output_dir(self, tmp_path):
        """Create temporary output directory."""
        return tmp_path / "scan_results"

    def test_basic_initialization(self, temp_output_dir):
        """Test basic orchestrator initialization."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(temp_output_dir)
            )
            orch = Orchestrator("example.com", config)

            assert orch.domain == "example.com"
            assert orch.target == "https://example.com"
            assert orch.findings == []
            assert orch.subdomains == []
            assert orch.live_hosts == []

    def test_target_normalization_https(self, temp_output_dir):
        """Test target normalization adds https."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(temp_output_dir)
            )
            orch = Orchestrator("example.com", config)

            assert orch.target == "https://example.com"

    def test_target_normalization_preserves_http(self, temp_output_dir):
        """Test target normalization preserves http."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="http://example.com",
                output_dir=str(temp_output_dir)
            )
            orch = Orchestrator("http://example.com", config)

            assert orch.target == "http://example.com"

    def test_domain_extraction(self, temp_output_dir):
        """Test domain extraction from URL."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="https://api.example.com:8443/path",
                output_dir=str(temp_output_dir)
            )
            orch = Orchestrator("https://api.example.com:8443/path", config)

            assert orch.domain == "api.example.com"

    def test_output_directory_created(self, temp_output_dir):
        """Test output directory is created."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(temp_output_dir)
            )
            orch = Orchestrator("example.com", config)

            assert orch.output_dir.exists()

    def test_callbacks_default_to_none(self, temp_output_dir):
        """Test callbacks are None by default."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(temp_output_dir)
            )
            orch = Orchestrator("example.com", config)

            assert orch.on_phase_start is None
            assert orch.on_phase_complete is None
            assert orch.on_finding is None


class TestOrchestratorStaticMethods:
    """Tests for Orchestrator static methods."""

    def test_normalize_target_adds_https(self):
        """Test target normalization adds https."""
        from aipt_v2.orchestrator import Orchestrator

        assert Orchestrator._normalize_target("example.com") == "https://example.com"

    def test_normalize_target_preserves_https(self):
        """Test normalization preserves https."""
        from aipt_v2.orchestrator import Orchestrator

        assert Orchestrator._normalize_target("https://example.com") == "https://example.com"

    def test_normalize_target_preserves_http(self):
        """Test normalization preserves http."""
        from aipt_v2.orchestrator import Orchestrator

        assert Orchestrator._normalize_target("http://example.com") == "http://example.com"

    def test_extract_domain_simple(self):
        """Test domain extraction from simple URL."""
        from aipt_v2.orchestrator import Orchestrator

        assert Orchestrator._extract_domain("https://example.com") == "example.com"

    def test_extract_domain_with_port(self):
        """Test domain extraction strips port."""
        from aipt_v2.orchestrator import Orchestrator

        assert Orchestrator._extract_domain("https://example.com:8443") == "example.com"

    def test_extract_domain_with_path(self):
        """Test domain extraction strips path."""
        from aipt_v2.orchestrator import Orchestrator

        assert Orchestrator._extract_domain("https://example.com/api/v1") == "example.com"

    def test_extract_domain_subdomain(self):
        """Test domain extraction preserves subdomain."""
        from aipt_v2.orchestrator import Orchestrator

        assert Orchestrator._extract_domain("https://api.example.com") == "api.example.com"


class TestOrchestratorHelperMethods:
    """Tests for Orchestrator helper methods."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator instance for testing."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results")
            )
            return Orchestrator("example.com", config)

    def test_parse_nuclei_severity_critical(self, orchestrator):
        """Test parsing critical severity."""
        assert orchestrator._parse_nuclei_severity("[cve-2024] [critical] target") == "critical"

    def test_parse_nuclei_severity_high(self, orchestrator):
        """Test parsing high severity."""
        assert orchestrator._parse_nuclei_severity("[sqli] [high] target") == "high"

    def test_parse_nuclei_severity_medium(self, orchestrator):
        """Test parsing medium severity."""
        assert orchestrator._parse_nuclei_severity("[xss] [medium] target") == "medium"

    def test_parse_nuclei_severity_low(self, orchestrator):
        """Test parsing low severity."""
        assert orchestrator._parse_nuclei_severity("[misc] [low] target") == "low"

    def test_parse_nuclei_severity_default(self, orchestrator):
        """Test default severity parsing."""
        assert orchestrator._parse_nuclei_severity("[template] target") == "info"

    def test_add_finding_triggers_callback(self, orchestrator):
        """Test adding finding triggers callback."""
        from aipt_v2.orchestrator import Finding

        callback_called = []

        def on_finding(f):
            callback_called.append(f)

        orchestrator.on_finding = on_finding

        finding = Finding(
            type="test",
            value="test",
            description="test",
            severity="info",
            phase="test",
            tool="test",
        )
        orchestrator._add_finding(finding)

        assert len(callback_called) == 1
        assert callback_called[0] == finding
        assert finding in orchestrator.findings


class TestOrchestratorCommandExecution:
    """Tests for command execution."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator instance."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results")
            )
            return Orchestrator("example.com", config)

    @pytest.mark.asyncio
    async def test_run_command_success(self, orchestrator):
        """Test successful command execution."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"output", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"output", b"")):
            ret, output = await orchestrator._run_command("echo test")

            assert ret == 0
            assert "output" in output

    @pytest.mark.asyncio
    async def test_run_command_timeout(self, orchestrator):
        """Test command timeout handling."""
        with patch("asyncio.create_subprocess_shell", side_effect=asyncio.TimeoutError()):
            ret, output = await orchestrator._run_command("sleep 1000", timeout=1)

            assert ret == -1
            assert "timed out" in output.lower()

    @pytest.mark.asyncio
    async def test_run_command_exception(self, orchestrator):
        """Test command exception handling."""
        with patch("asyncio.create_subprocess_shell", side_effect=Exception("Test error")):
            ret, output = await orchestrator._run_command("bad command")

            assert ret == -1
            assert "Test error" in output


# ============== Phase Execution Tests ==============

class TestReconPhase:
    """Tests for reconnaissance phase."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator for recon testing."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results"),
                recon_tools=["subfinder"],  # Minimal tools for testing
            )
            return Orchestrator("example.com", config)

    @pytest.mark.asyncio
    async def test_recon_runs_tools(self, orchestrator):
        """Test recon runs configured tools."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"sub1.example.com\nsub2.example.com", b"")
        mock_proc.returncode = 0

        with patch.object(orchestrator, "_run_command", return_value=(0, "sub1.example.com\nsub2.example.com")):
            result = await orchestrator.run_recon()

            assert result.status == "completed"
            assert "subfinder" in result.tools_run

    @pytest.mark.asyncio
    async def test_recon_callbacks_triggered(self, orchestrator):
        """Test recon phase callbacks are triggered."""
        phase_started = []
        phase_completed = []

        orchestrator.on_phase_start = lambda p: phase_started.append(p)
        orchestrator.on_phase_complete = lambda r: phase_completed.append(r)

        with patch.object(orchestrator, "_run_command", return_value=(0, "")):
            await orchestrator.run_recon()

        from aipt_v2.orchestrator import Phase
        assert Phase.RECON in phase_started
        assert len(phase_completed) == 1


class TestScanPhase:
    """Tests for scanning phase."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator for scan testing."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results"),
                scan_tools=["nuclei"],  # Minimal tools
                use_acunetix=False,
                use_burp=False,
            )
            return Orchestrator("example.com", config)

    @pytest.mark.asyncio
    async def test_scan_runs_nuclei(self, orchestrator):
        """Test scan runs nuclei."""
        with patch.object(orchestrator, "_run_command", return_value=(0, "[template-id] [high] https://example.com")):
            result = await orchestrator.run_scan()

            assert result.status == "completed"
            assert "nuclei" in result.tools_run

    @pytest.mark.asyncio
    async def test_scan_parses_nuclei_findings(self, orchestrator):
        """Test scan parses nuclei findings correctly."""
        nuclei_output = "[xss-reflected] [high] https://example.com/search"

        with patch.object(orchestrator, "_run_command", return_value=(0, nuclei_output)):
            result = await orchestrator.run_scan()

            assert len(result.findings) > 0


class TestExploitPhase:
    """Tests for exploitation phase."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator for exploit testing."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results"),
                check_sensitive_paths=True,
            )
            return Orchestrator("example.com", config)

    @pytest.mark.asyncio
    async def test_exploit_checks_sensitive_paths(self, orchestrator):
        """Test exploit phase checks sensitive paths."""
        # Mock curl returning 200 for /.env
        async def mock_run(cmd, timeout=300):
            if "/.env" in cmd:
                return (0, "200")
            return (0, "404")

        with patch.object(orchestrator, "_run_command", side_effect=mock_run):
            result = await orchestrator.run_exploit()

            assert result.status == "completed"
            # Should find exposed /.env
            exposed = [f for f in result.findings if f.type == "exposed_endpoint"]
            assert len(exposed) >= 1

    @pytest.mark.asyncio
    async def test_exploit_detects_waf(self, orchestrator):
        """Test WAF detection."""
        with patch.object(orchestrator, "_run_command", return_value=(0, "HTTP/1.1 403 Forbidden")):
            result = await orchestrator.run_exploit()

            # WAF detected should not add "no waf" finding
            waf_findings = [f for f in result.findings if f.type == "waf_bypass"]
            assert len(waf_findings) == 0


class TestReportPhase:
    """Tests for report generation phase."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator for report testing."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig, Finding

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results"),
                report_format="html",
            )
            orch = Orchestrator("example.com", config)

            # Add some findings
            orch.findings = [
                Finding(
                    type="vulnerability",
                    value="XSS",
                    description="Reflected XSS found",
                    severity="high",
                    phase="scan",
                    tool="nuclei",
                    target="https://example.com"
                ),
                Finding(
                    type="open_port",
                    value="443/tcp",
                    description="HTTPS port open",
                    severity="info",
                    phase="recon",
                    tool="nmap",
                    target="example.com"
                ),
            ]
            return orch

    @pytest.mark.asyncio
    async def test_report_generates_summary(self, orchestrator):
        """Test report generates summary markdown."""
        result = await orchestrator.run_report()

        assert result.status == "completed"
        assert "summary_generator" in result.tools_run

        summary_file = orchestrator.output_dir / "SUMMARY.md"
        assert summary_file.exists()

    @pytest.mark.asyncio
    async def test_report_generates_findings_json(self, orchestrator):
        """Test report generates findings JSON."""
        await orchestrator.run_report()

        findings_file = orchestrator.output_dir / "findings.json"
        assert findings_file.exists()

        data = json.loads(findings_file.read_text())
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_report_generates_html(self, orchestrator):
        """Test report generates HTML file."""
        await orchestrator.run_report()

        html_files = list(orchestrator.output_dir.glob("*.html"))
        assert len(html_files) == 1

    def test_generate_summary_content(self, orchestrator):
        """Test summary content structure."""
        summary = orchestrator._generate_summary()

        assert "# AIPT Scan Summary" in summary
        assert "example.com" in summary
        assert "Vulnerability Summary" in summary

    def test_generate_html_report_content(self, orchestrator):
        """Test HTML report content."""
        html = orchestrator._generate_html_report()

        assert "<!DOCTYPE html>" in html
        assert "VAPT Report" in html
        assert "example.com" in html
        assert "XSS" in html  # Finding should be included


# ============== Full Pipeline Tests ==============

class TestFullPipeline:
    """Tests for full orchestration pipeline."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator for pipeline testing."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results"),
                recon_tools=[],  # Empty for faster tests
                scan_tools=[],
                use_acunetix=False,
                use_burp=False,
                check_sensitive_paths=False,
            )
            return Orchestrator("example.com", config)

    @pytest.mark.asyncio
    async def test_run_all_phases(self, orchestrator):
        """Test running all phases."""
        with patch.object(orchestrator, "_run_command", return_value=(0, "")):
            results = await orchestrator.run()

            assert "target" in results
            assert "domain" in results
            assert "duration" in results
            assert "phases" in results
            assert "findings_count" in results

    @pytest.mark.asyncio
    async def test_run_selected_phases(self, orchestrator):
        """Test running selected phases only."""
        from aipt_v2.orchestrator import Phase

        with patch.object(orchestrator, "_run_command", return_value=(0, "")):
            results = await orchestrator.run(phases=[Phase.RECON, Phase.REPORT])

            assert "recon" in results["phases"]
            assert "report" in results["phases"]
            # Scan and exploit not run
            assert "scan" not in results["phases"]
            assert "exploit" not in results["phases"]

    @pytest.mark.asyncio
    async def test_run_skips_phases_via_config(self, orchestrator):
        """Test phases are skipped via config."""
        orchestrator.config.skip_recon = True
        orchestrator.config.skip_scan = True
        orchestrator.config.skip_exploit = True

        results = await orchestrator.run()

        assert "recon" not in results["phases"]
        assert "scan" not in results["phases"]
        assert "exploit" not in results["phases"]
        assert "report" in results["phases"]

    @pytest.mark.asyncio
    async def test_run_returns_output_dir(self, orchestrator):
        """Test run returns output directory."""
        results = await orchestrator.run()

        assert "output_dir" in results
        assert Path(results["output_dir"]).exists()


# ============== Callback Tests ==============

class TestOrchestratorCallbacks:
    """Tests for orchestrator callbacks."""

    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator with callbacks."""
        with patch("aipt_v2.orchestrator.get_acunetix"), \
             patch("aipt_v2.orchestrator.get_burp"):
            from aipt_v2.orchestrator import Orchestrator, OrchestratorConfig

            config = OrchestratorConfig(
                target="example.com",
                output_dir=str(tmp_path / "results"),
                recon_tools=[],
                scan_tools=[],
                use_acunetix=False,
                use_burp=False,
                check_sensitive_paths=False,
            )
            return Orchestrator("example.com", config)

    @pytest.mark.asyncio
    async def test_on_phase_start_callback(self, orchestrator):
        """Test on_phase_start callback is called."""
        phases_started = []
        orchestrator.on_phase_start = lambda p: phases_started.append(p)

        await orchestrator.run()

        from aipt_v2.orchestrator import Phase
        assert Phase.RECON in phases_started
        assert Phase.REPORT in phases_started

    @pytest.mark.asyncio
    async def test_on_phase_complete_callback(self, orchestrator):
        """Test on_phase_complete callback is called."""
        phases_completed = []
        orchestrator.on_phase_complete = lambda r: phases_completed.append(r.phase)

        await orchestrator.run()

        from aipt_v2.orchestrator import Phase
        assert Phase.RECON in phases_completed
        assert Phase.REPORT in phases_completed

    @pytest.mark.asyncio
    async def test_on_finding_callback(self, orchestrator):
        """Test on_finding callback is called."""
        findings_received = []
        orchestrator.on_finding = lambda f: findings_received.append(f)

        # Run recon which adds subdomain count finding
        with patch.object(orchestrator, "_run_command", return_value=(0, "")):
            await orchestrator.run_recon()

        # Should have at least subdomain count finding
        assert len(findings_received) >= 1


# ============== Security Input Validation Tests ==============

class TestValidateDomain:
    """Tests for validate_domain function - Security Critical."""

    def test_valid_domain_simple(self):
        """Test valid simple domain."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("example.com") == "example.com"

    def test_valid_domain_subdomain(self):
        """Test valid domain with subdomain."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("api.example.com") == "api.example.com"
        assert validate_domain("sub.api.example.com") == "sub.api.example.com"

    def test_valid_domain_uppercase_normalized(self):
        """Test uppercase domains are normalized to lowercase."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("EXAMPLE.COM") == "example.com"
        assert validate_domain("Api.Example.Com") == "api.example.com"

    def test_valid_domain_with_whitespace_trimmed(self):
        """Test whitespace is trimmed."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("  example.com  ") == "example.com"

    def test_valid_ipv4_address(self):
        """Test valid IPv4 addresses pass."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("192.168.1.1") == "192.168.1.1"
        assert validate_domain("10.0.0.1") == "10.0.0.1"
        assert validate_domain("255.255.255.255") == "255.255.255.255"

    def test_valid_domain_with_hyphens(self):
        """Test domains with hyphens are valid."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("my-example.com") == "my-example.com"
        assert validate_domain("api-v2.example.com") == "api-v2.example.com"

    def test_invalid_empty_domain(self):
        """Test empty domain raises ValueError."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="cannot be empty"):
            validate_domain("")

    def test_invalid_domain_too_long(self):
        """Test domain exceeding 253 chars raises ValueError."""
        from aipt_v2.orchestrator import validate_domain

        long_domain = "a" * 250 + ".com"  # 254 chars
        with pytest.raises(ValueError, match="too long"):
            validate_domain(long_domain)

    def test_invalid_domain_command_injection_semicolon(self):
        """Test command injection via semicolon is blocked."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("example.com; rm -rf /")

    def test_invalid_domain_command_injection_pipe(self):
        """Test command injection via pipe is blocked."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("example.com | cat /etc/passwd")

    def test_invalid_domain_command_injection_ampersand(self):
        """Test command injection via ampersand is blocked."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("example.com && whoami")

    def test_invalid_domain_command_injection_backtick(self):
        """Test command injection via backticks is blocked."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("`whoami`.example.com")

    def test_invalid_domain_command_injection_dollar(self):
        """Test command injection via $ is blocked."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("$(whoami).example.com")

    def test_invalid_domain_command_injection_newline(self):
        """Test command injection via newline is blocked."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("example.com\nrm -rf /")

    def test_invalid_domain_format_no_tld(self):
        """Test domain without TLD raises ValueError."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("example")

    def test_invalid_domain_format_single_char_tld(self):
        """Test domain with single char TLD raises ValueError."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("example.c")


class TestSanitizeForShell:
    """Tests for sanitize_for_shell function."""

    def test_simple_string(self):
        """Test simple string is properly quoted."""
        from aipt_v2.orchestrator import sanitize_for_shell

        result = sanitize_for_shell("example.com")
        assert result == "'example.com'" or result == "example.com"

    def test_string_with_spaces(self):
        """Test string with spaces is quoted."""
        from aipt_v2.orchestrator import sanitize_for_shell

        result = sanitize_for_shell("hello world")
        assert " " not in result or result.startswith("'")

    def test_string_with_special_chars(self):
        """Test special characters are escaped."""
        from aipt_v2.orchestrator import sanitize_for_shell

        result = sanitize_for_shell("test;whoami")
        # Should be escaped so semicolon isn't interpreted
        assert ";" not in result or result.startswith("'")

    def test_empty_string(self):
        """Test empty string returns quoted empty."""
        from aipt_v2.orchestrator import sanitize_for_shell

        result = sanitize_for_shell("")
        assert result == "''"

    def test_string_with_quotes(self):
        """Test strings with quotes are properly escaped."""
        from aipt_v2.orchestrator import sanitize_for_shell

        result = sanitize_for_shell("it's a test")
        # Should handle the single quote
        assert "'" in result or '"' in result


# ============== Input Validation Edge Cases ==============

class TestInputValidationEdgeCases:
    """Additional edge case tests for input validation."""

    def test_valid_domains_various_tlds(self):
        """Test various TLD formats."""
        from aipt_v2.orchestrator import validate_domain

        valid_domains = [
            "example.io",
            "example.co.uk",
            "example.com.br",
            "example.technology",
            "example.museum",
        ]
        for domain in valid_domains:
            result = validate_domain(domain)
            assert result == domain.lower()

    def test_valid_ipv4_edge_cases(self):
        """Test IPv4 edge cases."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("0.0.0.0") == "0.0.0.0"
        assert validate_domain("127.0.0.1") == "127.0.0.1"

    def test_invalid_ipv4_out_of_range(self):
        """Test invalid IPv4 addresses."""
        from aipt_v2.orchestrator import validate_domain

        with pytest.raises(ValueError):
            validate_domain("256.1.1.1")  # Out of range

    def test_domain_with_numbers(self):
        """Test domains with numbers are valid."""
        from aipt_v2.orchestrator import validate_domain

        assert validate_domain("123.example.com") == "123.example.com"
        assert validate_domain("api2.example.com") == "api2.example.com"
