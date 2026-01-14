"""
AIPT v2 Integration Tests

Comprehensive integration tests to verify all Phase 2 components work together.
"""

import asyncio
import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure aipt_v2 is importable (package is in src/aipt_v2/)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestImports:
    """Test that all modules can be imported correctly."""

    def test_import_llm_module(self):
        """Test LLM module imports."""
        from aipt_v2.llm import LLM, LLMConfig
        from aipt_v2.llm.memory import MemoryCompressor
        from aipt_v2.llm.utils import parse_tool_invocations, clean_content
        assert LLM is not None
        assert LLMConfig is not None

    def test_import_agents_module(self):
        """Test agents module imports."""
        from aipt_v2.agents import PTT, Task, Phase, TaskStatus, PhaseType, AgentState
        from aipt_v2.agents.base import BaseAgent
        assert PTT is not None
        assert AgentState is not None

    def test_import_aiptx_agent(self):
        """Test AIPTxAgent import."""
        from aipt_v2.agents.AIPTxAgent import AIPTxAgent
        assert AIPTxAgent is not None

    def test_import_intelligence_module(self):
        """Test intelligence module imports."""
        from aipt_v2.intelligence import CVEIntelligence, CVEInfo, ToolRAG, ToolMatch
        assert CVEIntelligence is not None
        assert ToolRAG is not None

    def test_import_tools_module(self):
        """Test tools module imports."""
        from aipt_v2.tools import OutputParser, Finding, process_tool_invocations
        assert OutputParser is not None

    def test_import_runtime_module(self):
        """Test runtime module imports."""
        from aipt_v2.runtime import get_runtime, AbstractRuntime
        assert get_runtime is not None

    def test_import_database_module(self):
        """Test database module imports."""
        from aipt_v2.database.repository import Repository
        from aipt_v2.database.models import Project, Session, Finding, Task
        assert Repository is not None

    def test_import_telemetry_module(self):
        """Test telemetry module imports."""
        from aipt_v2.telemetry import Tracer, get_global_tracer, set_global_tracer
        assert Tracer is not None

    def test_import_interface_module(self):
        """Test interface module imports."""
        from aipt_v2.interface.utils import (
            get_severity_color,
            build_final_stats_text,
            build_live_stats_text,
            generate_run_name,
            infer_target_type,
        )
        assert get_severity_color is not None


class TestLLMConfig:
    """Test LLM configuration."""

    def test_llm_config_defaults(self):
        """Test LLMConfig with default values."""
        # Set environment variable for test
        os.environ["AIPT_LLM"] = "openai/gpt-4"
        from aipt_v2.llm.config import LLMConfig

        config = LLMConfig()
        assert config.model_name == "openai/gpt-4"
        assert config.enable_prompt_caching is True
        assert config.timeout == 300

    def test_llm_config_custom(self):
        """Test LLMConfig with custom values."""
        from aipt_v2.llm.config import LLMConfig

        config = LLMConfig(
            model_name="anthropic/claude-3-opus",
            enable_prompt_caching=False,
            timeout=600,
        )
        assert config.model_name == "anthropic/claude-3-opus"
        assert config.enable_prompt_caching is False
        assert config.timeout == 600


class TestPTT:
    """Test Penetration Testing Tree."""

    def test_ptt_initialization(self, tmp_path):
        """Test PTT initialization."""
        from aipt_v2.agents.ptt import PTT

        ptt = PTT(session_dir=str(tmp_path))
        result = ptt.initialize("192.168.1.1")

        assert ptt.target == "192.168.1.1"
        assert ptt.current_phase == "recon"
        assert len(ptt.phases) == 5
        assert "recon" in ptt.phases
        assert "enum" in ptt.phases
        assert "exploit" in ptt.phases

    def test_ptt_add_task(self, tmp_path):
        """Test adding tasks to PTT."""
        from aipt_v2.agents.ptt import PTT, TaskStatus

        ptt = PTT(session_dir=str(tmp_path))
        ptt.initialize("example.com")

        task_id = ptt.add_task("recon", "Port scanning", TaskStatus.IN_PROGRESS)
        assert task_id == "R1"

        task_id2 = ptt.add_task("recon", "Service detection")
        assert task_id2 == "R2"

    def test_ptt_update_task(self, tmp_path):
        """Test updating task status."""
        from aipt_v2.agents.ptt import PTT, TaskStatus

        ptt = PTT(session_dir=str(tmp_path))
        ptt.initialize("example.com")

        task_id = ptt.add_task("recon", "Port scanning", TaskStatus.TODO)
        ptt.update_task(task_id, status=TaskStatus.COMPLETED)

        task = ptt._find_task(task_id)
        assert task.status == TaskStatus.COMPLETED

    def test_ptt_advance_phase(self, tmp_path):
        """Test phase advancement."""
        from aipt_v2.agents.ptt import PTT, TaskStatus

        ptt = PTT(session_dir=str(tmp_path))
        ptt.initialize("example.com")

        assert ptt.current_phase == "recon"
        new_phase = ptt.advance_phase()
        assert new_phase == "enum"
        assert ptt.phases["recon"].status == TaskStatus.COMPLETED

    def test_ptt_to_prompt(self, tmp_path):
        """Test PTT prompt generation."""
        from aipt_v2.agents.ptt import PTT, TaskStatus

        ptt = PTT(session_dir=str(tmp_path))
        ptt.initialize("example.com")
        ptt.add_task("recon", "Port scan", TaskStatus.COMPLETED)

        prompt = ptt.to_prompt()
        assert "example.com" in prompt
        assert "Recon" in prompt
        assert "Port scan" in prompt

    def test_ptt_save_load(self, tmp_path):
        """Test PTT save and load."""
        from aipt_v2.agents.ptt import PTT, TaskStatus

        ptt = PTT(session_dir=str(tmp_path))
        ptt.initialize("example.com")
        ptt.add_task("recon", "Test task", TaskStatus.IN_PROGRESS)

        # Save
        filepath = ptt.save()
        assert Path(filepath).exists()

        # Load into new PTT
        ptt2 = PTT(session_dir=str(tmp_path))
        ptt2.load(filepath)

        assert ptt2.target == "example.com"
        assert len(ptt2.phases["recon"].tasks) == 1


class TestAgentState:
    """Test AgentState management."""

    def test_agent_state_creation(self):
        """Test AgentState initialization."""
        from aipt_v2.agents.state import AgentState

        state = AgentState(agent_name="TestAgent", max_iterations=100)

        assert state.agent_name == "TestAgent"
        assert state.max_iterations == 100
        assert state.iteration == 0
        assert not state.completed

    def test_agent_state_iteration(self):
        """Test iteration tracking."""
        from aipt_v2.agents.state import AgentState

        state = AgentState()
        state.increment_iteration()
        assert state.iteration == 1

        state.increment_iteration()
        assert state.iteration == 2

    def test_agent_state_messages(self):
        """Test message handling."""
        from aipt_v2.agents.state import AgentState

        state = AgentState()
        state.add_message("user", "Test message")
        state.add_message("assistant", "Response")

        assert len(state.messages) == 2
        assert state.messages[0]["role"] == "user"
        assert state.messages[1]["role"] == "assistant"

    def test_agent_state_stop_conditions(self):
        """Test stop conditions."""
        from aipt_v2.agents.state import AgentState

        state = AgentState(max_iterations=10)

        assert not state.should_stop()

        state.iteration = 10
        assert state.should_stop()

        state.iteration = 5
        state.request_stop()
        assert state.should_stop()

    def test_agent_state_waiting(self):
        """Test waiting state."""
        from aipt_v2.agents.state import AgentState

        state = AgentState()

        assert not state.is_waiting_for_input()

        state.enter_waiting_state()
        assert state.is_waiting_for_input()

        state.resume_from_waiting()
        assert not state.is_waiting_for_input()


class TestTracer:
    """Test telemetry tracer."""

    def test_tracer_creation(self):
        """Test Tracer initialization."""
        from aipt_v2.telemetry import Tracer

        tracer = Tracer("test_scan")
        assert tracer.scan_id == "test_scan"
        assert len(tracer.agents) == 0

    def test_tracer_agent_logging(self):
        """Test agent logging."""
        from aipt_v2.telemetry import Tracer

        tracer = Tracer("test_scan")
        tracer.log_agent_creation("agent_1", "TestAgent", "Test task")

        assert "agent_1" in tracer.agents
        assert tracer.agents["agent_1"].name == "TestAgent"

    def test_tracer_tool_execution(self):
        """Test tool execution tracking."""
        from aipt_v2.telemetry import Tracer

        tracer = Tracer("test_scan")

        exec_id = tracer.log_tool_execution_start("agent_1", "nmap", {"target": "example.com"})
        assert exec_id == 1

        tracer.update_tool_execution(exec_id, "completed", {"ports": [80, 443]})
        assert tracer.tool_executions[exec_id].status == "completed"

    def test_tracer_vulnerability_reporting(self):
        """Test vulnerability reporting."""
        from aipt_v2.telemetry import Tracer

        tracer = Tracer("test_scan")
        tracer.report_vulnerability(
            "VULN001",
            "SQL Injection",
            "Found SQL injection in login form",
            "high"
        )

        assert len(tracer.vulnerability_reports) == 1
        assert tracer.vulnerability_reports[0]["title"] == "SQL Injection"

    def test_tracer_llm_stats(self):
        """Test LLM stats tracking."""
        from aipt_v2.telemetry import Tracer

        tracer = Tracer("test_scan")
        tracer.update_llm_stats(
            "agent_1",
            input_tokens=100,
            output_tokens=50,
            cost=0.01
        )

        stats = tracer.get_total_llm_stats()
        assert stats["total"]["input_tokens"] == 100
        assert stats["total"]["output_tokens"] == 50
        assert stats["total"]["cost"] == 0.01

    def test_tracer_real_tool_count(self):
        """Test real tool count (excluding internal tools)."""
        from aipt_v2.telemetry import Tracer

        tracer = Tracer("test_scan")
        tracer.log_tool_execution_start("agent_1", "scan_start_info", {})
        tracer.log_tool_execution_start("agent_1", "nmap", {})
        tracer.log_tool_execution_start("agent_1", "nuclei", {})

        # Should exclude scan_start_info
        assert tracer.get_real_tool_count() == 2


class TestToolRAG:
    """Test RAG-based tool selection."""

    def test_tool_rag_initialization(self):
        """Test ToolRAG initialization."""
        from aipt_v2.intelligence.rag import ToolRAG

        # Use lazy load to avoid loading embeddings
        rag = ToolRAG(lazy_load=True)
        assert rag is not None

    def test_tool_rag_get_tool_by_name(self):
        """Test getting tool by name."""
        from aipt_v2.intelligence.rag import ToolRAG

        rag = ToolRAG(lazy_load=True)

        # Add a test tool
        rag.add_tool({
            "name": "test_tool",
            "description": "A test tool",
            "phase": "recon",
            "keywords": ["test"]
        })

        tool = rag.get_tool_by_name("test_tool")
        assert tool is not None
        assert tool["name"] == "test_tool"

    def test_tool_rag_list_tools(self):
        """Test listing tools."""
        from aipt_v2.intelligence.rag import ToolRAG

        rag = ToolRAG(lazy_load=True)
        tools = rag.list_tools()
        assert isinstance(tools, list)


class TestCVEIntelligence:
    """Test CVE intelligence."""

    def test_cve_intelligence_creation(self, tmp_path):
        """Test CVEIntelligence initialization."""
        from aipt_v2.intelligence.cve_aipt import CVEIntelligence

        cve = CVEIntelligence(cache_dir=str(tmp_path))
        assert cve is not None

    def test_cve_priority_calculation(self, tmp_path):
        """Test priority score calculation."""
        from aipt_v2.intelligence.cve_aipt import CVEIntelligence

        cve = CVEIntelligence(cache_dir=str(tmp_path))

        score = cve.calculate_priority(
            cvss=9.8,
            epss=0.5,
            trending=True,
            has_poc=True
        )

        # Score should be between 0 and 1
        assert 0 <= score <= 1
        # High CVSS + EPSS + trending + POC should give high score
        assert score > 0.5


class TestOutputParser:
    """Test output parsing."""

    def test_output_parser_creation(self):
        """Test OutputParser initialization."""
        from aipt_v2.tools.parser import OutputParser

        parser = OutputParser()
        assert parser is not None

    def test_output_parser_nmap(self):
        """Test parsing nmap output."""
        from aipt_v2.tools.parser import OutputParser

        parser = OutputParser()

        nmap_output = """
Starting Nmap 7.94
Nmap scan report for example.com (93.184.216.34)
Host is up (0.010s latency).
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
"""

        findings = parser.parse(nmap_output, "nmap")
        assert isinstance(findings, list)


class TestDatabase:
    """Test database operations."""

    def test_repository_creation(self, tmp_path):
        """Test Repository initialization."""
        from aipt_v2.database.repository import Repository

        db_path = tmp_path / "test.db"
        repo = Repository(f"sqlite:///{db_path}")
        assert repo is not None

    def test_repository_project_crud(self, tmp_path):
        """Test project CRUD operations."""
        from aipt_v2.database.repository import Repository

        db_path = tmp_path / "test.db"
        repo = Repository(f"sqlite:///{db_path}")

        # Create
        project = repo.create_project(
            name="Test Project",
            target="example.com",
            description="Test"
        )
        assert project.id is not None

        # Read
        fetched = repo.get_project(project.id)
        assert fetched is not None
        assert fetched.name == "Test Project"

        # Update
        updated = repo.update_project(project.id, status="running")
        assert updated.status == "running"

        # Delete
        result = repo.delete_project(project.id)
        assert result is True


class TestInterfaceUtils:
    """Test interface utilities."""

    def test_severity_color(self):
        """Test severity color mapping."""
        from aipt_v2.interface.utils import get_severity_color

        assert get_severity_color("critical") == "#dc2626"
        assert get_severity_color("high") == "#ea580c"
        assert get_severity_color("medium") == "#d97706"
        assert get_severity_color("low") == "#65a30d"
        assert get_severity_color("info") == "#0284c7"

    def test_target_inference(self):
        """Test target type inference."""
        from aipt_v2.interface.utils import infer_target_type

        # Web application
        target_type, details = infer_target_type("https://example.com")
        assert target_type == "web_application"

        # GitHub repository
        target_type, details = infer_target_type("https://github.com/user/repo")
        assert target_type == "repository"

        # IP address
        target_type, details = infer_target_type("192.168.1.1")
        assert target_type == "ip_address"

        # Domain (should be inferred as web app)
        target_type, details = infer_target_type("example.com")
        assert target_type == "web_application"

    def test_run_name_generation(self):
        """Test run name generation."""
        from aipt_v2.interface.utils import generate_run_name

        name = generate_run_name([{"original": "example.com", "type": "web_application", "details": {}}])
        assert name is not None
        assert len(name) > 0


class TestAIPTxAgent:
    """Test AIPTxAgent (main pentest agent)."""

    def test_aiptx_agent_creation(self):
        """Test AIPTxAgent initialization."""
        os.environ["AIPT_LLM"] = "openai/gpt-4"
        from aipt_v2.agents.AIPTxAgent import AIPTxAgent
        from aipt_v2.llm.config import LLMConfig

        config = {
            "llm_config": LLMConfig(),
            "max_iterations": 10,
            "non_interactive": True,
        }

        agent = AIPTxAgent(config)
        assert agent is not None
        assert agent.agent_name == "AIPTxAgent"
        assert agent.max_iterations == 10

    def test_aiptx_agent_task_prompt_building(self):
        """Test task prompt generation."""
        os.environ["AIPT_LLM"] = "openai/gpt-4"
        from aipt_v2.agents.AIPTxAgent import AIPTxAgent
        from aipt_v2.llm.config import LLMConfig

        config = {
            "llm_config": LLMConfig(),
            "max_iterations": 10,
            "non_interactive": True,
        }

        agent = AIPTxAgent(config)

        scan_config = {
            "scan_id": "test_scan",
            "targets": [{"original": "example.com", "type": "web_application", "details": {}}],
            "user_instructions": "Focus on XSS vulnerabilities",
        }

        prompt = agent._build_task_prompt(scan_config)
        assert "example.com" in prompt
        assert "XSS vulnerabilities" in prompt


# Async tests
class TestAsyncOperations:
    """Test async operations."""

    @pytest.mark.asyncio
    async def test_tool_processing(self):
        """Test tool invocation processing."""
        from aipt_v2.tools.tool_processing import process_tool_invocations
        from aipt_v2.agents.state import AgentState

        state = AgentState()
        conversation = []

        actions = [
            {"name": "execute_command", "arguments": {"command": "echo test"}}
        ]

        result = await process_tool_invocations(actions, conversation, state)
        assert isinstance(result, bool)
        assert len(conversation) > 0  # Should have added tool result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
