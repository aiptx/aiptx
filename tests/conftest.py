"""
AIPT v2 Test Configuration
==========================

Pytest fixtures and configuration for all tests.
"""

import os
import sys
import asyncio
import tempfile
from pathlib import Path
from typing import Generator, AsyncGenerator
from unittest.mock import Mock, AsyncMock, patch, MagicMock

import pytest

# Add src directory to path for imports (package is in src/aipt_v2/)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ============== Async Support ==============

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============== Environment Fixtures ==============

@pytest.fixture
def clean_env():
    """Provide a clean environment without AIPT variables."""
    original_env = os.environ.copy()

    # Remove all AIPT-related env vars
    aipt_vars = [k for k in os.environ if k.startswith(("AIPT_", "ANTHROPIC_", "OPENAI_", "ACUNETIX_", "BURP_", "NESSUS_", "VPS_", "ZAP_"))]
    for var in aipt_vars:
        os.environ.pop(var, None)

    yield os.environ

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_env():
    """Provide mock environment variables for testing."""
    env_vars = {
        "ANTHROPIC_API_KEY": "sk-ant-test-key-12345",
        "AIPT_LLM_PROVIDER": "anthropic",
        "AIPT_LLM_MODEL": "claude-sonnet-4-20250514",
        "ACUNETIX_URL": "https://test-acunetix.local:3443",
        "ACUNETIX_API_KEY": "test-acunetix-api-key",
        "BURP_URL": "http://test-burp.local:1337",
        "BURP_API_KEY": "test-burp-api-key",
        "VPS_HOST": "192.168.1.100",
        "VPS_USER": "testuser",
        "VPS_KEY": "/tmp/test_key.pem",
    }

    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars


# ============== Temporary Directory Fixtures ==============

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_output_dir(temp_dir: Path) -> Path:
    """Provide a temporary output directory."""
    output_dir = temp_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


@pytest.fixture
def temp_reports_dir(temp_dir: Path) -> Path:
    """Provide a temporary reports directory."""
    reports_dir = temp_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


# ============== Mock LLM Fixtures ==============

@pytest.fixture
def mock_litellm_response():
    """Create a mock LiteLLM response."""
    def _create_response(content: str = "Test response", tool_calls: list = None):
        mock_message = Mock()
        mock_message.content = content
        mock_message.tool_calls = tool_calls or []

        mock_choice = Mock()
        mock_choice.message = mock_message

        mock_usage = Mock()
        mock_usage.prompt_tokens = 100
        mock_usage.completion_tokens = 50
        mock_usage.total_tokens = 150

        mock_response = Mock()
        mock_response.choices = [mock_choice]
        mock_response.usage = mock_usage

        return mock_response

    return _create_response


@pytest.fixture
def mock_llm(mock_litellm_response):
    """Create a mocked LLM instance."""
    with patch("litellm.acompletion") as mock_completion:
        mock_completion.return_value = mock_litellm_response("Mocked LLM response")
        yield mock_completion


# ============== Mock HTTP Fixtures ==============

@pytest.fixture
def mock_httpx_client():
    """Create a mocked httpx async client."""
    mock_client = AsyncMock()

    # Default successful response
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "success"}
    mock_response.text = "OK"
    mock_response.is_success = True

    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response
    mock_client.put.return_value = mock_response
    mock_client.delete.return_value = mock_response

    return mock_client


@pytest.fixture
def mock_requests():
    """Create mocked requests module."""
    with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.ok = True
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}
        mock_response.text = "OK"

        mock_get.return_value = mock_response
        mock_post.return_value = mock_response

        yield {"get": mock_get, "post": mock_post}


# ============== Scanner Mock Fixtures ==============

@pytest.fixture
def mock_acunetix_response():
    """Create mock Acunetix API responses."""
    return {
        "target_create": {"target_id": "test-target-id-123"},
        "scan_start": {"scan_id": "test-scan-id-456"},
        "scan_status": {"status": "completed", "severity_counts": {"critical": 2, "high": 5}},
        "vulnerabilities": [
            {"severity": "critical", "name": "SQL Injection", "url": "https://example.com/api"},
            {"severity": "high", "name": "XSS", "url": "https://example.com/search"},
        ],
    }


@pytest.fixture
def mock_burp_response():
    """Create mock Burp Suite API responses."""
    return {
        "scan_start": {"task_id": "test-task-id-789"},
        "scan_status": {"status": "succeeded"},
        "issues": [
            {"severity": "high", "name": "CSRF", "path": "/admin"},
            {"severity": "medium", "name": "Cookie without HttpOnly", "path": "/"},
        ],
    }


# ============== Database Fixtures ==============

@pytest.fixture
def mock_repository():
    """Create a mocked Repository instance."""
    mock_repo = Mock()

    # Mock project methods
    mock_repo.create_project.return_value = Mock(id=1, name="Test Project")
    mock_repo.get_project.return_value = Mock(id=1, name="Test Project", target="example.com")
    mock_repo.list_projects.return_value = []

    # Mock session methods
    mock_repo.create_session.return_value = Mock(id=1, name="Test Session")
    mock_repo.get_session.return_value = Mock(id=1, name="Test Session")
    mock_repo.list_sessions.return_value = []

    # Mock finding methods
    mock_repo.create_finding.return_value = Mock(id=1, type="vulnerability")
    mock_repo.get_findings.return_value = []

    return mock_repo


# ============== Process/Runtime Fixtures ==============

@pytest.fixture
def mock_subprocess():
    """Create mocked subprocess for command execution."""
    with patch("asyncio.create_subprocess_shell") as mock_shell:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"output", b"")
        mock_proc.returncode = 0
        mock_proc.pid = 12345
        mock_proc.kill = Mock()
        mock_proc.wait = AsyncMock()

        mock_shell.return_value = mock_proc
        yield mock_shell


@pytest.fixture
def mock_ssh():
    """Create mocked paramiko SSH client."""
    with patch("paramiko.SSHClient") as mock_client_class:
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Mock SSH operations
        mock_stdin = Mock()
        mock_stdout = Mock()
        mock_stdout.read.return_value = b"command output"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = Mock()
        mock_stderr.read.return_value = b""

        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_client.connect.return_value = None

        yield mock_client


# ============== Sample Data Fixtures ==============

@pytest.fixture
def sample_cve_data():
    """Provide sample CVE data for testing."""
    return {
        "cve_id": "CVE-2024-12345",
        "cvss": 8.5,
        "epss": 0.75,
        "description": "Test vulnerability description",
        "affected_products": ["product-a", "product-b"],
        "references": ["https://example.com/advisory"],
        "is_trending": True,
        "has_poc": True,
    }


@pytest.fixture
def sample_finding():
    """Provide sample finding data for testing."""
    return {
        "type": "vulnerability",
        "title": "SQL Injection in Login Form",
        "severity": "critical",
        "description": "The login form is vulnerable to SQL injection attacks.",
        "url": "https://example.com/login",
        "evidence": "' OR '1'='1",
        "remediation": "Use parameterized queries",
        "cve_id": "CVE-2024-12345",
        "cvss": 9.8,
    }


@pytest.fixture
def sample_scan_target():
    """Provide sample scan target for testing."""
    return {
        "target": "https://example.com",
        "client": "Test Client",
        "scope": ["example.com", "*.example.com"],
    }


# ============== FastAPI Test Client ==============

@pytest.fixture
def test_client():
    """Create FastAPI test client."""
    from fastapi.testclient import TestClient

    # Import with mocked dependencies
    with patch("aipt_v2.app.Repository"), \
         patch("aipt_v2.app.ToolRAG"), \
         patch("aipt_v2.app.CVEIntelligence"):
        from aipt_v2.app import app

        client = TestClient(app)
        yield client


# ============== Async Test Client ==============

@pytest.fixture
async def async_test_client():
    """Create async FastAPI test client."""
    from httpx import AsyncClient, ASGITransport

    with patch("aipt_v2.app.Repository"), \
         patch("aipt_v2.app.ToolRAG"), \
         patch("aipt_v2.app.CVEIntelligence"):
        from aipt_v2.app import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


# ============== Utility Functions ==============

def assert_valid_finding(finding: dict):
    """Assert that a finding has required fields."""
    required_fields = ["type", "severity"]
    for field in required_fields:
        assert field in finding, f"Finding missing required field: {field}"

    valid_severities = ["critical", "high", "medium", "low", "info"]
    assert finding["severity"] in valid_severities, f"Invalid severity: {finding['severity']}"


def assert_valid_cve_id(cve_id: str):
    """Assert that a CVE ID has valid format."""
    import re
    pattern = r"^CVE-\d{4}-\d{4,}$"
    assert re.match(pattern, cve_id), f"Invalid CVE ID format: {cve_id}"
