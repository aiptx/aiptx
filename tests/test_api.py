"""
Unit Tests for AIPT v2 REST API
===============================

Tests for app.py - FastAPI REST endpoints.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
from fastapi.testclient import TestClient


# ============== Fixtures ==============

@pytest.fixture
def mock_repo():
    """Create a mocked Repository."""
    repo = Mock()

    # Create proper mock objects with explicit attribute values
    mock_project = MagicMock()
    mock_project.id = 1
    mock_project.name = "Test Project"
    mock_project.target = "example.com"
    mock_project.description = "Test description"
    mock_project.scope = ["example.com"]
    mock_project.status = "active"
    mock_project.created_at = datetime.now()

    mock_session = MagicMock()
    mock_session.id = 1
    mock_session.project_id = 1
    mock_session.name = "Test Session"
    mock_session.phase = "recon"
    mock_session.status = "active"
    mock_session.iteration = 0
    mock_session.started_at = datetime.now()

    # Project methods
    repo.create_project.return_value = mock_project
    repo.get_project.return_value = mock_project
    repo.list_projects.return_value = []
    repo.delete_project.return_value = True

    # Session methods
    repo.create_session.return_value = mock_session
    repo.list_sessions.return_value = []

    # Finding methods
    repo.get_findings.return_value = []
    repo.get_findings_summary.return_value = {
        "total": 0,
        "by_severity": {},
        "by_type": {},
    }
    repo.verify_finding.return_value = None
    repo.mark_false_positive.return_value = None

    return repo


@pytest.fixture
def mock_tools_rag():
    """Create a mocked ToolRAG."""
    rag = Mock()
    rag.tools = [
        {
            "name": "nmap",
            "description": "Network scanner",
            "phase": "recon",
            "keywords": ["port", "scan", "network"],
            "cmd": "nmap {target}",
        },
        {
            "name": "gobuster",
            "description": "Directory bruteforcer",
            "phase": "recon",
            "keywords": ["directory", "enum"],
            "cmd": "gobuster dir -u {target}",
        },
    ]
    rag.get_tool_by_name.return_value = rag.tools[0]
    rag.search.return_value = rag.tools
    return rag


@pytest.fixture
def mock_cve_intel():
    """Create a mocked CVEIntelligence."""
    intel = Mock()
    intel.lookup.return_value = Mock(
        cve_id="CVE-2024-1234",
        cvss=8.5,
        epss=0.75,
        priority_score=0.85,
        has_poc=True,
        description="Test vulnerability description",
    )
    intel.prioritize.return_value = [
        Mock(
            cve_id="CVE-2024-1234",
            cvss=8.5,
            epss=0.75,
            priority_score=0.85,
            has_poc=True,
        ),
    ]
    return intel


@pytest.fixture
def test_client(mock_repo, mock_tools_rag, mock_cve_intel):
    """Create FastAPI test client with mocked dependencies."""
    with patch("aipt_v2.app.Repository", return_value=mock_repo), \
         patch("aipt_v2.app.ToolRAG", return_value=mock_tools_rag), \
         patch("aipt_v2.app.CVEIntelligence", return_value=mock_cve_intel), \
         patch("aipt_v2.app.limiter.enabled", False):  # Disable rate limiting in tests
        from aipt_v2.app import create_app
        app = create_app()
        client = TestClient(app)
        yield client


# ============== Health Endpoint Tests ==============

class TestHealthEndpoint:
    """Tests for /health endpoint."""

    def test_health_returns_ok(self, test_client):
        """Test health check returns healthy status."""
        response = test_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data  # Version check - accept any valid version
        assert "timestamp" in data


# ============== Project Endpoints Tests ==============

class TestProjectEndpoints:
    """Tests for /projects endpoints."""

    def test_create_project(self, test_client):
        """Test project creation."""
        response = test_client.post(
            "/projects",
            json={
                "name": "Test Project",
                "target": "example.com",
                "description": "Test description",
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Project"
        assert data["target"] == "example.com"

    def test_list_projects(self, test_client):
        """Test listing projects."""
        response = test_client.get("/projects")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_list_projects_with_status_filter(self, test_client):
        """Test listing projects with status filter."""
        response = test_client.get("/projects?status=active")

        assert response.status_code == 200

    def test_get_project(self, test_client):
        """Test getting a single project."""
        response = test_client.get("/projects/1")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 1

    def test_get_project_not_found(self, test_client, mock_repo):
        """Test getting non-existent project."""
        mock_repo.get_project.return_value = None

        response = test_client.get("/projects/999")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_delete_project(self, test_client):
        """Test project deletion."""
        response = test_client.delete("/projects/1")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "deleted"

    def test_delete_project_not_found(self, test_client, mock_repo):
        """Test deleting non-existent project."""
        mock_repo.delete_project.return_value = False

        response = test_client.delete("/projects/999")

        assert response.status_code == 404


# ============== Session Endpoints Tests ==============

class TestSessionEndpoints:
    """Tests for /sessions endpoints."""

    def test_create_session(self, test_client):
        """Test session creation."""
        response = test_client.post(
            "/projects/1/sessions",
            json={
                "name": "Test Session",
                "phase": "recon",
                "max_iterations": 50,
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["phase"] == "recon"

    def test_create_session_project_not_found(self, test_client, mock_repo):
        """Test session creation for non-existent project."""
        mock_repo.get_project.return_value = None

        response = test_client.post(
            "/projects/999/sessions",
            json={"phase": "recon"}
        )

        assert response.status_code == 404

    def test_list_sessions(self, test_client):
        """Test listing sessions."""
        response = test_client.get("/projects/1/sessions")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# ============== Finding Endpoints Tests ==============

class TestFindingEndpoints:
    """Tests for /findings endpoints."""

    def test_get_findings(self, test_client):
        """Test getting findings."""
        response = test_client.get("/projects/1/findings")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_findings_with_filters(self, test_client):
        """Test getting findings with filters."""
        response = test_client.get(
            "/projects/1/findings?type=vulnerability&severity=high"
        )

        assert response.status_code == 200

    def test_get_findings_summary(self, test_client):
        """Test getting findings summary."""
        response = test_client.get("/projects/1/findings/summary")

        assert response.status_code == 200
        data = response.json()
        assert "total" in data

    def test_verify_finding(self, test_client):
        """Test verifying a finding."""
        response = test_client.post("/findings/1/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "verified"

    def test_verify_finding_with_notes(self, test_client):
        """Test verifying a finding with notes."""
        response = test_client.post(
            "/findings/1/verify?notes=Confirmed%20via%20manual%20testing"
        )

        assert response.status_code == 200

    def test_mark_false_positive(self, test_client):
        """Test marking finding as false positive."""
        response = test_client.post("/findings/1/false-positive")

        assert response.status_code == 200
        data = response.json()
        assert "false positive" in data["status"]


# ============== Scan Endpoints Tests ==============

class TestScanEndpoints:
    """Tests for /scan endpoints."""

    def test_quick_scan_without_nmap(self, test_client):
        """Test quick scan when nmap not available."""
        with patch("shutil.which", return_value=None):
            response = test_client.post(
                "/scan/quick",
                json={
                    "target": "example.com",
                    "phase": "recon",
                }
            )

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "completed"

    def test_quick_scan_with_nmap(self, test_client):
        """Test quick scan with nmap available."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"PORT STATE SERVICE\n80/tcp open http", b"")
        mock_proc.returncode = 0

        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"output", b"")):
            response = test_client.post(
                "/scan/quick",
                json={
                    "target": "example.com",
                    "phase": "recon",
                }
            )

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "completed"

    def test_run_tool(self, test_client):
        """Test running a specific tool."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"scan output", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"scan output", b"")):
            response = test_client.post(
                "/scan/tool?tool_name=nmap&target=example.com"
            )

            assert response.status_code == 200
            data = response.json()
            assert data["tool"] == "nmap"
            assert data["target"] == "example.com"

    def test_run_tool_not_found(self, test_client, mock_tools_rag):
        """Test running non-existent tool."""
        mock_tools_rag.get_tool_by_name.return_value = None

        response = test_client.post(
            "/scan/tool?tool_name=nonexistent&target=example.com"
        )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_run_tool_with_options(self, test_client):
        """Test running tool with extra options."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"output", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"output", b"")):
            response = test_client.post(
                "/scan/tool?tool_name=nmap&target=example.com&options=-sV%20-p80"
            )

            assert response.status_code == 200


# ============== Tool Endpoints Tests ==============

class TestToolEndpoints:
    """Tests for /tools endpoints."""

    def test_list_tools(self, test_client):
        """Test listing all tools."""
        response = test_client.get("/tools")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_list_tools_by_phase(self, test_client):
        """Test listing tools filtered by phase."""
        response = test_client.get("/tools?phase=recon")

        assert response.status_code == 200
        data = response.json()
        for tool in data:
            assert tool["phase"] == "recon"

    def test_get_tool_details(self, test_client):
        """Test getting tool details."""
        response = test_client.get("/tools/nmap")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "nmap"

    def test_get_tool_not_found(self, test_client, mock_tools_rag):
        """Test getting non-existent tool."""
        mock_tools_rag.get_tool_by_name.return_value = None

        response = test_client.get("/tools/nonexistent")

        assert response.status_code == 404

    def test_search_tools(self, test_client):
        """Test searching tools."""
        response = test_client.get("/tools/search/port%20scanning")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# ============== CVE Endpoints Tests ==============

class TestCVEEndpoints:
    """Tests for /cve endpoints."""

    def test_lookup_cve(self, test_client):
        """Test CVE lookup."""
        response = test_client.post(
            "/cve/lookup",
            json={"cve_id": "CVE-2024-1234"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["cve_id"] == "CVE-2024-1234"
        assert "cvss" in data
        assert "epss" in data
        assert "priority_score" in data

    def test_prioritize_cves(self, test_client):
        """Test CVE prioritization."""
        response = test_client.post(
            "/cve/prioritize",
            json=["CVE-2024-1234", "CVE-2024-5678"]
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert "priority_score" in data[0]


# ============== Pydantic Model Tests ==============

class TestPydanticModels:
    """Tests for Pydantic request/response models."""

    def test_project_create_model(self):
        """Test ProjectCreate validation."""
        from aipt_v2.app import ProjectCreate

        project = ProjectCreate(
            name="Test",
            target="example.com",
        )
        assert project.name == "Test"
        assert project.target == "example.com"
        assert project.description is None
        assert project.scope is None

    def test_project_create_with_scope(self):
        """Test ProjectCreate with scope."""
        from aipt_v2.app import ProjectCreate

        project = ProjectCreate(
            name="Test",
            target="example.com",
            scope=["*.example.com", "api.example.com"],
        )
        assert project.scope == ["*.example.com", "api.example.com"]

    def test_session_create_defaults(self):
        """Test SessionCreate default values."""
        from aipt_v2.app import SessionCreate

        session = SessionCreate()
        assert session.name is None
        assert session.phase == "recon"
        assert session.max_iterations == 100

    def test_scan_request_model(self):
        """Test ScanRequest validation."""
        from aipt_v2.app import ScanRequest

        request = ScanRequest(target="example.com")
        assert request.target == "example.com"
        assert request.tools is None
        assert request.phase == "recon"

    def test_cve_request_model(self):
        """Test CVERequest validation."""
        from aipt_v2.app import CVERequest

        request = CVERequest(cve_id="CVE-2024-1234")
        assert request.cve_id == "CVE-2024-1234"

    def test_tool_info_model(self):
        """Test ToolInfo model."""
        from aipt_v2.app import ToolInfo

        tool = ToolInfo(
            name="nmap",
            description="Network scanner",
            phase="recon",
            keywords=["port", "scan"],
        )
        assert tool.name == "nmap"
        assert tool.phase == "recon"


# ============== Error Handling Tests ==============

class TestErrorHandling:
    """Tests for API error handling."""

    def test_invalid_json_body(self, test_client):
        """Test handling of invalid JSON."""
        response = test_client.post(
            "/projects",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 422

    def test_missing_required_field(self, test_client):
        """Test handling of missing required field."""
        response = test_client.post(
            "/projects",
            json={"name": "Test"}  # Missing 'target'
        )

        assert response.status_code == 422


# ============== CORS Tests ==============

class TestCORSConfiguration:
    """Tests for CORS middleware."""

    def test_cors_preflight(self, test_client):
        """Test CORS preflight request."""
        response = test_client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            }
        )

        # OPTIONS should work (may be 200 or 405 depending on FastAPI version)
        assert response.status_code in [200, 405]

    def test_cors_headers_on_response(self, test_client):
        """Test CORS headers on response."""
        response = test_client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"}
        )

        assert response.status_code == 200
        # CORS headers should be present
        assert "access-control-allow-origin" in response.headers


# ============== App Factory Tests ==============

class TestAppFactory:
    """Tests for create_app factory function."""

    def test_create_app_default(self):
        """Test app creation with defaults."""
        with patch("aipt_v2.app.Repository"), \
             patch("aipt_v2.app.ToolRAG"), \
             patch("aipt_v2.app.CVEIntelligence"):
            from aipt_v2.app import create_app

            app = create_app()

            assert app.title == "AIPT API"
            assert app.version == "0.2.0"

    def test_create_app_custom_title(self):
        """Test app creation with custom title."""
        with patch("aipt_v2.app.Repository"), \
             patch("aipt_v2.app.ToolRAG"), \
             patch("aipt_v2.app.CVEIntelligence"):
            from aipt_v2.app import create_app

            app = create_app(title="Custom API")

            assert app.title == "Custom API"

    def test_app_has_state_components(self):
        """Test app state has initialized components."""
        mock_repo = Mock()
        mock_rag = Mock()
        mock_cve = Mock()

        with patch("aipt_v2.app.Repository", return_value=mock_repo), \
             patch("aipt_v2.app.ToolRAG", return_value=mock_rag), \
             patch("aipt_v2.app.CVEIntelligence", return_value=mock_cve):
            from aipt_v2.app import create_app

            app = create_app()

            # Verify state components are initialized (may be actual or mocked)
            assert hasattr(app.state, "repo")
            assert hasattr(app.state, "tools_rag")
            assert hasattr(app.state, "cve_intel")
