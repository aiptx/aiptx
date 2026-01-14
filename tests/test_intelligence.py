"""
Unit Tests for AIPT Intelligence Module
=======================================

Tests for:
- Scope enforcement (ScopeConfig, ScopeEnforcer)
- Vulnerability chaining (VulnerabilityType, ChainType enums)
- Triage enums and dataclasses
- RAG tool loading

These tests focus on logic that doesn't require external services (LLMs, embeddings).
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock


# ============== ScopeConfig Tests ==============

class TestScopeConfig:
    """Tests for ScopeConfig dataclass."""

    def test_default_values(self):
        """Test ScopeConfig default values."""
        from aipt_v2.intelligence.scope import ScopeConfig

        config = ScopeConfig()

        assert config.included_domains == []
        assert config.included_ips == []
        assert config.excluded_domains == []
        assert config.max_requests_per_second == 10
        assert config.max_requests_per_minute == 300
        assert config.block_out_of_scope is True
        assert config.allow_subdomains is True

    def test_custom_values(self):
        """Test ScopeConfig with custom values."""
        from aipt_v2.intelligence.scope import ScopeConfig

        config = ScopeConfig(
            included_domains=["example.com", "test.com"],
            included_ips=["192.168.1.0/24"],
            excluded_domains=["admin.example.com"],
            excluded_paths=[r"/api/internal/.*"],
            max_requests_per_second=5,
            block_out_of_scope=False,
            engagement_id="ENG-001",
            client_name="Test Client",
        )

        assert "example.com" in config.included_domains
        assert "192.168.1.0/24" in config.included_ips
        assert "admin.example.com" in config.excluded_domains
        assert config.max_requests_per_second == 5
        assert config.engagement_id == "ENG-001"

    def test_from_dict(self):
        """Test ScopeConfig creation from dictionary."""
        from aipt_v2.intelligence.scope import ScopeConfig

        data = {
            "included_domains": ["example.com"],
            "included_ips": ["10.0.0.0/8"],
            "excluded_domains": ["prod.example.com"],
            "max_requests_per_second": 20,
        }

        config = ScopeConfig.from_dict(data)

        assert config.included_domains == ["example.com"]
        assert config.included_ips == ["10.0.0.0/8"]
        assert config.excluded_domains == ["prod.example.com"]


class TestScopeDecision:
    """Tests for ScopeDecision enum."""

    def test_scope_decision_values(self):
        """Test ScopeDecision enum values."""
        from aipt_v2.intelligence.scope import ScopeDecision

        assert ScopeDecision.IN_SCOPE.value == "in_scope"
        assert ScopeDecision.OUT_OF_SCOPE.value == "out_of_scope"
        assert ScopeDecision.EXCLUDED.value == "excluded"
        assert ScopeDecision.RATE_LIMITED.value == "rate_limited"
        assert ScopeDecision.UNKNOWN.value == "unknown"


class TestScopeViolation:
    """Tests for ScopeViolation dataclass."""

    def test_violation_creation(self):
        """Test creating a scope violation."""
        from aipt_v2.intelligence.scope import ScopeViolation, ScopeDecision

        now = datetime.utcnow()
        violation = ScopeViolation(
            timestamp=now,
            url="https://out-of-scope.com/path",
            reason="Domain not in allowlist",
            decision=ScopeDecision.OUT_OF_SCOPE,
            tool="nuclei",
            blocked=True,
        )

        assert violation.url == "https://out-of-scope.com/path"
        assert violation.decision == ScopeDecision.OUT_OF_SCOPE
        assert violation.blocked is True

    def test_violation_to_dict(self):
        """Test converting violation to dictionary."""
        from aipt_v2.intelligence.scope import ScopeViolation, ScopeDecision

        now = datetime.utcnow()
        violation = ScopeViolation(
            timestamp=now,
            url="https://test.com",
            reason="Test reason",
            decision=ScopeDecision.EXCLUDED,
            tool="nmap",
            blocked=True,
        )

        data = violation.to_dict()

        assert data["url"] == "https://test.com"
        assert data["reason"] == "Test reason"
        assert data["decision"] == "excluded"
        assert data["tool"] == "nmap"
        assert data["blocked"] is True


class TestCreateScopeFromTarget:
    """Tests for create_scope_from_target helper."""

    def test_create_scope_simple_domain(self):
        """Test creating scope from simple domain (needs scheme)."""
        from aipt_v2.intelligence.scope import create_scope_from_target

        # Note: urlparse requires scheme to properly extract netloc
        config = create_scope_from_target("https://example.com")

        assert "example.com" in config.included_domains

    def test_create_scope_url(self):
        """Test creating scope from full URL."""
        from aipt_v2.intelligence.scope import create_scope_from_target

        config = create_scope_from_target("https://api.example.com/v1")

        assert "api.example.com" in config.included_domains

    def test_create_scope_sets_defaults(self):
        """Test create_scope sets sensible defaults."""
        from aipt_v2.intelligence.scope import create_scope_from_target

        config = create_scope_from_target("https://test.com")

        assert config.allow_subdomains is True
        assert "production" in config.excluded_keywords
        assert "prod" in config.excluded_keywords


# ============== Vulnerability Chaining Tests ==============

class TestVulnerabilityType:
    """Tests for VulnerabilityType enum."""

    def test_injection_types(self):
        """Test injection vulnerability types."""
        from aipt_v2.intelligence.chaining import VulnerabilityType

        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"
        assert VulnerabilityType.XSS_STORED.value == "xss_stored"
        assert VulnerabilityType.XSS_REFLECTED.value == "xss_reflected"
        assert VulnerabilityType.COMMAND_INJECTION.value == "command_injection"

    def test_auth_types(self):
        """Test authentication vulnerability types."""
        from aipt_v2.intelligence.chaining import VulnerabilityType

        assert VulnerabilityType.AUTH_BYPASS.value == "auth_bypass"
        assert VulnerabilityType.BROKEN_AUTH.value == "broken_authentication"
        assert VulnerabilityType.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert VulnerabilityType.IDOR.value == "idor"

    def test_server_side_types(self):
        """Test server-side vulnerability types."""
        from aipt_v2.intelligence.chaining import VulnerabilityType

        assert VulnerabilityType.SSRF.value == "ssrf"
        assert VulnerabilityType.RCE.value == "rce"
        assert VulnerabilityType.FILE_UPLOAD.value == "file_upload"
        assert VulnerabilityType.XXE.value == "xxe"
        assert VulnerabilityType.LFI.value == "lfi"
        assert VulnerabilityType.RFI.value == "rfi"


class TestChainType:
    """Tests for ChainType enum."""

    def test_chain_types(self):
        """Test attack chain types."""
        from aipt_v2.intelligence.chaining import ChainType

        assert ChainType.DATA_EXFILTRATION.value == "data_exfiltration"
        assert ChainType.ACCOUNT_TAKEOVER.value == "account_takeover"
        assert ChainType.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert ChainType.REMOTE_CODE_EXECUTION.value == "remote_code_execution"
        assert ChainType.INTERNAL_NETWORK_ACCESS.value == "internal_network_access"
        assert ChainType.LATERAL_MOVEMENT.value == "lateral_movement"


class TestChainImpact:
    """Tests for ChainImpact enum."""

    def test_impact_levels(self):
        """Test chain impact levels."""
        from aipt_v2.intelligence.chaining import ChainImpact

        assert ChainImpact.CATASTROPHIC.value == "catastrophic"
        assert ChainImpact.SEVERE.value == "severe"
        assert ChainImpact.SIGNIFICANT.value == "significant"
        assert ChainImpact.MODERATE.value == "moderate"
        assert ChainImpact.MINIMAL.value == "minimal"


# ============== Triage Tests ==============

class TestExploitability:
    """Tests for Exploitability enum."""

    def test_exploitability_levels(self):
        """Test exploitability levels."""
        from aipt_v2.intelligence.triage import Exploitability

        assert Exploitability.TRIVIAL.value == "trivial"
        assert Exploitability.EASY.value == "easy"
        assert Exploitability.MODERATE.value == "moderate"
        assert Exploitability.DIFFICULT.value == "difficult"
        assert Exploitability.THEORETICAL.value == "theoretical"


class TestBusinessCriticality:
    """Tests for BusinessCriticality enum."""

    def test_criticality_levels(self):
        """Test business criticality levels."""
        from aipt_v2.intelligence.triage import BusinessCriticality

        assert BusinessCriticality.CRITICAL.value == "critical"
        assert BusinessCriticality.HIGH.value == "high"
        assert BusinessCriticality.MEDIUM.value == "medium"
        assert BusinessCriticality.LOW.value == "low"
        assert BusinessCriticality.MINIMAL.value == "minimal"


class TestExploitabilityRules:
    """Tests for exploitability rules mapping."""

    def test_sql_injection_exploitability(self):
        """Test SQL injection exploitability rule."""
        from aipt_v2.intelligence.triage import EXPLOITABILITY_RULES, Exploitability
        from aipt_v2.intelligence.chaining import VulnerabilityType

        rule = EXPLOITABILITY_RULES[VulnerabilityType.SQL_INJECTION]

        assert rule["base"] == Exploitability.EASY
        assert rule["score"] == 85
        assert "sqlmap" in rule["tools"]

    def test_xss_exploitability(self):
        """Test XSS exploitability rule."""
        from aipt_v2.intelligence.triage import EXPLOITABILITY_RULES, Exploitability
        from aipt_v2.intelligence.chaining import VulnerabilityType

        rule = EXPLOITABILITY_RULES[VulnerabilityType.XSS_REFLECTED]

        assert rule["base"] == Exploitability.TRIVIAL
        assert rule["score"] == 90


# ============== RAG Tests ==============

class TestToolRAG:
    """Tests for ToolRAG class."""

    def test_default_tools_path(self):
        """Test default tools path resolution."""
        from aipt_v2.intelligence.rag import ToolRAG

        # Create with default path (lazy load to avoid needing sentence-transformers)
        rag = ToolRAG(lazy_load=True)

        assert rag.tools_path.endswith("tools.json")
        assert len(rag.tools) > 0  # Should load tools from JSON

    def test_tools_loaded(self):
        """Test that tools are loaded from JSON."""
        from aipt_v2.intelligence.rag import ToolRAG

        rag = ToolRAG(lazy_load=True)

        # Should have loaded tools
        assert isinstance(rag.tools, list)
        # Check that tools have expected structure
        if len(rag.tools) > 0:
            tool = rag.tools[0]
            assert "name" in tool or "description" in tool

    def test_scoring_weights(self):
        """Test RAG scoring weights are set correctly."""
        from aipt_v2.intelligence.rag import ToolRAG

        assert ToolRAG.WEIGHT_DESCRIPTION == 0.5
        assert ToolRAG.WEIGHT_SAMPLES == 0.5
        assert ToolRAG.WEIGHT_KEYWORDS == 2.0  # Keywords heavily weighted


class TestToolMatch:
    """Tests for ToolMatch dataclass."""

    def test_tool_match_creation(self):
        """Test creating a ToolMatch."""
        from aipt_v2.intelligence.rag import ToolMatch

        match = ToolMatch(
            name="nmap",
            score=0.95,
            tool={"name": "nmap", "description": "Network scanner"},
        )

        assert match.name == "nmap"
        assert match.score == 0.95
        assert match.tool["description"] == "Network scanner"


# ============== Auth Module Tests ==============

class TestAuthMethod:
    """Tests for AuthMethod enum."""

    def test_auth_methods(self):
        """Test authentication method types."""
        from aipt_v2.intelligence.auth import AuthMethod

        # Use actual enum values from the module
        assert AuthMethod.BEARER_TOKEN.value == "bearer_token"
        assert AuthMethod.BASIC_AUTH.value == "basic_auth"
        assert AuthMethod.API_KEY.value == "api_key"
        assert AuthMethod.COOKIE.value == "cookie"
        assert AuthMethod.FORM_LOGIN.value == "form_login"
        assert AuthMethod.OAUTH2.value == "oauth2"
        assert AuthMethod.NONE.value == "none"
        assert AuthMethod.AWS_SIGV4.value == "aws_sigv4"


class TestAuthCredentials:
    """Tests for AuthCredentials dataclass."""

    def test_bearer_credentials(self):
        """Test creating bearer token credentials."""
        from aipt_v2.intelligence.auth import AuthCredentials, AuthMethod

        creds = AuthCredentials(
            method=AuthMethod.BEARER_TOKEN,
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        )

        assert creds.method == AuthMethod.BEARER_TOKEN
        assert creds.token.startswith("eyJ")

    def test_basic_credentials(self):
        """Test creating basic auth credentials."""
        from aipt_v2.intelligence.auth import AuthCredentials, AuthMethod

        creds = AuthCredentials(
            method=AuthMethod.BASIC_AUTH,
            username="admin",
            password="secret123",
        )

        assert creds.method == AuthMethod.BASIC_AUTH
        assert creds.username == "admin"
        assert creds.password == "secret123"

    def test_api_key_credentials(self):
        """Test creating API key credentials."""
        from aipt_v2.intelligence.auth import AuthCredentials, AuthMethod

        creds = AuthCredentials(
            method=AuthMethod.API_KEY,
            api_key="sk-1234567890abcdef",
            api_key_header="X-API-Key",
        )

        assert creds.method == AuthMethod.API_KEY
        assert creds.api_key == "sk-1234567890abcdef"
        assert creds.api_key_header == "X-API-Key"


class TestAuthHelperFunctions:
    """Tests for auth helper functions."""

    def test_create_bearer_auth(self):
        """Test create_bearer_auth helper."""
        from aipt_v2.intelligence.auth import create_bearer_auth, AuthMethod

        creds = create_bearer_auth("my-token-123")

        assert creds.method == AuthMethod.BEARER_TOKEN
        assert creds.token == "my-token-123"

    def test_create_basic_auth(self):
        """Test create_basic_auth helper."""
        from aipt_v2.intelligence.auth import create_basic_auth, AuthMethod

        creds = create_basic_auth("user", "pass")

        assert creds.method == AuthMethod.BASIC_AUTH
        assert creds.username == "user"
        assert creds.password == "pass"

    def test_create_api_key_auth(self):
        """Test create_api_key_auth helper."""
        from aipt_v2.intelligence.auth import create_api_key_auth, AuthMethod

        creds = create_api_key_auth("my-api-key", header="Authorization")

        assert creds.method == AuthMethod.API_KEY
        assert creds.api_key == "my-api-key"

    def test_create_cookie_auth(self):
        """Test create_cookie_auth helper."""
        from aipt_v2.intelligence.auth import create_cookie_auth, AuthMethod

        creds = create_cookie_auth({"session": "abc123", "csrf": "xyz789"})

        assert creds.method == AuthMethod.COOKIE
        assert creds.cookies["session"] == "abc123"


# ============== Integration-Style Tests ==============

class TestIntelligenceModuleImports:
    """Test that all intelligence module exports work."""

    def test_all_exports_importable(self):
        """Test all __all__ exports can be imported."""
        from aipt_v2.intelligence import (
            # CVE
            CVEIntelligence,
            CVEInfo,
            ToolRAG,
            ToolMatch,
            # Chaining
            VulnerabilityChainer,
            AttackChain,
            ChainLink,
            # Triage
            AITriage,
            TriageResult,
            RiskAssessment,
            # Scope
            ScopeEnforcer,
            ScopeConfig,
            ScopeViolation,
            ScopeDecision,
            create_scope_from_target,
            # Auth
            AuthenticationManager,
            AuthCredentials,
            AuthSession,
            AuthMethod,
            AuthenticationError,
            create_bearer_auth,
            create_basic_auth,
            create_api_key_auth,
            create_cookie_auth,
        )

        # All imports successful
        assert ScopeConfig is not None
        assert VulnerabilityChainer is not None
        assert AITriage is not None
        assert AuthenticationManager is not None
