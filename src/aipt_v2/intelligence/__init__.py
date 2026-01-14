"""
AIPT Intelligence Module

Advanced analysis capabilities for penetration testing:
- CVE prioritization and RAG-based tool selection
- Vulnerability chaining (connect related findings into attack paths)
- AI-powered triage (prioritize findings by real-world impact)
- Scope enforcement (ensure testing stays within authorization)
- Authenticated scanning (test protected resources)
"""

from aipt_v2.intelligence.cve_aipt import CVEIntelligence, CVEInfo
from aipt_v2.intelligence.rag import ToolRAG, ToolMatch

# Vulnerability Chaining - Connect related findings into attack paths
from aipt_v2.intelligence.chaining import (
    VulnerabilityChainer,
    AttackChain,
    ChainLink,
)

# AI-Powered Triage - Prioritize by real-world impact
from aipt_v2.intelligence.triage import (
    AITriage,
    TriageResult,
    RiskAssessment,
)

# Scope Enforcement - Stay within authorization
from aipt_v2.intelligence.scope import (
    ScopeEnforcer,
    ScopeConfig,
    ScopeViolation,
    ScopeDecision,
    create_scope_from_target,
)

# Authentication - Test protected resources
from aipt_v2.intelligence.auth import (
    AuthenticationManager,
    AuthCredentials,
    AuthSession,
    AuthMethod,
    AuthenticationError,
    create_bearer_auth,
    create_basic_auth,
    create_api_key_auth,
    create_cookie_auth,
    create_form_login_auth,
    create_oauth2_auth,
)

__all__ = [
    # CVE Intelligence (existing)
    "CVEIntelligence",
    "CVEInfo",
    "ToolRAG",
    "ToolMatch",
    # Vulnerability Chaining (new)
    "VulnerabilityChainer",
    "AttackChain",
    "ChainLink",
    # AI Triage (new)
    "AITriage",
    "TriageResult",
    "RiskAssessment",
    # Scope Enforcement (new)
    "ScopeEnforcer",
    "ScopeConfig",
    "ScopeViolation",
    "ScopeDecision",
    "create_scope_from_target",
    # Authentication (new)
    "AuthenticationManager",
    "AuthCredentials",
    "AuthSession",
    "AuthMethod",
    "AuthenticationError",
    "create_bearer_auth",
    "create_basic_auth",
    "create_api_key_auth",
    "create_cookie_auth",
    "create_form_login_auth",
    "create_oauth2_auth",
]
