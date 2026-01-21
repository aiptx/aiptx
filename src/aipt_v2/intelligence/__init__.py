"""
AIPT Intelligence Module

Advanced analysis capabilities for penetration testing:
- CVE prioritization and RAG-based tool selection
- Vulnerability chaining (connect related findings into attack paths)
- AI-powered triage (prioritize findings by real-world impact)
- Scope enforcement (ensure testing stays within authorization)
- Authenticated scanning (test protected resources)
- LLM-powered tool selection and vulnerability analysis
- Feedback learning from exploitation attempts
- Adaptive payload generation
- Knowledge graph for findings
- Real-time adaptation to defenses
- Cross-target correlation
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

# LLM-Powered Tool Selection
from aipt_v2.intelligence.llm_tool_selector import (
    LLMToolSelector,
    ToolSelection,
    ToolSelectionResult,
    AVAILABLE_TOOLS,
)

# LLM-Powered Vulnerability Analysis
from aipt_v2.intelligence.llm_analyzer import (
    LLMVulnerabilityAnalyzer,
    LLMAnalysisResult,
    DiscoveredChain,
    ImplicitVulnerability,
    ExploitationAssessment,
)

# Feedback Learning System
from aipt_v2.intelligence.learning import (
    ExploitationLearner,
    ExploitAttempt,
    PayloadSuggestion,
    TechniqueStats,
)

# Adaptive Payload Generation
from aipt_v2.intelligence.payload_generator import (
    AdaptivePayloadGenerator,
    GeneratedPayload,
    PayloadGenerationResult,
    PAYLOAD_TEMPLATES,
    WAF_BYPASS_TECHNIQUES,
)

# Security Knowledge Graph
from aipt_v2.intelligence.knowledge_graph import (
    SecurityKnowledgeGraph,
    GraphNode,
    GraphEdge,
    AttackPath,
)

# Real-Time Adaptation
from aipt_v2.intelligence.adaptation import (
    RealTimeAdapter,
    DefenseType,
    AdaptationAction,
    DefenseDetection,
    AdaptationStrategy,
    RequestResult,
    AdaptationState,
)

# Cross-Target Correlation
from aipt_v2.intelligence.correlation import (
    CrossTargetAnalyzer,
    TargetSummary,
    CommonVulnerability,
    SystemicIssue,
    PortfolioReport,
)

# Beast Mode - LLM Attack Planning
from aipt_v2.intelligence.llm_attack_planner import (
    LLMAttackPlanner,
    AttackPlan,
    AttackStep,
    AttackPhase,
    AttackObjective,
    ATTACK_TEMPLATES,
)

# Beast Mode - Novel Chain Discovery
from aipt_v2.intelligence.chain_discoverer import (
    ChainDiscoverer,
    NovelChain,
    CHAIN_PATTERNS,
    discover_attack_chains,
)

# Beast Mode - Business Logic Analysis
from aipt_v2.intelligence.business_logic_analyzer import (
    BusinessLogicAnalyzer,
    BusinessLogicFlaw,
    BL_CATEGORIES,
    analyze_business_logic,
)

__all__ = [
    # CVE Intelligence (existing)
    "CVEIntelligence",
    "CVEInfo",
    "ToolRAG",
    "ToolMatch",
    # Vulnerability Chaining
    "VulnerabilityChainer",
    "AttackChain",
    "ChainLink",
    # AI Triage
    "AITriage",
    "TriageResult",
    "RiskAssessment",
    # Scope Enforcement
    "ScopeEnforcer",
    "ScopeConfig",
    "ScopeViolation",
    "ScopeDecision",
    "create_scope_from_target",
    # Authentication
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
    # LLM Tool Selection
    "LLMToolSelector",
    "ToolSelection",
    "ToolSelectionResult",
    "AVAILABLE_TOOLS",
    # LLM Vulnerability Analysis
    "LLMVulnerabilityAnalyzer",
    "LLMAnalysisResult",
    "DiscoveredChain",
    "ImplicitVulnerability",
    "ExploitationAssessment",
    # Feedback Learning
    "ExploitationLearner",
    "ExploitAttempt",
    "PayloadSuggestion",
    "TechniqueStats",
    # Adaptive Payload Generation
    "AdaptivePayloadGenerator",
    "GeneratedPayload",
    "PayloadGenerationResult",
    "PAYLOAD_TEMPLATES",
    "WAF_BYPASS_TECHNIQUES",
    # Knowledge Graph
    "SecurityKnowledgeGraph",
    "GraphNode",
    "GraphEdge",
    "AttackPath",
    # Real-Time Adaptation
    "RealTimeAdapter",
    "DefenseType",
    "AdaptationAction",
    "DefenseDetection",
    "AdaptationStrategy",
    "RequestResult",
    "AdaptationState",
    # Cross-Target Correlation
    "CrossTargetAnalyzer",
    "TargetSummary",
    "CommonVulnerability",
    "SystemicIssue",
    "PortfolioReport",
    # Beast Mode - LLM Attack Planning
    "LLMAttackPlanner",
    "AttackPlan",
    "AttackStep",
    "AttackPhase",
    "AttackObjective",
    "ATTACK_TEMPLATES",
    # Beast Mode - Novel Chain Discovery
    "ChainDiscoverer",
    "NovelChain",
    "CHAIN_PATTERNS",
    "discover_attack_chains",
    # Beast Mode - Business Logic Analysis
    "BusinessLogicAnalyzer",
    "BusinessLogicFlaw",
    "BL_CATEGORIES",
    "analyze_business_logic",
]
