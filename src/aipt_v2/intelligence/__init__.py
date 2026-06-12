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

# AD Attack Planning - LLM-guided Active Directory attack path selection
from aipt_v2.intelligence.ad_attack_planner import (
    ADAttackPlanner,
    ADEnvironment,
)
from aipt_v2.intelligence.ad_attack_planner import AttackObjective as ADAttackObjective
from aipt_v2.intelligence.ad_attack_planner import AttackPlan as ADAttackPlan
from aipt_v2.intelligence.ad_attack_planner import AttackStep as ADAttackStep
from aipt_v2.intelligence.ad_attack_planner import (
    plan_ad_attack,
)

# Real-Time Adaptation
from aipt_v2.intelligence.adaptation import (
    AdaptationAction,
    AdaptationState,
    AdaptationStrategy,
    DefenseDetection,
    DefenseType,
    RealTimeAdapter,
    RequestResult,
)

# Extended Attack Patterns - 50+ additional patterns for modern attacks
from aipt_v2.intelligence.attack_patterns import (
    ATTACK_TOOL_RECOMMENDATIONS,
    EXTENDED_CHAIN_PATTERNS,
    EXTENDED_TECHNIQUE_MAP,
    get_all_patterns,
    get_pattern_statistics,
    get_patterns_by_impact,
    get_patterns_by_keywords,
    get_patterns_by_tactic,
    get_recommended_tools,
    get_technique_for_attack,
)

# Authentication - Test protected resources
from aipt_v2.intelligence.auth import (
    AuthCredentials,
    AuthenticationError,
    AuthenticationManager,
    AuthMethod,
    AuthSession,
    create_api_key_auth,
    create_basic_auth,
    create_bearer_auth,
    create_cookie_auth,
    create_form_login_auth,
    create_oauth2_auth,
)

# Beast Mode - Business Logic Analysis
from aipt_v2.intelligence.business_logic_analyzer import (
    BL_CATEGORIES,
    BusinessLogicAnalyzer,
    BusinessLogicFlaw,
    analyze_business_logic,
)

# Chain Analysis - Advanced attack path detection with MITRE ATT&CK
from aipt_v2.intelligence.chain_analysis import CHAIN_PATTERNS as ADVANCED_CHAIN_PATTERNS
from aipt_v2.intelligence.chain_analysis import (
    TECHNIQUE_MAP,
)
from aipt_v2.intelligence.chain_analysis import AttackChain as AdvancedAttackChain
from aipt_v2.intelligence.chain_analysis import (
    ChainAnalyzer,
    ChainConfidence,
    ChainImpact,
    ChainNode,
    ChainPattern,
    MitreTactic,
    MitreTechnique,
    analyze_findings,
    get_top_attack_paths,
)

# Beast Mode - Novel Chain Discovery
from aipt_v2.intelligence.chain_discoverer import (
    CHAIN_PATTERNS,
    ChainDiscoverer,
    NovelChain,
    discover_attack_chains,
)

# Vulnerability Chaining - Connect related findings into attack paths
from aipt_v2.intelligence.chaining import (
    AttackChain,
    ChainLink,
    VulnerabilityChainer,
)

# Cross-Target Correlation
from aipt_v2.intelligence.correlation import (
    CommonVulnerability,
    CrossTargetAnalyzer,
    PortfolioReport,
    SystemicIssue,
    TargetSummary,
)
from aipt_v2.intelligence.cve_aipt import CVEInfo, CVEIntelligence

# Security Knowledge Graph
from aipt_v2.intelligence.knowledge_graph import (
    AttackPath,
    GraphEdge,
    GraphNode,
    SecurityKnowledgeGraph,
)

# Feedback Learning System
from aipt_v2.intelligence.learning import (
    ExploitationLearner,
    ExploitAttempt,
    PayloadSuggestion,
    TechniqueStats,
)

# LLM-Powered Vulnerability Analysis
from aipt_v2.intelligence.llm_analyzer import (
    DiscoveredChain,
    ExploitationAssessment,
    ImplicitVulnerability,
    LLMAnalysisResult,
    LLMVulnerabilityAnalyzer,
)

# Beast Mode - LLM Attack Planning
from aipt_v2.intelligence.llm_attack_planner import (
    ATTACK_TEMPLATES,
    AttackObjective,
    AttackPhase,
    AttackPlan,
    AttackStep,
    LLMAttackPlanner,
)

# LLM Crawler Analyzer - Intelligent attack surface analysis
from aipt_v2.intelligence.llm_crawler_analyzer import (
    AttackChainRecommendation,
    AttackType,
    CrawlerAnalysisResult,
    FormTarget,
    LLMCrawlerAnalyzer,
    ParameterTarget,
)

# LLM-Powered Tool Selection
from aipt_v2.intelligence.llm_tool_selector import (
    AVAILABLE_TOOLS,
    LLMToolSelector,
    ToolSelection,
    ToolSelectionResult,
)

# Adaptive Payload Generation
from aipt_v2.intelligence.payload_generator import (
    PAYLOAD_TEMPLATES,
    WAF_BYPASS_TECHNIQUES,
    AdaptivePayloadGenerator,
    GeneratedPayload,
    PayloadGenerationResult,
)
from aipt_v2.intelligence.rag import ToolMatch, ToolRAG

# Scope Enforcement - Stay within authorization
from aipt_v2.intelligence.scope import (
    ScopeConfig,
    ScopeDecision,
    ScopeEnforcer,
    ScopeViolation,
    create_scope_from_target,
)

# AI-Powered Triage - Prioritize by real-world impact
from aipt_v2.intelligence.triage import (
    AITriage,
    RiskAssessment,
    TriageResult,
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
    # LLM Crawler Analyzer - Attack Surface Intelligence
    "LLMCrawlerAnalyzer",
    "CrawlerAnalysisResult",
    "ParameterTarget",
    "FormTarget",
    "AttackChainRecommendation",
    "AttackType",
    # Chain Analysis - Advanced Attack Path Detection
    "ChainAnalyzer",
    "AdvancedAttackChain",
    "ChainNode",
    "ChainPattern",
    "ChainConfidence",
    "ChainImpact",
    "MitreTactic",
    "MitreTechnique",
    "ADVANCED_CHAIN_PATTERNS",
    "TECHNIQUE_MAP",
    "analyze_findings",
    "get_top_attack_paths",
    # Extended Attack Patterns (50+ additional patterns)
    "EXTENDED_CHAIN_PATTERNS",
    "EXTENDED_TECHNIQUE_MAP",
    "ATTACK_TOOL_RECOMMENDATIONS",
    "get_all_patterns",
    "get_patterns_by_tactic",
    "get_patterns_by_impact",
    "get_patterns_by_keywords",
    "get_recommended_tools",
    "get_technique_for_attack",
    "get_pattern_statistics",
    # AD Attack Planning - LLM-guided path selection
    "ADAttackPlanner",
    "ADAttackPlan",
    "ADAttackStep",
    "ADEnvironment",
    "ADAttackObjective",
    "plan_ad_attack",
]
