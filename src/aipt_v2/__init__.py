"""
AIPTX - AI-Powered Penetration Testing Framework
=================================================

A fully autonomous security testing framework with advanced capabilities.

v5.2.0 Features (Zen-AI-Pentest Integration):
- Comprehensive SQL injection payload database (6+ DB types)
- False positive reduction engine with multi-LLM consensus
- OSINT module (email harvesting, domain recon)
- Targeted wordlist generator
- SARIF output for GitHub/GitLab CI/CD integration
- Risk scoring with CVSS + EPSS + business impact

v5.1.0 Features (PentestAgent Integration):
- MCP Protocol server management
- Structured playbooks for methodologies
- Worker pool for parallel execution

Core Features:
- Universal LLM support via litellm (100+ models)
- Docker sandbox execution
- Browser automation via Playwright
- Proxy interception via mitmproxy
- CVE prioritization (CVSS + EPSS + trending + POC)
- RAG tool selection with semantic search
- Hierarchical task tracking
- SQLAlchemy persistence
- FastAPI REST API
"""

__version__ = "5.2.14"
__author__ = "AIPT Team"

# Available submodules (direct import)
__all__ = [
    # Core - LangGraph agent, LLM providers, memory
    "core",
    # Docker - Container management and sandboxing
    "docker",
    # Execution - Terminal, parser, sandbox integration
    "execution",
    # Orchestration - Pipeline, scheduler, progress tracking
    "orchestration",
    # Intelligence - Vulnerability analysis, triage, scope
    "intelligence",
    # Tools - Scanner integrations (Acunetix, Burp, etc.)
    "tools",
    # Payloads - XSS, SQLi, SSRF, SSTI, etc.
    "payloads",
    # Scanners - Nuclei, Nmap, Nikto wrappers
    "scanners",
    # Recon - Subdomain, DNS, tech detection
    "recon",
    # Browser - Playwright automation
    "browser",
    # Terminal - Command execution
    "terminal",
    # Proxy - mitmproxy interception
    "proxy",
    # v5.1 - PentestAgent Integration
    # MCP - Model Context Protocol server management
    "mcp",
    # Playbooks - Structured attack methodologies
    "playbooks",
    # Agents/Crew - Worker pool for parallel execution
    "agents",
    # v5.2 - Zen-AI-Pentest Integration
    # OSINT - Email harvesting, domain recon
    "osint",
    # Validation - False positive engine, risk scoring
    "validation",
]

# Lazy imports to avoid failures when optional dependencies are missing


def __getattr__(name):
    """Lazy import handler for optional dependencies"""
    if name == "LLM":
        from aipt_v2.llm.llm import LLM

        return LLM
    elif name == "LLMConfig":
        from aipt_v2.llm.config import LLMConfig

        return LLMConfig
    elif name == "PTT":
        from aipt_v2.agents.ptt import PTT

        return PTT
    elif name == "BaseAgent":
        from aipt_v2.agents.base import BaseAgent

        return BaseAgent
    elif name == "CVEIntelligence":
        from aipt_v2.intelligence.cve_aipt import CVEIntelligence

        return CVEIntelligence
    elif name == "ToolRAG":
        from aipt_v2.intelligence.rag import ToolRAG

        return ToolRAG
    elif name == "OutputParser":
        from aipt_v2.tools.parser import OutputParser

        return OutputParser
    elif name == "Repository":
        from aipt_v2.database.repository import Repository

        return Repository
    # New models module
    elif name == "Finding":
        from aipt_v2.models.findings import Finding

        return Finding
    elif name == "Severity":
        from aipt_v2.models.findings import Severity

        return Severity
    elif name == "ScanConfig":
        from aipt_v2.models.scan_config import ScanConfig

        return ScanConfig
    elif name == "ScanMode":
        from aipt_v2.models.scan_config import ScanMode

        return ScanMode
    elif name == "PhaseResult":
        from aipt_v2.models.phase_result import PhaseResult

        return PhaseResult
    # Reports module
    elif name == "ReportGenerator":
        from aipt_v2.reports.generator import ReportGenerator

        return ReportGenerator
    elif name == "ReportConfig":
        from aipt_v2.reports.generator import ReportConfig

        return ReportConfig
    # v5.1 - MCP Module
    elif name == "MCPManager":
        from aipt_v2.mcp.manager import MCPManager

        return MCPManager
    elif name == "MCPServerConfig":
        from aipt_v2.mcp.manager import MCPServerConfig

        return MCPServerConfig
    # v5.1 - Playbooks Module
    elif name == "get_playbook":
        from aipt_v2.playbooks import get_playbook

        return get_playbook
    elif name == "list_playbooks":
        from aipt_v2.playbooks import list_playbooks

        return list_playbooks
    elif name == "BasePlaybook":
        from aipt_v2.playbooks.base_playbook import BasePlaybook

        return BasePlaybook
    # v5.1 - Worker Pool Module
    elif name == "WorkerPool":
        from aipt_v2.agents.crew.worker_pool import WorkerPool

        return WorkerPool
    elif name == "AgentWorker":
        from aipt_v2.agents.crew.models import AgentWorker

        return AgentWorker
    # v5.2 - SQL Injection Payloads
    elif name == "SQLInjectionDB":
        from aipt_v2.payloads.sqli_payloads import SQLInjectionDB

        return SQLInjectionDB
    elif name == "DBType":
        from aipt_v2.payloads.sqli_payloads import DBType

        return DBType
    elif name == "SQLITechnique":
        from aipt_v2.payloads.sqli_payloads import SQLITechnique

        return SQLITechnique
    # v5.2 - False Positive Engine
    elif name == "FalsePositiveEngine":
        from aipt_v2.validation.false_positive_engine import FalsePositiveEngine

        return FalsePositiveEngine
    elif name == "RiskScorer":
        from aipt_v2.validation.risk_scorer import RiskScorer

        return RiskScorer
    # v5.2 - OSINT Module
    elif name == "EmailHarvester":
        from aipt_v2.osint.email_harvester import EmailHarvester

        return EmailHarvester
    elif name == "DomainRecon":
        from aipt_v2.osint.domain_recon import DomainRecon

        return DomainRecon
    # v5.2 - Wordlist Generator
    elif name == "WordlistGenerator":
        from aipt_v2.tools.wordlist_generator import WordlistGenerator

        return WordlistGenerator
    # v5.2 - SARIF Generator
    elif name == "SARIFGenerator":
        from aipt_v2.reports.sarif import SARIFGenerator

        return SARIFGenerator
    raise AttributeError(f"module 'aipt_v2' has no attribute '{name}'")
