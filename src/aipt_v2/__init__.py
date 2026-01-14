"""
AIPT v2 - AI-Powered Penetration Testing Framework
===================================================

A unified penetration testing framework built on top of 8 reference tools:
- AIPTx: LLM (litellm), Runtime (Docker), Tools (Browser, Terminal, Proxy)
- pentest-agent: CVE Intelligence with EPSS scoring
- PentestAssistant: RAG-based tool selection with BGE embeddings
- PentestGPT: PTT (Penetration Testing Tree) task tracking
- VulnBot: Output parsing patterns
- HackSynth: Multi-step reasoning
- Pentagi: Docker isolation
- ez-ai-agent: Simple execution model

Features:
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

__version__ = "2.0.4"
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
    raise AttributeError(f"module 'aipt_v2' has no attribute '{name}'")
