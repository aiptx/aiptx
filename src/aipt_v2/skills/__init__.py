"""
AIPTX AI Skills Module
======================

AI-powered penetration testing capabilities using LLMs (Claude, GPT, etc.)
for autonomous security testing, code review, and vulnerability discovery.

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    AIPTX Skills System                       │
    ├─────────────────────────────────────────────────────────────┤
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
    │  │ Code Review │  │ API Testing │  │ Web Pentest │         │
    │  │   Agent     │  │   Agent     │  │   Agent     │   ...   │
    │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
    │         │                │                │                 │
    │         ▼                ▼                ▼                 │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │              Security Skill Prompts                  │   │
    │  │  (SQLi, XSS, IDOR, Auth, RCE, SSRF, XXE, ...)       │   │
    │  └─────────────────────────────────────────────────────┘   │
    │         │                │                │                 │
    │         ▼                ▼                ▼                 │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │              LLM Interface (LiteLLM)                 │   │
    │  │  Claude | GPT-4 | DeepSeek | Gemini | Local LLMs    │   │
    │  └─────────────────────────────────────────────────────┘   │
    │         │                │                │                 │
    │         ▼                ▼                ▼                 │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │                Security Tools                        │   │
    │  │  Terminal | Browser | Code Analysis | HTTP Client   │   │
    │  └─────────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from aipt_v2.skills import SecurityAgent, CodeReviewAgent, APITestAgent

    # Code Review
    agent = CodeReviewAgent(target_path="/path/to/code")
    findings = await agent.run()

    # API Testing
    agent = APITestAgent(base_url="https://api.example.com", openapi_spec="openapi.json")
    findings = await agent.run()

    # Web Penetration Testing
    agent = WebPentestAgent(target="https://example.com")
    findings = await agent.run()
"""

__version__ = "1.0.0"

# Lazy imports for optional dependencies
def __getattr__(name):
    if name == "SecurityAgent":
        from aipt_v2.skills.agents.security_agent import SecurityAgent
        return SecurityAgent
    elif name == "CodeReviewAgent":
        from aipt_v2.skills.agents.code_review import CodeReviewAgent
        return CodeReviewAgent
    elif name == "APITestAgent":
        from aipt_v2.skills.agents.api_tester import APITestAgent
        return APITestAgent
    elif name == "WebPentestAgent":
        from aipt_v2.skills.agents.web_pentest import WebPentestAgent
        return WebPentestAgent
    elif name == "SkillPrompts":
        from aipt_v2.skills.prompts import SkillPrompts
        return SkillPrompts
    raise AttributeError(f"module 'aipt_v2.skills' has no attribute '{name}'")


__all__ = [
    "SecurityAgent",
    "CodeReviewAgent",
    "APITestAgent",
    "WebPentestAgent",
    "SkillPrompts",
]
