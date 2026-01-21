"""
AIPTX AI Skills Module
======================

AI-powered penetration testing capabilities using LLMs (Claude, GPT, etc.)
for autonomous security testing, code review, and vulnerability discovery.

NEW in v2.1.0: Integrated Strix vulnerability skills library with 17 attack guides.

Architecture:
    - Vulnerability Skills: Jinja2 templates with attack methodology
    - Skills Loader: Phase-based skill selection and caching
    - Agent Integration: Skills injected into agent system prompts

Usage:
    # Load vulnerability skills (NEW - from Strix)
    from aipt_v2.skills import load_skill, load_skills, get_available_skills

    xss_knowledge = load_skill("xss")
    skills = load_skills(["xss", "sqli", "ssrf"])
    available = get_available_skills()

    # Agent usage
    from aipt_v2.skills import SecurityAgent, CodeReviewAgent, APITestAgent

    agent = CodeReviewAgent(target_path="/path/to/code")
    findings = await agent.run()
"""

__version__ = "2.1.0"


# Lazy imports for optional dependencies
def __getattr__(name):
    # Vulnerability skills loader (NEW - from Strix integration)
    if name == "load_skill":
        from aipt_v2.skills.loader import load_skill
        return load_skill
    elif name == "load_skills":
        from aipt_v2.skills.loader import load_skills
        return load_skills
    elif name == "get_available_skills":
        from aipt_v2.skills.loader import get_available_skills
        return get_available_skills
    elif name == "get_all_skill_names":
        from aipt_v2.skills.loader import get_all_skill_names
        return get_all_skill_names
    elif name == "validate_skill_names":
        from aipt_v2.skills.loader import validate_skill_names
        return validate_skill_names
    elif name == "generate_skills_description":
        from aipt_v2.skills.loader import generate_skills_description
        return generate_skills_description
    elif name == "load_skills_for_phase":
        from aipt_v2.skills.loader import load_skills_for_phase
        return load_skills_for_phase
    elif name == "SkillsLoader":
        from aipt_v2.skills.loader import SkillsLoader
        return SkillsLoader
    # Existing agent imports
    elif name == "SecurityAgent":
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
    # Skills loader (NEW)
    "load_skill",
    "load_skills",
    "get_available_skills",
    "get_all_skill_names",
    "validate_skill_names",
    "generate_skills_description",
    "load_skills_for_phase",
    "SkillsLoader",
    # Existing agents
    "SecurityAgent",
    "CodeReviewAgent",
    "APITestAgent",
    "WebPentestAgent",
    "SkillPrompts",
]
