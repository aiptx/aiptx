"""
AIPTX Skills Loader
===================

Loads vulnerability-specific knowledge from Jinja2 templates.
Skills provide structured attack methodology, payloads, and validation techniques.

Features:
- Category-based skill organization (vulnerabilities/, frameworks/, etc.)
- Jinja2 template rendering with context variables
- Skill caching for performance
- Phase-based skill selection

Integrated from Strix's skills library.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


logger = logging.getLogger(__name__)

# Skills directory
SKILLS_DIR = Path(__file__).parent


class SkillsLoader:
    """
    Loader for vulnerability skills with caching and Jinja2 rendering.

    Example:
        loader = SkillsLoader()
        xss_skill = loader.load("xss")
        all_skills = loader.load_multiple(["xss", "sqli", "ssrf"])
    """

    def __init__(self, skills_dir: Path | None = None):
        """
        Initialize the skills loader.

        Args:
            skills_dir: Optional custom skills directory. Defaults to built-in skills.
        """
        self.skills_dir = skills_dir or SKILLS_DIR
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.skills_dir)),
            autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
        )
        self._cache: dict[str, str] = {}

    def get_available_skills(self) -> dict[str, list[str]]:
        """
        Get all available skills organized by category.

        Returns:
            Dict mapping category names to lists of skill names.
        """
        available_skills: dict[str, list[str]] = {}

        for category_dir in self.skills_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("__"):
                category_name = category_dir.name
                skills = []

                for file_path in category_dir.glob("*.jinja"):
                    skill_name = file_path.stem
                    skills.append(skill_name)

                if skills:
                    available_skills[category_name] = sorted(skills)

        return available_skills

    def get_all_skill_names(self) -> set[str]:
        """Get a flat set of all available skill names."""
        all_skills: set[str] = set()
        for category_skills in self.get_available_skills().values():
            all_skills.update(category_skills)
        return all_skills

    def _find_skill_path(self, skill_name: str) -> Path | None:
        """
        Find the path to a skill file.

        Args:
            skill_name: Name of the skill (e.g., "xss" or "vulnerabilities/xss")

        Returns:
            Path to the skill file, or None if not found.
        """
        # If category is specified (e.g., "vulnerabilities/xss")
        if "/" in skill_name:
            skill_path = self.skills_dir / f"{skill_name}.jinja"
            if skill_path.exists():
                return skill_path
            return None

        # Search in all categories
        available = self.get_available_skills()
        for category, skills in available.items():
            if skill_name in skills:
                return self.skills_dir / category / f"{skill_name}.jinja"

        # Check root directory
        root_candidate = self.skills_dir / f"{skill_name}.jinja"
        if root_candidate.exists():
            return root_candidate

        return None

    def load(self, skill_name: str, context: dict[str, Any] | None = None) -> str | None:
        """
        Load a single skill by name.

        Args:
            skill_name: Name of the skill to load.
            context: Optional context variables for Jinja2 rendering.

        Returns:
            Rendered skill content, or None if not found.
        """
        # Check cache first
        cache_key = f"{skill_name}:{hash(frozenset((context or {}).items()))}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        skill_path = self._find_skill_path(skill_name)
        if not skill_path:
            logger.warning(f"Skill not found: {skill_name}")
            return None

        try:
            # Get relative path for Jinja2
            rel_path = skill_path.relative_to(self.skills_dir)
            template = self.jinja_env.get_template(str(rel_path))
            content = template.render(**(context or {}))

            # Cache the result
            self._cache[cache_key] = content
            logger.info(f"Loaded skill: {skill_name}")

            return content

        except Exception as e:
            logger.warning(f"Failed to load skill {skill_name}: {e}")
            return None

    def load_multiple(
        self, skill_names: list[str], context: dict[str, Any] | None = None
    ) -> dict[str, str]:
        """
        Load multiple skills by name.

        Args:
            skill_names: List of skill names to load.
            context: Optional context variables for Jinja2 rendering.

        Returns:
            Dict mapping skill names to their rendered content.
        """
        result: dict[str, str] = {}
        for name in skill_names:
            content = self.load(name, context)
            if content:
                # Use the base name (without category) as key
                key = name.split("/")[-1]
                result[key] = content
        return result

    def clear_cache(self) -> None:
        """Clear the skills cache."""
        self._cache.clear()


# Global loader instance
_default_loader: SkillsLoader | None = None


def _get_loader() -> SkillsLoader:
    """Get or create the default skills loader."""
    global _default_loader
    if _default_loader is None:
        _default_loader = SkillsLoader()
    return _default_loader


def get_available_skills() -> dict[str, list[str]]:
    """
    Get all available skills organized by category.

    Returns:
        Dict mapping category names to lists of skill names.
    """
    return _get_loader().get_available_skills()


def get_all_skill_names() -> set[str]:
    """Get a flat set of all available skill names."""
    return _get_loader().get_all_skill_names()


def validate_skill_names(skill_names: list[str]) -> dict[str, list[str]]:
    """
    Validate a list of skill names.

    Args:
        skill_names: List of skill names to validate.

    Returns:
        Dict with "valid" and "invalid" lists of skill names.
    """
    available = get_all_skill_names()
    valid = []
    invalid = []

    for name in skill_names:
        if name in available:
            valid.append(name)
        else:
            invalid.append(name)

    return {"valid": valid, "invalid": invalid}


def generate_skills_description() -> str:
    """
    Generate a description of available skills for prompts.

    Returns:
        Human-readable description of available skills.
    """
    available = get_available_skills()

    if not available:
        return "No skills available"

    all_names = get_all_skill_names()
    if not all_names:
        return "No skills available"

    sorted_skills = sorted(all_names)
    skills_str = ", ".join(sorted_skills)

    description = f"Available vulnerability skills: {skills_str}. "
    description += "Skills provide attack methodology, payloads, and validation techniques."

    return description


def load_skill(skill_name: str, context: dict[str, Any] | None = None) -> str | None:
    """
    Load a single skill by name.

    Args:
        skill_name: Name of the skill to load (e.g., "xss", "sqli").
        context: Optional context variables for Jinja2 rendering.

    Returns:
        Rendered skill content, or None if not found.

    Example:
        xss_knowledge = load_skill("xss")
        ssrf_with_context = load_skill("ssrf", {"target": "internal-api.local"})
    """
    return _get_loader().load(skill_name, context)


def load_skills(
    skill_names: list[str], context: dict[str, Any] | None = None
) -> dict[str, str]:
    """
    Load multiple skills by name.

    Args:
        skill_names: List of skill names to load.
        context: Optional context variables for Jinja2 rendering.

    Returns:
        Dict mapping skill names to their rendered content.

    Example:
        skills = load_skills(["xss", "sqli", "ssrf"])
        for name, content in skills.items():
            print(f"{name}: {len(content)} chars")
    """
    return _get_loader().load_multiple(skill_names, context)


def load_skills_for_phase(
    phase: str, vulnerability_hints: list[str] | None = None
) -> str:
    """
    Load relevant skills for a pentest phase.

    Args:
        phase: Pentest phase (recon, scan, exploit, etc.)
        vulnerability_hints: Optional list of suspected vulnerability types.

    Returns:
        Combined skill content for the phase.

    Example:
        skills = load_skills_for_phase("exploit", ["xss", "sqli"])
    """
    # Default skills per phase
    phase_skills = {
        "recon": ["information_disclosure", "subdomain_takeover"],
        "scan": ["xss", "sql_injection", "ssrf", "path_traversal_lfi_rfi"],
        "exploit": ["xss", "sql_injection", "ssrf", "rce", "idor"],
        "post_exploit": ["authentication_jwt", "broken_function_level_authorization"],
    }

    # Get base skills for phase
    skill_names = phase_skills.get(phase.lower(), [])

    # Add vulnerability hints if provided
    if vulnerability_hints:
        skill_names = list(set(skill_names + vulnerability_hints))

    # Limit to 5 skills to avoid context bloat
    skill_names = skill_names[:5]

    skills = load_skills(skill_names)

    if not skills:
        return ""

    # Combine skills with headers
    combined = []
    for name, content in skills.items():
        combined.append(f"<!-- Skill: {name} -->\n{content}")

    return "\n\n".join(combined)
