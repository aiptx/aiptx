"""
AIPTX Playbooks - Structured Attack Methodologies
=================================================

Playbooks define structured penetration testing workflows
that guide AIPTX agents through systematic testing phases.

Available Playbooks:
    - web: Web Application Black-Box Testing
    - api: REST/GraphQL API Security Testing
    - graphql: GraphQL-Specific Testing
    - ad: Active Directory Penetration Testing
    - ad_quick: Quick AD Assessment

Example usage:
    from aipt_v2.playbooks import get_playbook, list_playbooks

    # Get a playbook
    playbook = get_playbook("web")

    # Get task description for agent
    task = playbook.get_task()

    # List all available playbooks
    for name, desc in list_playbooks():
        print(f"{name}: {desc}")

CLI Usage:
    aiptx scan --target http://example.com --playbook web
    aiptx scan --target dc.corp.local --playbook ad
"""

from typing import Dict, List, Optional, Tuple, Type

from .ad_playbook import ADPlaybook, ADQuickPlaybook
from .api_playbook import APIPlaybook, GraphQLPlaybook
from .base_playbook import BasePlaybook, Phase, PlaybookMode
from .web_playbook import WebAPIPlaybook, WebPlaybook

# Registry of available playbooks
PLAYBOOKS: Dict[str, Type[BasePlaybook]] = {
    "web": WebPlaybook,
    "web_api": WebAPIPlaybook,
    "api": APIPlaybook,
    "graphql": GraphQLPlaybook,
    "ad": ADPlaybook,
    "ad_quick": ADQuickPlaybook,
}


def get_playbook(name: str) -> Optional[BasePlaybook]:
    """
    Get a playbook instance by name.

    Args:
        name: Playbook name (e.g., "web", "ad")

    Returns:
        Playbook instance or None if not found
    """
    playbook_class = PLAYBOOKS.get(name.lower())
    if playbook_class:
        return playbook_class()
    return None


def list_playbooks() -> List[Tuple[str, str]]:
    """
    List all available playbooks.

    Returns:
        List of (name, description) tuples
    """
    result = []
    for name, cls in PLAYBOOKS.items():
        instance = cls()
        result.append((name, instance.description))
    return result


def get_playbook_names() -> List[str]:
    """
    Get list of all playbook names.

    Returns:
        List of playbook names
    """
    return list(PLAYBOOKS.keys())


def register_playbook(name: str, playbook_class: Type[BasePlaybook]) -> None:
    """
    Register a custom playbook.

    Args:
        name: Unique playbook name
        playbook_class: Playbook class to register
    """
    PLAYBOOKS[name.lower()] = playbook_class


__all__ = [
    # Base classes
    "BasePlaybook",
    "Phase",
    "PlaybookMode",
    # Web playbooks
    "WebPlaybook",
    "WebAPIPlaybook",
    # API playbooks
    "APIPlaybook",
    "GraphQLPlaybook",
    # AD playbooks
    "ADPlaybook",
    "ADQuickPlaybook",
    # Registry
    "PLAYBOOKS",
    # Functions
    "get_playbook",
    "list_playbooks",
    "get_playbook_names",
    "register_playbook",
]
