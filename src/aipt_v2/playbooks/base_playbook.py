"""
Base Playbook Classes for AIPTX.

Provides structured attack workflows that guide autonomous testing.
Playbooks define phases, objectives, and techniques for systematic
penetration testing.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class PlaybookMode(str, Enum):
    """Execution mode for playbooks."""

    SEQUENTIAL = "sequential"  # Execute phases one after another
    PARALLEL = "parallel"  # Execute compatible phases in parallel
    ADAPTIVE = "adaptive"  # LLM decides based on findings


@dataclass
class Phase:
    """
    A phase in a penetration testing playbook.

    Each phase represents a logical step in the testing process
    with specific objectives and techniques.
    """

    name: str
    objective: str
    techniques: List[str]
    required_tools: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    timeout: int = 600  # Default 10 minutes per phase
    depends_on: List[str] = field(default_factory=list)  # Phase names this depends on
    parallel_safe: bool = False  # Can run in parallel with others
    skip_on_failure: bool = False  # Continue even if this phase fails

    def __post_init__(self):
        """Validate phase configuration."""
        if not self.name:
            raise ValueError("Phase name is required")
        if not self.objective:
            raise ValueError("Phase objective is required")
        if not self.techniques:
            raise ValueError("At least one technique is required")


class BasePlaybook:
    """
    Base class for all attack playbooks.

    Playbooks define structured testing methodologies that can be
    executed by AIPTX agents. They provide consistency and coverage
    while allowing adaptive behavior based on findings.
    """

    name: str = "base"
    description: str = "Base playbook"
    mode: PlaybookMode = PlaybookMode.SEQUENTIAL
    phases: List[Phase] = []
    target_type: str = "generic"  # web, api, network, ad
    estimated_duration: int = 3600  # Estimated total time in seconds

    def get_task(self) -> str:
        """
        Convert playbook to a structured task description for agents.

        Returns:
            Formatted string describing the playbook and its phases
        """
        lines = [
            f"# {self.name.upper()} Playbook",
            f"{self.description}",
            "",
            f"Mode: {self.mode.value}",
            f"Target Type: {self.target_type}",
            "",
            "## Phases",
            "",
        ]

        for i, phase in enumerate(self.phases, 1):
            lines.append(f"### Phase {i}: {phase.name}")
            lines.append(f"**Objective:** {phase.objective}")
            lines.append("")
            lines.append("**Techniques:**")
            for j, technique in enumerate(phase.techniques, 1):
                lines.append(f"  {j}. {technique}")
            lines.append("")

            if phase.required_tools:
                lines.append(f"**Tools:** {', '.join(phase.required_tools)}")

            if phase.mitre_techniques:
                lines.append(f"**MITRE ATT&CK:** {', '.join(phase.mitre_techniques)}")

            if phase.depends_on:
                lines.append(f"**Depends on:** {', '.join(phase.depends_on)}")

            lines.append("")

        return "\n".join(lines)

    def get_phase_by_name(self, name: str) -> Optional[Phase]:
        """
        Get a specific phase by name.

        Args:
            name: Phase name to find

        Returns:
            Phase if found, None otherwise
        """
        for phase in self.phases:
            if phase.name.lower() == name.lower():
                return phase
        return None

    def get_phases_for_parallel(self) -> List[List[Phase]]:
        """
        Group phases for parallel execution based on dependencies.

        Returns:
            List of phase groups that can run in parallel
        """
        groups = []
        completed = set()
        remaining = list(self.phases)

        while remaining:
            # Find phases with all dependencies satisfied
            ready = []
            for phase in remaining:
                deps_met = all(d in completed for d in phase.depends_on)
                if deps_met:
                    ready.append(phase)

            if not ready:
                # No phases ready - circular dependency or error
                # Add remaining as sequential
                groups.extend([[p] for p in remaining])
                break

            # Group parallel-safe phases together
            parallel_group = [p for p in ready if p.parallel_safe]
            sequential = [p for p in ready if not p.parallel_safe]

            if parallel_group:
                groups.append(parallel_group)
            for p in sequential:
                groups.append([p])

            # Mark as completed
            for phase in ready:
                completed.add(phase.name)
                remaining.remove(phase)

        return groups

    def get_required_tools(self) -> List[str]:
        """
        Get all tools required by this playbook.

        Returns:
            Deduplicated list of tool names
        """
        tools = set()
        for phase in self.phases:
            tools.update(phase.required_tools)
        return sorted(tools)

    def get_mitre_coverage(self) -> List[str]:
        """
        Get all MITRE ATT&CK techniques covered.

        Returns:
            Deduplicated list of technique IDs
        """
        techniques = set()
        for phase in self.phases:
            techniques.update(phase.mitre_techniques)
        return sorted(techniques)

    def validate(self) -> List[str]:
        """
        Validate playbook configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not self.name:
            errors.append("Playbook name is required")

        if not self.phases:
            errors.append("At least one phase is required")

        # Check for circular dependencies
        phase_names = {p.name for p in self.phases}
        for phase in self.phases:
            for dep in phase.depends_on:
                if dep not in phase_names:
                    errors.append(f"Phase '{phase.name}' depends on unknown phase '{dep}'")

        return errors

    def to_dict(self) -> dict:
        """
        Convert playbook to dictionary for serialization.

        Returns:
            Dictionary representation
        """
        return {
            "name": self.name,
            "description": self.description,
            "mode": self.mode.value,
            "target_type": self.target_type,
            "estimated_duration": self.estimated_duration,
            "phases": [
                {
                    "name": p.name,
                    "objective": p.objective,
                    "techniques": p.techniques,
                    "required_tools": p.required_tools,
                    "mitre_techniques": p.mitre_techniques,
                    "timeout": p.timeout,
                    "depends_on": p.depends_on,
                    "parallel_safe": p.parallel_safe,
                }
                for p in self.phases
            ],
            "required_tools": self.get_required_tools(),
            "mitre_coverage": self.get_mitre_coverage(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BasePlaybook":
        """
        Create playbook from dictionary.

        Args:
            data: Dictionary representation

        Returns:
            Playbook instance
        """
        playbook = cls()
        playbook.name = data.get("name", playbook.name)
        playbook.description = data.get("description", playbook.description)
        playbook.mode = PlaybookMode(data.get("mode", "sequential"))
        playbook.target_type = data.get("target_type", playbook.target_type)
        playbook.estimated_duration = data.get("estimated_duration", 3600)

        playbook.phases = [
            Phase(
                name=p["name"],
                objective=p["objective"],
                techniques=p["techniques"],
                required_tools=p.get("required_tools", []),
                mitre_techniques=p.get("mitre_techniques", []),
                timeout=p.get("timeout", 600),
                depends_on=p.get("depends_on", []),
                parallel_safe=p.get("parallel_safe", False),
            )
            for p in data.get("phases", [])
        ]

        return playbook
