"""
AIPTX Beast Mode - LLM Attack Planner
=====================================

AI-powered strategic attack planning and execution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AttackPhase(str, Enum):
    """Phases of an attack plan."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"


class AttackObjective(str, Enum):
    """Objectives for attack planning."""
    FULL_COMPROMISE = "full_compromise"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    SPECIFIC_SYSTEM = "specific_system"
    CREDENTIAL_HARVEST = "credential_harvest"


@dataclass
class AttackStep:
    """A single step in an attack plan."""
    phase: AttackPhase
    action: str
    tool: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    prerequisites: list[str] = field(default_factory=list)
    expected_outcome: str = ""
    fallback_actions: list[str] = field(default_factory=list)
    risk_level: str = "medium"
    success_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "phase": self.phase.value,
            "action": self.action,
            "tool": self.tool,
            "target": self.target,
            "parameters": self.parameters,
            "prerequisites": self.prerequisites,
            "expected_outcome": self.expected_outcome,
            "fallback_actions": self.fallback_actions,
            "risk_level": self.risk_level,
            "success_indicators": self.success_indicators,
        }


@dataclass
class AttackPlan:
    """A complete attack plan."""
    objective: AttackObjective
    target: str
    steps: list[AttackStep] = field(default_factory=list)
    estimated_duration: str = ""
    risk_assessment: str = ""
    success_criteria: list[str] = field(default_factory=list)
    abort_conditions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "objective": self.objective.value,
            "target": self.target,
            "steps": [s.to_dict() for s in self.steps],
            "estimated_duration": self.estimated_duration,
            "risk_assessment": self.risk_assessment,
            "success_criteria": self.success_criteria,
            "abort_conditions": self.abort_conditions,
            "metadata": self.metadata,
        }


# Attack plan templates
ATTACK_TEMPLATES = {
    "web_app_full_compromise": {
        "objective": AttackObjective.FULL_COMPROMISE,
        "phases": [
            {
                "phase": AttackPhase.RECONNAISSANCE,
                "steps": [
                    "Passive reconnaissance (OSINT, DNS, subdomains)",
                    "Technology fingerprinting (Wappalyzer, WhatWeb)",
                    "Directory and file enumeration",
                ],
            },
            {
                "phase": AttackPhase.SCANNING,
                "steps": [
                    "Port scan target range",
                    "Web vulnerability scan (SQLi, XSS, etc.)",
                    "API endpoint discovery",
                ],
            },
            {
                "phase": AttackPhase.EXPLOITATION,
                "steps": [
                    "Exploit highest-confidence vulnerability",
                    "Establish initial access (webshell, RCE)",
                    "Validate access level",
                ],
            },
            {
                "phase": AttackPhase.POST_EXPLOITATION,
                "steps": [
                    "Enumerate local system",
                    "Harvest credentials",
                    "Check for privilege escalation vectors",
                ],
            },
        ],
    },
    "internal_network_pivot": {
        "objective": AttackObjective.LATERAL_MOVEMENT,
        "phases": [
            {
                "phase": AttackPhase.POST_EXPLOITATION,
                "steps": [
                    "Enumerate network interfaces",
                    "Discover internal network ranges",
                    "Identify high-value targets",
                ],
            },
            {
                "phase": AttackPhase.LATERAL_MOVEMENT,
                "steps": [
                    "Establish pivot point (SOCKS proxy)",
                    "Scan internal network through pivot",
                    "Test harvested credentials",
                    "Move to new targets",
                ],
            },
        ],
    },
}


class LLMAttackPlanner:
    """
    AI-powered attack planning engine.

    Uses LLM capabilities to generate strategic attack plans
    based on discovered vulnerabilities and target context.
    """

    def __init__(self):
        """Initialize the attack planner."""
        self._plans: list[AttackPlan] = []
        self._context: dict[str, Any] = {}

    def create_plan(
        self,
        target: str,
        objective: AttackObjective,
        discovered_vulns: list[dict[str, Any]] | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> AttackPlan:
        """
        Create an attack plan for a target.

        Args:
            target: Target URL or IP
            objective: Attack objective
            discovered_vulns: Known vulnerabilities
            constraints: Planning constraints

        Returns:
            Generated attack plan
        """
        # Start with template if available
        template_name = self._select_template(objective)
        plan = AttackPlan(
            objective=objective,
            target=target,
        )

        # Add reconnaissance steps
        plan.steps.extend(self._generate_recon_steps(target))

        # Add vulnerability-specific steps if we have findings
        if discovered_vulns:
            plan.steps.extend(self._generate_exploit_steps(discovered_vulns))

        # Add post-exploitation steps based on objective
        if objective == AttackObjective.FULL_COMPROMISE:
            plan.steps.extend(self._generate_full_compromise_steps())
        elif objective == AttackObjective.CREDENTIAL_HARVEST:
            plan.steps.extend(self._generate_credential_harvest_steps())
        elif objective == AttackObjective.LATERAL_MOVEMENT:
            plan.steps.extend(self._generate_lateral_movement_steps())

        # Apply constraints
        if constraints:
            plan = self._apply_constraints(plan, constraints)

        # Calculate metadata
        plan.estimated_duration = self._estimate_duration(plan)
        plan.risk_assessment = self._assess_risk(plan)
        plan.success_criteria = self._define_success_criteria(objective)
        plan.abort_conditions = self._define_abort_conditions()

        self._plans.append(plan)
        return plan

    def _select_template(self, objective: AttackObjective) -> str | None:
        """Select appropriate template for objective."""
        mapping = {
            AttackObjective.FULL_COMPROMISE: "web_app_full_compromise",
            AttackObjective.LATERAL_MOVEMENT: "internal_network_pivot",
        }
        return mapping.get(objective)

    def _generate_recon_steps(self, target: str) -> list[AttackStep]:
        """Generate reconnaissance steps."""
        return [
            AttackStep(
                phase=AttackPhase.RECONNAISSANCE,
                action="Subdomain enumeration",
                tool="subfinder/amass",
                target=target,
                expected_outcome="List of subdomains",
                success_indicators=["Found subdomains"],
            ),
            AttackStep(
                phase=AttackPhase.RECONNAISSANCE,
                action="Technology fingerprinting",
                tool="whatweb/wappalyzer",
                target=target,
                expected_outcome="Tech stack identification",
            ),
            AttackStep(
                phase=AttackPhase.SCANNING,
                action="Port scan",
                tool="nmap",
                target=target,
                parameters={"ports": "top-1000", "timing": "T4"},
                expected_outcome="Open ports and services",
            ),
            AttackStep(
                phase=AttackPhase.SCANNING,
                action="Web vulnerability scan",
                tool="nuclei/nikto",
                target=target,
                expected_outcome="Vulnerability findings",
            ),
        ]

    def _generate_exploit_steps(
        self,
        vulns: list[dict[str, Any]],
    ) -> list[AttackStep]:
        """Generate exploitation steps based on vulnerabilities."""
        steps = []

        # Sort by severity/confidence
        sorted_vulns = sorted(
            vulns,
            key=lambda v: v.get("severity", 0),
            reverse=True,
        )

        for vuln in sorted_vulns[:3]:  # Top 3 vulnerabilities
            vuln_type = vuln.get("type", "unknown")
            steps.append(AttackStep(
                phase=AttackPhase.EXPLOITATION,
                action=f"Exploit {vuln_type}",
                tool=self._get_exploit_tool(vuln_type),
                target=vuln.get("url", ""),
                parameters=vuln.get("parameters", {}),
                expected_outcome=f"Successful {vuln_type} exploitation",
                fallback_actions=self._get_fallback_actions(vuln_type),
                risk_level=vuln.get("risk", "medium"),
            ))

        return steps

    def _generate_full_compromise_steps(self) -> list[AttackStep]:
        """Generate steps for full system compromise."""
        return [
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="System enumeration",
                tool="linpeas/winpeas",
                target="local",
                expected_outcome="System configuration details",
            ),
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="Credential harvesting",
                tool="credential_harvester",
                target="local",
                expected_outcome="Harvested credentials",
            ),
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="Privilege escalation",
                tool="privesc_engine",
                target="local",
                expected_outcome="Elevated privileges",
                prerequisites=["Credential harvesting"],
            ),
            AttackStep(
                phase=AttackPhase.PERSISTENCE,
                action="Establish persistence",
                tool="persistence_module",
                target="local",
                expected_outcome="Persistent access",
                prerequisites=["Privilege escalation"],
            ),
        ]

    def _generate_credential_harvest_steps(self) -> list[AttackStep]:
        """Generate credential harvesting steps."""
        return [
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="Search config files",
                tool="file_search_harvester",
                target="local",
                expected_outcome="Credentials from files",
            ),
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="Extract environment variables",
                tool="env_secret_harvester",
                target="local",
                expected_outcome="Credentials from env",
            ),
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="Check cloud metadata",
                tool="cloud_metadata_harvester",
                target="169.254.169.254",
                expected_outcome="Cloud credentials",
            ),
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="Browser credential extraction",
                tool="browser_creds_harvester",
                target="local",
                expected_outcome="Browser saved passwords",
            ),
        ]

    def _generate_lateral_movement_steps(self) -> list[AttackStep]:
        """Generate lateral movement steps."""
        return [
            AttackStep(
                phase=AttackPhase.POST_EXPLOITATION,
                action="Network discovery",
                tool="route_manager",
                target="local",
                expected_outcome="Internal network ranges",
            ),
            AttackStep(
                phase=AttackPhase.LATERAL_MOVEMENT,
                action="Establish pivot",
                tool="pivot_manager",
                target="internal",
                expected_outcome="SOCKS proxy active",
            ),
            AttackStep(
                phase=AttackPhase.LATERAL_MOVEMENT,
                action="Internal scanning",
                tool="internal_scanner",
                target="internal_range",
                expected_outcome="Internal hosts and services",
                prerequisites=["Establish pivot"],
            ),
            AttackStep(
                phase=AttackPhase.LATERAL_MOVEMENT,
                action="Credential spraying",
                tool="credential_sprayer",
                target="internal_hosts",
                expected_outcome="Valid credentials for internal hosts",
                prerequisites=["Internal scanning", "Credential harvesting"],
            ),
        ]

    def _get_exploit_tool(self, vuln_type: str) -> str:
        """Get appropriate exploit tool for vulnerability type."""
        tools = {
            "sqli": "sqlmap",
            "xss": "xss_scanner",
            "rce": "chain_executor",
            "lfi": "lfi_exploit",
            "ssrf": "ssrf_exploit",
            "upload": "upload_exploit",
        }
        return tools.get(vuln_type.lower(), "manual_exploit")

    def _get_fallback_actions(self, vuln_type: str) -> list[str]:
        """Get fallback actions for failed exploitation."""
        fallbacks = {
            "sqli": ["Try different SQLi techniques", "Use WAF bypass", "Try blind SQLi"],
            "xss": ["Try different context escapes", "Use encoding bypass"],
            "rce": ["Try command obfuscation", "Use alternative payload"],
        }
        return fallbacks.get(vuln_type.lower(), ["Try manual exploitation"])

    def _apply_constraints(
        self,
        plan: AttackPlan,
        constraints: dict[str, Any],
    ) -> AttackPlan:
        """Apply constraints to plan."""
        max_risk = constraints.get("max_risk", "high")
        risk_levels = ["low", "medium", "high", "critical"]
        max_risk_idx = risk_levels.index(max_risk)

        # Filter steps by risk
        plan.steps = [
            s for s in plan.steps
            if risk_levels.index(s.risk_level) <= max_risk_idx
        ]

        return plan

    def _estimate_duration(self, plan: AttackPlan) -> str:
        """Estimate plan duration."""
        step_durations = {
            AttackPhase.RECONNAISSANCE: 30,
            AttackPhase.SCANNING: 60,
            AttackPhase.ENUMERATION: 45,
            AttackPhase.EXPLOITATION: 120,
            AttackPhase.POST_EXPLOITATION: 60,
            AttackPhase.LATERAL_MOVEMENT: 90,
        }

        total_minutes = sum(
            step_durations.get(s.phase, 30)
            for s in plan.steps
        )

        if total_minutes < 60:
            return f"{total_minutes} minutes"
        else:
            return f"{total_minutes // 60} hours {total_minutes % 60} minutes"

    def _assess_risk(self, plan: AttackPlan) -> str:
        """Assess overall plan risk."""
        risks = [s.risk_level for s in plan.steps]
        if "critical" in risks:
            return "critical"
        elif "high" in risks:
            return "high"
        elif "medium" in risks:
            return "medium"
        return "low"

    def _define_success_criteria(self, objective: AttackObjective) -> list[str]:
        """Define success criteria for objective."""
        criteria = {
            AttackObjective.FULL_COMPROMISE: [
                "Root/SYSTEM access achieved",
                "Persistence established",
                "Lateral movement capability",
            ],
            AttackObjective.CREDENTIAL_HARVEST: [
                "At least 5 valid credentials",
                "Admin/privileged credentials found",
                "Cloud/API credentials obtained",
            ],
            AttackObjective.LATERAL_MOVEMENT: [
                "Access to 3+ internal hosts",
                "Domain credentials obtained",
                "Pivot point stable",
            ],
        }
        return criteria.get(objective, ["Objective completed"])

    def _define_abort_conditions(self) -> list[str]:
        """Define conditions to abort the operation."""
        return [
            "Active incident response detected",
            "Account lockouts triggered",
            "Network isolation detected",
            "Out of scope access detected",
        ]

    def get_plans(self) -> list[AttackPlan]:
        """Get all generated plans."""
        return self._plans.copy()

    def get_llm_prompt(
        self,
        target: str,
        objective: str,
        context: dict[str, Any],
    ) -> str:
        """
        Generate LLM prompt for attack planning.

        Args:
            target: Target description
            objective: Attack objective
            context: Additional context

        Returns:
            Prompt for LLM
        """
        return f"""You are a professional penetration tester planning an authorized security assessment.

Target: {target}
Objective: {objective}

Context:
- Discovered technologies: {context.get('technologies', 'Unknown')}
- Known vulnerabilities: {context.get('vulnerabilities', 'None yet')}
- Constraints: {context.get('constraints', 'None')}

Generate a detailed attack plan with:
1. Reconnaissance steps
2. Scanning/enumeration strategy
3. Exploitation approach (prioritized by likelihood of success)
4. Post-exploitation activities
5. Fallback strategies

For each step, provide:
- Tool to use
- Expected outcome
- Risk level (low/medium/high)
- Prerequisites

Output as structured JSON."""


__all__ = [
    "AttackPhase",
    "AttackObjective",
    "AttackStep",
    "AttackPlan",
    "LLMAttackPlanner",
    "ATTACK_TEMPLATES",
]
