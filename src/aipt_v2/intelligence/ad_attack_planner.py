"""
AIPTX Active Directory Attack Planner

LLM-guided attack path planning for AD penetration testing.
Analyzes BloodHound data, enumeration results, and available
attack techniques to generate optimal attack plans.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AttackObjective(Enum):
    """Attack objectives for AD testing"""

    DOMAIN_ADMIN = "domain_admin"
    ENTERPRISE_ADMIN = "enterprise_admin"
    SPECIFIC_USER = "specific_user"
    SPECIFIC_HOST = "specific_host"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    CREDENTIAL_HARVEST = "credential_harvest"
    LATERAL_MOVEMENT = "lateral_movement"


class AttackPhase(Enum):
    """Phases of AD attack"""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DOMAIN_DOMINANCE = "domain_dominance"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"


@dataclass
class AttackStep:
    """Individual step in an attack plan"""

    phase: AttackPhase
    action: str
    description: str
    tool: str
    parameters: dict = field(default_factory=dict)

    # Dependencies
    prerequisites: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)

    # Risk assessment
    risk_level: str = "medium"  # low, medium, high
    detection_likelihood: str = "medium"

    # Execution
    estimated_time: str = ""
    success_indicators: list[str] = field(default_factory=list)
    fallback_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "phase": self.phase.value,
            "action": self.action,
            "description": self.description,
            "tool": self.tool,
            "parameters": self.parameters,
            "prerequisites": self.prerequisites,
            "produces": self.produces,
            "risk_level": self.risk_level,
            "fallback_actions": self.fallback_actions,
        }


@dataclass
class AttackPlan:
    """Complete attack plan"""

    objective: AttackObjective
    target: str
    steps: list[AttackStep] = field(default_factory=list)

    # Risk assessment
    overall_risk: str = "medium"
    estimated_duration: str = ""
    success_probability: float = 0.0

    # Conditions
    abort_conditions: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    rationale: str = ""

    def to_dict(self) -> dict:
        return {
            "objective": self.objective.value,
            "target": self.target,
            "steps": [s.to_dict() for s in self.steps],
            "overall_risk": self.overall_risk,
            "estimated_duration": self.estimated_duration,
            "success_probability": self.success_probability,
            "abort_conditions": self.abort_conditions,
            "success_criteria": self.success_criteria,
            "rationale": self.rationale,
        }


@dataclass
class ADEnvironment:
    """AD environment context for planning"""

    domain: str
    dc_ip: str
    forest_level: str = ""
    domain_level: str = ""

    # Discovered assets
    domain_controllers: list[str] = field(default_factory=list)
    computers: int = 0
    users: int = 0

    # Attack surface
    kerberoastable_users: list[str] = field(default_factory=list)
    asrep_roastable_users: list[str] = field(default_factory=list)
    unconstrained_delegation: list[str] = field(default_factory=list)
    constrained_delegation: list[str] = field(default_factory=list)
    adcs_vulnerable: list[str] = field(default_factory=list)  # ESC1-ESC8

    # BloodHound paths
    paths_to_da: list[dict] = field(default_factory=list)
    high_value_targets: list[str] = field(default_factory=list)

    # Current access
    current_user: str = ""
    current_groups: list[str] = field(default_factory=list)
    admin_on: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "forest_level": self.forest_level,
            "kerberoastable_users": len(self.kerberoastable_users),
            "asrep_roastable_users": len(self.asrep_roastable_users),
            "unconstrained_delegation": len(self.unconstrained_delegation),
            "adcs_vulnerable": len(self.adcs_vulnerable),
            "paths_to_da": len(self.paths_to_da),
            "current_user": self.current_user,
            "admin_on": len(self.admin_on),
        }


class ADAttackPlanner:
    """
    LLM-guided AD attack planner.

    Analyzes the AD environment and generates optimal attack plans
    based on discovered vulnerabilities, BloodHound paths, and
    available attack techniques.
    """

    def __init__(self, llm_client: Optional[Any] = None):
        """
        Initialize planner.

        Args:
            llm_client: Optional LLM client for AI-guided planning
        """
        self.llm_client = llm_client

    async def plan_attack(
        self,
        environment: ADEnvironment,
        objective: AttackObjective,
        constraints: Optional[dict] = None,
    ) -> AttackPlan:
        """
        Generate attack plan for given objective.

        Args:
            environment: AD environment context
            objective: Attack objective
            constraints: Optional constraints (stealth, time, etc.)

        Returns:
            AttackPlan with steps
        """
        constraints = constraints or {}

        # Try LLM-guided planning first
        if self.llm_client:
            try:
                plan = await self._llm_plan_attack(environment, objective, constraints)
                if plan:
                    return plan
            except Exception as e:
                logger.warning(f"LLM planning failed, using rule-based: {e}")

        # Fallback to rule-based planning
        return self._rule_based_plan(environment, objective, constraints)

    async def _llm_plan_attack(
        self,
        environment: ADEnvironment,
        objective: AttackObjective,
        constraints: dict,
    ) -> Optional[AttackPlan]:
        """Generate attack plan using LLM"""
        prompt = self._build_planning_prompt(environment, objective, constraints)

        try:
            response = await self.llm_client.generate(prompt)
            return self._parse_llm_plan(response, objective, environment.dc_ip)
        except Exception as e:
            logger.error(f"LLM planning error: {e}")
            return None

    def _build_planning_prompt(
        self,
        environment: ADEnvironment,
        objective: AttackObjective,
        constraints: dict,
    ) -> str:
        """Build prompt for LLM attack planning"""
        return f"""You are an expert Active Directory penetration tester planning an authorized security assessment.

## Target Environment
- Domain: {environment.domain}
- Forest Functional Level: {environment.forest_level}
- Domain Controllers: {len(environment.domain_controllers)}
- Total Computers: {environment.computers}
- Total Users: {environment.users}

## Current Access
- Username: {environment.current_user}
- Group Memberships: {', '.join(environment.current_groups[:5])}
- Admin Access On: {len(environment.admin_on)} hosts

## Discovered Attack Surface
- Kerberoastable Users: {len(environment.kerberoastable_users)} ({', '.join(environment.kerberoastable_users[:3])}...)
- AS-REP Roastable: {len(environment.asrep_roastable_users)} users
- Unconstrained Delegation: {len(environment.unconstrained_delegation)} servers
- Constrained Delegation: {len(environment.constrained_delegation)} accounts
- ADCS Vulnerabilities: {len(environment.adcs_vulnerable)} (ESC1-ESC8)
- BloodHound Paths to DA: {len(environment.paths_to_da)}

## Objective
{objective.value}

## Constraints
- Stealth Level: {constraints.get('stealth', 'medium')}
- Time Budget: {constraints.get('time_budget', 'unlimited')}
- Avoid: {constraints.get('avoid', 'none')}

## Task
Generate an optimal attack plan with the following structure:
1. Prioritize the most reliable and stealthy attack path
2. Include fallback options for each step
3. Consider detection risk for each action
4. Provide specific tool commands where possible

Return the plan as JSON with this structure:
{{
    "rationale": "Why this path was chosen",
    "steps": [
        {{
            "phase": "reconnaissance|credential_access|privilege_escalation|lateral_movement|domain_dominance",
            "action": "Short action name",
            "description": "What this step does",
            "tool": "Tool to use",
            "parameters": {{}},
            "prerequisites": ["What's needed"],
            "produces": ["What this creates"],
            "risk_level": "low|medium|high",
            "fallback_actions": ["Alternative if this fails"]
        }}
    ],
    "success_probability": 0.0-1.0,
    "estimated_duration": "Time estimate"
}}
"""

    def _parse_llm_plan(
        self,
        response: str,
        objective: AttackObjective,
        target: str,
    ) -> Optional[AttackPlan]:
        """Parse LLM response into AttackPlan"""
        try:
            # Extract JSON from response
            import re

            json_match = re.search(r"\{[\s\S]*\}", response)
            if not json_match:
                return None

            data = json.loads(json_match.group())

            plan = AttackPlan(
                objective=objective,
                target=target,
                rationale=data.get("rationale", ""),
                success_probability=data.get("success_probability", 0.5),
                estimated_duration=data.get("estimated_duration", ""),
            )

            for step_data in data.get("steps", []):
                step = AttackStep(
                    phase=AttackPhase(step_data.get("phase", "reconnaissance")),
                    action=step_data.get("action", ""),
                    description=step_data.get("description", ""),
                    tool=step_data.get("tool", ""),
                    parameters=step_data.get("parameters", {}),
                    prerequisites=step_data.get("prerequisites", []),
                    produces=step_data.get("produces", []),
                    risk_level=step_data.get("risk_level", "medium"),
                    fallback_actions=step_data.get("fallback_actions", []),
                )
                plan.steps.append(step)

            return plan

        except Exception as e:
            logger.error(f"Failed to parse LLM plan: {e}")
            return None

    def _rule_based_plan(
        self,
        environment: ADEnvironment,
        objective: AttackObjective,
        constraints: dict,
    ) -> AttackPlan:
        """Generate attack plan using rules"""
        plan = AttackPlan(
            objective=objective,
            target=environment.dc_ip,
        )

        stealth = constraints.get("stealth", "medium")

        # Prioritize attack paths based on environment
        if objective == AttackObjective.DOMAIN_ADMIN:
            plan = self._plan_domain_admin(environment, stealth)
        elif objective == AttackObjective.CREDENTIAL_HARVEST:
            plan = self._plan_credential_harvest(environment, stealth)
        elif objective == AttackObjective.LATERAL_MOVEMENT:
            plan = self._plan_lateral_movement(environment, stealth)
        else:
            plan = self._plan_domain_admin(environment, stealth)  # Default

        return plan

    def _plan_domain_admin(
        self,
        environment: ADEnvironment,
        stealth: str,
    ) -> AttackPlan:
        """Plan path to Domain Admin"""
        plan = AttackPlan(
            objective=AttackObjective.DOMAIN_ADMIN,
            target=environment.dc_ip,
            rationale="",
        )

        # Priority 1: ADCS ESC1/ESC8 (if available, most direct)
        if environment.adcs_vulnerable:
            plan.rationale = "ADCS ESC vulnerability provides direct path to DA"
            plan.steps = self._build_adcs_steps(environment)
            plan.success_probability = 0.9

        # Priority 2: BloodHound shortest path
        elif environment.paths_to_da:
            plan.rationale = "Following BloodHound-identified attack path"
            plan.steps = self._build_bloodhound_steps(environment)
            plan.success_probability = 0.7

        # Priority 3: Kerberoasting
        elif environment.kerberoastable_users:
            plan.rationale = "Kerberoasting service accounts for potential DA access"
            plan.steps = self._build_kerberoast_steps(environment)
            plan.success_probability = 0.5

        # Priority 4: Unconstrained delegation
        elif environment.unconstrained_delegation:
            plan.rationale = "Abusing unconstrained delegation to capture DC TGT"
            plan.steps = self._build_unconstrained_steps(environment)
            plan.success_probability = 0.6

        # Fallback: Password spray
        else:
            plan.rationale = "No quick wins available, attempting password spray"
            plan.steps = self._build_spray_steps(environment)
            plan.success_probability = 0.3

        return plan

    def _plan_credential_harvest(
        self,
        environment: ADEnvironment,
        stealth: str,
    ) -> AttackPlan:
        """Plan credential harvesting"""
        plan = AttackPlan(
            objective=AttackObjective.CREDENTIAL_HARVEST,
            target=environment.dc_ip,
            rationale="Harvesting credentials from multiple sources",
        )

        steps = []

        # Kerberoasting
        if environment.kerberoastable_users:
            steps.append(
                AttackStep(
                    phase=AttackPhase.CREDENTIAL_ACCESS,
                    action="Kerberoast",
                    description=f"Request TGS for {len(environment.kerberoastable_users)} accounts",
                    tool="GetUserSPNs.py",
                    produces=["tgs_hashes"],
                    risk_level="low",
                )
            )

        # AS-REP roasting
        if environment.asrep_roastable_users:
            steps.append(
                AttackStep(
                    phase=AttackPhase.CREDENTIAL_ACCESS,
                    action="AS-REP Roast",
                    description=f"Request AS-REP for {len(environment.asrep_roastable_users)} accounts",
                    tool="GetNPUsers.py",
                    produces=["asrep_hashes"],
                    risk_level="low",
                )
            )

        # LSASS dump if we have admin
        if environment.admin_on:
            steps.append(
                AttackStep(
                    phase=AttackPhase.CREDENTIAL_ACCESS,
                    action="LSASS Dump",
                    description=f"Dump LSASS from {len(environment.admin_on)} hosts",
                    tool="lsassy",
                    produces=["cleartext_creds", "ntlm_hashes"],
                    risk_level="medium" if stealth == "high" else "low",
                )
            )

        plan.steps = steps
        return plan

    def _plan_lateral_movement(
        self,
        environment: ADEnvironment,
        stealth: str,
    ) -> AttackPlan:
        """Plan lateral movement"""
        plan = AttackPlan(
            objective=AttackObjective.LATERAL_MOVEMENT,
            target=environment.dc_ip,
            rationale="Expanding access across the domain",
        )

        steps = [
            AttackStep(
                phase=AttackPhase.LATERAL_MOVEMENT,
                action="Find Local Admin",
                description="Identify hosts where current creds have admin",
                tool="crackmapexec",
                produces=["admin_hosts"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.LATERAL_MOVEMENT,
                action="Execute on Targets",
                description="Execute commands on accessible hosts",
                tool="wmiexec.py" if stealth == "high" else "psexec.py",
                prerequisites=["admin_hosts"],
                produces=["shell_access"],
                risk_level="medium",
            ),
            AttackStep(
                phase=AttackPhase.CREDENTIAL_ACCESS,
                action="Harvest Credentials",
                description="Extract credentials from compromised hosts",
                tool="lsassy",
                prerequisites=["shell_access"],
                produces=["new_credentials"],
                risk_level="medium",
            ),
        ]

        plan.steps = steps
        return plan

    def _build_adcs_steps(self, environment: ADEnvironment) -> list[AttackStep]:
        """Build ADCS attack steps"""
        return [
            AttackStep(
                phase=AttackPhase.RECONNAISSANCE,
                action="Enumerate ADCS",
                description="Find vulnerable certificate templates",
                tool="certipy",
                produces=["vulnerable_templates", "ca_info"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                action="Request Certificate",
                description="Request certificate as Domain Admin",
                tool="certipy",
                prerequisites=["vulnerable_templates"],
                produces=["admin_certificate"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.CREDENTIAL_ACCESS,
                action="Authenticate with Cert",
                description="PKINIT authentication + UnPAC-the-hash",
                tool="certipy",
                prerequisites=["admin_certificate"],
                produces=["admin_tgt", "admin_ntlm"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.DOMAIN_DOMINANCE,
                action="DCSync",
                description="Extract all domain credentials",
                tool="secretsdump.py",
                prerequisites=["admin_ntlm"],
                produces=["all_credentials"],
                risk_level="medium",
            ),
        ]

    def _build_bloodhound_steps(self, environment: ADEnvironment) -> list[AttackStep]:
        """Build steps based on BloodHound path"""
        steps = []

        for i, path_step in enumerate(environment.paths_to_da[:5]):  # Max 5 steps
            steps.append(
                AttackStep(
                    phase=AttackPhase.PRIVILEGE_ESCALATION,
                    action=path_step.get("relationship", f"Step {i+1}"),
                    description=f"From {path_step.get('source', '?')} to {path_step.get('target', '?')}",
                    tool=self._get_tool_for_relationship(path_step.get("relationship", "")),
                    risk_level="medium",
                )
            )

        return steps

    def _build_kerberoast_steps(self, environment: ADEnvironment) -> list[AttackStep]:
        """Build Kerberoasting steps"""
        return [
            AttackStep(
                phase=AttackPhase.CREDENTIAL_ACCESS,
                action="Kerberoast",
                description=f"Request TGS for {len(environment.kerberoastable_users)} service accounts",
                tool="GetUserSPNs.py",
                produces=["tgs_hashes"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.CREDENTIAL_ACCESS,
                action="Crack Hashes",
                description="Offline hash cracking",
                tool="hashcat",
                prerequisites=["tgs_hashes"],
                produces=["cleartext_passwords"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.LATERAL_MOVEMENT,
                action="Use Credentials",
                description="Access systems with cracked credentials",
                tool="crackmapexec",
                prerequisites=["cleartext_passwords"],
                produces=["service_access"],
                risk_level="medium",
            ),
        ]

    def _build_unconstrained_steps(self, environment: ADEnvironment) -> list[AttackStep]:
        """Build unconstrained delegation attack steps"""
        return [
            AttackStep(
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                action="Compromise Delegation Server",
                description="Gain admin on unconstrained delegation host",
                tool="psexec.py",
                produces=["delegation_access"],
                risk_level="medium",
            ),
            AttackStep(
                phase=AttackPhase.CREDENTIAL_ACCESS,
                action="Monitor for TGTs",
                description="Set up TGT capture",
                tool="Rubeus",
                prerequisites=["delegation_access"],
                produces=["tgt_monitor"],
                risk_level="medium",
            ),
            AttackStep(
                phase=AttackPhase.CREDENTIAL_ACCESS,
                action="Coerce DC Authentication",
                description="Trigger DC to authenticate",
                tool="PetitPotam.py",
                produces=["dc_tgt"],
                risk_level="medium",
            ),
            AttackStep(
                phase=AttackPhase.DOMAIN_DOMINANCE,
                action="Use DC TGT",
                description="DCSync with captured DC ticket",
                tool="secretsdump.py",
                prerequisites=["dc_tgt"],
                produces=["all_credentials"],
                risk_level="medium",
            ),
        ]

    def _build_spray_steps(self, environment: ADEnvironment) -> list[AttackStep]:
        """Build password spray steps"""
        return [
            AttackStep(
                phase=AttackPhase.RECONNAISSANCE,
                action="Enumerate Users",
                description="Build user list",
                tool="kerbrute",
                produces=["user_list"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.RECONNAISSANCE,
                action="Get Password Policy",
                description="Check lockout threshold",
                tool="crackmapexec",
                produces=["password_policy"],
                risk_level="low",
            ),
            AttackStep(
                phase=AttackPhase.INITIAL_ACCESS,
                action="Password Spray",
                description="Spray common passwords",
                tool="crackmapexec",
                prerequisites=["user_list", "password_policy"],
                produces=["valid_credentials"],
                risk_level="medium",
            ),
        ]

    def _get_tool_for_relationship(self, relationship: str) -> str:
        """Map BloodHound relationship to tool"""
        tool_map = {
            "MemberOf": "net user",
            "AdminTo": "psexec.py",
            "HasSession": "lsassy",
            "CanRDP": "xfreerdp",
            "CanPSRemote": "evil-winrm",
            "GenericAll": "rbcd.py",
            "GenericWrite": "rbcd.py",
            "WriteDacl": "dacledit.py",
            "WriteOwner": "owneredit.py",
            "ForceChangePassword": "net user",
            "AddMember": "net group",
            "AllowedToDelegate": "getST.py",
            "ReadLAPSPassword": "laps.py",
        }
        return tool_map.get(relationship, "manual")


# Convenience function
async def plan_ad_attack(
    domain: str,
    dc_ip: str,
    objective: str = "domain_admin",
    current_user: str = "",
    kerberoastable: Optional[list[str]] = None,
    asrep_roastable: Optional[list[str]] = None,
    unconstrained: Optional[list[str]] = None,
    adcs_vulnerable: Optional[list[str]] = None,
    llm_client: Optional[Any] = None,
) -> AttackPlan:
    """
    Plan AD attack based on discovered information.

    Args:
        domain: Domain name
        dc_ip: DC IP
        objective: Attack objective
        current_user: Current username
        kerberoastable: List of Kerberoastable users
        asrep_roastable: List of AS-REP roastable users
        unconstrained: List of unconstrained delegation hosts
        adcs_vulnerable: List of ADCS vulnerabilities
        llm_client: Optional LLM client

    Returns:
        AttackPlan
    """
    environment = ADEnvironment(
        domain=domain,
        dc_ip=dc_ip,
        current_user=current_user,
        kerberoastable_users=kerberoastable or [],
        asrep_roastable_users=asrep_roastable or [],
        unconstrained_delegation=unconstrained or [],
        adcs_vulnerable=adcs_vulnerable or [],
    )

    objective_enum = AttackObjective(objective)

    planner = ADAttackPlanner(llm_client)
    return await planner.plan_attack(environment, objective_enum)
