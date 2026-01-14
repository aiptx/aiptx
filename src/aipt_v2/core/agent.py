"""
AIPT Agent - LangGraph-based autonomous pentesting agent

The heart of AIPT: Think → Select → Execute → Learn loop

Inspired by:
- Strix: LangGraph state machine, 300 iterations
- PentestGPT: PTT task tracking
- Pentagi: Message chain isolation
"""
from __future__ import annotations

from typing import Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

try:
    from pydantic import BaseModel, Field
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object
    def Field(**kwargs): return None

try:
    from langgraph.graph import StateGraph, END
    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    StateGraph = None
    END = "END"

from .memory import MemoryManager


class Phase(str, Enum):
    """Penetration testing phases"""
    RECON = "recon"
    ENUM = "enum"
    EXPLOIT = "exploit"
    POST = "post"
    REPORT = "report"


if PYDANTIC_AVAILABLE:
    class PentestState(BaseModel):
        """
        State object passed through the LangGraph.
        Contains all information about the current pentest session.
        """
        # Target information
        target: str = Field(default="", description="Primary target (IP, domain, or range)")
        scope: list[str] = Field(default_factory=list, description="In-scope targets")

        # Current phase and progress
        phase: Phase = Field(default=Phase.RECON, description="Current pentest phase")
        iteration: int = Field(default=0, description="Current iteration count")
        max_iterations: int = Field(default=100, description="Maximum iterations")

        # Current action
        current_objective: str = Field(default="", description="What we're trying to do")
        selected_tool: Optional[dict] = Field(default=None, description="Selected tool")
        tool_command: str = Field(default="", description="Command to execute")

        # Results
        last_output: str = Field(default="", description="Last tool output")
        findings: list[dict] = Field(default_factory=list, description="All findings")

        # PTT (Penetration Testing Tree)
        ptt: dict = Field(default_factory=dict, description="Task hierarchy")

        # Control flags
        needs_human_confirm: bool = Field(default=False, description="Needs human confirmation")
        stop_reason: Optional[str] = Field(default=None, description="Why agent stopped")
        error: Optional[str] = Field(default=None, description="Last error if any")

        class Config:
            arbitrary_types_allowed = True
else:
    @dataclass
    class PentestState:
        """Fallback state without Pydantic"""
        target: str = ""
        scope: list = field(default_factory=list)
        phase: Phase = Phase.RECON
        iteration: int = 0
        max_iterations: int = 100
        current_objective: str = ""
        selected_tool: Optional[dict] = None
        tool_command: str = ""
        last_output: str = ""
        findings: list = field(default_factory=list)
        ptt: dict = field(default_factory=dict)
        needs_human_confirm: bool = False
        stop_reason: Optional[str] = None
        error: Optional[str] = None


class AIPTAgent:
    """
    Autonomous AI Penetration Testing Agent.

    Uses a 4-node LangGraph state machine:
    1. THINK: Analyze current state, decide next action
    2. SELECT: Use RAG to choose the best tool
    3. EXECUTE: Run the tool, capture output
    4. LEARN: Extract findings, update PTT, decide next phase

    Example:
        from aipt_v2.core import AIPTAgent, get_llm

        llm = get_llm("openai")
        agent = AIPTAgent(llm, tools_rag, terminal, ptt)
        result = agent.run("192.168.1.0/24")
    """

    # System prompt for the pentesting agent
    SYSTEM_PROMPT = """You are AIPT, an expert AI penetration testing assistant.

Your goal is to systematically test the target for security vulnerabilities.

## Current Phase: {phase}
## Target: {target}
## Iteration: {iteration}/{max_iterations}

## Phases:
1. RECON: Discover hosts, ports, services (nmap, masscan, subfinder)
2. ENUM: Enumerate services, find vulnerabilities (gobuster, nikto, nuclei)
3. EXPLOIT: Exploit vulnerabilities (sqlmap, metasploit, hydra)
4. POST: Post-exploitation, privilege escalation (linpeas, mimikatz)
5. REPORT: Generate final report

## Current PTT (Penetration Testing Tree):
{ptt}

## Recent Findings:
{findings}

## Rules:
1. Be methodical - complete reconnaissance before exploitation
2. Document everything - update PTT with each finding
3. Stay in scope - only test authorized targets
4. Be efficient - don't repeat the same scans
5. Escalate phases when current phase objectives are met

Respond with your analysis and recommended next action.
"""

    def __init__(
        self,
        llm: Any,
        tools_rag: Any = None,
        terminal: Any = None,
        ptt_tracker: Any = None,
        human_confirm_exploits: bool = True,
        on_think: Optional[Callable] = None,
        on_select: Optional[Callable] = None,
        on_execute: Optional[Callable] = None,
        on_learn: Optional[Callable] = None,
    ):
        """
        Initialize AIPT Agent.

        Args:
            llm: LLM provider instance
            tools_rag: Tool RAG for tool selection
            terminal: Terminal executor for running commands
            ptt_tracker: PTT tracker for task management
            human_confirm_exploits: Require human confirmation for exploits
            on_think: Callback for think phase
            on_select: Callback for select phase
            on_execute: Callback for execute phase
            on_learn: Callback for learn phase
        """
        self.llm = llm
        self.tools_rag = tools_rag
        self.terminal = terminal
        self.ptt = ptt_tracker
        self.human_confirm_exploits = human_confirm_exploits
        self.memory = MemoryManager(llm)

        # Callbacks
        self.on_think = on_think
        self.on_select = on_select
        self.on_execute = on_execute
        self.on_learn = on_learn

        # Build the graph if LangGraph is available
        self.graph = self._build_graph() if LANGGRAPH_AVAILABLE else None

    def _build_graph(self):
        """Build the LangGraph state machine"""
        if not LANGGRAPH_AVAILABLE:
            return None

        graph = StateGraph(PentestState)

        # Add nodes
        graph.add_node("think", self._think)
        graph.add_node("select", self._select)
        graph.add_node("execute", self._execute)
        graph.add_node("learn", self._learn)

        # Add edges
        graph.add_edge("think", "select")
        graph.add_conditional_edges(
            "select",
            self._should_execute,
            {
                "execute": "execute",
                "think": "think",
                "end": END,
            }
        )
        graph.add_edge("execute", "learn")
        graph.add_conditional_edges(
            "learn",
            self._should_continue,
            {
                "continue": "think",
                "end": END,
            }
        )

        # Set entry point
        graph.set_entry_point("think")

        return graph.compile()

    def _think(self, state: PentestState) -> dict:
        """THINK node: Analyze current state and decide next action."""
        if self.on_think:
            self.on_think(state)

        # Build context
        ptt_str = self._format_ptt(state)
        findings_str = self._format_recent_findings(state.findings[-5:])

        system_prompt = self.SYSTEM_PROMPT.format(
            phase=state.phase.value.upper(),
            target=state.target,
            iteration=state.iteration,
            max_iterations=state.max_iterations,
            ptt=ptt_str,
            findings=findings_str,
        )

        self.memory.add_system(system_prompt)

        # Build user prompt
        user_prompt = f"""Based on the current state, what should we do next?

Target: {state.target}
Phase: {state.phase.value}
Last Output: {state.last_output[:1000] if state.last_output else 'None'}

Provide:
1. ANALYSIS: What do we know so far?
2. OBJECTIVE: What should we do next?
3. TOOL_HINT: What type of tool would help? (e.g., "port scanner", "directory brute-forcer")

Be specific and actionable."""

        self.memory.add_user(user_prompt)

        # Get LLM response
        messages = self.memory.get_messages()
        response = self.llm.invoke(messages)

        self.memory.add_assistant(response.content)

        # Extract objective from response
        objective = self._extract_objective(response.content)

        return {"current_objective": objective}

    def _select(self, state: PentestState) -> dict:
        """SELECT node: Use RAG to choose the best tool for the objective."""
        if self.on_select:
            self.on_select(state)

        if not state.current_objective:
            return {"selected_tool": None, "error": "No objective set"}

        if not self.tools_rag:
            # No RAG available, use LLM to suggest tool
            return self._select_tool_via_llm(state)

        try:
            tools = self.tools_rag.search(
                query=state.current_objective,
                phase=state.phase.value,
                top_k=3,
            )

            if not tools:
                return {"selected_tool": None, "error": "No suitable tools found"}

            selected = tools[0]
            command = self._build_command(selected, state.target)

            return {
                "selected_tool": selected,
                "tool_command": command,
                "error": None,
            }

        except Exception as e:
            return {"selected_tool": None, "error": str(e)}

    def _select_tool_via_llm(self, state: PentestState) -> dict:
        """Select tool using LLM when RAG is not available"""
        prompt = f"""Given the objective: {state.current_objective}
Target: {state.target}
Phase: {state.phase.value}

Suggest a security tool and command to achieve this objective.
Return JSON: {{"tool": "tool_name", "command": "full command"}}"""

        try:
            response = self.llm.invoke([
                {"role": "system", "content": "You are a security tool expert. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ])

            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]

            tool_info = json.loads(content)
            return {
                "selected_tool": {"name": tool_info.get("tool", "unknown")},
                "tool_command": tool_info.get("command", ""),
                "error": None,
            }
        except Exception as e:
            return {"selected_tool": None, "error": f"Tool selection failed: {e}"}

    def _should_execute(self, state: PentestState) -> str:
        """Decide whether to execute, rethink, or end"""
        if state.error:
            return "think"

        if not state.selected_tool:
            return "think"

        if state.phase == Phase.EXPLOIT and self.human_confirm_exploits:
            state.needs_human_confirm = True

        return "execute"

    def _execute(self, state: PentestState) -> dict:
        """EXECUTE node: Run the selected tool."""
        if self.on_execute:
            self.on_execute(state)

        if not state.tool_command:
            return {"last_output": "", "error": "No command to execute"}

        if not self.terminal:
            return {"last_output": "[No terminal configured]", "error": "Terminal not available"}

        try:
            result = self.terminal.execute(
                command=state.tool_command,
                timeout=300,
            )

            return {
                "last_output": result.output if hasattr(result, 'output') else str(result),
                "error": result.error if hasattr(result, 'error') and result.error else None,
            }

        except Exception as e:
            return {"last_output": "", "error": str(e)}

    def _learn(self, state: PentestState) -> dict:
        """LEARN node: Extract findings, update PTT, decide next steps."""
        if self.on_learn:
            self.on_learn(state)

        updates = {}

        # Parse output for findings
        if state.last_output:
            findings = self._extract_findings(
                state.last_output,
                state.selected_tool,
                state.phase,
            )

            if findings:
                current_findings = list(state.findings)
                current_findings.extend(findings)
                updates["findings"] = current_findings

                # Update PTT
                self._update_ptt(state, findings)

        # Increment iteration
        updates["iteration"] = state.iteration + 1

        # Check for phase transition
        new_phase = self._check_phase_transition(state)
        if new_phase != state.phase:
            updates["phase"] = new_phase

        return updates

    def _should_continue(self, state: PentestState) -> str:
        """Decide whether to continue or end"""
        if state.iteration >= state.max_iterations:
            return "end"

        if state.phase == Phase.REPORT:
            return "end"

        if self._has_shell_access(state.findings):
            return "end"

        if state.error and "CRITICAL" in str(state.error):
            return "end"

        return "continue"

    def run(
        self,
        target: str,
        scope: Optional[list[str]] = None,
        max_iterations: int = 100,
        start_phase: Phase = Phase.RECON,
    ) -> PentestState:
        """
        Run the autonomous pentest agent.

        Args:
            target: Primary target (IP, domain, range)
            scope: List of in-scope targets (defaults to target only)
            max_iterations: Maximum iterations
            start_phase: Starting phase

        Returns:
            Final PentestState with all findings
        """
        initial_state = PentestState(
            target=target,
            scope=scope or [target],
            phase=start_phase,
            max_iterations=max_iterations,
            ptt=self._initialize_ptt(target),
        )

        if self.graph:
            # Use LangGraph
            final_state = self.graph.invoke(initial_state)
        else:
            # Fallback: manual loop
            final_state = self._run_manual_loop(initial_state)

        return final_state

    def _run_manual_loop(self, state: PentestState) -> PentestState:
        """Manual execution loop when LangGraph is not available"""
        while state.iteration < state.max_iterations:
            # Think
            updates = self._think(state)
            state.current_objective = updates.get("current_objective", "")

            # Select
            updates = self._select(state)
            state.selected_tool = updates.get("selected_tool")
            state.tool_command = updates.get("tool_command", "")
            state.error = updates.get("error")

            # Check if should execute
            if self._should_execute(state) != "execute":
                continue

            # Execute
            updates = self._execute(state)
            state.last_output = updates.get("last_output", "")
            state.error = updates.get("error")

            # Learn
            updates = self._learn(state)
            state.iteration = updates.get("iteration", state.iteration)
            state.phase = updates.get("phase", state.phase)
            if "findings" in updates:
                state.findings = updates["findings"]

            # Check if should continue
            if self._should_continue(state) == "end":
                break

        return state

    # ============== Helper Methods ==============

    def _format_ptt(self, state: PentestState) -> str:
        """Format PTT for prompt"""
        if self.ptt and hasattr(self.ptt, 'to_prompt'):
            return self.ptt.to_prompt()
        return json.dumps(state.ptt, indent=2) if state.ptt else "No tasks yet."

    def _initialize_ptt(self, target: str) -> dict:
        """Initialize PTT structure"""
        if self.ptt and hasattr(self.ptt, 'initialize'):
            return self.ptt.initialize(target)
        return {
            "target": target,
            "phases": {
                "recon": {"status": "pending", "tasks": []},
                "enum": {"status": "pending", "tasks": []},
                "exploit": {"status": "pending", "tasks": []},
                "post": {"status": "pending", "tasks": []},
            }
        }

    def _extract_objective(self, llm_response: str) -> str:
        """Extract objective from LLM response"""
        lines = llm_response.split("\n")
        for line in lines:
            if "OBJECTIVE:" in line.upper():
                return line.split(":", 1)[1].strip()

        for line in reversed(lines):
            if line.strip() and len(line.strip()) > 10:
                return line.strip()

        return "Continue reconnaissance"

    def _build_command(self, tool: dict, target: str) -> str:
        """Build command string from tool definition"""
        cmd_template = tool.get("cmd", tool.get("command", ""))
        return cmd_template.replace("{target}", target).replace("{url}", target)

    def _format_recent_findings(self, findings: list[dict]) -> str:
        """Format findings for prompt"""
        if not findings:
            return "No findings yet."

        lines = []
        for f in findings:
            lines.append(f"- [{f.get('type', 'info')}] {f.get('description', 'Unknown')}")
        return "\n".join(lines)

    def _extract_findings(
        self,
        output: str,
        tool: Optional[dict],
        phase: Phase,
    ) -> list[dict]:
        """Extract structured findings from tool output using LLM."""
        if not output or len(output) < 10:
            return []

        extract_prompt = f"""Analyze this security tool output and extract findings.

Tool: {tool.get('name', 'unknown') if tool else 'unknown'}
Phase: {phase.value}

Output:
{output[:5000]}

Extract findings in this JSON format:
[
  {{"type": "port|service|vuln|credential|host", "description": "brief description", "severity": "info|low|medium|high|critical", "data": {{}}}}
]

Only return valid JSON array. If no findings, return []."""

        try:
            response = self.llm.invoke([
                {"role": "system", "content": "You are a security findings parser. Return only valid JSON."},
                {"role": "user", "content": extract_prompt},
            ], max_tokens=1000)

            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]

            return json.loads(content)
        except (json.JSONDecodeError, Exception):
            return [{
                "type": "info",
                "description": f"Tool output captured ({len(output)} chars)",
                "severity": "info",
                "data": {"raw_length": len(output)},
            }]

    def _update_ptt(self, state: PentestState, findings: list[dict]) -> None:
        """Update PTT with new findings"""
        if self.ptt and hasattr(self.ptt, 'add_findings'):
            self.ptt.add_findings(state.phase.value, findings)

    def _check_phase_transition(self, state: PentestState) -> Phase:
        """Check if we should move to next phase"""
        finding_types = [f.get("type") for f in state.findings]

        if state.phase == Phase.RECON:
            if "port" in finding_types or "service" in finding_types:
                if len([f for f in finding_types if f in ["port", "service"]]) >= 3:
                    return Phase.ENUM

        elif state.phase == Phase.ENUM:
            if "vuln" in finding_types:
                return Phase.EXPLOIT

        elif state.phase == Phase.EXPLOIT:
            if "credential" in finding_types or self._has_shell_access(state.findings):
                return Phase.POST

        elif state.phase == Phase.POST:
            if state.iteration > 10:
                return Phase.REPORT

        return state.phase

    def _has_shell_access(self, findings: list[dict]) -> bool:
        """Check if we've obtained shell access"""
        for f in findings:
            desc = f.get("description", "").lower()
            if any(kw in desc for kw in ["shell", "rce", "command execution", "reverse shell"]):
                return True
        return False
