"""
AIPT Execution Engine - Unified execution interface

Provides a unified interface for command execution with:
- Local terminal execution
- Docker sandbox execution
- Automatic mode selection
- Result parsing integration
"""
from __future__ import annotations

from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum
import asyncio

from .terminal import Terminal, ExecutionResult
from .parser import OutputParser, Finding


class ExecutionMode(str, Enum):
    """Execution mode"""
    LOCAL = "local"          # Direct local execution
    DOCKER = "docker"        # Docker sandbox
    AUTO = "auto"            # Auto-select based on tool/risk


@dataclass
class ExecutionConfig:
    """Configuration for execution engine"""
    mode: ExecutionMode = ExecutionMode.AUTO
    default_timeout: int = 300
    max_output: int = 50000
    parse_output: bool = True
    sandbox_image: str = "kalilinux/kali-rolling"


class ExecutionEngine:
    """
    Unified execution engine for AIPT.

    Provides a single interface for:
    - Local command execution
    - Docker sandbox execution
    - Output parsing
    - Result handling

    Example:
        engine = ExecutionEngine()

        # Execute locally
        result = engine.execute("nmap -F target.com")

        # Execute in Docker
        result = engine.execute("nmap -F target.com", mode=ExecutionMode.DOCKER)

        # Auto-select mode based on risk
        result = engine.execute("sqlmap -u http://target.com/page?id=1")
    """

    # Tools that should run in sandbox by default
    SANDBOX_TOOLS = {
        "metasploit", "msfconsole", "msfvenom",
        "sqlmap", "hydra", "john", "hashcat",
        "exploitdb", "searchsploit",
    }

    # Tools safe to run locally
    LOCAL_TOOLS = {
        "nmap", "masscan", "ping", "whois", "dig", "host",
        "curl", "wget", "httpx", "nuclei", "nikto",
        "gobuster", "ffuf", "dirb", "subfinder",
    }

    def __init__(
        self,
        config: Optional[ExecutionConfig] = None,
        terminal: Optional[Terminal] = None,
        parser: Optional[OutputParser] = None,
    ):
        self.config = config or ExecutionConfig()
        self.terminal = terminal or Terminal(
            default_timeout=self.config.default_timeout,
            max_output=self.config.max_output,
        )
        self.parser = parser or OutputParser()
        self._sandbox = None

    @property
    def sandbox(self):
        """Lazy-load Docker sandbox"""
        if self._sandbox is None:
            try:
                from ..docker import DockerSandbox, SandboxConfig
                self._sandbox = DockerSandbox(
                    SandboxConfig(image=self.config.sandbox_image)
                )
            except ImportError:
                self._sandbox = False  # Mark as unavailable
        return self._sandbox if self._sandbox is not False else None

    def execute(
        self,
        command: str,
        mode: Optional[ExecutionMode] = None,
        timeout: Optional[int] = None,
        tool_name: Optional[str] = None,
        parse: Optional[bool] = None,
        callback: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute a command with automatic mode selection.

        Args:
            command: Command to execute
            mode: Execution mode (local, docker, auto)
            timeout: Command timeout
            tool_name: Name of the tool (for parsing)
            parse: Whether to parse output
            callback: Streaming callback function
            **kwargs: Additional execution options

        Returns:
            Dict with:
                - result: ExecutionResult
                - findings: List[Finding] (if parse=True)
                - mode: ExecutionMode used
        """
        mode = mode or self.config.mode
        timeout = timeout or self.config.default_timeout
        parse = parse if parse is not None else self.config.parse_output

        # Auto-select mode
        if mode == ExecutionMode.AUTO:
            mode = self._select_mode(command, tool_name)

        # Execute
        if mode == ExecutionMode.DOCKER:
            result = self._execute_docker(command, timeout, callback, **kwargs)
        else:
            result = self._execute_local(command, timeout, callback, **kwargs)

        # Parse output
        findings = []
        if parse and result.output:
            detected_tool = tool_name or self._detect_tool(command)
            findings = self.parser.parse(result.output, detected_tool)

        return {
            "result": result,
            "findings": findings,
            "mode": mode,
            "tool": tool_name or self._detect_tool(command),
        }

    async def execute_async(
        self,
        command: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Async version of execute"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.execute(command, **kwargs)
        )

    def execute_batch(
        self,
        commands: List[str],
        parallel: bool = False,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Execute multiple commands.

        Args:
            commands: List of commands
            parallel: Execute in parallel (async)
            **kwargs: Execution options

        Returns:
            List of execution results
        """
        if parallel:
            return asyncio.run(self._execute_batch_async(commands, **kwargs))

        return [self.execute(cmd, **kwargs) for cmd in commands]

    async def _execute_batch_async(
        self,
        commands: List[str],
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Execute commands in parallel"""
        tasks = [self.execute_async(cmd, **kwargs) for cmd in commands]
        return await asyncio.gather(*tasks)

    def _execute_local(
        self,
        command: str,
        timeout: int,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> ExecutionResult:
        """Execute command locally"""
        if callback:
            return self.terminal.execute_streaming(command, callback, timeout)
        return self.terminal.execute(command, timeout, **kwargs)

    def _execute_docker(
        self,
        command: str,
        timeout: int,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> ExecutionResult:
        """Execute command in Docker sandbox"""
        if not self.sandbox:
            # Fallback to local if Docker unavailable
            return self._execute_local(command, timeout, callback, **kwargs)

        if callback:
            result = self.sandbox.execute_streaming(command, callback, timeout)
        else:
            result = self.sandbox.execute(command, timeout)

        # Convert SandboxResult to ExecutionResult
        return ExecutionResult(
            command=command,
            output=result.output,
            error=result.error,
            return_code=result.return_code,
            timed_out=result.error and "timed out" in result.error.lower() if result.error else False,
            duration=result.duration,
        )

    def _select_mode(self, command: str, tool_name: Optional[str] = None) -> ExecutionMode:
        """Auto-select execution mode based on command/tool"""
        tool = tool_name or self._detect_tool(command)

        if tool in self.SANDBOX_TOOLS:
            return ExecutionMode.DOCKER if self.sandbox else ExecutionMode.LOCAL

        if tool in self.LOCAL_TOOLS:
            return ExecutionMode.LOCAL

        # Check for dangerous patterns
        dangerous_patterns = [
            "rm -rf", "mkfs", "dd if=", "> /dev/",
            "chmod 777", "wget -O - | sh", "curl | bash",
        ]
        for pattern in dangerous_patterns:
            if pattern in command:
                return ExecutionMode.DOCKER if self.sandbox else ExecutionMode.LOCAL

        return ExecutionMode.LOCAL

    def _detect_tool(self, command: str) -> str:
        """Detect tool name from command"""
        parts = command.strip().split()
        if not parts:
            return "unknown"

        tool = parts[0]

        # Handle sudo, env, etc.
        if tool in ["sudo", "env", "time", "timeout"]:
            if len(parts) > 1:
                tool = parts[1]

        # Handle full paths
        if "/" in tool:
            tool = tool.split("/")[-1]

        return tool

    def check_tool(self, tool_name: str) -> Dict[str, Any]:
        """Check if a tool is available"""
        available = self.terminal.check_tool_available(tool_name)
        version = self.terminal.get_tool_version(tool_name) if available else None

        return {
            "tool": tool_name,
            "available": available,
            "version": version,
            "recommended_mode": (
                ExecutionMode.DOCKER if tool_name in self.SANDBOX_TOOLS
                else ExecutionMode.LOCAL
            ),
        }

    def check_tools(self, tools: List[str]) -> Dict[str, Dict[str, Any]]:
        """Check availability of multiple tools"""
        return {tool: self.check_tool(tool) for tool in tools}


# Factory function
def get_execution_engine(**kwargs) -> ExecutionEngine:
    """Create and return execution engine"""
    return ExecutionEngine(**kwargs)
