"""
AIPTX Local Runner - Execute tools via local subprocess

This runner executes security tools on the local machine using asyncio
subprocess. It handles:
- Process spawning and monitoring
- Timeout enforcement
- Output capture and parsing
- Tool availability checking
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .base import BaseRunner, RunnerConfig, RunnerResult, RunnerStatus

logger = logging.getLogger(__name__)


class LocalRunner(BaseRunner):
    """
    Execute tools locally via subprocess.

    This is the most common runner, used for tools installed on the
    local machine (nuclei, ffuf, sslscan, etc.).
    """

    def __init__(self, config: Optional[RunnerConfig] = None):
        super().__init__(config)
        self.runner_type = "local"

        # Cache for tool availability checks
        self._tool_cache: dict[str, bool] = {}

    async def execute(
        self,
        tool: str,
        args: list[str],
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """
        Execute a tool locally via subprocess.

        Args:
            tool: Name of the tool (e.g., "nuclei", "ffuf")
            args: Command line arguments
            timeout: Timeout in seconds (uses config default if not specified)
            **kwargs: Additional options:
                - parse_output: bool - Attempt to parse findings from output
                - output_file: Path - File where tool writes results
                - json_output: bool - Expect JSON output

        Returns:
            RunnerResult with execution details
        """
        # Check tool availability
        if not await self.check_tool_available(tool):
            return self._create_result(
                tool=tool,
                status=RunnerStatus.UNAVAILABLE,
                error_message=f"Tool '{tool}' is not installed or not in PATH",
            )

        # Determine timeout
        effective_timeout = timeout or self.config.default_timeout
        effective_timeout = min(effective_timeout, self.config.max_timeout)

        started_at = datetime.utcnow()

        try:
            # Build command
            cmd = [tool] + args

            # Prepare environment
            env = os.environ.copy()
            env.update(self.config.env_vars)

            # Create process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE if self.config.capture_stdout else None,
                stderr=asyncio.subprocess.PIPE if self.config.capture_stderr else None,
                env=env,
                cwd=str(self.config.working_dir) if self.config.working_dir else None,
            )

            # Wait with timeout
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=effective_timeout,
                )
                stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
                stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
                exit_code = process.returncode

            except asyncio.TimeoutError:
                # Kill the process
                process.kill()
                await process.wait()

                completed_at = datetime.utcnow()
                return self._create_result(
                    tool=tool,
                    status=RunnerStatus.TIMEOUT,
                    error_message=f"Tool timed out after {effective_timeout}s",
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=(completed_at - started_at).total_seconds(),
                )

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            # Parse findings if requested
            findings = []
            if kwargs.get("parse_output", True):
                findings = self._parse_output(
                    tool=tool,
                    stdout=stdout,
                    stderr=stderr,
                    output_file=kwargs.get("output_file"),
                    json_output=kwargs.get("json_output", False),
                )

            # Determine status
            if exit_code == 0:
                status = RunnerStatus.COMPLETED
            else:
                # Some tools return non-zero for "no findings" which is actually success
                if self._is_acceptable_exit_code(tool, exit_code):
                    status = RunnerStatus.COMPLETED
                else:
                    status = RunnerStatus.FAILED

            return self._create_result(
                tool=tool,
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                findings=findings,
                findings_count=len(findings),
                error_message=stderr if status == RunnerStatus.FAILED else None,
            )

        except FileNotFoundError:
            return self._create_result(
                tool=tool,
                status=RunnerStatus.UNAVAILABLE,
                error_message=f"Tool '{tool}' not found in PATH",
            )

        except PermissionError:
            return self._create_result(
                tool=tool,
                status=RunnerStatus.FAILED,
                error_message=f"Permission denied executing '{tool}'",
            )

        except Exception as e:
            logger.exception(f"Unexpected error executing {tool}")
            return self._create_result(
                tool=tool,
                status=RunnerStatus.FAILED,
                error_message=str(e),
            )

    async def get_status(self) -> dict[str, Any]:
        """Get local runner status"""
        # Check commonly used tools
        common_tools = [
            "nuclei",
            "ffuf",
            "nmap",
            "sslscan",
            "testssl.sh",
            "sqlmap",
            "nikto",
            "subfinder",
            "httpx",
        ]

        available_tools = []
        for tool in common_tools:
            if await self.check_tool_available(tool):
                available_tools.append(tool)

        return {
            "healthy": True,
            "runner_type": self.runner_type,
            "available_tools": available_tools,
            "tool_count": len(available_tools),
            "config": {
                "default_timeout": self.config.default_timeout,
                "max_timeout": self.config.max_timeout,
                "max_retries": self.config.max_retries,
            },
        }

    async def check_tool_available(self, tool: str) -> bool:
        """Check if tool is available locally"""
        # Check cache first
        if tool in self._tool_cache:
            return self._tool_cache[tool]

        # Use shutil.which for quick check
        available = shutil.which(tool) is not None

        # Cache the result
        self._tool_cache[tool] = available

        return available

    def _parse_output(
        self,
        tool: str,
        stdout: str,
        stderr: str,
        output_file: Optional[Path] = None,
        json_output: bool = False,
    ) -> list[dict[str, Any]]:
        """Parse tool output to extract findings"""
        findings = []

        # Try to parse JSON output first
        if json_output or output_file:
            content = ""
            if output_file and output_file.exists():
                try:
                    content = output_file.read_text()
                except Exception as e:
                    logger.warning(f"Failed to read output file: {e}")
            elif json_output:
                content = stdout

            if content:
                findings = self._parse_json_output(tool, content)
                if findings:
                    return findings

        # Fall back to tool-specific parsing
        parser = self._get_parser(tool)
        if parser:
            findings = parser(stdout, stderr)

        return findings

    def _parse_json_output(
        self,
        tool: str,
        content: str,
    ) -> list[dict[str, Any]]:
        """Parse JSON output from tools"""
        findings = []

        # Handle JSONL format (one JSON object per line)
        for line in content.strip().split("\n"):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    obj["source"] = tool
                    findings.append(obj)
                elif isinstance(obj, list):
                    for item in obj:
                        if isinstance(item, dict):
                            item["source"] = tool
                            findings.append(item)
            except json.JSONDecodeError:
                continue

        # If JSONL failed, try parsing as single JSON
        if not findings and content.strip():
            try:
                obj = json.loads(content)
                if isinstance(obj, list):
                    for item in obj:
                        if isinstance(item, dict):
                            item["source"] = tool
                            findings.append(item)
                elif isinstance(obj, dict):
                    # Handle wrapper objects
                    if "findings" in obj:
                        for item in obj["findings"]:
                            item["source"] = tool
                            findings.append(item)
                    elif "vulnerabilities" in obj:
                        for item in obj["vulnerabilities"]:
                            item["source"] = tool
                            findings.append(item)
                    else:
                        obj["source"] = tool
                        findings.append(obj)
            except json.JSONDecodeError:
                pass

        return findings

    def _get_parser(self, tool: str) -> Optional[callable]:
        """Get tool-specific output parser"""
        parsers = {
            "nuclei": self._parse_nuclei,
            "ffuf": self._parse_ffuf,
            # Add more parsers as needed
        }
        return parsers.get(tool.lower())

    def _parse_nuclei(
        self,
        stdout: str,
        stderr: str,
    ) -> list[dict[str, Any]]:
        """Parse nuclei text output"""
        findings = []
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("[INF]"):
                continue

            # Nuclei output format: [severity] [template-id] [protocol] matched-url
            parts = line.split()
            if len(parts) >= 3:
                findings.append(
                    {
                        "source": "nuclei",
                        "raw": line,
                    }
                )

        return findings

    def _parse_ffuf(
        self,
        stdout: str,
        stderr: str,
    ) -> list[dict[str, Any]]:
        """Parse ffuf text output"""
        findings = []
        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            # ffuf output has status codes and response info
            if "[Status:" in line:
                findings.append(
                    {
                        "source": "ffuf",
                        "raw": line,
                    }
                )

        return findings

    def _is_acceptable_exit_code(self, tool: str, exit_code: int) -> bool:
        """Check if exit code is acceptable for specific tools"""
        # Some tools return 1 when no findings (which is success)
        acceptable_codes = {
            "grep": [0, 1],  # 1 = no matches
            "ffuf": [0, 1],  # 1 = no results
            "nuclei": [0, 1],  # 1 = no matches
        }
        return exit_code in acceptable_codes.get(tool.lower(), [0])
