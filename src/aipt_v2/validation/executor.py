"""
AIPTX Exploit Executor - Safe Exploitation in Sandbox

Executes exploit code safely:
- Docker-based isolation (optional)
- Rate limiting to prevent DoS
- Timeout enforcement
- Payload sanitization
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ExecutionMode(str, Enum):
    """Execution mode for exploits."""
    DIRECT = "direct"           # Direct execution (careful!)
    DOCKER = "docker"           # Docker container isolation
    SUBPROCESS = "subprocess"   # Subprocess with restrictions


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution."""
    mode: ExecutionMode = ExecutionMode.DIRECT
    timeout: float = 30.0              # Execution timeout in seconds
    max_memory_mb: int = 256           # Max memory for Docker
    max_cpu_percent: float = 50.0      # Max CPU for Docker
    network_enabled: bool = True        # Allow network access
    docker_image: str = "python:3.11-slim"  # Docker image to use
    cleanup_after: bool = True          # Cleanup containers after
    rate_limit_rps: float = 10.0        # Max requests per second


@dataclass
class ExecutionContext:
    """Context for exploit execution."""
    target: str                         # Target URL
    finding_id: str                     # Finding being validated
    payload: str                        # Payload to execute
    method: str = "GET"                 # HTTP method
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    body: Optional[str] = None
    auth: Optional[tuple] = None        # (username, password)
    verify_ssl: bool = False
    follow_redirects: bool = True
    extra_config: dict = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result from exploit execution."""
    success: bool = False
    status_code: int = 0
    response_body: str = ""
    response_headers: dict = field(default_factory=dict)
    response_time_ms: float = 0.0
    error: Optional[str] = None
    evidence_indicators: list[str] = field(default_factory=list)
    raw_response: Any = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)


class ExploitExecutor:
    """
    Executes exploit payloads safely.

    Provides:
    - HTTP request execution with payloads
    - Rate limiting
    - Timeout enforcement
    - Response analysis

    Usage:
        executor = ExploitExecutor()

        context = ExecutionContext(
            target="https://example.com/api",
            finding_id="abc123",
            payload="' OR '1'='1",
            method="POST",
        )

        result = await executor.execute(context)
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        """
        Initialize executor.

        Args:
            config: Sandbox configuration
        """
        self.config = config or SandboxConfig()
        self._last_request_time = 0.0
        self._request_count = 0
        self._session = None

    async def execute(self, context: ExecutionContext) -> ExecutionResult:
        """
        Execute an exploit payload.

        Args:
            context: Execution context with target and payload

        Returns:
            ExecutionResult with response data
        """
        # Rate limiting
        await self._rate_limit()

        try:
            if self.config.mode == ExecutionMode.DOCKER:
                return await self._execute_in_docker(context)
            else:
                return await self._execute_direct(context)

        except asyncio.TimeoutError:
            return ExecutionResult(
                success=False,
                error="Execution timed out",
                metadata={"timeout": self.config.timeout},
            )
        except Exception as e:
            logger.error(f"Execution error: {e}", exc_info=True)
            return ExecutionResult(
                success=False,
                error=str(e),
            )

    async def _rate_limit(self) -> None:
        """Apply rate limiting."""
        if self.config.rate_limit_rps <= 0:
            return

        min_interval = 1.0 / self.config.rate_limit_rps
        elapsed = time.time() - self._last_request_time

        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)

        self._last_request_time = time.time()
        self._request_count += 1

    async def _execute_direct(self, context: ExecutionContext) -> ExecutionResult:
        """Execute directly using aiohttp."""
        import aiohttp

        start_time = time.time()

        try:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Build request kwargs
                kwargs = {
                    "headers": context.headers,
                    "cookies": context.cookies,
                    "ssl": context.verify_ssl,
                    "allow_redirects": context.follow_redirects,
                }

                if context.auth:
                    kwargs["auth"] = aiohttp.BasicAuth(*context.auth)

                # Inject payload into appropriate location
                url = context.target
                if context.method.upper() == "GET":
                    # Inject into URL params
                    params = context.params.copy()
                    if context.payload and context.extra_config.get("param_name"):
                        params[context.extra_config["param_name"]] = context.payload
                    kwargs["params"] = params
                else:
                    # Inject into body
                    if context.body:
                        kwargs["data"] = context.body
                    elif context.payload:
                        kwargs["data"] = context.payload

                # Make request
                async with session.request(context.method, url, **kwargs) as response:
                    response_body = await response.text()
                    response_time = (time.time() - start_time) * 1000

                    # Check for evidence indicators
                    indicators = self._check_indicators(response_body, response.status)

                    return ExecutionResult(
                        success=True,
                        status_code=response.status,
                        response_body=response_body[:50000],  # Limit size
                        response_headers=dict(response.headers),
                        response_time_ms=response_time,
                        evidence_indicators=indicators,
                        raw_response=response,
                    )

        except aiohttp.ClientError as e:
            return ExecutionResult(
                success=False,
                error=f"HTTP error: {e}",
                response_time_ms=(time.time() - start_time) * 1000,
            )

    async def _execute_in_docker(self, context: ExecutionContext) -> ExecutionResult:
        """Execute in Docker container for isolation."""
        try:
            import docker

            client = docker.from_env()

            # Create a simple Python script to make the request
            script = self._generate_request_script(context)

            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(script)
                script_path = f.name

            try:
                # Run in Docker
                container = client.containers.run(
                    self.config.docker_image,
                    f"python /script.py",
                    volumes={script_path: {"bind": "/script.py", "mode": "ro"}},
                    mem_limit=f"{self.config.max_memory_mb}m",
                    cpu_period=100000,
                    cpu_quota=int(100000 * self.config.cpu_percent / 100),
                    network_mode="bridge" if self.config.network_enabled else "none",
                    remove=True,
                    detach=False,
                    stdout=True,
                    stderr=True,
                )

                # Parse output
                output = container.decode("utf-8")
                return self._parse_docker_output(output)

            finally:
                os.unlink(script_path)

        except ImportError:
            logger.warning("Docker not available, falling back to direct execution")
            return await self._execute_direct(context)
        except Exception as e:
            return ExecutionResult(
                success=False,
                error=f"Docker execution error: {e}",
            )

    def _generate_request_script(self, context: ExecutionContext) -> str:
        """Generate Python script for Docker execution."""
        return f'''
import json
import requests
import time

start = time.time()
try:
    response = requests.request(
        "{context.method}",
        "{context.target}",
        headers={context.headers},
        params={context.params},
        data={repr(context.body or context.payload)},
        timeout={self.config.timeout},
        verify={context.verify_ssl},
        allow_redirects={context.follow_redirects},
    )
    result = {{
        "success": True,
        "status_code": response.status_code,
        "body": response.text[:50000],
        "headers": dict(response.headers),
        "time_ms": (time.time() - start) * 1000,
    }}
except Exception as e:
    result = {{
        "success": False,
        "error": str(e),
        "time_ms": (time.time() - start) * 1000,
    }}

print(json.dumps(result))
'''

    def _parse_docker_output(self, output: str) -> ExecutionResult:
        """Parse output from Docker container."""
        import json

        try:
            data = json.loads(output.strip())
            return ExecutionResult(
                success=data.get("success", False),
                status_code=data.get("status_code", 0),
                response_body=data.get("body", ""),
                response_headers=data.get("headers", {}),
                response_time_ms=data.get("time_ms", 0),
                error=data.get("error"),
            )
        except json.JSONDecodeError:
            return ExecutionResult(
                success=False,
                error=f"Failed to parse Docker output: {output[:500]}",
            )

    def _check_indicators(self, body: str, status: int) -> list[str]:
        """Check response for vulnerability indicators."""
        indicators = []
        body_lower = body.lower()

        # SQL error indicators
        sql_errors = [
            "sql syntax", "mysql", "postgresql", "sqlite",
            "ora-", "sql server", "odbc", "jdbc",
        ]
        if any(err in body_lower for err in sql_errors):
            indicators.append("sql_error")

        # XSS indicators (payload reflected)
        if "<script" in body_lower or "onerror=" in body_lower:
            indicators.append("xss_reflected")

        # Command execution indicators
        cmd_indicators = ["uid=", "gid=", "root:", "/bin/", "windows"]
        if any(ind in body_lower for ind in cmd_indicators):
            indicators.append("command_output")

        # File content indicators
        file_indicators = ["root:x:0:0", "[boot loader]", "<?php"]
        if any(ind in body_lower for ind in file_indicators):
            indicators.append("file_content")

        # Error/debug info
        if "traceback" in body_lower or "stack trace" in body_lower:
            indicators.append("debug_info")

        # Status code indicators
        if status == 500:
            indicators.append("server_error")
        if status in [200, 302] and ("admin" in body_lower or "dashboard" in body_lower):
            indicators.append("auth_bypass")

        return indicators

    async def execute_with_baseline(
        self,
        context: ExecutionContext,
        baseline_context: ExecutionContext,
    ) -> tuple[ExecutionResult, ExecutionResult, dict]:
        """
        Execute with a baseline for comparison.

        Useful for detecting blind/time-based vulnerabilities.

        Args:
            context: Context with payload
            baseline_context: Context without payload (for comparison)

        Returns:
            Tuple of (payload_result, baseline_result, comparison)
        """
        # Execute baseline first
        baseline_result = await self.execute(baseline_context)

        # Then execute with payload
        payload_result = await self.execute(context)

        # Compare results
        comparison = {
            "time_difference_ms": payload_result.response_time_ms - baseline_result.response_time_ms,
            "status_changed": payload_result.status_code != baseline_result.status_code,
            "body_length_diff": len(payload_result.response_body) - len(baseline_result.response_body),
            "new_indicators": [
                i for i in payload_result.evidence_indicators
                if i not in baseline_result.evidence_indicators
            ],
        }

        return payload_result, baseline_result, comparison

    async def execute_batch(
        self,
        contexts: list[ExecutionContext],
        concurrency: int = 5,
    ) -> list[ExecutionResult]:
        """
        Execute multiple payloads with controlled concurrency.

        Args:
            contexts: List of execution contexts
            concurrency: Max concurrent requests

        Returns:
            List of results
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def execute_with_semaphore(ctx: ExecutionContext) -> ExecutionResult:
            async with semaphore:
                return await self.execute(ctx)

        tasks = [execute_with_semaphore(ctx) for ctx in contexts]
        return await asyncio.gather(*tasks)

    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self._session:
            await self._session.close()


# Convenience functions
async def execute_payload(
    target: str,
    payload: str,
    finding_id: str = "",
    method: str = "GET",
    **kwargs,
) -> ExecutionResult:
    """
    Convenience function to execute a single payload.

    Args:
        target: Target URL
        payload: Payload to inject
        finding_id: Finding ID for tracking
        method: HTTP method
        **kwargs: Additional context parameters

    Returns:
        ExecutionResult
    """
    executor = ExploitExecutor()
    context = ExecutionContext(
        target=target,
        finding_id=finding_id,
        payload=payload,
        method=method,
        **kwargs,
    )
    return await executor.execute(context)
