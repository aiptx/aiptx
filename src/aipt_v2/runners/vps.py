"""
AIPTX VPS Runner - Execute tools on remote VPS via SSH

This runner executes security tools on a remote VPS server,
useful for:
- Running tools that need a different source IP
- Distributed scanning from multiple locations
- Using tools not available locally
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .base import BaseRunner, RunnerConfig, RunnerResult, RunnerStatus

logger = logging.getLogger(__name__)


class VPSRunner(BaseRunner):
    """
    Execute tools on remote VPS via SSH.

    Connects to a remote server and executes tools there,
    capturing output and returning results.
    """

    def __init__(
        self,
        host: str,
        username: str = "root",
        port: int = 22,
        key_file: Optional[Path] = None,
        password: Optional[str] = None,
        config: Optional[RunnerConfig] = None,
    ):
        super().__init__(config)
        self.runner_type = "vps"
        self.host = host
        self.username = username
        self.port = port
        self.key_file = key_file
        self.password = password

        # Connection state
        self._connection = None
        self._connected = False

    async def connect(self) -> bool:
        """Establish SSH connection to VPS"""
        try:
            import asyncssh

            if self.key_file:
                self._connection = await asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    client_keys=[str(self.key_file)],
                    known_hosts=None,
                )
            else:
                self._connection = await asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    known_hosts=None,
                )

            self._connected = True
            logger.info(f"Connected to VPS {self.host}")
            return True

        except ImportError:
            logger.error("asyncssh not installed. Install with: pip install asyncssh")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to VPS {self.host}: {e}")
            return False

    async def disconnect(self):
        """Close SSH connection"""
        if self._connection:
            self._connection.close()
            await self._connection.wait_closed()
            self._connected = False
            logger.info(f"Disconnected from VPS {self.host}")

    async def execute(
        self,
        tool: str,
        args: list[str],
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Execute tool on remote VPS via SSH"""
        # Ensure connected
        if not self._connected:
            if not await self.connect():
                return self._create_result(
                    tool=tool,
                    status=RunnerStatus.UNAVAILABLE,
                    error_message=f"Cannot connect to VPS {self.host}",
                )

        # Check tool availability on remote
        if not await self.check_tool_available(tool):
            return self._create_result(
                tool=tool,
                status=RunnerStatus.UNAVAILABLE,
                error_message=f"Tool '{tool}' not available on VPS {self.host}",
            )

        effective_timeout = timeout or self.config.default_timeout
        started_at = datetime.utcnow()

        try:
            # Build command
            cmd = f"{tool} " + " ".join(f'"{arg}"' if " " in arg else arg for arg in args)

            # Execute on remote
            result = await asyncio.wait_for(
                self._connection.run(cmd, check=False),
                timeout=effective_timeout,
            )

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            # Determine status
            if result.exit_status == 0:
                status = RunnerStatus.COMPLETED
            else:
                status = RunnerStatus.FAILED

            return self._create_result(
                tool=tool,
                status=status,
                exit_code=result.exit_status,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                error_message=result.stderr if status == RunnerStatus.FAILED else None,
                metadata={"vps_host": self.host},
            )

        except asyncio.TimeoutError:
            completed_at = datetime.utcnow()
            return self._create_result(
                tool=tool,
                status=RunnerStatus.TIMEOUT,
                error_message=f"Tool timed out after {effective_timeout}s on VPS",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=(completed_at - started_at).total_seconds(),
            )

        except Exception as e:
            logger.exception(f"Error executing {tool} on VPS")
            return self._create_result(
                tool=tool,
                status=RunnerStatus.FAILED,
                error_message=str(e),
            )

    async def get_status(self) -> dict[str, Any]:
        """Get VPS runner status"""
        return {
            "healthy": self._connected,
            "runner_type": self.runner_type,
            "host": self.host,
            "port": self.port,
            "connected": self._connected,
        }

    async def check_tool_available(self, tool: str) -> bool:
        """Check if tool is available on remote VPS"""
        if not self._connected:
            return False

        try:
            result = await self._connection.run(f"which {tool}", check=False)
            return result.exit_status == 0
        except Exception:
            return False

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
