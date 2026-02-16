"""
MCP Transport Layer - JSON-RPC over subprocess stdin/stdout.

Provides communication with MCP (Model Context Protocol) servers
via subprocess-based stdio transport.
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class MCPTransport:
    """Base class for MCP transports."""

    async def connect(self) -> None:
        """Establish connection to the MCP server."""
        raise NotImplementedError

    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        raise NotImplementedError

    async def send(self, message: Dict[str, Any], timeout: float = 30.0) -> Dict[str, Any]:
        """Send a message and wait for response."""
        raise NotImplementedError


class StdioTransport(MCPTransport):
    """
    JSON-RPC transport over subprocess stdin/stdout.

    Communicates with MCP servers by spawning them as subprocesses
    and exchanging JSON-RPC messages via stdin/stdout.
    """

    def __init__(
        self,
        command: str,
        args: list[str] = None,
        env: Dict[str, str] = None,
    ):
        """
        Initialize the stdio transport.

        Args:
            command: The command to execute (e.g., "npx", "python")
            args: Arguments to pass to the command
            env: Environment variables for the subprocess
        """
        self.command = command
        self.args = args or []
        self.env = env
        self._process: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._pending_requests: Dict[int, asyncio.Future] = {}
        self._message_id = 0
        self._connected = False

    async def connect(self) -> None:
        """Start the subprocess and establish communication."""
        if self._connected:
            return

        try:
            # Build full command
            cmd = [self.command] + self.args

            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.env,
            )

            # Start background reader for responses
            self._reader_task = asyncio.create_task(self._read_responses())
            self._connected = True

            logger.debug(f"MCP transport connected: {' '.join(cmd)}")

        except Exception as e:
            logger.error(f"Failed to start MCP server: {e}")
            raise

    async def disconnect(self) -> None:
        """Stop the subprocess and cleanup."""
        self._connected = False

        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
            except Exception as e:
                logger.warning(f"Error terminating MCP process: {e}")
            self._process = None

        # Cancel any pending requests
        for future in self._pending_requests.values():
            if not future.done():
                future.cancel()
        self._pending_requests.clear()

        logger.debug("MCP transport disconnected")

    async def send(self, message: Dict[str, Any], timeout: float = 30.0) -> Dict[str, Any]:
        """
        Send a JSON-RPC message and wait for response.

        Args:
            message: The JSON-RPC message to send
            timeout: Maximum time to wait for response (seconds)

        Returns:
            The JSON-RPC response
        """
        if not self._connected or not self._process:
            raise RuntimeError("Transport not connected")

        # Assign message ID if not present (for requests)
        msg_id = message.get("id")
        is_notification = msg_id is None and "method" in message

        if not is_notification and msg_id is None:
            self._message_id += 1
            msg_id = self._message_id
            message = {**message, "id": msg_id}

        # Serialize and send
        data = json.dumps(message, separators=(",", ":")) + "\n"

        try:
            self._process.stdin.write(data.encode("utf-8"))
            await self._process.stdin.drain()
        except Exception as e:
            logger.error(f"Failed to send MCP message: {e}")
            raise

        # Notifications don't expect responses
        if is_notification:
            return {}

        # Wait for response
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_requests[msg_id] = future

        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            return response
        except asyncio.TimeoutError:
            logger.error(f"MCP request timed out (id={msg_id})")
            self._pending_requests.pop(msg_id, None)
            raise
        except asyncio.CancelledError:
            self._pending_requests.pop(msg_id, None)
            raise

    async def _read_responses(self) -> None:
        """Background task to read responses from stdout."""
        while self._connected and self._process:
            try:
                line = await self._process.stdout.readline()
                if not line:
                    # Process exited
                    logger.warning("MCP server process exited unexpectedly")
                    break

                line = line.decode("utf-8").strip()
                if not line:
                    continue

                try:
                    response = json.loads(line)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON from MCP server: {e}")
                    continue

                # Route response to waiting request
                msg_id = response.get("id")
                if msg_id is not None and msg_id in self._pending_requests:
                    future = self._pending_requests.pop(msg_id)
                    if not future.done():
                        future.set_result(response)
                else:
                    # Notification or unmatched response
                    logger.debug(f"Unmatched MCP message: {response}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error reading MCP response: {e}")
                await asyncio.sleep(0.1)

    @property
    def is_connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected and self._process is not None
