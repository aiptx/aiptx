"""
AIPTX WebSocket Agent - WebSocket Security Testing

Tests WebSocket connections for:
- Message injection (SQL, NoSQL, Command)
- Authentication bypasses
- Message replay attacks
- Cross-site WebSocket hijacking
- Message interception
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from aipt_v2.agents.specialized.base_specialized import (
    SpecializedAgent,
    AgentCapability,
    AgentConfig,
)
from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    VulnerabilityType,
    Evidence,
)

logger = logging.getLogger(__name__)


class WebSocketAgent(SpecializedAgent):
    """
    WebSocket security testing agent.

    Tests for:
    - Injection in WebSocket messages
    - Missing authentication
    - Message tampering
    - Cross-site WebSocket hijacking (CSWSH)
    - Information disclosure
    """

    name = "WebSocketAgent"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ws_endpoints: list[str] = []
        self._intercepted_messages: list[dict] = []

    def get_capabilities(self) -> list[AgentCapability]:
        return [
            AgentCapability.WS_INTERCEPTION,
            AgentCapability.WS_FUZZING,
            AgentCapability.WS_INJECTION,
        ]

    async def run(self) -> dict[str, Any]:
        """Execute WebSocket security testing."""
        await self.initialize()
        self._progress.status = "running"

        results = {
            "endpoints_tested": 0,
            "messages_intercepted": 0,
            "findings_count": 0,
            "success": True,
        }

        try:
            # Phase 1: Discover WebSocket endpoints (15%)
            await self.update_progress("Discovering WebSocket endpoints", 0)
            endpoints = await self._discover_ws_endpoints()
            self._ws_endpoints = endpoints
            results["endpoints_tested"] = len(endpoints)

            if not endpoints:
                logger.info("No WebSocket endpoints found")
                return results

            # Phase 2: Intercept messages (30%)
            self.check_cancelled()
            await self.update_progress("Intercepting messages", 15)
            messages = await self._intercept_messages(endpoints)
            self._intercepted_messages = messages
            results["messages_intercepted"] = len(messages)

            # Phase 3: Test authentication (45%)
            self.check_cancelled()
            await self.update_progress("Testing authentication", 30)
            await self._test_ws_authentication(endpoints)

            # Phase 4: Test injection (60%)
            self.check_cancelled()
            await self.update_progress("Testing injection", 45)
            await self._test_ws_injection(endpoints, messages)

            # Phase 5: Test message replay (75%)
            self.check_cancelled()
            await self.update_progress("Testing message replay", 60)
            await self._test_message_replay(endpoints, messages)

            # Phase 6: Test CSWSH (90%)
            self.check_cancelled()
            await self.update_progress("Testing CSWSH", 75)
            await self._test_cswsh(endpoints)

            # Phase 7: Fuzz messages (100%)
            self.check_cancelled()
            await self.update_progress("Fuzzing messages", 90)
            await self._fuzz_messages(endpoints, messages)

            await self.update_progress("Complete", 100)
            results["findings_count"] = self._findings_count

        except asyncio.CancelledError:
            logger.info("WebSocketAgent cancelled")
            results["success"] = False
            results["error"] = "Cancelled"
        except Exception as e:
            logger.error(f"WebSocketAgent error: {e}", exc_info=True)
            results["success"] = False
            results["error"] = str(e)
        finally:
            await self.cleanup()

        return results

    async def _discover_ws_endpoints(self) -> list[str]:
        """Discover WebSocket endpoints."""
        endpoints = []

        # Common WebSocket paths
        common_ws_paths = [
            "/ws",
            "/websocket",
            "/socket",
            "/realtime",
            "/live",
            "/stream",
            "/chat",
            "/notifications",
            "/api/ws",
            "/api/websocket",
        ]

        # Convert target URL to WebSocket URL
        parsed = urlparse(self.target)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        base_ws_url = f"{ws_scheme}://{parsed.netloc}"

        # Try to find endpoints from page content
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(self.target, timeout=10) as resp:
                    html = await resp.text()

                    # Look for WebSocket URLs in the page
                    import re
                    ws_pattern = r'["\']wss?://[^"\']+["\']'
                    for match in re.finditer(ws_pattern, html):
                        url = match.group().strip('"\'')
                        if url not in endpoints:
                            endpoints.append(url)

                    # Look for Socket.IO
                    if "socket.io" in html.lower():
                        endpoints.append(f"{base_ws_url}/socket.io/?EIO=4&transport=websocket")

        except Exception as e:
            logger.warning(f"Error discovering WS from HTML: {e}")

        # Test common paths
        for path in common_ws_paths:
            ws_url = f"{base_ws_url}{path}"
            if await self._test_ws_endpoint(ws_url):
                if ws_url not in endpoints:
                    endpoints.append(ws_url)

        return endpoints

    async def _test_ws_endpoint(self, url: str) -> bool:
        """Test if a WebSocket endpoint exists."""
        try:
            import websockets

            async with websockets.connect(url, close_timeout=5) as ws:
                return True
        except Exception:
            return False

    async def _intercept_messages(self, endpoints: list[str]) -> list[dict]:
        """Intercept WebSocket messages."""
        messages = []

        try:
            import websockets

            for endpoint in endpoints:
                self.check_cancelled()

                try:
                    async with websockets.connect(endpoint, close_timeout=10) as ws:
                        # Wait for messages for a few seconds
                        try:
                            async for message in asyncio.wait_for(
                                self._receive_messages(ws), timeout=10
                            ):
                                messages.append({
                                    "endpoint": endpoint,
                                    "direction": "recv",
                                    "data": message,
                                })
                        except asyncio.TimeoutError:
                            pass

                except Exception as e:
                    logger.debug(f"Error intercepting from {endpoint}: {e}")

        except ImportError:
            logger.warning("websockets library not installed")

        return messages

    async def _receive_messages(self, ws):
        """Receive messages from WebSocket."""
        while True:
            try:
                message = await ws.recv()
                yield message
            except Exception:
                break

    async def _test_ws_authentication(self, endpoints: list[str]) -> None:
        """Test WebSocket authentication."""
        try:
            import websockets

            for endpoint in endpoints:
                self.check_cancelled()

                try:
                    # Try to connect without authentication
                    async with websockets.connect(
                        endpoint,
                        close_timeout=5,
                        extra_headers={}  # No auth headers
                    ) as ws:
                        # If we can connect and send/receive, auth might be missing
                        await ws.send('{"type": "ping"}')

                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=5)

                            # Check if we got a valid response
                            if response and "error" not in response.lower():
                                finding = Finding(
                                    vuln_type=VulnerabilityType.BROKEN_AUTH,
                                    title="WebSocket lacks authentication",
                                    description="WebSocket accepts connections without authentication",
                                    severity=FindingSeverity.HIGH,
                                    target=self.target,
                                    url=endpoint,
                                    evidence=Evidence(
                                        request='{"type": "ping"}',
                                        response=response[:500] if response else None,
                                    ),
                                    tags=["websocket", "auth"],
                                )
                                await self.add_finding(finding)

                        except asyncio.TimeoutError:
                            pass

                except Exception as e:
                    logger.debug(f"Auth test error for {endpoint}: {e}")

        except ImportError:
            pass

    async def _test_ws_injection(
        self,
        endpoints: list[str],
        messages: list[dict],
    ) -> None:
        """Test for injection in WebSocket messages."""
        injection_payloads = {
            "sqli": [
                "' OR '1'='1",
                "1; DROP TABLE users--",
                "admin'--",
            ],
            "nosql": [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$where": "1==1"}',
            ],
            "command": [
                "; ls -la",
                "| cat /etc/passwd",
                "`id`",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
            ],
        }

        try:
            import websockets

            for endpoint in endpoints:
                self.check_cancelled()

                # Get message templates from intercepted messages
                templates = [m for m in messages if m["endpoint"] == endpoint]

                try:
                    async with websockets.connect(endpoint, close_timeout=10) as ws:
                        for injection_type, payloads in injection_payloads.items():
                            for payload in payloads:
                                # Try raw payload
                                await ws.send(payload)

                                try:
                                    response = await asyncio.wait_for(ws.recv(), timeout=3)

                                    # Check for error responses that indicate injection
                                    error_indicators = [
                                        "syntax", "error", "exception",
                                        "mysql", "postgres", "mongo",
                                        "command", "shell"
                                    ]

                                    if any(ind in response.lower() for ind in error_indicators):
                                        finding = Finding(
                                            vuln_type=self._map_injection_type(injection_type),
                                            title=f"WebSocket {injection_type.upper()} injection",
                                            description=f"Error response indicates potential {injection_type} injection",
                                            severity=FindingSeverity.HIGH,
                                            target=self.target,
                                            url=endpoint,
                                            payload=payload,
                                            evidence=Evidence(
                                                request=payload,
                                                response=response[:500],
                                            ),
                                            tags=["websocket", injection_type],
                                        )
                                        await self.add_finding(finding)

                                except asyncio.TimeoutError:
                                    pass

                                # Try in JSON message if we have templates
                                for template in templates[:3]:
                                    if isinstance(template.get("data"), str):
                                        try:
                                            data = json.loads(template["data"])
                                            # Inject into string fields
                                            modified = self._inject_into_json(data, payload)
                                            await ws.send(json.dumps(modified))

                                            try:
                                                response = await asyncio.wait_for(
                                                    ws.recv(), timeout=3
                                                )
                                                if any(ind in response.lower()
                                                       for ind in error_indicators):
                                                    finding = Finding(
                                                        vuln_type=self._map_injection_type(injection_type),
                                                        title=f"WebSocket JSON {injection_type} injection",
                                                        description="Injection in JSON message parameter",
                                                        severity=FindingSeverity.HIGH,
                                                        target=self.target,
                                                        url=endpoint,
                                                        payload=json.dumps(modified),
                                                        evidence=Evidence(response=response[:500]),
                                                        tags=["websocket", injection_type, "json"],
                                                    )
                                                    await self.add_finding(finding)
                                            except asyncio.TimeoutError:
                                                pass
                                        except json.JSONDecodeError:
                                            pass

                except Exception as e:
                    logger.debug(f"Injection test error for {endpoint}: {e}")

        except ImportError:
            pass

    def _inject_into_json(self, data: Any, payload: str) -> Any:
        """Inject payload into JSON structure."""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if isinstance(value, str):
                    result[key] = payload
                else:
                    result[key] = self._inject_into_json(value, payload)
            return result
        elif isinstance(data, list):
            return [self._inject_into_json(item, payload) for item in data]
        elif isinstance(data, str):
            return payload
        return data

    def _map_injection_type(self, injection_type: str) -> VulnerabilityType:
        """Map injection type to vulnerability type."""
        mapping = {
            "sqli": VulnerabilityType.SQLI,
            "nosql": VulnerabilityType.NOSQL_INJECTION,
            "command": VulnerabilityType.COMMAND_INJECTION,
            "xss": VulnerabilityType.XSS,
        }
        return mapping.get(injection_type, VulnerabilityType.WEBSOCKET)

    async def _test_message_replay(
        self,
        endpoints: list[str],
        messages: list[dict],
    ) -> None:
        """Test for message replay vulnerabilities."""
        try:
            import websockets

            for endpoint in endpoints:
                self.check_cancelled()

                endpoint_messages = [m for m in messages if m["endpoint"] == endpoint]

                if not endpoint_messages:
                    continue

                try:
                    async with websockets.connect(endpoint, close_timeout=10) as ws:
                        for msg in endpoint_messages[:5]:
                            # Replay the message
                            await ws.send(msg["data"])

                            try:
                                response = await asyncio.wait_for(ws.recv(), timeout=3)

                                # Check if replay was accepted
                                if "success" in response.lower() or "accepted" in response.lower():
                                    finding = Finding(
                                        vuln_type=VulnerabilityType.WEBSOCKET,
                                        title="WebSocket message replay accepted",
                                        description="Server accepts replayed messages without validation",
                                        severity=FindingSeverity.MEDIUM,
                                        target=self.target,
                                        url=endpoint,
                                        evidence=Evidence(
                                            request=str(msg["data"])[:500],
                                            response=response[:500],
                                        ),
                                        tags=["websocket", "replay"],
                                    )
                                    await self.add_finding(finding)
                                    break

                            except asyncio.TimeoutError:
                                pass

                except Exception as e:
                    logger.debug(f"Replay test error for {endpoint}: {e}")

        except ImportError:
            pass

    async def _test_cswsh(self, endpoints: list[str]) -> None:
        """Test for Cross-Site WebSocket Hijacking."""
        try:
            import websockets

            for endpoint in endpoints:
                self.check_cancelled()

                try:
                    # Try to connect from a different origin
                    async with websockets.connect(
                        endpoint,
                        close_timeout=5,
                        extra_headers={
                            "Origin": "https://evil.example.com"
                        }
                    ) as ws:
                        # If connection succeeds with foreign origin, vulnerable
                        await ws.send('{"type": "test"}')

                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=5)

                            if response and "error" not in response.lower():
                                finding = Finding(
                                    vuln_type=VulnerabilityType.WEBSOCKET,
                                    title="Cross-Site WebSocket Hijacking (CSWSH)",
                                    description="WebSocket accepts connections from arbitrary origins",
                                    severity=FindingSeverity.HIGH,
                                    target=self.target,
                                    url=endpoint,
                                    evidence=Evidence(
                                        request="Origin: https://evil.example.com",
                                        response=response[:500] if response else None,
                                    ),
                                    tags=["websocket", "cswsh"],
                                )
                                await self.add_finding(finding)

                        except asyncio.TimeoutError:
                            pass

                except Exception as e:
                    # Connection refused is good - means origin check is working
                    logger.debug(f"CSWSH test for {endpoint}: {e}")

        except ImportError:
            pass

    async def _fuzz_messages(
        self,
        endpoints: list[str],
        messages: list[dict],
    ) -> None:
        """Fuzz WebSocket messages."""
        fuzz_payloads = [
            "",  # Empty
            "null",
            "{}",
            "[]",
            '{"": ""}',
            "A" * 10000,  # Long string
            "\x00\x00\x00",  # Null bytes
            '{"type": null}',
            '{"id": -1}',
            '{"id": 999999999999}',
        ]

        try:
            import websockets

            for endpoint in endpoints[:3]:  # Limit fuzzing
                self.check_cancelled()

                try:
                    async with websockets.connect(endpoint, close_timeout=10) as ws:
                        for payload in fuzz_payloads:
                            try:
                                await ws.send(payload)
                                response = await asyncio.wait_for(ws.recv(), timeout=2)

                                # Check for interesting responses
                                error_indicators = [
                                    "exception", "traceback", "internal error",
                                    "stack trace", "debug", "path"
                                ]

                                if any(ind in response.lower() for ind in error_indicators):
                                    finding = Finding(
                                        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                        title="WebSocket error disclosure",
                                        description="WebSocket reveals error details on malformed input",
                                        severity=FindingSeverity.LOW,
                                        target=self.target,
                                        url=endpoint,
                                        payload=payload[:100],
                                        evidence=Evidence(response=response[:500]),
                                        tags=["websocket", "fuzzing", "info-disclosure"],
                                    )
                                    await self.add_finding(finding)

                            except asyncio.TimeoutError:
                                pass
                            except Exception:
                                pass

                except Exception as e:
                    logger.debug(f"Fuzzing error for {endpoint}: {e}")

        except ImportError:
            pass
