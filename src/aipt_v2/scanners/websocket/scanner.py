"""
AIPTX WebSocket Scanner - Comprehensive WebSocket Security Testing

Tests WebSocket connections for:
- Injection vulnerabilities (SQL, NoSQL, Command)
- Cross-Site WebSocket Hijacking (CSWSH)
- Authentication/authorization issues
- Message replay attacks
- Origin validation bypass
- DoS via message flooding
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

from aipt_v2.scanners.base import BaseScanner, ScanResult, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)


class MessageDirection(str, Enum):
    """Direction of WebSocket message."""
    SENT = "sent"
    RECEIVED = "received"


class AttackType(str, Enum):
    """Types of WebSocket attacks."""
    SQLI = "sql_injection"
    NOSQLI = "nosql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "cross_site_scripting"
    CSWSH = "cross_site_websocket_hijacking"
    AUTH_BYPASS = "authentication_bypass"
    MESSAGE_REPLAY = "message_replay"
    ORIGIN_BYPASS = "origin_bypass"
    DOS = "denial_of_service"


@dataclass
class WebSocketMessage:
    """Captured WebSocket message."""
    direction: MessageDirection
    data: str
    timestamp: datetime = field(default_factory=datetime.now)
    is_binary: bool = False
    message_type: str = "text"  # text, binary, ping, pong, close

    def to_dict(self) -> dict:
        return {
            "direction": self.direction.value,
            "data": self.data[:1000] if self.data else "",
            "timestamp": self.timestamp.isoformat(),
            "is_binary": self.is_binary,
            "type": self.message_type,
        }


@dataclass
class WebSocketFinding:
    """Security finding from WebSocket testing."""
    attack_type: AttackType
    title: str
    description: str
    severity: ScanSeverity
    endpoint: str
    payload: str = ""
    response: str = ""
    evidence: str = ""
    cwe: Optional[str] = None
    remediation: str = ""

    def to_scan_finding(self) -> ScanFinding:
        return ScanFinding(
            title=self.title,
            severity=self.severity,
            description=self.description,
            url=self.endpoint,
            evidence=self.evidence,
            cwe=self.cwe,
            scanner="websocket_scanner",
            tags=[self.attack_type.value],
        )


@dataclass
class WebSocketScanConfig:
    """Configuration for WebSocket scanning."""
    timeout: float = 30.0
    max_messages: int = 100
    test_injection: bool = True
    test_cswsh: bool = True
    test_replay: bool = True
    test_auth: bool = True
    test_dos: bool = False  # Disabled by default (can be disruptive)
    custom_payloads: list[str] = field(default_factory=list)
    custom_headers: dict[str, str] = field(default_factory=dict)
    origin: Optional[str] = None  # For CSWSH testing
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class WebSocketScanResult:
    """Result of WebSocket security scan."""
    endpoint: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    connected: bool = False
    findings: list[WebSocketFinding] = field(default_factory=list)
    messages: list[WebSocketMessage] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ScanSeverity.CRITICAL)

    def to_scan_result(self) -> ScanResult:
        result = ScanResult(
            scanner="websocket_scanner",
            target=self.endpoint,
            status="completed" if self.completed_at else "failed",
            start_time=self.started_at,
            end_time=self.completed_at,
        )
        for finding in self.findings:
            result.add_finding(finding.to_scan_finding())
        result.errors = self.errors
        return result


class WebSocketScanner(BaseScanner):
    """
    Comprehensive WebSocket security scanner.

    Tests for:
    - Injection attacks (SQL, NoSQL, Command, XSS)
    - Cross-Site WebSocket Hijacking (CSWSH)
    - Authentication bypass
    - Message replay attacks
    - Origin validation issues

    Usage:
        scanner = WebSocketScanner()
        result = await scanner.scan("wss://example.com/ws")

        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
    """

    def __init__(self, config: Optional[WebSocketScanConfig] = None):
        super().__init__()
        self.config = config or WebSocketScanConfig()
        self._ws = None

    def is_available(self) -> bool:
        """Check if websockets library is available."""
        try:
            import websockets
            return True
        except ImportError:
            return False

    def parse_output(self, output: str) -> list[ScanFinding]:
        """Parse output (not used for WebSocket scanner)."""
        return []

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Scan a WebSocket endpoint.

        Args:
            target: WebSocket URL (ws:// or wss://)
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        # Normalize URL
        if not target.startswith(("ws://", "wss://")):
            if target.startswith("https://"):
                target = target.replace("https://", "wss://")
            elif target.startswith("http://"):
                target = target.replace("http://", "ws://")
            else:
                target = f"wss://{target}"

        ws_result = await self.scan_websocket(target)
        return ws_result.to_scan_result()

    async def scan_websocket(self, endpoint: str) -> WebSocketScanResult:
        """
        Perform comprehensive WebSocket security scan.

        Args:
            endpoint: WebSocket endpoint URL

        Returns:
            WebSocketScanResult with findings
        """
        result = WebSocketScanResult(
            endpoint=endpoint,
            started_at=datetime.now(),
        )

        try:
            import websockets

            # Test basic connection
            logger.info(f"[WebSocket] Connecting to {endpoint}")

            try:
                async with websockets.connect(
                    endpoint,
                    extra_headers=self.config.custom_headers,
                    close_timeout=5,
                    open_timeout=self.config.timeout,
                ) as ws:
                    result.connected = True
                    logger.info(f"[WebSocket] Connected successfully")

                    # Run security tests
                    if self.config.test_injection:
                        await self._test_injection(ws, result)

                    if self.config.test_cswsh:
                        await self._test_cswsh(endpoint, result)

                    if self.config.test_replay:
                        await self._test_replay(ws, result)

                    if self.config.test_auth:
                        await self._test_auth(ws, result)

                    if self.config.test_dos:
                        await self._test_dos(ws, result)

            except websockets.exceptions.InvalidStatusCode as e:
                result.errors.append(f"Connection rejected: HTTP {e.status_code}")
            except websockets.exceptions.InvalidHandshake as e:
                result.errors.append(f"Handshake failed: {e}")
            except asyncio.TimeoutError:
                result.errors.append("Connection timed out")

        except ImportError:
            result.errors.append("websockets library not installed")
        except Exception as e:
            logger.error(f"WebSocket scan error: {e}", exc_info=True)
            result.errors.append(str(e))

        result.completed_at = datetime.now()
        return result

    async def _test_injection(self, ws, result: WebSocketScanResult) -> None:
        """Test for injection vulnerabilities."""
        injection_payloads = {
            AttackType.SQLI: [
                "' OR '1'='1",
                "1; DROP TABLE users--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND SLEEP(5)--",
            ],
            AttackType.NOSQLI: [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$where": "1==1"}',
                '{"$regex": ".*"}',
            ],
            AttackType.COMMAND_INJECTION: [
                "; id",
                "| id",
                "$(id)",
                "`id`",
                "; cat /etc/passwd",
            ],
            AttackType.XSS: [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
            ],
        }

        # Add custom payloads
        if self.config.custom_payloads:
            injection_payloads[AttackType.SQLI].extend(self.config.custom_payloads)

        for attack_type, payloads in injection_payloads.items():
            for payload in payloads:
                try:
                    # Send payload in different formats
                    await self._test_payload_formats(ws, result, payload, attack_type)
                except Exception as e:
                    logger.debug(f"Injection test error: {e}")

    async def _test_payload_formats(
        self,
        ws,
        result: WebSocketScanResult,
        payload: str,
        attack_type: AttackType,
    ) -> None:
        """Test payload in different message formats."""
        formats = [
            # Plain text
            payload,
            # JSON with common keys
            json.dumps({"message": payload}),
            json.dumps({"data": payload}),
            json.dumps({"query": payload}),
            json.dumps({"input": payload}),
            json.dumps({"cmd": payload}),
        ]

        for msg in formats:
            try:
                await ws.send(msg)
                result.messages.append(
                    WebSocketMessage(direction=MessageDirection.SENT, data=msg)
                )

                # Wait for response with timeout
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    result.messages.append(
                        WebSocketMessage(direction=MessageDirection.RECEIVED, data=response)
                    )

                    # Check for vulnerability indicators
                    vuln = self._check_vulnerability_indicators(
                        payload, response, attack_type
                    )
                    if vuln:
                        result.findings.append(vuln)

                except asyncio.TimeoutError:
                    pass  # No response, continue

            except Exception as e:
                logger.debug(f"Payload test error: {e}")

    def _check_vulnerability_indicators(
        self,
        payload: str,
        response: str,
        attack_type: AttackType,
    ) -> Optional[WebSocketFinding]:
        """Check response for vulnerability indicators."""
        response_lower = response.lower()

        # SQL injection indicators
        if attack_type == AttackType.SQLI:
            sql_errors = [
                "sql syntax", "mysql", "postgresql", "sqlite",
                "ora-", "sql server", "odbc", "database error",
            ]
            if any(err in response_lower for err in sql_errors):
                return WebSocketFinding(
                    attack_type=AttackType.SQLI,
                    title="SQL Injection in WebSocket",
                    description="SQL error messages indicate injection vulnerability",
                    severity=ScanSeverity.CRITICAL,
                    endpoint="",
                    payload=payload,
                    response=response[:500],
                    evidence=f"SQL error in response: {response[:200]}",
                    cwe="CWE-89",
                    remediation="Use parameterized queries for all database operations",
                )

        # NoSQL injection indicators
        if attack_type == AttackType.NOSQLI:
            nosql_indicators = ["mongodb", "$where", "bson", "operator"]
            if any(ind in response_lower for ind in nosql_indicators):
                return WebSocketFinding(
                    attack_type=AttackType.NOSQLI,
                    title="NoSQL Injection in WebSocket",
                    description="NoSQL error or behavior indicates injection",
                    severity=ScanSeverity.HIGH,
                    endpoint="",
                    payload=payload,
                    response=response[:500],
                    cwe="CWE-943",
                    remediation="Validate and sanitize all query parameters",
                )

        # Command injection indicators
        if attack_type == AttackType.COMMAND_INJECTION:
            cmd_indicators = ["uid=", "gid=", "root:", "/bin/", "command not found"]
            if any(ind in response_lower for ind in cmd_indicators):
                return WebSocketFinding(
                    attack_type=AttackType.COMMAND_INJECTION,
                    title="Command Injection in WebSocket",
                    description="Command output indicates injection vulnerability",
                    severity=ScanSeverity.CRITICAL,
                    endpoint="",
                    payload=payload,
                    response=response[:500],
                    evidence=f"Command output detected: {response[:200]}",
                    cwe="CWE-78",
                    remediation="Never pass user input to shell commands",
                )

        # XSS reflection
        if attack_type == AttackType.XSS:
            if payload in response:
                return WebSocketFinding(
                    attack_type=AttackType.XSS,
                    title="XSS Reflection in WebSocket",
                    description="Payload reflected without encoding",
                    severity=ScanSeverity.MEDIUM,
                    endpoint="",
                    payload=payload,
                    response=response[:500],
                    cwe="CWE-79",
                    remediation="Encode all output sent to clients",
                )

        return None

    async def _test_cswsh(self, endpoint: str, result: WebSocketScanResult) -> None:
        """Test for Cross-Site WebSocket Hijacking."""
        import websockets

        # Test with different origins
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "",
        ]

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                async with websockets.connect(
                    endpoint,
                    extra_headers=headers,
                    close_timeout=5,
                    open_timeout=10,
                ) as ws:
                    # Connection successful with malicious origin
                    result.findings.append(
                        WebSocketFinding(
                            attack_type=AttackType.CSWSH,
                            title="Cross-Site WebSocket Hijacking (CSWSH)",
                            description=f"WebSocket accepts connection from origin: {origin}",
                            severity=ScanSeverity.HIGH,
                            endpoint=endpoint,
                            evidence=f"Successfully connected with Origin: {origin}",
                            cwe="CWE-346",
                            remediation="Validate Origin header against whitelist",
                        )
                    )
                    break  # Found vulnerability

            except websockets.exceptions.InvalidStatusCode:
                pass  # Origin rejected, good
            except Exception:
                pass

    async def _test_replay(self, ws, result: WebSocketScanResult) -> None:
        """Test for message replay vulnerabilities."""
        # Capture some messages first
        captured = []
        try:
            # Send a test message
            test_msg = json.dumps({"action": "test", "data": "probe"})
            await ws.send(test_msg)

            # Capture response
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                captured.append((test_msg, response))
            except asyncio.TimeoutError:
                pass

        except Exception:
            pass

        # Try replaying captured messages
        for original_msg, _ in captured:
            try:
                # Replay same message
                await ws.send(original_msg)
                replay_response = await asyncio.wait_for(ws.recv(), timeout=2.0)

                # If we get similar response, replay might work
                result.findings.append(
                    WebSocketFinding(
                        attack_type=AttackType.MESSAGE_REPLAY,
                        title="Potential Message Replay Vulnerability",
                        description="Messages can be replayed without rejection",
                        severity=ScanSeverity.LOW,
                        endpoint="",
                        payload=original_msg,
                        response=replay_response[:500] if replay_response else "",
                        cwe="CWE-294",
                        remediation="Implement message nonces or timestamps",
                    )
                )
                break

            except Exception:
                pass

    async def _test_auth(self, ws, result: WebSocketScanResult) -> None:
        """Test for authentication/authorization issues."""
        # Test accessing sensitive operations without proper auth
        auth_test_messages = [
            json.dumps({"action": "admin", "command": "list_users"}),
            json.dumps({"action": "get_user", "user_id": "1"}),
            json.dumps({"action": "delete", "id": "1"}),
            json.dumps({"role": "admin", "action": "privileged"}),
        ]

        for msg in auth_test_messages:
            try:
                await ws.send(msg)
                response = await asyncio.wait_for(ws.recv(), timeout=2.0)

                # Check if we got data without proper auth
                if self._looks_like_success(response):
                    result.findings.append(
                        WebSocketFinding(
                            attack_type=AttackType.AUTH_BYPASS,
                            title="Potential Authorization Bypass",
                            description="Sensitive action succeeded without proper authentication",
                            severity=ScanSeverity.MEDIUM,
                            endpoint="",
                            payload=msg,
                            response=response[:500],
                            cwe="CWE-862",
                            remediation="Implement proper authentication and authorization checks",
                        )
                    )

            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

    def _looks_like_success(self, response: str) -> bool:
        """Check if response looks like a successful operation."""
        try:
            data = json.loads(response)
            # Check for success indicators
            if isinstance(data, dict):
                if data.get("success") is True:
                    return True
                if data.get("status") == "ok":
                    return True
                if "data" in data or "users" in data or "result" in data:
                    return True
        except json.JSONDecodeError:
            pass

        # Check string response
        success_indicators = ["success", "ok", "done", "completed"]
        return any(ind in response.lower() for ind in success_indicators)

    async def _test_dos(self, ws, result: WebSocketScanResult) -> None:
        """Test for DoS vulnerabilities (use with caution)."""
        # Large message test
        large_msg = "A" * 1000000  # 1MB

        try:
            start = time.time()
            await ws.send(large_msg)
            response = await asyncio.wait_for(ws.recv(), timeout=5.0)
            elapsed = time.time() - start

            if elapsed > 3.0:  # Slow response
                result.findings.append(
                    WebSocketFinding(
                        attack_type=AttackType.DOS,
                        title="Potential DoS via Large Messages",
                        description="Server is slow to process large messages",
                        severity=ScanSeverity.LOW,
                        endpoint="",
                        evidence=f"Response time: {elapsed:.2f}s for 1MB message",
                        cwe="CWE-400",
                        remediation="Implement message size limits",
                    )
                )

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
