"""
AIPT Proxy Interceptor

HTTP/HTTPS traffic interception using mitmproxy.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# mitmproxy import with fallback
try:
    from mitmproxy import http, options
    from mitmproxy.tools import dump
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    logger.warning("mitmproxy not installed. Install with: pip install mitmproxy")


@dataclass
class InterceptedRequest:
    """Captured HTTP request"""
    id: str
    timestamp: datetime
    method: str
    url: str
    host: str
    path: str
    headers: dict[str, str]
    body: bytes = b""
    query_params: dict[str, list[str]] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    # Classification
    content_type: str = ""
    is_json: bool = False
    is_form: bool = False
    is_multipart: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body_size": len(self.body),
            "content_type": self.content_type,
        }

    def get_body_text(self) -> str:
        """Get body as text"""
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return f"[Binary: {len(self.body)} bytes]"

    def get_body_json(self) -> Optional[dict]:
        """Parse body as JSON"""
        if self.is_json:
            try:
                return json.loads(self.body)
            except json.JSONDecodeError:
                pass
        return None


@dataclass
class InterceptedResponse:
    """Captured HTTP response"""
    request_id: str
    timestamp: datetime
    status_code: int
    reason: str
    headers: dict[str, str]
    body: bytes = b""

    # Timing
    response_time_ms: float = 0.0

    # Classification
    content_type: str = ""
    is_json: bool = False
    is_html: bool = False

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "status_code": self.status_code,
            "reason": self.reason,
            "headers": self.headers,
            "body_size": len(self.body),
            "response_time_ms": self.response_time_ms,
            "content_type": self.content_type,
        }

    def get_body_text(self) -> str:
        """Get body as text"""
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return f"[Binary: {len(self.body)} bytes]"


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080

    # SSL/TLS
    ssl_insecure: bool = True  # Accept invalid certs from upstream

    # Filtering
    include_hosts: list[str] = field(default_factory=list)
    exclude_hosts: list[str] = field(default_factory=lambda: [
        "*.google.com",
        "*.googleapis.com",
        "*.gstatic.com",
        "*.doubleclick.net",
        "*.google-analytics.com",
    ])

    # Capture settings
    capture_requests: bool = True
    capture_responses: bool = True
    max_body_size: int = 10 * 1024 * 1024  # 10MB

    # Modification
    inject_headers: dict[str, str] = field(default_factory=dict)
    remove_headers: list[str] = field(default_factory=list)


class ProxyInterceptor:
    """
    HTTP/HTTPS traffic interceptor.

    Features:
    - Request/response capture
    - Traffic modification
    - Scope filtering
    - Request/response callbacks

    Example:
        proxy = ProxyInterceptor(ProxyConfig(listen_port=8080))

        @proxy.on_request
        def handle_request(request):
            print(f"Request: {request.method} {request.url}")

        await proxy.start()
        # Configure browser to use proxy at 127.0.0.1:8080
        # ...
        await proxy.stop()
    """

    def __init__(self, config: Optional[ProxyConfig] = None):
        if not MITMPROXY_AVAILABLE:
            raise ImportError("mitmproxy is required. Install with: pip install mitmproxy")

        self.config = config or ProxyConfig()
        self._requests: dict[str, InterceptedRequest] = {}
        self._responses: dict[str, InterceptedResponse] = {}
        self._request_callbacks: list[Callable[[InterceptedRequest], Optional[InterceptedRequest]]] = []
        self._response_callbacks: list[Callable[[InterceptedResponse], Optional[InterceptedResponse]]] = []
        self._master = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._request_count = 0

    def on_request(self, callback: Callable[[InterceptedRequest], Optional[InterceptedRequest]]):
        """Register request callback (decorator)"""
        self._request_callbacks.append(callback)
        return callback

    def on_response(self, callback: Callable[[InterceptedResponse], Optional[InterceptedResponse]]):
        """Register response callback (decorator)"""
        self._response_callbacks.append(callback)
        return callback

    async def start(self) -> bool:
        """Start the proxy server"""
        if self._running:
            return True

        try:
            # Create mitmproxy options
            opts = options.Options(
                listen_host=self.config.listen_host,
                listen_port=self.config.listen_port,
                ssl_insecure=self.config.ssl_insecure,
            )

            # Create master
            self._master = dump.DumpMaster(
                opts,
                with_termlog=False,
                with_dumper=False,
            )

            # Add our addon
            self._master.addons.add(self._create_addon())

            # Run in thread
            def run_proxy():
                asyncio.set_event_loop(asyncio.new_event_loop())
                self._master.run()

            self._thread = threading.Thread(target=run_proxy, daemon=True)
            self._thread.start()
            self._running = True

            logger.info(f"Proxy started on {self.config.listen_host}:{self.config.listen_port}")
            return True

        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            return False

    async def stop(self) -> None:
        """Stop the proxy server"""
        if self._master:
            self._master.shutdown()
        self._running = False
        logger.info("Proxy stopped")

    def _create_addon(self) -> Any:
        """Create mitmproxy addon"""
        interceptor = self

        class AIPTAddon:
            def request(self, flow: http.HTTPFlow) -> None:
                # Check scope
                if not interceptor._in_scope(flow.request.host):
                    return

                interceptor._request_count += 1
                request_id = f"req_{interceptor._request_count}"

                # Create intercepted request
                req = InterceptedRequest(
                    id=request_id,
                    timestamp=datetime.utcnow(),
                    method=flow.request.method,
                    url=flow.request.url,
                    host=flow.request.host,
                    path=flow.request.path,
                    headers=dict(flow.request.headers),
                    body=flow.request.content or b"",
                )

                # Parse content type
                content_type = flow.request.headers.get("content-type", "")
                req.content_type = content_type
                req.is_json = "application/json" in content_type
                req.is_form = "application/x-www-form-urlencoded" in content_type
                req.is_multipart = "multipart/form-data" in content_type

                # Parse cookies
                if "cookie" in flow.request.headers:
                    for cookie in flow.request.headers["cookie"].split(";"):
                        if "=" in cookie:
                            name, value = cookie.strip().split("=", 1)
                            req.cookies[name] = value

                # Store and notify
                interceptor._requests[request_id] = req
                flow.metadata["aipt_request_id"] = request_id

                # Call callbacks
                for callback in interceptor._request_callbacks:
                    try:
                        modified = callback(req)
                        if modified:
                            # Apply modifications to flow
                            flow.request.headers = http.Headers([(k, v) for k, v in modified.headers.items()])
                            if modified.body:
                                flow.request.content = modified.body
                    except Exception as e:
                        logger.error(f"Request callback error: {e}")

                # Apply configured modifications
                for header, value in interceptor.config.inject_headers.items():
                    flow.request.headers[header] = value
                for header in interceptor.config.remove_headers:
                    if header in flow.request.headers:
                        del flow.request.headers[header]

            def response(self, flow: http.HTTPFlow) -> None:
                request_id = flow.metadata.get("aipt_request_id")
                if not request_id:
                    return

                # Get request for timing
                request = interceptor._requests.get(request_id)

                # Create intercepted response
                resp = InterceptedResponse(
                    request_id=request_id,
                    timestamp=datetime.utcnow(),
                    status_code=flow.response.status_code,
                    reason=flow.response.reason or "",
                    headers=dict(flow.response.headers),
                    body=flow.response.content or b"",
                )

                # Calculate response time
                if request:
                    resp.response_time_ms = (resp.timestamp - request.timestamp).total_seconds() * 1000

                # Parse content type
                content_type = flow.response.headers.get("content-type", "")
                resp.content_type = content_type
                resp.is_json = "application/json" in content_type
                resp.is_html = "text/html" in content_type

                # Store
                interceptor._responses[request_id] = resp

                # Call callbacks
                for callback in interceptor._response_callbacks:
                    try:
                        modified = callback(resp)
                        if modified:
                            flow.response.headers = http.Headers([(k, v) for k, v in modified.headers.items()])
                            if modified.body:
                                flow.response.content = modified.body
                    except Exception as e:
                        logger.error(f"Response callback error: {e}")

        return AIPTAddon()

    def _in_scope(self, host: str) -> bool:
        """Check if host is in scope"""
        # Check excludes
        for pattern in self.config.exclude_hosts:
            if self._host_matches(host, pattern):
                return False

        # If includes specified, host must match
        if self.config.include_hosts:
            for pattern in self.config.include_hosts:
                if self._host_matches(host, pattern):
                    return True
            return False

        return True

    def _host_matches(self, host: str, pattern: str) -> bool:
        """Check if host matches pattern"""
        if pattern.startswith("*."):
            return host.endswith(pattern[1:]) or host == pattern[2:]
        return host == pattern

    def get_requests(self) -> list[InterceptedRequest]:
        """Get all captured requests"""
        return list(self._requests.values())

    def get_responses(self) -> list[InterceptedResponse]:
        """Get all captured responses"""
        return list(self._responses.values())

    def get_request(self, request_id: str) -> Optional[InterceptedRequest]:
        """Get specific request by ID"""
        return self._requests.get(request_id)

    def get_response(self, request_id: str) -> Optional[InterceptedResponse]:
        """Get response for a request"""
        return self._responses.get(request_id)

    def clear_history(self) -> None:
        """Clear captured traffic"""
        self._requests.clear()
        self._responses.clear()

    def export_har(self, filepath: str) -> bool:
        """Export traffic to HAR format"""
        try:
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "AIPT", "version": "2.0"},
                    "entries": [],
                }
            }

            for req_id, request in self._requests.items():
                response = self._responses.get(req_id)

                entry = {
                    "startedDateTime": request.timestamp.isoformat(),
                    "request": {
                        "method": request.method,
                        "url": request.url,
                        "headers": [{"name": k, "value": v} for k, v in request.headers.items()],
                        "queryString": [],
                        "bodySize": len(request.body),
                    },
                }

                if response:
                    entry["response"] = {
                        "status": response.status_code,
                        "statusText": response.reason,
                        "headers": [{"name": k, "value": v} for k, v in response.headers.items()],
                        "content": {
                            "size": len(response.body),
                            "mimeType": response.content_type,
                        },
                    }
                    entry["time"] = response.response_time_ms

                har["log"]["entries"].append(entry)

            with open(filepath, "w") as f:
                json.dump(har, f, indent=2)

            return True
        except Exception as e:
            logger.error(f"HAR export error: {e}")
            return False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def request_count(self) -> int:
        return self._request_count


# Convenience function for simple proxy usage
def create_proxy(port: int = 8080, hosts: Optional[list[str]] = None) -> ProxyInterceptor:
    """Create a configured proxy"""
    config = ProxyConfig(listen_port=port)
    if hosts:
        config.include_hosts = hosts
    return ProxyInterceptor(config)
