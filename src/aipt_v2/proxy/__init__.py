"""
AIPT Proxy Module

HTTP/HTTPS traffic interception and manipulation:
- Request/response capture
- Traffic modification
- WebSocket support
- Integration with mitmproxy
"""

from .history import (
    HistoryEntry,
    ProxyHistory,
)
from .interceptor import (
    InterceptedRequest,
    InterceptedResponse,
    ProxyConfig,
    ProxyInterceptor,
)

__all__ = [
    "ProxyInterceptor",
    "ProxyConfig",
    "InterceptedRequest",
    "InterceptedResponse",
    "ProxyHistory",
    "HistoryEntry",
]
