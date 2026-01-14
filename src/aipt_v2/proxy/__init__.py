"""
AIPT Proxy Module

HTTP/HTTPS traffic interception and manipulation:
- Request/response capture
- Traffic modification
- WebSocket support
- Integration with mitmproxy
"""

from .interceptor import (
    ProxyInterceptor,
    ProxyConfig,
    InterceptedRequest,
    InterceptedResponse,
)
from .history import (
    ProxyHistory,
    HistoryEntry,
)

__all__ = [
    "ProxyInterceptor",
    "ProxyConfig",
    "InterceptedRequest",
    "InterceptedResponse",
    "ProxyHistory",
    "HistoryEntry",
]
