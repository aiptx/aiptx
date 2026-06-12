"""
AIPTX WebSocket Scanner - Real-Time Protocol Security Testing

Provides comprehensive WebSocket security testing:
- Connection interception and analysis
- Message fuzzing and injection
- Authentication bypass testing
- CSWSH (Cross-Site WebSocket Hijacking)
- Message replay attacks
"""

from aipt_v2.scanners.websocket.scanner import (
    WebSocketFinding,
    WebSocketMessage,
    WebSocketScanConfig,
    WebSocketScanner,
    WebSocketScanResult,
)

__all__ = [
    "WebSocketScanner",
    "WebSocketScanConfig",
    "WebSocketScanResult",
    "WebSocketMessage",
    "WebSocketFinding",
]
