"""
AIPTX Beast Mode - Lateral Movement Module
===========================================

Network pivoting, internal scanning, and credential spraying
for post-exploitation lateral movement.

Components:
- pivot_manager: SOCKS proxy and tunnel management
- tunnel_creator: SSH/Chisel tunnel establishment
- route_manager: Internal network routing
- internal_scanner: Port scanning through pivot
- credential_sprayer: Multi-protocol credential testing
"""

from __future__ import annotations

from aipt_v2.lateral.pivot_manager import (
    PivotManager,
    PivotSession,
    PivotType,
)
from aipt_v2.lateral.tunnel_creator import (
    TunnelCreator,
    TunnelConfig,
    TunnelType,
)
from aipt_v2.lateral.route_manager import (
    RouteManager,
    InternalRoute,
)
from aipt_v2.lateral.internal_scanner import (
    InternalScanner,
    ScanResult,
    ServiceInfo,
)
from aipt_v2.lateral.credential_sprayer import (
    CredentialSprayer,
    SprayResult,
    SprayConfig,
    SprayProtocol,
)

__all__ = [
    # Pivot management
    "PivotManager",
    "PivotSession",
    "PivotType",
    # Tunnels
    "TunnelCreator",
    "TunnelConfig",
    "TunnelType",
    # Routing
    "RouteManager",
    "InternalRoute",
    # Scanning
    "InternalScanner",
    "ScanResult",
    "ServiceInfo",
    # Spraying
    "CredentialSprayer",
    "SprayResult",
    "SprayConfig",
    "SprayProtocol",
]
