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

# AD Lateral Movement
from aipt_v2.lateral.ad_lateral import (
    ADLateralConfig,
    ADLateralMovement,
    AuthMethod,
    ExecMethod,
    ExecResult,
    execute_remote,
    find_local_admin_access,
)
from aipt_v2.lateral.credential_sprayer import (
    CredentialSprayer,
    SprayConfig,
    SprayProtocol,
    SprayResult,
)
from aipt_v2.lateral.internal_scanner import (
    InternalScanner,
    ScanResult,
    ServiceInfo,
)
from aipt_v2.lateral.pivot_manager import (
    PivotManager,
    PivotSession,
    PivotType,
)
from aipt_v2.lateral.route_manager import (
    InternalRoute,
    RouteManager,
)
from aipt_v2.lateral.tunnel_creator import (
    TunnelConfig,
    TunnelCreator,
    TunnelType,
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
    # AD Lateral Movement
    "ADLateralMovement",
    "ADLateralConfig",
    "ExecResult",
    "ExecMethod",
    "AuthMethod",
    "execute_remote",
    "find_local_admin_access",
]
