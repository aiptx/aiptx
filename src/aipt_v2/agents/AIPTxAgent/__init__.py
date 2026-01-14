"""
AIPT AIPTxAgent - Main penetration testing agent
"""

from aipt_v2.agents.AIPTxAgent.aiptx_agent import AIPTxAgent

# Backwards compatibility alias
StrixAgent = AIPTxAgent

__all__ = ["AIPTxAgent", "StrixAgent"]
