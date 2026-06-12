"""
AIPT Core Module

LangGraph-based autonomous pentesting agent with:
- Multi-provider LLM abstraction (OpenAI, Anthropic, Ollama)
- Memory management with automatic compression
- State machine for pentest workflow
- Centralized event loop management

Inspired by: Strix (LangGraph state machine, 300 iterations)
"""

from __future__ import annotations

from .agent import AIPTAgent, PentestState, Phase
from .event_loop_manager import (
    EventLoopManager,
    current_time,
    get_current_loop,
    run_async,
)
from .llm import (
    AnthropicProvider,
    LLMProvider,
    LLMResponse,
    OllamaProvider,
    OpenAIProvider,
    get_llm,
)
from .memory import MemoryConfig, MemoryManager
from .ptt import PTTNode, PTTTracker

__all__ = [
    # LLM
    "LLMProvider",
    "LLMResponse",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "get_llm",
    # Memory
    "MemoryManager",
    "MemoryConfig",
    # Agent
    "AIPTAgent",
    "PentestState",
    "Phase",
    # PTT
    "PTTTracker",
    "PTTNode",
    # Event Loop Management
    "EventLoopManager",
    "run_async",
    "get_current_loop",
    "current_time",
]
