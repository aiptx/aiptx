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

from .llm import (
    LLMProvider,
    LLMResponse,
    OpenAIProvider,
    AnthropicProvider,
    OllamaProvider,
    get_llm,
)
from .memory import MemoryManager, MemoryConfig
from .agent import AIPTAgent, PentestState, Phase
from .ptt import PTTTracker, PTTNode
from .event_loop_manager import (
    EventLoopManager,
    run_async,
    get_current_loop,
    current_time,
)

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
