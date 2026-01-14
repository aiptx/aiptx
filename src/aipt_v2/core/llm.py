"""
AIPT LLM Provider - Multi-provider LLM abstraction

Supports: OpenAI, Anthropic, Ollama (local)
Inspired by: Strix's multi-provider approach
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional, Generator, Any
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Standardized LLM response"""
    content: str
    model: str
    tokens_used: int
    finish_reason: str
    raw_response: Any = None


class LLMProvider(ABC):
    """Abstract base class for LLM providers"""

    @abstractmethod
    def invoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Synchronous invocation"""
        pass

    @abstractmethod
    async def ainvoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Async invocation"""
        pass

    @abstractmethod
    def stream(self, messages: list[dict], **kwargs) -> Generator[str, None, None]:
        """Streaming invocation"""
        pass

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        pass

    def format_messages(self, system: str, user: str, history: list[dict] = None) -> list[dict]:
        """Format messages for the provider"""
        messages = [{"role": "system", "content": system}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user})
        return messages


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider (GPT-4o, GPT-4, etc.)"""

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        base_url: Optional[str] = None,
    ):
        try:
            from openai import OpenAI, AsyncOpenAI
            self._openai_available = True
        except ImportError:
            self._openai_available = False
            return

        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

        kwargs = {"api_key": api_key or os.getenv("OPENAI_API_KEY")}
        if base_url:
            kwargs["base_url"] = base_url

        self.client = OpenAI(**kwargs)
        self.async_client = AsyncOpenAI(**kwargs)

    def invoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Invoke OpenAI API"""
        if not self._openai_available:
            raise RuntimeError("OpenAI package not installed. Run: pip install openai")

        response = self.client.chat.completions.create(
            model=kwargs.get("model", self.model),
            messages=messages,
            temperature=kwargs.get("temperature", self.temperature),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=self.model,
            tokens_used=response.usage.total_tokens if response.usage else 0,
            finish_reason=response.choices[0].finish_reason or "stop",
            raw_response=response,
        )

    async def ainvoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Async invoke OpenAI API"""
        if not self._openai_available:
            raise RuntimeError("OpenAI package not installed. Run: pip install openai")

        response = await self.async_client.chat.completions.create(
            model=kwargs.get("model", self.model),
            messages=messages,
            temperature=kwargs.get("temperature", self.temperature),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=self.model,
            tokens_used=response.usage.total_tokens if response.usage else 0,
            finish_reason=response.choices[0].finish_reason or "stop",
            raw_response=response,
        )

    def stream(self, messages: list[dict], **kwargs) -> Generator[str, None, None]:
        """Stream OpenAI response"""
        if not self._openai_available:
            raise RuntimeError("OpenAI package not installed")

        stream = self.client.chat.completions.create(
            model=kwargs.get("model", self.model),
            messages=messages,
            temperature=kwargs.get("temperature", self.temperature),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
            stream=True,
        )

        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def count_tokens(self, text: str) -> int:
        """Approximate token count (4 chars per token)"""
        try:
            import tiktoken
            enc = tiktoken.encoding_for_model(self.model)
            return len(enc.encode(text))
        except ImportError:
            return len(text) // 4


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider (Claude 3.5, Claude 4, etc.)"""

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ):
        try:
            from anthropic import Anthropic, AsyncAnthropic
            self._anthropic_available = True
        except ImportError:
            self._anthropic_available = False
            return

        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

        api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = Anthropic(api_key=api_key)
        self.async_client = AsyncAnthropic(api_key=api_key)

    def _extract_messages(self, messages: list[dict]) -> tuple[str, list[dict]]:
        """Extract system message and chat messages"""
        system = None
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                chat_messages.append(msg)
        return system or "You are an expert penetration testing AI assistant.", chat_messages

    def invoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Invoke Anthropic API"""
        if not self._anthropic_available:
            raise RuntimeError("Anthropic package not installed. Run: pip install anthropic")

        system, chat_messages = self._extract_messages(messages)

        response = self.client.messages.create(
            model=kwargs.get("model", self.model),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
            system=system,
            messages=chat_messages,
        )

        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text

        return LLMResponse(
            content=content,
            model=self.model,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            finish_reason=response.stop_reason or "end_turn",
            raw_response=response,
        )

    async def ainvoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Async invoke Anthropic API"""
        if not self._anthropic_available:
            raise RuntimeError("Anthropic package not installed")

        system, chat_messages = self._extract_messages(messages)

        response = await self.async_client.messages.create(
            model=kwargs.get("model", self.model),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
            system=system,
            messages=chat_messages,
        )

        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text

        return LLMResponse(
            content=content,
            model=self.model,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            finish_reason=response.stop_reason or "end_turn",
            raw_response=response,
        )

    def stream(self, messages: list[dict], **kwargs) -> Generator[str, None, None]:
        """Stream Anthropic response"""
        if not self._anthropic_available:
            raise RuntimeError("Anthropic package not installed")

        system, chat_messages = self._extract_messages(messages)

        with self.client.messages.stream(
            model=kwargs.get("model", self.model),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
            system=system,
            messages=chat_messages,
        ) as stream:
            for text in stream.text_stream:
                yield text

    def count_tokens(self, text: str) -> int:
        """Approximate token count"""
        return len(text) // 4


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider (llama3, mistral, etc.)"""

    def __init__(
        self,
        model: str = "llama3:70b",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.7,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature

    def invoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Invoke Ollama API"""
        import httpx

        with httpx.Client(timeout=300.0) as client:
            response = client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": kwargs.get("model", self.model),
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": kwargs.get("temperature", self.temperature),
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=self.model,
            tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
            finish_reason="stop",
            raw_response=data,
        )

    async def ainvoke(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Async invoke Ollama API"""
        import httpx

        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": kwargs.get("model", self.model),
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": kwargs.get("temperature", self.temperature),
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=self.model,
            tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
            finish_reason="stop",
            raw_response=data,
        )

    def stream(self, messages: list[dict], **kwargs) -> Generator[str, None, None]:
        """Stream Ollama response"""
        import httpx
        import json

        with httpx.stream(
            "POST",
            f"{self.base_url}/api/chat",
            json={
                "model": kwargs.get("model", self.model),
                "messages": messages,
                "stream": True,
                "options": {
                    "temperature": kwargs.get("temperature", self.temperature),
                },
            },
            timeout=300.0,
        ) as response:
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    if "message" in data and "content" in data["message"]:
                        yield data["message"]["content"]

    def count_tokens(self, text: str) -> int:
        """Approximate token count"""
        return len(text) // 4


def get_llm(
    provider: str = "openai",
    model: Optional[str] = None,
    **kwargs
) -> LLMProvider:
    """
    Factory function to get LLM provider.

    Args:
        provider: One of "openai", "anthropic", "ollama"
        model: Model name (uses default if not specified)
        **kwargs: Additional provider-specific arguments

    Returns:
        LLMProvider instance

    Example:
        llm = get_llm("openai", model="gpt-4o")
        llm = get_llm("anthropic", model="claude-sonnet-4-20250514")
        llm = get_llm("ollama", model="llama3:70b")
    """
    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
    }

    if provider not in providers:
        raise ValueError(f"Unknown provider: {provider}. Choose from: {list(providers.keys())}")

    provider_class = providers[provider]

    if model:
        kwargs["model"] = model

    return provider_class(**kwargs)
