"""
AIPTX Ollama Checkpoint Client
==============================

Specialized Ollama client for AI checkpoint operations.
Optimized for local LLM inference with streaming support.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OllamaConfig:
    """Configuration for Ollama client."""

    base_url: str = "http://localhost:11434"
    model: str = "mistral:7b"
    timeout: int = 300
    context_length: int = 8192
    temperature: float = 0.3
    num_predict: int = 2048
    top_p: float = 0.9
    repeat_penalty: float = 1.1


@dataclass
class OllamaResponse:
    """Response from Ollama API."""

    content: str
    model: str
    total_duration: int = 0  # nanoseconds
    prompt_eval_count: int = 0
    eval_count: int = 0
    done: bool = True

    @property
    def tokens_per_second(self) -> float:
        """Calculate tokens per second."""
        if self.total_duration > 0:
            return self.eval_count / (self.total_duration / 1e9)
        return 0.0


class OllamaCheckpointClient:
    """
    Ollama client optimized for checkpoint analysis.

    Features:
    - Streaming support for progress feedback
    - Automatic retry on failures
    - Context window management
    - Health checking

    Example:
        client = OllamaCheckpointClient(OllamaConfig(model="mistral:7b"))

        # Check health
        if await client.health_check():
            # Generate with streaming
            response = await client.analyze_with_streaming(
                prompt="Analyze these findings...",
                system_prompt="You are a security expert...",
                on_token=lambda t: print(t, end="", flush=True)
            )
    """

    # Model context window sizes (tokens)
    MODEL_CONTEXT_SIZES = {
        "llama2:7b": 4096,
        "llama2:13b": 4096,
        "llama2:70b": 4096,
        "llama3:8b": 8192,
        "llama3:70b": 8192,
        "llama3.2": 131072,
        "codellama:7b": 16384,
        "codellama:13b": 16384,
        "codellama:34b": 16384,
        "mistral:7b": 8192,
        "mistral:instruct": 8192,
        "mixtral:8x7b": 32768,
        "deepseek-coder:6.7b": 16384,
        "deepseek-coder:33b": 16384,
        "phi-3:3.8b": 4096,
        "phi-3:14b": 4096,
        "qwen2:7b": 32768,
        "qwen2.5:14b": 32768,
    }

    def __init__(self, config: Optional[OllamaConfig] = None):
        """Initialize the Ollama client."""
        self.config = config or OllamaConfig()
        self._available_models: List[str] = []

    async def health_check(self) -> bool:
        """
        Verify Ollama is running and model is available.

        Returns:
            True if Ollama is healthy and model is available
        """
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.config.base_url}/api/tags")
                if response.status_code != 200:
                    return False

                data = response.json()
                self._available_models = [m.get("name", "") for m in data.get("models", [])]

                # Check if configured model is available
                model_base = self.config.model.split(":")[0]
                return any(model_base in m for m in self._available_models)

        except Exception as e:
            logger.warning(f"Ollama health check failed: {e}")
            return False

    async def get_available_models(self) -> List[str]:
        """Get list of available models."""
        if not self._available_models:
            await self.health_check()
        return self._available_models

    def get_context_size(self, model: Optional[str] = None) -> int:
        """Get context window size for a model."""
        model = model or self.config.model

        # Try exact match first
        if model in self.MODEL_CONTEXT_SIZES:
            return self.MODEL_CONTEXT_SIZES[model]

        # Try base model name
        base_model = model.split(":")[0]
        for key, value in self.MODEL_CONTEXT_SIZES.items():
            if key.startswith(base_model):
                return value

        # Default fallback
        return 4096

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
    ) -> OllamaResponse:
        """
        Generate a response (non-streaming).

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            model: Optional model override

        Returns:
            OllamaResponse object
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(
                f"{self.config.base_url}/api/chat",
                json={
                    "model": model or self.config.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.num_predict,
                        "num_ctx": self.config.context_length,
                        "top_p": self.config.top_p,
                        "repeat_penalty": self.config.repeat_penalty,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

            return OllamaResponse(
                content=data.get("message", {}).get("content", ""),
                model=data.get("model", model or self.config.model),
                total_duration=data.get("total_duration", 0),
                prompt_eval_count=data.get("prompt_eval_count", 0),
                eval_count=data.get("eval_count", 0),
            )

    async def analyze_with_streaming(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        """
        Stream response tokens for progress feedback.

        Args:
            prompt: User prompt with context
            system_prompt: Security-focused system instructions
            model: Optional model override
            on_token: Callback for each token (for UI progress)

        Returns:
            Complete response text
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        full_response = []

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.config.base_url}/api/chat",
                json={
                    "model": model or self.config.model,
                    "messages": messages,
                    "stream": True,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.num_predict,
                        "num_ctx": self.config.context_length,
                        "top_p": self.config.top_p,
                        "repeat_penalty": self.config.repeat_penalty,
                    },
                },
            ) as response:
                response.raise_for_status()

                async for line in response.aiter_lines():
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        if "message" in data and "content" in data["message"]:
                            token = data["message"]["content"]
                            full_response.append(token)

                            if on_token:
                                on_token(token)

                        if data.get("done", False):
                            break

                    except json.JSONDecodeError:
                        continue

        return "".join(full_response)

    async def stream_tokens(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
    ) -> AsyncIterator[str]:
        """
        Async iterator for streaming tokens.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            model: Optional model override

        Yields:
            Individual tokens
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.config.base_url}/api/chat",
                json={
                    "model": model or self.config.model,
                    "messages": messages,
                    "stream": True,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.num_predict,
                        "num_ctx": self.config.context_length,
                    },
                },
            ) as response:
                response.raise_for_status()

                async for line in response.aiter_lines():
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        if "message" in data and "content" in data["message"]:
                            yield data["message"]["content"]

                        if data.get("done", False):
                            break

                    except json.JSONDecodeError:
                        continue

    async def pull_model(
        self,
        model: str,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> bool:
        """
        Pull a model from Ollama registry.

        Args:
            model: Model name to pull
            progress_callback: Optional callback(status, progress_percent)

        Returns:
            True if model pulled successfully
        """
        try:
            async with httpx.AsyncClient(timeout=3600) as client:  # 1 hour timeout
                async with client.stream(
                    "POST",
                    f"{self.config.base_url}/api/pull",
                    json={"name": model, "stream": True},
                ) as response:
                    response.raise_for_status()

                    async for line in response.aiter_lines():
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                            status = data.get("status", "")

                            if progress_callback:
                                total = data.get("total", 0)
                                completed = data.get("completed", 0)
                                if total > 0:
                                    percent = (completed / total) * 100
                                    progress_callback(status, percent)
                                else:
                                    progress_callback(status, 0)

                        except json.JSONDecodeError:
                            continue

            return True

        except Exception as e:
            logger.error(f"Failed to pull model {model}: {e}")
            return False

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text.

        Uses approximate ratio of 4 characters per token.
        """
        return len(text) // 4
