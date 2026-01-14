"""
Model Manager for AIPT v2
=========================

Provides a unified interface for LLM model access.
This is a compatibility layer for intelligence modules that
reference utils.model_manager.
"""

import os
from typing import Any, Optional, Dict, List
from dataclasses import dataclass

from aipt_v2.utils.logging import logger


@dataclass
class ModelConfig:
    """Configuration for model instances."""
    model_name: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 120


class ModelWrapper:
    """
    Wrapper around litellm for consistent model access.

    Provides both sync and async completion methods.
    """

    def __init__(self, config: ModelConfig):
        self.config = config
        self._litellm = None

    def _get_litellm(self):
        """Lazy load litellm."""
        if self._litellm is None:
            try:
                import litellm
                self._litellm = litellm
            except ImportError:
                raise ImportError(
                    "litellm is required for model_manager. "
                    "Install with: pip install litellm"
                )
        return self._litellm

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Synchronous completion.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            **kwargs: Additional arguments passed to litellm

        Returns:
            Model response text
        """
        litellm = self._get_litellm()

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = litellm.completion(
                model=self.config.model_name,
                messages=messages,
                temperature=kwargs.get("temperature", self.config.temperature),
                max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
                timeout=kwargs.get("timeout", self.config.timeout),
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error("Model completion failed", model=self.config.model_name, error=str(e))
            raise

    async def acomplete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Asynchronous completion.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            **kwargs: Additional arguments passed to litellm

        Returns:
            Model response text
        """
        litellm = self._get_litellm()

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = await litellm.acompletion(
                model=self.config.model_name,
                messages=messages,
                temperature=kwargs.get("temperature", self.config.temperature),
                max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
                timeout=kwargs.get("timeout", self.config.timeout),
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error("Async model completion failed", model=self.config.model_name, error=str(e))
            raise

    def embed(self, text: str) -> List[float]:
        """
        Get embedding for text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        litellm = self._get_litellm()

        try:
            response = litellm.embedding(
                model="text-embedding-ada-002",
                input=text,
            )
            return response.data[0]["embedding"]
        except Exception as e:
            logger.error("Embedding failed", error=str(e))
            raise


# Cache for model instances
_model_cache: Dict[str, ModelWrapper] = {}


def get_model(
    model_name: Optional[str] = None,
    **kwargs
) -> ModelWrapper:
    """
    Get or create a model instance.

    Args:
        model_name: Model identifier (default from env or gpt-4)
        **kwargs: Additional config options

    Returns:
        ModelWrapper instance
    """
    if model_name is None:
        model_name = os.getenv("AIPT_LLM_MODEL", "gpt-4")

    cache_key = f"{model_name}:{hash(frozenset(kwargs.items()))}"

    if cache_key not in _model_cache:
        config = ModelConfig(
            model_name=model_name,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens", 4096),
            timeout=kwargs.get("timeout", 120),
        )
        _model_cache[cache_key] = ModelWrapper(config)
        logger.info("Created model instance", model=model_name)

    return _model_cache[cache_key]


def clear_model_cache():
    """Clear the model cache."""
    global _model_cache
    _model_cache = {}
    logger.info("Model cache cleared")
