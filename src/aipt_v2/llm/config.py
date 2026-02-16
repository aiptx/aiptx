"""AIPT LLM Configuration"""

from __future__ import annotations
import os
from typing import Optional, List


# Providers that require explicit prefix for litellm routing
PROVIDERS_REQUIRING_PREFIX = {
    "ollama",
    "openrouter",
    "groq",
    "together",
    "anyscale",
    "replicate",
    "huggingface",
    "bedrock",
    "vertex_ai",
    "azure",
    "deepinfra",
    "perplexity",
    "fireworks_ai",
}

# Providers where model names are auto-detected or commonly used without prefix
PROVIDERS_AUTO_DETECTED = {
    "anthropic",  # claude-* models auto-detected
    "openai",     # gpt-* models auto-detected
    "deepseek",   # deepseek-* models
}


def _build_model_name_for_litellm(provider: str, model: str) -> str:
    """
    Build the model name in litellm format by combining provider and model.

    litellm uses model name prefixes to route to the correct provider.
    For example: "ollama/llama3.2:latest", "anthropic/claude-3-7-sonnet-20250219"

    Args:
        provider: Provider name (e.g., "ollama", "anthropic", "openai")
        model: Model identifier (e.g., "llama3.2:latest", "claude-3-7-sonnet-20250219")

    Returns:
        Combined model name in litellm format
    """
    provider_lower = provider.lower().strip()
    model = model.strip()

    # If model already has a provider prefix, return as-is
    if "/" in model:
        return model

    # For providers that require explicit prefix (like Ollama), always add it
    if provider_lower in PROVIDERS_REQUIRING_PREFIX:
        return f"{provider_lower}/{model}"

    # For auto-detected providers, check if model name suggests the provider
    # and add prefix for clarity (some edge cases need it)
    if provider_lower == "anthropic" and not model.startswith("claude"):
        return f"anthropic/{model}"

    if provider_lower == "openai" and not model.startswith(("gpt", "o1", "o3", "o4", "text-", "davinci")):
        return f"openai/{model}"

    # For deepseek with custom models
    if provider_lower == "deepseek" and not model.startswith("deepseek"):
        return f"deepseek/{model}"

    # Default: return model as-is for auto-detected providers
    return model


def _get_model_name_from_env() -> str:
    """
    Get model name from environment variables.

    Checks multiple sources in priority order:
    1. AIPT_LLM - complete model name (e.g., "ollama/llama3.2:latest")
    2. AIPT_LLM__PROVIDER + AIPT_LLM__MODEL - separate provider and model
    3. Default to "anthropic/claude-3-7-sonnet-20250219"

    Returns:
        Model name in litellm format
    """
    # First, check for complete model name
    complete_model = os.getenv("AIPT_LLM")
    if complete_model and complete_model.strip():
        return complete_model.strip()

    # Check for separate provider and model (from setup wizard)
    provider = os.getenv("AIPT_LLM__PROVIDER") or os.getenv("AIPT_LLM_PROVIDER")
    model = os.getenv("AIPT_LLM__MODEL") or os.getenv("AIPT_LLM_MODEL")

    if provider and model:
        return _build_model_name_for_litellm(provider, model)

    # Fallback to default
    return "anthropic/claude-3-7-sonnet-20250219"


class LLMConfig:
    """Configuration for LLM interactions"""

    def __init__(
        self,
        model_name: Optional[str] = None,
        enable_prompt_caching: bool = True,
        prompt_modules: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ):
        self.model_name = model_name or _get_model_name_from_env()

        if not self.model_name:
            raise ValueError("AIPT_LLM environment variable must be set and not empty")

        self.enable_prompt_caching = enable_prompt_caching
        self.prompt_modules = prompt_modules or []

        self.timeout = timeout or int(os.getenv("LLM_TIMEOUT", "300"))
