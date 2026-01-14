"""AIPT LLM Configuration"""

from __future__ import annotations
import os
from typing import Optional, List


class LLMConfig:
    """Configuration for LLM interactions"""

    def __init__(
        self,
        model_name: Optional[str] = None,
        enable_prompt_caching: bool = True,
        prompt_modules: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ):
        self.model_name = model_name or os.getenv("AIPT_LLM", "openai/gpt-4")

        if not self.model_name:
            raise ValueError("AIPT_LLM environment variable must be set and not empty")

        self.enable_prompt_caching = enable_prompt_caching
        self.prompt_modules = prompt_modules or []

        self.timeout = timeout or int(os.getenv("LLM_TIMEOUT", "300"))
