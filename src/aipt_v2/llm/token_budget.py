"""
AIPTX Token Budget Manager
==========================

Manages token allocation for local LLMs with limited context windows.
Provides accurate token estimation and dynamic budget allocation.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TokenBudget:
    """Token budget allocation."""

    total: int
    system_prompt: int
    conversation_history: int
    current_findings: int
    phase_context: int
    reserved_for_response: int

    @property
    def available_for_content(self) -> int:
        """Tokens available for dynamic content."""
        return self.total - self.system_prompt - self.reserved_for_response

    @property
    def used(self) -> int:
        """Total tokens allocated."""
        return (
            self.system_prompt
            + self.conversation_history
            + self.current_findings
            + self.phase_context
            + self.reserved_for_response
        )

    @property
    def remaining(self) -> int:
        """Remaining unallocated tokens."""
        return self.total - self.used

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "system_prompt": self.system_prompt,
            "conversation_history": self.conversation_history,
            "current_findings": self.current_findings,
            "phase_context": self.phase_context,
            "reserved_for_response": self.reserved_for_response,
            "available": self.available_for_content,
            "remaining": self.remaining,
        }


class TokenEstimator:
    """
    Accurate token estimation for different LLM models.

    Different models use different tokenizers, so we apply
    model-specific multipliers to improve accuracy.
    """

    # Model context window sizes
    MODEL_CONTEXT_LIMITS = {
        # Llama 2
        "llama2:7b": 4096,
        "llama2:13b": 4096,
        "llama2:70b": 4096,
        # Llama 3
        "llama3:8b": 8192,
        "llama3:70b": 8192,
        "llama3.1:8b": 131072,
        "llama3.2": 131072,
        # CodeLlama
        "codellama:7b": 16384,
        "codellama:13b": 16384,
        "codellama:34b": 16384,
        # Mistral
        "mistral:7b": 8192,
        "mistral:instruct": 8192,
        "mixtral:8x7b": 32768,
        # DeepSeek
        "deepseek-coder:6.7b": 16384,
        "deepseek-coder:33b": 16384,
        "deepseek-r1:8b": 32768,
        # Phi
        "phi-3:3.8b": 4096,
        "phi-3:14b": 4096,
        # Qwen
        "qwen2:7b": 32768,
        "qwen2.5:14b": 32768,
        "qwen2.5:32b": 32768,
        # Gemma
        "gemma:7b": 8192,
        "gemma2:9b": 8192,
    }

    # Token estimation multipliers (chars per token varies by model)
    MODEL_MULTIPLIERS = {
        "llama": 1.1,      # Llama tokenizes slightly more
        "mistral": 1.0,    # Baseline
        "codellama": 0.95, # Code-optimized, slightly fewer tokens
        "deepseek": 0.95,  # Similar to codellama
        "phi": 1.05,       # Microsoft's tokenizer
        "qwen": 1.0,       # Standard
        "gemma": 1.0,      # Standard
    }

    def __init__(self, model: str = "mistral:7b"):
        """Initialize with model name."""
        self.model = model
        self._multiplier = self._get_multiplier(model)

    def _get_multiplier(self, model: str) -> float:
        """Get tokenization multiplier for model."""
        model_lower = model.lower()
        for prefix, mult in self.MODEL_MULTIPLIERS.items():
            if prefix in model_lower:
                return mult
        return 1.0  # Default

    def get_context_limit(self, model: Optional[str] = None) -> int:
        """Get context window limit for model."""
        model = model or self.model

        # Exact match
        if model in self.MODEL_CONTEXT_LIMITS:
            return self.MODEL_CONTEXT_LIMITS[model]

        # Try base name
        base = model.split(":")[0]
        for key, value in self.MODEL_CONTEXT_LIMITS.items():
            if key.startswith(base):
                return value

        # Default fallback
        return 4096

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text.

        Uses approximately 4 characters per token as baseline,
        adjusted by model-specific multiplier.
        """
        if not text:
            return 0

        # Base estimate: ~4 chars per token
        base_estimate = len(text) / 4

        # Apply multiplier
        return int(base_estimate * self._multiplier)

    def estimate_messages_tokens(self, messages: List[Dict[str, str]]) -> int:
        """
        Estimate tokens for a list of messages.

        Accounts for message structure overhead.
        """
        total = 0
        for msg in messages:
            # Message overhead (~4 tokens for role/structure)
            total += 4
            # Content tokens
            content = msg.get("content", "")
            total += self.estimate_tokens(content)

        return total

    def fits_in_context(
        self,
        text: str,
        budget: int,
        model: Optional[str] = None
    ) -> bool:
        """Check if text fits within budget."""
        return self.estimate_tokens(text) <= budget

    def truncate_to_budget(
        self,
        text: str,
        budget: int,
        preserve_end: bool = False
    ) -> str:
        """
        Truncate text to fit within token budget.

        Args:
            text: Text to truncate
            budget: Maximum tokens
            preserve_end: If True, keep end instead of start

        Returns:
            Truncated text
        """
        estimated = self.estimate_tokens(text)
        if estimated <= budget:
            return text

        # Calculate approximate character limit
        char_limit = int(budget * 4 / self._multiplier)

        if preserve_end:
            return "..." + text[-char_limit:]
        else:
            return text[:char_limit] + "..."


class BudgetAllocator:
    """
    Allocates token budget across context components.

    Implements dynamic allocation strategies based on content needs.
    """

    # Default allocation percentages (of available tokens after fixed allocations)
    DEFAULT_ALLOCATIONS = {
        "conversation_history": 0.40,  # 40%
        "current_findings": 0.40,       # 40%
        "phase_context": 0.20,          # 20%
    }

    # Fixed allocations
    DEFAULT_SYSTEM_PROMPT = 1500
    DEFAULT_RESPONSE_RESERVATION = 1000

    def __init__(
        self,
        estimator: Optional[TokenEstimator] = None,
        system_prompt_tokens: int = 1500,
        response_reservation: int = 1000,
    ):
        """Initialize budget allocator."""
        self.estimator = estimator or TokenEstimator()
        self.system_prompt_tokens = system_prompt_tokens
        self.response_reservation = response_reservation

    def allocate(
        self,
        total_context: int,
        conversation_weight: float = 0.4,
        findings_weight: float = 0.4,
        context_weight: float = 0.2,
    ) -> TokenBudget:
        """
        Allocate token budget.

        Args:
            total_context: Total context window size
            conversation_weight: Weight for conversation history
            findings_weight: Weight for current findings
            context_weight: Weight for phase context

        Returns:
            TokenBudget allocation
        """
        # Fixed allocations
        fixed = self.system_prompt_tokens + self.response_reservation

        # Available for dynamic allocation
        available = total_context - fixed

        if available <= 0:
            # Minimal allocation for very small context windows
            available = max(total_context // 2, 500)

        # Normalize weights
        total_weight = conversation_weight + findings_weight + context_weight
        if total_weight > 0:
            conversation_weight /= total_weight
            findings_weight /= total_weight
            context_weight /= total_weight

        return TokenBudget(
            total=total_context,
            system_prompt=self.system_prompt_tokens,
            conversation_history=int(available * conversation_weight),
            current_findings=int(available * findings_weight),
            phase_context=int(available * context_weight),
            reserved_for_response=self.response_reservation,
        )

    def allocate_for_checkpoint(
        self,
        checkpoint_type: str,
        total_context: int,
    ) -> TokenBudget:
        """
        Allocate budget optimized for checkpoint type.

        Different checkpoints have different content priorities.
        """
        if checkpoint_type == "post_recon":
            # More space for findings (recon generates lots of data)
            return self.allocate(
                total_context,
                conversation_weight=0.2,
                findings_weight=0.6,
                context_weight=0.2,
            )
        elif checkpoint_type == "post_scan":
            # Balanced - need vuln details and attack surface
            return self.allocate(
                total_context,
                conversation_weight=0.2,
                findings_weight=0.5,
                context_weight=0.3,
            )
        elif checkpoint_type == "post_exploit":
            # More context needed (previous attempts, chain state)
            return self.allocate(
                total_context,
                conversation_weight=0.3,
                findings_weight=0.3,
                context_weight=0.4,
            )
        else:
            # Default balanced allocation
            return self.allocate(total_context)

    def reallocate_dynamically(
        self,
        budget: TokenBudget,
        actual_conversation: int,
        actual_findings: int,
        actual_context: int,
    ) -> TokenBudget:
        """
        Reallocate budget based on actual content sizes.

        If one component is smaller than allocated, redistribute
        to components that need more space.
        """
        # Calculate unused tokens
        conv_unused = max(0, budget.conversation_history - actual_conversation)
        findings_unused = max(0, budget.current_findings - actual_findings)
        context_unused = max(0, budget.phase_context - actual_context)

        total_unused = conv_unused + findings_unused + context_unused

        if total_unused <= 0:
            return budget

        # Redistribute to components that need more
        conv_overflow = max(0, actual_conversation - budget.conversation_history)
        findings_overflow = max(0, actual_findings - budget.current_findings)
        context_overflow = max(0, actual_context - budget.phase_context)

        total_overflow = conv_overflow + findings_overflow + context_overflow

        if total_overflow <= 0:
            return budget

        # Proportional redistribution
        redistribution_ratio = min(1.0, total_unused / total_overflow)

        new_conversation = budget.conversation_history + int(conv_overflow * redistribution_ratio) - conv_unused
        new_findings = budget.current_findings + int(findings_overflow * redistribution_ratio) - findings_unused
        new_context = budget.phase_context + int(context_overflow * redistribution_ratio) - context_unused

        return TokenBudget(
            total=budget.total,
            system_prompt=budget.system_prompt,
            conversation_history=max(0, new_conversation),
            current_findings=max(0, new_findings),
            phase_context=max(0, new_context),
            reserved_for_response=budget.reserved_for_response,
        )


class TokenBudgetManager:
    """
    High-level token budget management for AIPTX.

    Combines estimation and allocation for easy use.
    """

    def __init__(self, model: str = "mistral:7b"):
        """Initialize manager for model."""
        self.estimator = TokenEstimator(model)
        self.allocator = BudgetAllocator(self.estimator)
        self.model = model

    def get_budget(self, checkpoint_type: str = "default") -> TokenBudget:
        """Get budget allocation for checkpoint type."""
        context_limit = self.estimator.get_context_limit()
        return self.allocator.allocate_for_checkpoint(checkpoint_type, context_limit)

    def estimate(self, text: str) -> int:
        """Estimate tokens for text."""
        return self.estimator.estimate_tokens(text)

    def fits(self, text: str, budget: int) -> bool:
        """Check if text fits budget."""
        return self.estimator.fits_in_context(text, budget)

    def truncate(self, text: str, budget: int, keep_end: bool = False) -> str:
        """Truncate text to fit budget."""
        return self.estimator.truncate_to_budget(text, budget, preserve_end=keep_end)

    def prepare_context(
        self,
        system_prompt: str,
        conversation: List[Dict[str, str]],
        findings_text: str,
        phase_context: str,
        checkpoint_type: str = "default",
    ) -> Tuple[str, str, str]:
        """
        Prepare context components to fit within budget.

        Returns truncated versions if needed.

        Args:
            system_prompt: System prompt (usually kept intact)
            conversation: Conversation messages
            findings_text: Current findings summary
            phase_context: Phase-specific context

        Returns:
            Tuple of (system_prompt, findings, context) - truncated if needed
        """
        budget = self.get_budget(checkpoint_type)

        # Estimate actual sizes
        conv_tokens = self.estimator.estimate_messages_tokens(conversation)
        findings_tokens = self.estimate(findings_text)
        context_tokens = self.estimate(phase_context)

        # Reallocate if needed
        budget = self.allocator.reallocate_dynamically(
            budget, conv_tokens, findings_tokens, context_tokens
        )

        # Truncate if over budget
        final_findings = findings_text
        if findings_tokens > budget.current_findings:
            final_findings = self.truncate(findings_text, budget.current_findings)

        final_context = phase_context
        if context_tokens > budget.phase_context:
            final_context = self.truncate(phase_context, budget.phase_context)

        return system_prompt, final_findings, final_context
