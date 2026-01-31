"""
AIPTX AI Checkpoints Module
===========================

Provides AI-powered checkpoints between pipeline phases using local Ollama LLMs.
Implements the "Sequential Pipeline with AI Checkpoints" pattern for intelligent
penetration testing.

Checkpoint Types:
- POST_RECON: Analyze recon results, recommend scan strategy
- POST_SCAN: Analyze vulnerabilities, plan exploitation
- POST_EXPLOIT: Evaluate results, adjust strategy

Example:
    from aipt_v2.intelligence.ai_checkpoints import AICheckpointManager

    manager = AICheckpointManager(config)

    # After recon phase
    strategy = await manager.post_recon_checkpoint(recon_findings)

    # After scan phase
    plan = await manager.post_scan_checkpoint(scan_findings)
"""

from .checkpoint_manager import AICheckpointManager, CheckpointResult, CheckpointType
from .ollama_client import OllamaCheckpointClient, OllamaConfig
from .checkpoint_prompts import (
    POST_RECON_PROMPT,
    POST_SCAN_PROMPT,
    POST_EXPLOIT_PROMPT,
    SYSTEM_PROMPT,
)
from .checkpoint_summarizers import (
    ReconSummarizer,
    ScanSummarizer,
    ExploitSummarizer,
    SummarizationConfig,
)

__all__ = [
    "AICheckpointManager",
    "CheckpointResult",
    "CheckpointType",
    "OllamaCheckpointClient",
    "OllamaConfig",
    "POST_RECON_PROMPT",
    "POST_SCAN_PROMPT",
    "POST_EXPLOIT_PROMPT",
    "SYSTEM_PROMPT",
    "ReconSummarizer",
    "ScanSummarizer",
    "ExploitSummarizer",
    "SummarizationConfig",
]
