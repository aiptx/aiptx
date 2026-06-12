"""
AIPT v2 Utilities Module
========================

Provides common utilities used across the framework:
- Structured logging with secret redaction
- Model management wrappers
- Searcher utilities
"""

from .logging import get_logger, logger, setup_logging

__all__ = [
    "logger",
    "setup_logging",
    "get_logger",
]
