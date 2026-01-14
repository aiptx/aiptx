"""
AIPT v2 Utilities Module
========================

Provides common utilities used across the framework:
- Structured logging with secret redaction
- Model management wrappers
- Searcher utilities
"""

from .logging import logger, setup_logging, get_logger

__all__ = [
    "logger",
    "setup_logging",
    "get_logger",
]
