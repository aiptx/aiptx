"""
Structured Logging Configuration for AIPT v2
=============================================

Provides:
- Structured logging via structlog
- Automatic secret redaction
- JSON format for production
- Console format for development
"""

import logging
import os
import sys
import re
from typing import Any, Optional
from functools import lru_cache

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False


# Patterns for secret redaction
SECRET_PATTERNS = [
    r"api[_-]?key",
    r"apikey",
    r"token",
    r"secret",
    r"password",
    r"credential",
    r"auth",
    r"bearer",
    r"sk-[a-zA-Z0-9]+",
    r"pk-[a-zA-Z0-9]+",
    r"access[_-]?key",
    r"private[_-]?key",
]

SECRET_REGEX = re.compile("|".join(SECRET_PATTERNS), re.IGNORECASE)


def _should_redact(key: str) -> bool:
    """Check if a key should be redacted."""
    return bool(SECRET_REGEX.search(key))


def _redact_value(value: str) -> str:
    """Redact a sensitive value, keeping first/last chars for debugging."""
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...{value[-4:]}"


def _redact_processor(logger: Any, method_name: str, event_dict: dict) -> dict:
    """Structlog processor to redact sensitive information."""
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            if _should_redact(key):
                event_dict[key] = "[REDACTED]"
            elif len(value) > 20 and SECRET_REGEX.search(value):
                event_dict[key] = _redact_value(value)
    return event_dict


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    redact_secrets: bool = True,
) -> Any:
    """
    Configure structured logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON format (for production)
        redact_secrets: Automatically redact sensitive values

    Returns:
        Configured logger instance
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    if STRUCTLOG_AVAILABLE:
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
        ]

        if redact_secrets:
            processors.append(_redact_processor)

        if json_format:
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer(colors=True))

        structlog.configure(
            processors=processors,
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=log_level,
        )

        return structlog.get_logger()
    else:
        # Fallback to standard logging
        logging.basicConfig(
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stdout,
            level=log_level,
        )
        return logging.getLogger("aipt_v2")


@lru_cache(maxsize=1)
def get_logger() -> Any:
    """Get or create the global logger instance."""
    log_level = os.getenv("AIPT_LOG_LEVEL", "INFO")
    json_format = os.getenv("AIPT_LOG_FORMAT", "console").lower() == "json"
    redact = os.getenv("AIPT_REDACT_SECRETS", "true").lower() == "true"

    return setup_logging(
        level=log_level,
        json_format=json_format,
        redact_secrets=redact,
    )


# Global logger instance
logger = get_logger()


class LoggerAdapter:
    """
    Adapter for consistent logging interface.

    Provides methods that work whether structlog is available or not.
    """

    def __init__(self, logger_instance: Any):
        self._logger = logger_instance
        self._is_structlog = STRUCTLOG_AVAILABLE

    def _log(self, level: str, msg: str, **kwargs):
        """Internal log method."""
        if self._is_structlog:
            getattr(self._logger, level)(msg, **kwargs)
        else:
            extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
            full_msg = f"{msg} {extra}" if extra else msg
            getattr(self._logger, level)(full_msg)

    def debug(self, msg: str, **kwargs):
        self._log("debug", msg, **kwargs)

    def info(self, msg: str, **kwargs):
        self._log("info", msg, **kwargs)

    def warning(self, msg: str, **kwargs):
        self._log("warning", msg, **kwargs)

    def error(self, msg: str, exc_info: bool = False, **kwargs):
        if self._is_structlog:
            if exc_info:
                kwargs["exc_info"] = True
            self._logger.error(msg, **kwargs)
        else:
            extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
            full_msg = f"{msg} {extra}" if extra else msg
            self._logger.error(full_msg, exc_info=exc_info)

    def critical(self, msg: str, **kwargs):
        self._log("critical", msg, **kwargs)

    def exception(self, msg: str, **kwargs):
        """Log exception with traceback."""
        self.error(msg, exc_info=True, **kwargs)


# Export a wrapped logger for consistent interface
def create_logger(name: Optional[str] = None) -> LoggerAdapter:
    """Create a named logger instance."""
    if STRUCTLOG_AVAILABLE:
        base_logger = structlog.get_logger(name) if name else get_logger()
    else:
        base_logger = logging.getLogger(name or "aipt_v2")

    return LoggerAdapter(base_logger)
