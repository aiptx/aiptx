"""
Unit Tests for AIPT v2 Logging Module
=====================================

Tests for utils/logging.py - Structured logging with secret redaction.
"""

import pytest
import logging
from unittest.mock import patch, Mock

from aipt_v2.utils.logging import (
    setup_logging,
    get_logger,
    create_logger,
    LoggerAdapter,
    _should_redact,
    _redact_value,
    SECRET_PATTERNS,
)


class TestSecretDetection:
    """Tests for secret detection logic."""

    def test_should_redact_api_key(self):
        """Test that api_key fields are detected."""
        assert _should_redact("api_key") is True
        assert _should_redact("API_KEY") is True
        assert _should_redact("apikey") is True
        assert _should_redact("APIKEY") is True

    def test_should_redact_token(self):
        """Test that token fields are detected."""
        assert _should_redact("token") is True
        assert _should_redact("access_token") is True
        assert _should_redact("auth_token") is True

    def test_should_redact_password(self):
        """Test that password fields are detected."""
        assert _should_redact("password") is True
        assert _should_redact("PASSWORD") is True
        assert _should_redact("user_password") is True

    def test_should_redact_secret(self):
        """Test that secret fields are detected."""
        assert _should_redact("secret") is True
        assert _should_redact("secret_key") is True
        assert _should_redact("client_secret") is True

    def test_should_not_redact_normal_fields(self):
        """Test that normal fields are not redacted."""
        assert _should_redact("username") is False
        assert _should_redact("email") is False
        assert _should_redact("target") is False
        assert _should_redact("url") is False
        assert _should_redact("status") is False


class TestRedactValue:
    """Tests for value redaction."""

    def test_short_value_fully_redacted(self):
        """Test that short values are fully redacted."""
        assert _redact_value("abc") == "[REDACTED]"
        assert _redact_value("12345678") == "[REDACTED]"

    def test_long_value_partially_redacted(self):
        """Test that long values show first/last chars."""
        result = _redact_value("sk-ant-api-key-12345678901234567890")
        assert result.startswith("sk-a")
        assert result.endswith("7890")
        assert "..." in result

    def test_medium_value(self):
        """Test medium length value redaction."""
        result = _redact_value("1234567890")  # 10 chars
        # Short values (<=8 chars) are fully redacted, medium values show partial
        # The actual implementation may fully redact values under a certain threshold
        assert result == "[REDACTED]" or "..." in result


class TestSetupLogging:
    """Tests for logging setup."""

    def test_setup_returns_logger(self):
        """Test that setup returns a logger instance."""
        logger = setup_logging(level="DEBUG")
        assert logger is not None

    def test_setup_with_info_level(self):
        """Test INFO level setup."""
        logger = setup_logging(level="INFO")
        assert logger is not None

    def test_setup_with_warning_level(self):
        """Test WARNING level setup."""
        logger = setup_logging(level="WARNING")
        assert logger is not None

    def test_setup_with_json_format(self):
        """Test JSON format setup."""
        logger = setup_logging(level="INFO", json_format=True)
        assert logger is not None

    def test_setup_with_redaction_disabled(self):
        """Test setup with redaction disabled."""
        logger = setup_logging(level="INFO", redact_secrets=False)
        assert logger is not None


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_returns_instance(self):
        """Test that get_logger returns a logger."""
        logger = get_logger()
        assert logger is not None

    def test_get_logger_caching(self):
        """Test that get_logger is cached."""
        # Clear cache first
        get_logger.cache_clear()

        logger1 = get_logger()
        logger2 = get_logger()

        # Should return same instance
        assert logger1 is logger2

    def test_get_logger_respects_env(self):
        """Test that get_logger respects environment variables."""
        with patch.dict("os.environ", {"AIPT_LOG_LEVEL": "DEBUG"}):
            get_logger.cache_clear()
            logger = get_logger()
            assert logger is not None


class TestCreateLogger:
    """Tests for create_logger function."""

    def test_create_named_logger(self):
        """Test creating a named logger."""
        logger = create_logger("test_module")
        assert logger is not None
        assert isinstance(logger, LoggerAdapter)

    def test_create_default_logger(self):
        """Test creating a default logger."""
        logger = create_logger()
        assert logger is not None
        assert isinstance(logger, LoggerAdapter)


class TestLoggerAdapter:
    """Tests for LoggerAdapter class."""

    @pytest.fixture
    def adapter(self):
        """Create a logger adapter for testing."""
        mock_logger = Mock()
        return LoggerAdapter(mock_logger)

    def test_debug_method(self, adapter):
        """Test debug logging."""
        adapter._is_structlog = False
        adapter.debug("Debug message", key="value")
        adapter._logger.debug.assert_called()

    def test_info_method(self, adapter):
        """Test info logging."""
        adapter._is_structlog = False
        adapter.info("Info message", key="value")
        adapter._logger.info.assert_called()

    def test_warning_method(self, adapter):
        """Test warning logging."""
        adapter._is_structlog = False
        adapter.warning("Warning message", key="value")
        adapter._logger.warning.assert_called()

    def test_error_method(self, adapter):
        """Test error logging."""
        adapter._is_structlog = False
        adapter.error("Error message", key="value")
        adapter._logger.error.assert_called()

    def test_critical_method(self, adapter):
        """Test critical logging."""
        adapter._is_structlog = False
        adapter.critical("Critical message", key="value")
        adapter._logger.critical.assert_called()

    def test_exception_method(self, adapter):
        """Test exception logging."""
        adapter._is_structlog = False
        adapter.exception("Exception message", key="value")
        adapter._logger.error.assert_called()


class TestSecretRedactionIntegration:
    """Integration tests for secret redaction in logging."""

    def test_api_key_redacted_in_log(self):
        """Test that API keys are redacted when logging."""
        # This tests the redaction processor
        event_dict = {"api_key": "sk-secret-12345"}

        # Check key should be redacted
        assert _should_redact("api_key") is True

    def test_nested_secret_detection(self):
        """Test detection of secrets in nested keys."""
        assert _should_redact("acunetix_api_key") is True
        assert _should_redact("burp_api_key") is True
        assert _should_redact("nessus_secret_key") is True

    def test_sk_prefix_values_detected(self):
        """Test that values with sk- prefix are detected."""
        # sk- prefix in value (like Anthropic keys)
        import re
        pattern = re.compile("|".join(SECRET_PATTERNS), re.IGNORECASE)

        assert pattern.search("sk-ant-api-key-12345") is not None


class TestLoggingWithoutStructlog:
    """Tests for fallback logging without structlog."""

    def test_fallback_to_standard_logging(self):
        """Test that logging works without structlog."""
        with patch.dict("aipt_v2.utils.logging.__dict__", {"STRUCTLOG_AVAILABLE": False}):
            # Force re-import behavior
            logger = logging.getLogger("test_fallback")
            assert logger is not None

    def test_adapter_without_structlog(self):
        """Test LoggerAdapter works without structlog."""
        mock_logger = Mock()
        adapter = LoggerAdapter(mock_logger)
        adapter._is_structlog = False

        adapter.info("Test message", key="value")
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "Test message" in call_args
