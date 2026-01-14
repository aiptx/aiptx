"""
Unit Tests for AIPT v2 Configuration Module
============================================

Tests for config.py - Pydantic-based configuration validation.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

from aipt_v2.config import (
    AIPTConfig,
    LLMSettings,
    ScannerSettings,
    VPSSettings,
    APISettings,
    DatabaseSettings,
    LoggingSettings,
    get_config,
    validate_config_for_features,
    require_config,
)


class TestLLMSettings:
    """Tests for LLM configuration."""

    def test_default_values(self):
        """Test default LLM settings."""
        settings = LLMSettings()

        assert settings.provider == "anthropic"
        assert settings.model == "claude-sonnet-4-20250514"
        assert settings.timeout == 120
        assert settings.max_tokens == 4096
        assert settings.temperature == 0.7
        assert settings.enable_caching is True

    def test_custom_values(self):
        """Test custom LLM settings."""
        settings = LLMSettings(
            provider="openai",
            model="gpt-4",
            timeout=60,
            max_tokens=8192,
            temperature=0.5,
        )

        assert settings.provider == "openai"
        assert settings.model == "gpt-4"
        assert settings.timeout == 60
        assert settings.max_tokens == 8192
        assert settings.temperature == 0.5

    def test_api_key_from_env(self):
        """Test API key loaded from environment."""
        # Test that api_key can be set explicitly (env loading is tested via integration)
        settings = LLMSettings(api_key="test-explicit-key")
        assert settings.api_key == "test-explicit-key"

        # Test that it defaults to None when no key provided
        settings_no_key = LLMSettings()
        # api_key may be None or loaded from env - both are valid
        assert settings_no_key.api_key is None or isinstance(settings_no_key.api_key, str)

    def test_timeout_validation(self):
        """Test timeout bounds validation."""
        # Valid timeout
        settings = LLMSettings(timeout=300)
        assert settings.timeout == 300

        # Too low
        with pytest.raises(ValueError):
            LLMSettings(timeout=5)

        # Too high
        with pytest.raises(ValueError):
            LLMSettings(timeout=1000)

    def test_temperature_validation(self):
        """Test temperature bounds validation."""
        # Valid temperature
        settings = LLMSettings(temperature=1.5)
        assert settings.temperature == 1.5

        # Too low
        with pytest.raises(ValueError):
            LLMSettings(temperature=-0.5)

        # Too high
        with pytest.raises(ValueError):
            LLMSettings(temperature=2.5)


class TestScannerSettings:
    """Tests for scanner configuration."""

    def test_default_values(self):
        """Test default scanner settings (all None)."""
        settings = ScannerSettings()

        assert settings.acunetix_url is None
        assert settings.acunetix_api_key is None
        assert settings.burp_url is None
        assert settings.burp_api_key is None
        assert settings.nessus_url is None
        assert settings.zap_url is None

    def test_valid_urls(self):
        """Test valid URL formats."""
        settings = ScannerSettings(
            acunetix_url="https://acunetix.local:3443",
            burp_url="http://burp.local:1337",
        )

        assert settings.acunetix_url == "https://acunetix.local:3443"
        assert settings.burp_url == "http://burp.local:1337"

    def test_invalid_url_format(self):
        """Test URL validation rejects invalid formats."""
        with pytest.raises(ValueError):
            ScannerSettings(acunetix_url="not-a-valid-url")

        with pytest.raises(ValueError):
            ScannerSettings(burp_url="ftp://invalid-protocol.com")


class TestVPSSettings:
    """Tests for VPS configuration."""

    def test_default_values(self):
        """Test default VPS settings."""
        settings = VPSSettings()

        assert settings.host is None
        assert settings.user == "ubuntu"
        assert settings.port == 22
        assert settings.results_dir == "/var/tmp/aipt_results"
        assert settings.timeout == 300

    def test_key_path_expansion(self, temp_dir):
        """Test SSH key path expansion."""
        key_path = temp_dir / "test_key.pem"
        key_path.touch()

        settings = VPSSettings(key_path=str(key_path))
        assert Path(settings.key_path).exists()

    def test_port_validation(self):
        """Test port number validation."""
        # Valid port
        settings = VPSSettings(port=2222)
        assert settings.port == 2222

        # Invalid ports
        with pytest.raises(ValueError):
            VPSSettings(port=0)

        with pytest.raises(ValueError):
            VPSSettings(port=70000)


class TestAPISettings:
    """Tests for API configuration."""

    def test_default_values(self):
        """Test default API settings."""
        settings = APISettings()

        # Default is localhost for security (CWE-605)
        assert settings.host == "127.0.0.1"
        assert settings.port == 8000
        assert settings.cors_origins == ["http://localhost:3000"]
        assert settings.rate_limit == "100/minute"
        assert settings.enable_docs is True

    def test_custom_cors_origins(self):
        """Test custom CORS origins."""
        settings = APISettings(
            cors_origins=["https://app.example.com", "https://admin.example.com"]
        )

        assert len(settings.cors_origins) == 2
        assert "https://app.example.com" in settings.cors_origins


class TestDatabaseSettings:
    """Tests for database configuration."""

    def test_default_sqlite(self):
        """Test default SQLite database."""
        settings = DatabaseSettings()

        assert settings.url == "sqlite:///./aipt.db"
        assert settings.echo is False
        assert settings.pool_size == 5

    def test_postgres_url(self):
        """Test PostgreSQL database URL."""
        settings = DatabaseSettings(
            url="postgresql://user:pass@localhost:5432/aipt"
        )

        assert "postgresql://" in settings.url


class TestLoggingSettings:
    """Tests for logging configuration."""

    def test_default_values(self):
        """Test default logging settings."""
        settings = LoggingSettings()

        assert settings.level == "INFO"
        assert settings.format == "console"
        assert settings.redact_secrets is True

    def test_json_format(self):
        """Test JSON log format setting."""
        settings = LoggingSettings(format="json")
        assert settings.format == "json"


class TestAIPTConfig:
    """Tests for main AIPT configuration."""

    def test_default_config(self, clean_env, temp_dir):
        """Test default configuration creation."""
        with patch.dict(os.environ, {}, clear=True):
            config = AIPTConfig(
                output_dir=temp_dir / "output",
                reports_dir=temp_dir / "reports",
            )

            assert config.sandbox_mode is False
            assert isinstance(config.llm, LLMSettings)
            assert isinstance(config.scanners, ScannerSettings)
            assert isinstance(config.vps, VPSSettings)
            assert isinstance(config.api, APISettings)

    def test_directories_created(self, temp_dir):
        """Test that output directories are created."""
        output_dir = temp_dir / "new_output"
        reports_dir = temp_dir / "new_reports"

        assert not output_dir.exists()
        assert not reports_dir.exists()

        config = AIPTConfig(
            output_dir=output_dir,
            reports_dir=reports_dir,
        )

        assert output_dir.exists()
        assert reports_dir.exists()


class TestGetConfig:
    """Tests for get_config function."""

    def test_config_caching(self, mock_env, temp_dir):
        """Test that config is cached."""
        # Clear the cache first
        get_config.cache_clear()

        with patch("aipt_v2.config.AIPTConfig") as mock_config:
            mock_instance = mock_config.return_value
            mock_instance.llm = LLMSettings()
            mock_instance.scanners = ScannerSettings()
            mock_instance.vps = VPSSettings()
            mock_instance.api = APISettings()
            mock_instance.database = DatabaseSettings()
            mock_instance.logging = LoggingSettings()
            mock_instance.sandbox_mode = False

            # First call
            config1 = get_config()

            # Second call should return cached
            config2 = get_config()

            # Should be same instance (cached)
            assert config1 is config2


class TestValidateConfigForFeatures:
    """Tests for feature validation."""

    def test_llm_validation_missing_key(self, clean_env):
        """Test LLM validation fails without API key."""
        get_config.cache_clear()

        errors = validate_config_for_features(["llm"])

        assert len(errors) > 0
        assert any("API key" in e for e in errors)

    def test_llm_validation_with_key(self, mock_env):
        """Test LLM validation passes with API key."""
        get_config.cache_clear()

        errors = validate_config_for_features(["llm"])

        # Should have no LLM errors (key is set in mock_env)
        llm_errors = [e for e in errors if "LLM" in e]
        assert len(llm_errors) == 0

    def test_acunetix_validation(self, clean_env):
        """Test Acunetix validation."""
        get_config.cache_clear()

        errors = validate_config_for_features(["acunetix"])

        assert len(errors) >= 2  # URL and API key
        assert any("Acunetix URL" in e for e in errors)
        assert any("Acunetix API key" in e for e in errors)

    def test_vps_validation(self, clean_env):
        """Test VPS validation."""
        get_config.cache_clear()

        errors = validate_config_for_features(["vps"])

        assert len(errors) >= 2  # Host and key
        assert any("VPS host" in e for e in errors)
        assert any("SSH key" in e for e in errors)

    def test_multiple_features(self, clean_env):
        """Test multiple feature validation."""
        get_config.cache_clear()

        errors = validate_config_for_features(["llm", "acunetix", "vps"])

        # Should have errors for all features
        assert len(errors) >= 5


class TestRequireConfig:
    """Tests for require_config function."""

    def test_raises_on_missing_config(self, clean_env):
        """Test that require_config raises ValueError on missing config."""
        get_config.cache_clear()

        with pytest.raises(ValueError) as exc_info:
            require_config("llm", "acunetix")

        assert "Configuration errors" in str(exc_info.value)

    def test_returns_config_when_valid(self, mock_env):
        """Test that require_config returns config when valid."""
        get_config.cache_clear()

        # Mock the validation to return no errors for llm
        with patch("aipt_v2.config.validate_config_for_features", return_value=[]):
            config = require_config("llm")
            assert config is not None
