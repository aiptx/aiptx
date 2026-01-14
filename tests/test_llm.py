"""
Unit Tests for AIPT v2 LLM Module
=================================

Tests for llm/ - Universal LLM interface via litellm.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio


# ============== LLMConfig Tests ==============

class TestLLMConfig:
    """Tests for LLMConfig class."""

    def test_default_model_from_env(self):
        """Test model defaults from environment."""
        with patch.dict("os.environ", {"AIPT_LLM": "anthropic/claude-3-opus"}):
            from aipt_v2.llm.config import LLMConfig
            config = LLMConfig()
            assert config.model_name == "anthropic/claude-3-opus"

    def test_explicit_model_name(self):
        """Test explicit model name overrides env."""
        from aipt_v2.llm.config import LLMConfig
        config = LLMConfig(model_name="openai/gpt-4")
        assert config.model_name == "openai/gpt-4"

    def test_default_model_fallback(self):
        """Test default fallback when env not set."""
        with patch.dict("os.environ", {}, clear=True):
            # Remove AIPT_LLM if present
            import os
            os.environ.pop("AIPT_LLM", None)

            from aipt_v2.llm.config import LLMConfig
            config = LLMConfig()
            # Should default to "openai/gpt-4"
            assert config.model_name == "openai/gpt-4"

    def test_prompt_caching_default(self):
        """Test prompt caching is enabled by default."""
        from aipt_v2.llm.config import LLMConfig
        config = LLMConfig(model_name="test-model")
        assert config.enable_prompt_caching is True

    def test_prompt_caching_disabled(self):
        """Test prompt caching can be disabled."""
        from aipt_v2.llm.config import LLMConfig
        config = LLMConfig(model_name="test-model", enable_prompt_caching=False)
        assert config.enable_prompt_caching is False

    def test_timeout_from_env(self):
        """Test timeout from environment variable."""
        with patch.dict("os.environ", {"LLM_TIMEOUT": "600"}):
            from aipt_v2.llm.config import LLMConfig
            config = LLMConfig(model_name="test-model")
            assert config.timeout == 600

    def test_timeout_default(self):
        """Test default timeout."""
        with patch.dict("os.environ", {}, clear=True):
            import os
            os.environ.pop("LLM_TIMEOUT", None)

            from aipt_v2.llm.config import LLMConfig
            config = LLMConfig(model_name="test-model")
            assert config.timeout == 300  # Default

    def test_prompt_modules_default(self):
        """Test prompt modules default to empty list."""
        from aipt_v2.llm.config import LLMConfig
        config = LLMConfig(model_name="test-model")
        assert config.prompt_modules == []

    def test_prompt_modules_custom(self):
        """Test custom prompt modules."""
        from aipt_v2.llm.config import LLMConfig
        modules = ["recon", "exploit"]
        config = LLMConfig(model_name="test-model", prompt_modules=modules)
        assert config.prompt_modules == modules


# ============== Model Name Utilities Tests ==============

class TestModelNameUtilities:
    """Tests for model name normalization and matching."""

    def test_normalize_basic_name(self):
        """Test basic model name normalization."""
        from aipt_v2.llm.llm import normalize_model_name
        assert normalize_model_name("GPT-4") == "gpt-4"
        assert normalize_model_name("Claude-3-Opus") == "claude-3-opus"

    def test_normalize_with_provider(self):
        """Test normalization strips provider prefix."""
        from aipt_v2.llm.llm import normalize_model_name
        assert normalize_model_name("openai/gpt-4") == "gpt-4"
        assert normalize_model_name("anthropic/claude-3-opus") == "claude-3-opus"

    def test_normalize_with_version(self):
        """Test normalization handles version suffixes."""
        from aipt_v2.llm.llm import normalize_model_name
        assert normalize_model_name("ollama/llama3:latest") == "llama3"

    def test_normalize_gguf_suffix(self):
        """Test normalization removes GGUF suffix."""
        from aipt_v2.llm.llm import normalize_model_name
        assert normalize_model_name("model-name-gguf") == "model-name"

    def test_normalize_whitespace(self):
        """Test normalization handles whitespace."""
        from aipt_v2.llm.llm import normalize_model_name
        assert normalize_model_name("  gpt-4  ") == "gpt-4"

    def test_model_matches_exact(self):
        """Test exact model matching."""
        from aipt_v2.llm.llm import model_matches
        assert model_matches("o1", ["o1"]) is True
        assert model_matches("gpt-4", ["gpt-4"]) is True

    def test_model_matches_wildcard(self):
        """Test wildcard model matching."""
        from aipt_v2.llm.llm import model_matches
        assert model_matches("o1-2024-12-17", ["o1*"]) is True
        assert model_matches("gpt-5-turbo", ["gpt-5*"]) is True

    def test_model_matches_with_provider(self):
        """Test model matching with provider prefix."""
        from aipt_v2.llm.llm import model_matches
        assert model_matches("openai/gpt-4", ["openai/gpt-4"]) is True
        assert model_matches("openai/gpt-4", ["gpt-4"]) is True

    def test_model_matches_case_insensitive(self):
        """Test case insensitive matching."""
        from aipt_v2.llm.llm import model_matches
        assert model_matches("GPT-4", ["gpt-4"]) is True
        assert model_matches("gpt-4", ["GPT-4"]) is True


# ============== RequestStats Tests ==============

class TestRequestStats:
    """Tests for RequestStats dataclass."""

    def test_default_values(self):
        """Test default RequestStats values."""
        from aipt_v2.llm.llm import RequestStats
        stats = RequestStats()
        assert stats.input_tokens == 0
        assert stats.output_tokens == 0
        assert stats.cached_tokens == 0
        assert stats.cache_creation_tokens == 0
        assert stats.cost == 0.0
        assert stats.requests == 0
        assert stats.failed_requests == 0

    def test_custom_values(self):
        """Test RequestStats with custom values."""
        from aipt_v2.llm.llm import RequestStats
        stats = RequestStats(
            input_tokens=100,
            output_tokens=50,
            cached_tokens=25,
            cost=0.005,
            requests=1,
        )
        assert stats.input_tokens == 100
        assert stats.output_tokens == 50
        assert stats.cached_tokens == 25
        assert stats.cost == 0.005
        assert stats.requests == 1

    def test_to_dict(self):
        """Test RequestStats serialization."""
        from aipt_v2.llm.llm import RequestStats
        stats = RequestStats(
            input_tokens=100,
            output_tokens=50,
            cost=0.00567,
            requests=1,
        )
        result = stats.to_dict()

        assert result["input_tokens"] == 100
        assert result["output_tokens"] == 50
        assert result["cost"] == 0.0057  # Rounded to 4 decimals
        assert result["requests"] == 1


# ============== LLMResponse Tests ==============

class TestLLMResponse:
    """Tests for LLMResponse dataclass."""

    def test_default_values(self):
        """Test default LLMResponse values."""
        from aipt_v2.llm.llm import LLMResponse, StepRole
        response = LLMResponse(content="Test response")

        assert response.content == "Test response"
        assert response.tool_invocations is None
        assert response.scan_id is None
        assert response.step_number == 1
        assert response.role == StepRole.AGENT

    def test_with_tool_invocations(self):
        """Test LLMResponse with tool invocations."""
        from aipt_v2.llm.llm import LLMResponse
        tools = [{"name": "nmap", "args": {"target": "example.com"}}]
        response = LLMResponse(
            content="Running nmap scan",
            tool_invocations=tools,
        )

        assert response.tool_invocations == tools

    def test_with_scan_context(self):
        """Test LLMResponse with scan context."""
        from aipt_v2.llm.llm import LLMResponse
        response = LLMResponse(
            content="Test",
            scan_id="scan-123",
            step_number=5,
        )

        assert response.scan_id == "scan-123"
        assert response.step_number == 5


# ============== LLM Class Tests ==============

class TestLLMClass:
    """Tests for LLM class."""

    @pytest.fixture
    def mock_litellm(self):
        """Mock litellm module."""
        with patch("aipt_v2.llm.llm.litellm") as mock:
            mock.drop_params = True
            mock.modify_params = True
            yield mock

    @pytest.fixture
    def mock_config(self):
        """Create a mock LLM config."""
        from aipt_v2.llm.config import LLMConfig
        return LLMConfig(
            model_name="anthropic/claude-3-opus",
            enable_prompt_caching=True,
            timeout=120,
        )

    def test_llm_initialization(self, mock_litellm, mock_config):
        """Test LLM initialization without agent."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            assert llm.config == mock_config
            assert llm.agent_name is None
            assert llm.system_prompt == "You are a helpful AI assistant."

    def test_llm_with_agent_identity(self, mock_litellm, mock_config):
        """Test LLM with agent identity."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            llm.set_agent_identity("recon_agent", "agent-123")

            assert llm.agent_name == "recon_agent"
            assert llm.agent_id == "agent-123"

    def test_is_anthropic_model(self, mock_litellm, mock_config):
        """Test Anthropic model detection."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            assert llm._is_anthropic_model() is True

    def test_is_not_anthropic_model(self, mock_litellm):
        """Test non-Anthropic model detection."""
        from aipt_v2.llm.config import LLMConfig
        config = LLMConfig(model_name="openai/gpt-4")

        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=config)

            assert llm._is_anthropic_model() is False

    def test_usage_stats_property(self, mock_litellm, mock_config):
        """Test usage stats property."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            stats = llm.usage_stats

            assert "total" in stats
            assert "last_request" in stats
            assert stats["total"]["requests"] == 0

    def test_get_cache_config(self, mock_litellm, mock_config):
        """Test cache config retrieval."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"), \
             patch("aipt_v2.llm.llm.supports_prompt_caching", return_value=True):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            cache_config = llm.get_cache_config()

            assert cache_config["enabled"] is True
            assert cache_config["supported"] is True

    def test_should_include_stop_param(self, mock_litellm, mock_config):
        """Test stop parameter inclusion logic."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            # Anthropic models should include stop param
            assert llm._should_include_stop_param() is True

    def test_should_not_include_stop_for_o1(self, mock_litellm):
        """Test stop param excluded for o1 models."""
        from aipt_v2.llm.config import LLMConfig
        config = LLMConfig(model_name="openai/o1-preview")

        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=config)

            assert llm._should_include_stop_param() is False

    def test_calculate_cache_interval(self, mock_litellm, mock_config):
        """Test cache interval calculation."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            # Small conversation
            assert llm._calculate_cache_interval(1) == 10

            # Medium conversation
            assert llm._calculate_cache_interval(25) == 10

            # Large conversation should increase interval
            interval = llm._calculate_cache_interval(100)
            assert interval >= 10

    def test_build_identity_message(self, mock_litellm, mock_config):
        """Test identity message building."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config, agent_name="test_agent", agent_id="agent-456")

            msg = llm._build_identity_message()

            assert msg is not None
            assert msg["role"] == "user"
            assert "test_agent" in msg["content"]
            assert "agent-456" in msg["content"]

    def test_build_identity_message_no_agent(self, mock_litellm, mock_config):
        """Test identity message returns None without agent."""
        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=mock_config)

            msg = llm._build_identity_message()

            assert msg is None


# ============== Memory Compressor Tests ==============

class TestMemoryCompressor:
    """Tests for MemoryCompressor class."""

    def test_initialization(self):
        """Test MemoryCompressor initialization."""
        with patch.dict("os.environ", {"AIPT_LLM": "test-model"}):
            from aipt_v2.llm.memory import MemoryCompressor
            compressor = MemoryCompressor(model_name="test-model")

            assert compressor.max_images == 3
            assert compressor.model_name == "test-model"
            assert compressor.timeout == 600

    def test_initialization_custom_params(self):
        """Test MemoryCompressor with custom parameters."""
        with patch.dict("os.environ", {"AIPT_LLM": "test-model"}):
            from aipt_v2.llm.memory import MemoryCompressor
            compressor = MemoryCompressor(
                max_images=5,
                model_name="custom-model",
                timeout=300,
            )

            assert compressor.max_images == 5
            assert compressor.model_name == "custom-model"
            assert compressor.timeout == 300

    def test_compress_empty_history(self):
        """Test compression of empty history."""
        with patch.dict("os.environ", {"AIPT_LLM": "test-model"}):
            from aipt_v2.llm.memory import MemoryCompressor
            compressor = MemoryCompressor(model_name="test-model")

            result = compressor.compress_history([])

            assert result == []

    def test_compress_short_history(self):
        """Test compression preserves short history."""
        with patch.dict("os.environ", {"AIPT_LLM": "test-model"}), \
             patch("aipt_v2.llm.memory._get_message_tokens", return_value=10):
            from aipt_v2.llm.memory import MemoryCompressor
            compressor = MemoryCompressor(model_name="test-model")

            messages = [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
            ]

            result = compressor.compress_history(messages)

            # Short history should not be compressed
            assert len(result) == 2


# ============== Helper Functions Tests ==============

class TestMemoryHelperFunctions:
    """Tests for memory module helper functions."""

    def test_count_tokens_fallback(self):
        """Test token counting fallback on error."""
        with patch("aipt_v2.llm.memory.litellm.token_counter", side_effect=Exception("Error")):
            from aipt_v2.llm.memory import _count_tokens

            text = "This is a test message with some words"
            count = _count_tokens(text, "test-model")

            # Should fall back to len/4 estimate
            assert count == len(text) // 4

    def test_extract_message_text_string(self):
        """Test text extraction from string content."""
        from aipt_v2.llm.memory import _extract_message_text

        msg = {"role": "user", "content": "Hello world"}
        result = _extract_message_text(msg)

        assert result == "Hello world"

    def test_extract_message_text_list(self):
        """Test text extraction from list content."""
        from aipt_v2.llm.memory import _extract_message_text

        msg = {
            "role": "user",
            "content": [
                {"type": "text", "text": "Hello"},
                {"type": "image_url", "image_url": {"url": "data:..."}},
                {"type": "text", "text": "World"},
            ]
        }
        result = _extract_message_text(msg)

        assert "Hello" in result
        assert "[IMAGE]" in result
        assert "World" in result

    def test_get_message_tokens_string(self):
        """Test token counting for string content."""
        with patch("aipt_v2.llm.memory._count_tokens", return_value=10):
            from aipt_v2.llm.memory import _get_message_tokens

            msg = {"role": "user", "content": "Test message"}
            tokens = _get_message_tokens(msg, "test-model")

            assert tokens == 10

    def test_get_message_tokens_list(self):
        """Test token counting for list content."""
        with patch("aipt_v2.llm.memory._count_tokens", return_value=5):
            from aipt_v2.llm.memory import _get_message_tokens

            msg = {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Hello"},
                    {"type": "text", "text": "World"},
                ]
            }
            tokens = _get_message_tokens(msg, "test-model")

            assert tokens == 10  # 5 + 5


# ============== Request Queue Tests ==============

class TestLLMRequestQueue:
    """Tests for LLMRequestQueue class."""

    def test_initialization_defaults(self):
        """Test queue initialization with defaults."""
        with patch.dict("os.environ", {}, clear=True):
            import os
            os.environ.pop("LLM_RATE_LIMIT_DELAY", None)
            os.environ.pop("LLM_RATE_LIMIT_CONCURRENT", None)

            from aipt_v2.llm.request_queue import LLMRequestQueue
            queue = LLMRequestQueue()

            assert queue.max_concurrent == 1
            assert queue.delay_between_requests == 4.0

    def test_initialization_from_env(self):
        """Test queue initialization from environment."""
        with patch.dict("os.environ", {
            "LLM_RATE_LIMIT_DELAY": "2.0",
            "LLM_RATE_LIMIT_CONCURRENT": "3",
        }):
            from aipt_v2.llm.request_queue import LLMRequestQueue
            queue = LLMRequestQueue()

            assert queue.max_concurrent == 3
            assert queue.delay_between_requests == 2.0

    def test_initialization_custom_params(self):
        """Test queue initialization with custom parameters."""
        with patch.dict("os.environ", {}, clear=True):
            import os
            os.environ.pop("LLM_RATE_LIMIT_DELAY", None)
            os.environ.pop("LLM_RATE_LIMIT_CONCURRENT", None)

            from aipt_v2.llm.request_queue import LLMRequestQueue
            queue = LLMRequestQueue(max_concurrent=5, delay_between_requests=1.0)

            assert queue.max_concurrent == 5
            assert queue.delay_between_requests == 1.0

    def test_get_global_queue_singleton(self):
        """Test global queue is a singleton."""
        from aipt_v2.llm.request_queue import get_global_queue, _global_queue

        # Reset global queue
        import aipt_v2.llm.request_queue as rq
        rq._global_queue = None

        queue1 = get_global_queue()
        queue2 = get_global_queue()

        assert queue1 is queue2


# ============== Retry Logic Tests ==============

class TestRetryLogic:
    """Tests for retry logic in request queue."""

    def test_should_retry_rate_limit(self):
        """Test retry on rate limit error."""
        from aipt_v2.llm.request_queue import should_retry_exception

        error = Mock()
        error.status_code = 429  # Rate limit

        with patch("aipt_v2.llm.request_queue.litellm._should_retry", return_value=True):
            assert should_retry_exception(error) is True

    def test_should_not_retry_auth_error(self):
        """Test no retry on authentication error."""
        from aipt_v2.llm.request_queue import should_retry_exception

        error = Mock()
        error.status_code = 401  # Auth error

        with patch("aipt_v2.llm.request_queue.litellm._should_retry", return_value=False):
            assert should_retry_exception(error) is False

    def test_should_retry_server_error(self):
        """Test retry on server error."""
        from aipt_v2.llm.request_queue import should_retry_exception

        error = Mock()
        error.status_code = 500  # Server error

        with patch("aipt_v2.llm.request_queue.litellm._should_retry", return_value=True):
            assert should_retry_exception(error) is True

    def test_should_retry_no_status_code(self):
        """Test retry when no status code available."""
        from aipt_v2.llm.request_queue import should_retry_exception

        error = Exception("Unknown error")

        # Should default to True when status code unavailable
        assert should_retry_exception(error) is True


# ============== LLMRequestFailedError Tests ==============

class TestLLMRequestFailedError:
    """Tests for LLMRequestFailedError exception."""

    def test_error_with_message(self):
        """Test error with message only."""
        from aipt_v2.llm.llm import LLMRequestFailedError

        error = LLMRequestFailedError("Request failed")

        assert str(error) == "Request failed"
        assert error.message == "Request failed"
        assert error.details is None

    def test_error_with_details(self):
        """Test error with message and details."""
        from aipt_v2.llm.llm import LLMRequestFailedError

        error = LLMRequestFailedError(
            "Rate limit exceeded",
            "Retry after 60 seconds",
        )

        assert error.message == "Rate limit exceeded"
        assert error.details == "Retry after 60 seconds"


# ============== Async Generation Tests ==============

class TestAsyncGeneration:
    """Tests for async LLM generation."""

    @pytest.fixture
    def mock_response(self):
        """Create a mock LLM response."""
        mock = Mock()
        mock.choices = [Mock()]
        mock.choices[0].message = Mock()
        mock.choices[0].message.content = "Test response content"
        mock.usage = Mock()
        mock.usage.prompt_tokens = 100
        mock.usage.completion_tokens = 50
        return mock

    @pytest.mark.asyncio
    async def test_generate_success(self, mock_response):
        """Test successful generation."""
        from aipt_v2.llm.config import LLMConfig

        config = LLMConfig(model_name="test-model")

        with patch("aipt_v2.llm.llm.MemoryCompressor") as mock_compressor, \
             patch("aipt_v2.llm.llm.get_global_queue") as mock_queue:

            mock_compressor.return_value.compress_history.return_value = []
            mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

            from aipt_v2.llm.llm import LLM
            llm = LLM(config=config)

            response = await llm.generate(
                conversation_history=[],
                scan_id="scan-123",
                step_number=1,
            )

            assert response.content == "Test response content"
            assert response.scan_id == "scan-123"
            assert response.step_number == 1

    @pytest.mark.asyncio
    async def test_generate_with_tool_invocations(self, mock_response):
        """Test generation with tool invocations in response."""
        from aipt_v2.llm.config import LLMConfig

        config = LLMConfig(model_name="test-model")
        mock_response.choices[0].message.content = (
            "Running scan <function>nmap</function>"
        )

        with patch("aipt_v2.llm.llm.MemoryCompressor") as mock_compressor, \
             patch("aipt_v2.llm.llm.get_global_queue") as mock_queue, \
             patch("aipt_v2.llm.llm.parse_tool_invocations", return_value=[{"name": "nmap"}]):

            mock_compressor.return_value.compress_history.return_value = []
            mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

            from aipt_v2.llm.llm import LLM
            llm = LLM(config=config)

            response = await llm.generate(
                conversation_history=[],
            )

            assert response.tool_invocations is not None
            assert len(response.tool_invocations) == 1


# ============== Image Filtering Tests ==============

class TestImageFiltering:
    """Tests for image filtering in messages."""

    def test_filter_images_preserves_text(self):
        """Test that text messages are preserved."""
        from aipt_v2.llm.config import LLMConfig

        config = LLMConfig(model_name="test-model")

        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=config)

            messages = [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
            ]

            filtered = llm._filter_images_from_messages(messages)

            assert len(filtered) == 2
            assert filtered[0]["content"] == "Hello"

    def test_filter_images_removes_images(self):
        """Test that images are replaced with placeholder."""
        from aipt_v2.llm.config import LLMConfig

        config = LLMConfig(model_name="test-model")

        with patch("aipt_v2.llm.llm.MemoryCompressor"):
            from aipt_v2.llm.llm import LLM
            llm = LLM(config=config)

            messages = [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Look at this:"},
                        {"type": "image_url", "image_url": {"url": "data:..."}},
                    ]
                }
            ]

            filtered = llm._filter_images_from_messages(messages)

            # Should contain placeholder text
            assert "Screenshot removed" in str(filtered[0]["content"])
