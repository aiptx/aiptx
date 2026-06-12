"""
Tests for PAT (PayloadsAllTheThings) Scanner Integration

Tests cover:
- Configuration validation
- Payload parsing and database
- Request generation
- Response analysis
- Detection patterns
- Executor rate limiting
- Full scanner integration
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from aipt_v2.scanners.pat.analyzer import (
    BaselineData,
    ResponseAnalyzer,
)

# Import PAT components
from aipt_v2.scanners.pat.config import (
    AnalyzerConfig,
    AuthorizationError,
    DetectionMethod,
    ExecutorConfig,
    InjectionPoint,
    PATScanConfig,
    PayloadConfig,
    PayloadTechnique,
    VulnerabilityType,
)
from aipt_v2.scanners.pat.detection_patterns import (
    SQL_ERROR_PATTERNS,
    compile_patterns,
    get_detection_patterns,
    match_any_pattern,
)
from aipt_v2.scanners.pat.executor import (
    ExecutionResult,
    RateLimiter,
    ScopeEnforcer,
    WAFDetector,
)
from aipt_v2.scanners.pat.pat_scanner import PATScanner, PATScanResult
from aipt_v2.scanners.pat.payload_database import PayloadDatabase
from aipt_v2.scanners.pat.payload_parser import ParsedPayload
from aipt_v2.scanners.pat.request_generator import InjectionRequest, RequestGenerator

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_payload():
    """Create a sample SQL injection payload."""
    return ParsedPayload(
        content="' OR '1'='1",
        category=VulnerabilityType.SQL_INJECTION,
        subcategory="mysql",
        technique=PayloadTechnique.BOOLEAN_BASED,
        description="Basic SQLi bypass",
        source_file="SQL Injection/README.md",
    )


@pytest.fixture
def xss_payload():
    """Create a sample XSS payload."""
    return ParsedPayload(
        content="<script>alert(1)</script>",
        category=VulnerabilityType.XSS,
        subcategory="reflected",
        technique=PayloadTechnique.REFLECTED,
        description="Basic XSS payload",
    )


@pytest.fixture
def scan_config():
    """Create a test scan configuration."""
    return PATScanConfig(
        target_url="http://testsite.local/api",
        parameters=["id", "user"],
        vuln_types=[VulnerabilityType.SQL_INJECTION, VulnerabilityType.XSS],
        authorized=True,
        executor=ExecutorConfig(
            max_concurrent=5,
            requests_per_second=10.0,
            timeout=10.0,
        ),
    )


@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    response = MagicMock()
    response.status_code = 200
    response.text = "Normal response content"
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def error_response():
    """Create a mock response with SQL error."""
    response = MagicMock()
    response.status_code = 500
    response.text = "Error: You have an error in your SQL syntax; check MySQL manual"
    response.headers = {"Content-Type": "text/html"}
    return response


# =============================================================================
# Configuration Tests
# =============================================================================


class TestPATConfiguration:
    """Tests for PAT configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = PATScanConfig()
        assert config.authorized == False
        assert config.executor.max_concurrent == 10
        assert config.executor.requests_per_second == 10.0
        assert VulnerabilityType.SQL_INJECTION in config.vuln_types

    def test_executor_config(self):
        """Test executor configuration."""
        config = ExecutorConfig(
            max_concurrent=20,
            requests_per_second=50.0,
            timeout=60.0,
            proxy="http://127.0.0.1:8080",
        )
        assert config.max_concurrent == 20
        assert config.requests_per_second == 50.0
        assert config.proxy == "http://127.0.0.1:8080"

    def test_analyzer_config(self):
        """Test analyzer configuration."""
        config = AnalyzerConfig(
            time_based_threshold_ms=10000.0,
            confidence_threshold=0.8,
        )
        assert config.time_based_threshold_ms == 10000.0
        assert config.confidence_threshold == 0.8

    def test_vulnerability_types(self):
        """Test vulnerability type enum."""
        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"
        assert VulnerabilityType.XSS.value == "xss"
        assert VulnerabilityType.COMMAND_INJECTION.value == "command_injection"

    def test_injection_points(self):
        """Test injection point enum."""
        assert InjectionPoint.URL_PARAM.value == "url_param"
        assert InjectionPoint.POST_JSON.value == "post_json"
        assert InjectionPoint.HEADER.value == "header"


# =============================================================================
# Payload Parser Tests
# =============================================================================


class TestPayloadParser:
    """Tests for payload parsing."""

    def test_parsed_payload_creation(self, sample_payload):
        """Test creating a parsed payload."""
        assert sample_payload.content == "' OR '1'='1"
        assert sample_payload.category == VulnerabilityType.SQL_INJECTION
        assert sample_payload.subcategory == "mysql"

    def test_payload_hash(self, sample_payload):
        """Test payload hashing for deduplication."""
        hash1 = hash(sample_payload)
        same_payload = ParsedPayload(
            content="' OR '1'='1",
            category=VulnerabilityType.SQL_INJECTION,
        )
        hash2 = hash(same_payload)
        assert hash1 == hash2

    def test_payload_equality(self, sample_payload):
        """Test payload equality comparison."""
        same = ParsedPayload(content="' OR '1'='1", category=VulnerabilityType.SQL_INJECTION)
        different = ParsedPayload(content="' OR '1'='2", category=VulnerabilityType.SQL_INJECTION)
        assert sample_payload == same
        assert sample_payload != different

    def test_dangerous_payload_detection(self):
        """Test detection of dangerous payloads."""
        from aipt_v2.scanners.pat.payload_parser import DANGEROUS_INDICATORS

        dangerous_payload = "'; DROP TABLE users;--"
        is_dangerous = any(ind.upper() in dangerous_payload.upper() for ind in DANGEROUS_INDICATORS)
        assert is_dangerous


# =============================================================================
# Request Generator Tests
# =============================================================================


class TestRequestGenerator:
    """Tests for HTTP request generation."""

    def test_url_param_injection(self, sample_payload, scan_config):
        """Test URL parameter injection."""
        generator = RequestGenerator(scan_config)
        requests = list(
            generator.generate_requests(
                target_url="http://test.local/api?id=1&name=test",
                payloads=[sample_payload],
                parameters=["id"],
                injection_points=[InjectionPoint.URL_PARAM],
            )
        )

        assert len(requests) >= 1
        request = requests[0]
        # Payload should be URL encoded (single or double encoding for WAF bypass)
        # %27 is single-encoded quote, %2527 is double-encoded
        assert "%27" in request.url or "%2527" in request.url
        assert request.injection_point == InjectionPoint.URL_PARAM
        assert request.parameter_name == "id"

    def test_post_json_injection(self, sample_payload, scan_config):
        """Test POST JSON body injection."""
        generator = RequestGenerator(scan_config)
        requests = list(
            generator.generate_requests(
                target_url="http://test.local/api",
                payloads=[sample_payload],
                parameters=["username"],
                injection_points=[InjectionPoint.POST_JSON],
                method="POST",
                body='{"username": "test"}',
            )
        )

        assert len(requests) >= 1
        request = requests[0]
        assert request.body is not None
        body_data = json.loads(request.body)
        assert body_data["username"] == sample_payload.content

    def test_header_injection(self, sample_payload, scan_config):
        """Test header injection."""
        generator = RequestGenerator(scan_config)
        requests = list(
            generator.generate_requests(
                target_url="http://test.local/api",
                payloads=[sample_payload],
                parameters=["X-Custom-Header"],
                injection_points=[InjectionPoint.HEADER],
            )
        )

        assert len(requests) >= 1
        request = requests[0]
        assert "X-Custom-Header" in request.headers
        assert request.headers["X-Custom-Header"] == sample_payload.content

    def test_curl_generation(self, sample_payload, scan_config):
        """Test curl command generation."""
        request = InjectionRequest(
            method="POST",
            url="http://test.local/api",
            headers={"Content-Type": "application/json"},
            body='{"id": "test"}',
            payload=sample_payload,
            injection_point=InjectionPoint.POST_JSON,
            parameter_name="id",
        )

        curl = request.to_curl()
        assert "curl" in curl
        assert "-X POST" in curl
        assert "http://test.local/api" in curl

    def test_baseline_request_generation(self, scan_config):
        """Test baseline request generation."""
        generator = RequestGenerator(scan_config)
        baselines = generator.generate_baseline_requests(
            target_url="http://test.local/api",
            count=3,
        )

        assert len(baselines) == 3
        for req in baselines:
            assert req.payload is None
            assert req.url == "http://test.local/api"


# =============================================================================
# Detection Pattern Tests
# =============================================================================


class TestDetectionPatterns:
    """Tests for vulnerability detection patterns."""

    def test_sql_error_patterns(self):
        """Test SQL error pattern matching."""
        error_text = "You have an error in your SQL syntax; check MySQL manual"
        matched, pattern, _ = match_any_pattern(error_text, VulnerabilityType.SQL_INJECTION)
        assert matched
        assert pattern is not None

    def test_postgresql_error_detection(self):
        """Test PostgreSQL error detection."""
        error_text = "PostgreSQL ERROR: syntax error at or near"
        matched, _, _ = match_any_pattern(error_text, VulnerabilityType.SQL_INJECTION)
        assert matched

    def test_xss_pattern_matching(self):
        """Test XSS pattern detection."""
        xss_content = "<script>alert(1)</script>"
        matched, _, _ = match_any_pattern(xss_content, VulnerabilityType.XSS)
        assert matched

    def test_lfi_pattern_matching(self):
        """Test LFI pattern detection."""
        lfi_content = "root:x:0:0:root:/root:/bin/bash"
        matched, _, _ = match_any_pattern(lfi_content, VulnerabilityType.LFI)
        assert matched

    def test_pattern_compilation(self):
        """Test pattern compilation for performance."""
        compiled = compile_patterns(SQL_ERROR_PATTERNS[:5])
        assert len(compiled) > 0
        for pattern in compiled:
            assert hasattr(pattern, "search")

    def test_get_detection_patterns(self):
        """Test getting detection patterns for vuln types."""
        patterns = get_detection_patterns(VulnerabilityType.SQL_INJECTION)
        assert len(patterns) > 0
        assert all(p.vuln_type == VulnerabilityType.SQL_INJECTION for p in patterns)


# =============================================================================
# Response Analyzer Tests
# =============================================================================


class TestResponseAnalyzer:
    """Tests for response analysis."""

    def test_error_based_detection(self, sample_payload, error_response):
        """Test error-based vulnerability detection."""
        analyzer = ResponseAnalyzer()

        exec_result = ExecutionResult(
            request=InjectionRequest(
                url="http://test.local/api?id=test",
                payload=sample_payload,
                injection_point=InjectionPoint.URL_PARAM,
                parameter_name="id",
            ),
            response=error_response,
            success=True,
        )

        analysis = analyzer.analyze(exec_result)
        assert analysis.vulnerable
        assert analysis.confidence > 0.5
        assert analysis.detection_method == DetectionMethod.ERROR_BASED

    def test_time_based_detection(self, sample_payload):
        """Test time-based vulnerability detection."""
        analyzer = ResponseAnalyzer()

        # Set baseline
        baseline = BaselineData(
            avg_response_time_ms=100.0,
            status_codes=[200],
            response_lengths=[1000],
        )

        # Create result with delayed response
        response = MagicMock()
        response.status_code = 200
        response.text = "Normal response"
        response.headers = {}

        exec_result = ExecutionResult(
            request=InjectionRequest(
                url="http://test.local/api",
                payload=sample_payload,
                injection_point=InjectionPoint.URL_PARAM,
                parameter_name="id",
            ),
            response=response,
            success=True,
            elapsed_ms=6000.0,  # 6 seconds (above threshold)
        )

        analysis = analyzer.analyze(exec_result, baseline=baseline)
        assert analysis.confidence > 0  # Time-based should detect delay

    def test_reflection_detection(self, xss_payload):
        """Test payload reflection detection."""
        analyzer = ResponseAnalyzer()

        response = MagicMock()
        response.status_code = 200
        response.text = "Search results: <script>alert(1)</script>"
        response.headers = {}

        exec_result = ExecutionResult(
            request=InjectionRequest(
                url="http://test.local/search",
                payload=xss_payload,
                injection_point=InjectionPoint.URL_PARAM,
                parameter_name="q",
            ),
            response=response,
            success=True,
        )

        analysis = analyzer.analyze(exec_result)
        assert analysis.vulnerable
        assert analysis.confidence >= 0.7

    def test_baseline_setting(self, mock_response):
        """Test baseline data collection."""
        analyzer = ResponseAnalyzer()

        results = [
            ExecutionResult(
                request=InjectionRequest(url="http://test.local"),
                response=mock_response,
                success=True,
                elapsed_ms=100.0,
            )
            for _ in range(3)
        ]

        analyzer.set_baseline(results)
        assert analyzer._baseline is not None
        assert analyzer._baseline.avg_response_time_ms > 0


# =============================================================================
# Executor Tests
# =============================================================================


class TestExecutor:
    """Tests for parallel execution."""

    def test_rate_limiter(self):
        """Test rate limiter token bucket."""
        limiter = RateLimiter(requests_per_second=10.0)
        assert limiter.rate == 10.0
        assert limiter.tokens == 10.0

    @pytest.mark.asyncio
    async def test_rate_limiter_acquire(self):
        """Test rate limiter token acquisition."""
        limiter = RateLimiter(requests_per_second=100.0)
        # Should not block for first few requests
        for _ in range(5):
            await limiter.acquire()

    def test_waf_detector_cloudflare(self):
        """Test WAF detection for Cloudflare."""
        response = MagicMock()
        response.status_code = 403
        response.headers = {"cf-ray": "123456", "server": "cloudflare"}
        response.text = "Attention required"

        is_waf, waf_type = WAFDetector.detect(response)
        assert is_waf
        assert waf_type == "cloudflare"

    def test_waf_detector_generic(self):
        """Test generic WAF detection."""
        response = MagicMock()
        response.status_code = 403
        response.headers = {}
        response.text = "Your request has been blocked"

        is_waf, waf_type = WAFDetector.detect(response)
        assert is_waf
        assert waf_type == "generic"

    def test_waf_detector_clean(self, mock_response):
        """Test that normal responses don't trigger WAF detection."""
        is_waf, _ = WAFDetector.detect(mock_response)
        assert not is_waf

    def test_scope_enforcer(self):
        """Test scope enforcement."""
        enforcer = ScopeEnforcer(["https://allowed.com/*", "http://test.local/*"])

        assert enforcer.is_in_scope("https://allowed.com/api")
        assert enforcer.is_in_scope("http://test.local/path")
        assert not enforcer.is_in_scope("https://evil.com/attack")

    def test_scope_enforcer_empty(self):
        """Test scope enforcer with no restrictions."""
        enforcer = ScopeEnforcer([])
        assert enforcer.is_in_scope("https://any.site.com")


# =============================================================================
# Scanner Integration Tests
# =============================================================================


class TestPATScanner:
    """Tests for main PAT scanner."""

    def test_scanner_availability(self):
        """Test scanner availability check."""
        # httpx should be available
        assert PATScanner.is_available()

    def test_authorization_required(self, scan_config):
        """Test that authorization is required."""
        scan_config.authorized = False
        scanner = PATScanner(scan_config)

        with pytest.raises(AuthorizationError):
            scanner._check_authorization()

    def test_authorization_granted(self, scan_config):
        """Test that authorization check passes when granted."""
        scan_config.authorized = True
        scanner = PATScanner(scan_config)
        scanner._check_authorization()  # Should not raise

    @pytest.mark.asyncio
    async def test_scanner_initialization(self, scan_config):
        """Test scanner component initialization."""
        scanner = PATScanner(scan_config)
        scanner._initialize_components()

        assert scanner._payload_db is not None
        assert scanner._generator is not None
        assert scanner._executor is not None
        assert scanner._analyzer is not None

    def test_severity_mapping(self):
        """Test vulnerability to severity mapping."""
        from aipt_v2.scanners.base import ScanSeverity
        from aipt_v2.scanners.pat.pat_scanner import VULN_SEVERITY_MAP

        assert VULN_SEVERITY_MAP[VulnerabilityType.SQL_INJECTION] == ScanSeverity.CRITICAL
        assert VULN_SEVERITY_MAP[VulnerabilityType.XSS] == ScanSeverity.MEDIUM
        assert VULN_SEVERITY_MAP[VulnerabilityType.COMMAND_INJECTION] == ScanSeverity.CRITICAL

    def test_pat_scan_result(self):
        """Test PAT scan result dataclass."""
        result = PATScanResult(
            target="http://test.local",
            status="completed",
            payloads_tested=100,
            requests_made=500,
            vulnerabilities_found=3,
        )

        assert result.scanner == "pat"
        assert result.payloads_tested == 100
        result_dict = result.to_dict()
        assert "payloads_tested" in result_dict


# =============================================================================
# Integration Tests (Mock HTTP)
# =============================================================================


class TestPATScannerIntegration:
    """Integration tests with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_full_scan_mock(self, scan_config, sample_payload):
        """Test full scan with mocked HTTP responses."""
        scan_config.authorized = True
        scanner = PATScanner(scan_config)

        # Mock the payload database
        mock_db = MagicMock()
        mock_db.load.return_value = True
        mock_db.get_payloads.return_value = [sample_payload]
        scanner._payload_db = mock_db

        # Mock the executor
        mock_exec = AsyncMock()
        mock_exec.__aenter__ = AsyncMock(return_value=mock_exec)
        mock_exec.__aexit__ = AsyncMock(return_value=None)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Normal response"
        mock_response.headers = {}

        async def mock_stream(requests):
            for req in requests:
                yield ExecutionResult(
                    request=req,
                    response=mock_response,
                    success=True,
                    elapsed_ms=50.0,
                )

        mock_exec.execute_batch = AsyncMock(
            return_value=[
                ExecutionResult(
                    request=InjectionRequest(url=scan_config.target_url),
                    response=mock_response,
                    success=True,
                )
            ]
        )
        mock_exec.execute_stream = mock_stream

        scanner._executor = mock_exec
        scanner._generator = RequestGenerator(scan_config)
        scanner._analyzer = ResponseAnalyzer(scan_config.analyzer)

        # Run scan
        result = await scanner.scan()

        assert result.status in ["completed", "failed"]
        assert result.scanner == "pat"


# =============================================================================
# Payload Database Tests
# =============================================================================


class TestPayloadDatabase:
    """Tests for payload database."""

    def test_database_initialization(self):
        """Test database initialization."""
        config = PayloadConfig()
        db = PayloadDatabase(config)
        assert db.config == config
        assert db._loaded == False

    def test_cache_file_path(self):
        """Test cache file path generation."""
        config = PayloadConfig()
        db = PayloadDatabase(config)
        assert db.cache_file.suffix == ".json"
        assert "payloads" in str(db.cache_file)

    def test_get_categories(self, sample_payload):
        """Test getting categories from database."""
        config = PayloadConfig()
        db = PayloadDatabase(config)
        # Manually add payloads
        db._payloads = {VulnerabilityType.SQL_INJECTION: [sample_payload]}
        db._loaded = True

        categories = db.get_categories()
        assert VulnerabilityType.SQL_INJECTION in categories

    def test_search_payloads(self, sample_payload):
        """Test payload search."""
        config = PayloadConfig()
        db = PayloadDatabase(config)
        db._payloads = {VulnerabilityType.SQL_INJECTION: [sample_payload]}
        db._loaded = True

        results = db.search("OR", limit=10)
        assert len(results) > 0
        assert "OR" in results[0].content


# =============================================================================
# Module Import Tests
# =============================================================================


class TestModuleImports:
    """Test module imports work correctly."""

    def test_main_module_import(self):
        """Test importing from main module."""
        from aipt_v2.scanners.pat import (
            PATScanConfig,
            PATScanner,
        )

        assert PATScanner is not None
        assert PATScanConfig is not None

    def test_scanners_module_import(self):
        """Test importing from scanners module."""
        from aipt_v2.scanners import (
            PATScanner,
            pat_scan_url,
        )

        assert PATScanner is not None
        assert pat_scan_url is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
