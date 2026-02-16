"""
AIPTX Pipeline Regression Tests

These tests enforce gates and counting integrity to prevent false positives
from appearing in reports and ensure accurate analytics.

Gate Tests:
- Critical findings MUST be CONFIRMED to appear in report
- SUPPRESSED_FP findings NEVER appear in report
- Totals must match actual finding counts

Counting Integrity:
- No duplicate fingerprints after deduplication
- Summary counts match actual findings
- Tool failure tracking is accurate
"""
import json
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

from aipt_v2.models.finding_v2 import (
    FindingV2,
    FindingCategory,
    VerificationStatusV2,
    ScannerType,
    SeverityV2,
    normalize_url,
    categorize_vuln_type,
    merge_findings_v2,
)
from aipt_v2.pipeline.normalizer import (
    FindingsNormalizer,
    ToolStatus,
    ToolStats,
    NormalizerResult,
)
from aipt_v2.pipeline.deduplicator import (
    Deduplicator,
    DeduplicationStats,
    generate_fingerprint,
)
from aipt_v2.pipeline.persistence import (
    CanonicalFindings,
    CanonicalSummary,
    ToolStatusEntry,
    save_canonical_findings,
    load_canonical_findings,
)


# ============================================================================
# Gate Tests - Verification Status Controls Report Inclusion
# ============================================================================

class TestVerificationGates:
    """Test that verification status properly gates report inclusion"""

    def test_critical_requires_confirmed(self):
        """Critical findings MUST be CONFIRMED to appear in report"""
        finding = FindingV2(
            title="Critical SQLi",
            severity=SeverityV2.CRITICAL,
            category=FindingCategory.INJECTION_SQLI,
            target="example.com",
            url="https://example.com/login",
            source_tool="sqlmap",
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
        )

        # NEEDS_REVIEW → not reportable
        assert not finding.is_reportable(), "Critical finding with NEEDS_REVIEW should NOT be reportable"

        # LIKELY → not reportable for Critical
        finding.verification_status = VerificationStatusV2.LIKELY
        assert not finding.is_reportable(), "Critical finding with LIKELY should NOT be reportable"

        # CONFIRMED → reportable
        finding.verification_status = VerificationStatusV2.CONFIRMED
        assert finding.is_reportable(), "Critical finding with CONFIRMED should be reportable"

    def test_high_requires_confirmed(self):
        """High findings MUST be CONFIRMED to appear in report"""
        finding = FindingV2(
            title="High Severity XSS",
            severity=SeverityV2.HIGH,
            category=FindingCategory.INJECTION_XSS,
            target="example.com",
            url="https://example.com/search",
            source_tool="nuclei",
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
        )

        assert not finding.is_reportable(), "High finding with NEEDS_REVIEW should NOT be reportable"

        finding.verification_status = VerificationStatusV2.CONFIRMED
        assert finding.is_reportable(), "High finding with CONFIRMED should be reportable"

    def test_medium_allows_likely(self):
        """Medium findings can be CONFIRMED or LIKELY"""
        finding = FindingV2(
            title="Medium Severity Issue",
            severity=SeverityV2.MEDIUM,
            category=FindingCategory.CONFIG,
            target="example.com",
            url="https://example.com/",
            source_tool="nuclei",
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
        )

        assert not finding.is_reportable(), "Medium finding with NEEDS_REVIEW should NOT be reportable"

        finding.verification_status = VerificationStatusV2.LIKELY
        assert finding.is_reportable(), "Medium finding with LIKELY should be reportable"

        finding.verification_status = VerificationStatusV2.CONFIRMED
        assert finding.is_reportable(), "Medium finding with CONFIRMED should be reportable"

    def test_suppressed_fp_never_reported(self):
        """SUPPRESSED_FP findings NEVER appear in report regardless of severity"""
        for severity in [SeverityV2.CRITICAL, SeverityV2.HIGH, SeverityV2.MEDIUM, SeverityV2.LOW, SeverityV2.INFO]:
            finding = FindingV2(
                title=f"{severity.value} False Positive",
                severity=severity,
                category=FindingCategory.OTHER,
                target="example.com",
                url="https://example.com/",
                source_tool="scanner",
                verification_status=VerificationStatusV2.SUPPRESSED_FP,
            )

            assert not finding.is_reportable(), f"SUPPRESSED_FP finding at {severity.value} severity should NEVER be reportable"

    def test_manual_review_low_info_reportable(self):
        """Low/Info findings in MANUAL_REVIEW are reportable"""
        for severity in [SeverityV2.LOW, SeverityV2.INFO]:
            finding = FindingV2(
                title=f"{severity.value} Manual Review",
                severity=severity,
                category=FindingCategory.OTHER,
                target="example.com",
                url="https://example.com/",
                source_tool="scanner",
                verification_status=VerificationStatusV2.MANUAL_REVIEW,
            )

            assert finding.is_reportable(), f"{severity.value} finding in MANUAL_REVIEW should be reportable"


# ============================================================================
# Counting Integrity Tests - Totals Must Match
# ============================================================================

class TestCountingIntegrity:
    """Test that summary totals match actual finding counts"""

    def test_summary_totals_match_findings(self, tmp_path):
        """Summary totals must match actual finding counts"""
        findings = [
            FindingV2(
                title=f"Finding {i}",
                severity=SeverityV2.MEDIUM,
                category=FindingCategory.OTHER,
                target="example.com",
                url=f"https://example.com/path{i}",
                source_tool="scanner",
                verification_status=VerificationStatusV2.CONFIRMED,
            )
            for i in range(10)
        ]

        # Save canonical findings
        path = save_canonical_findings(
            findings=findings,
            output_dir=tmp_path,
            scan_id="test-scan",
            target="example.com",
            total_raw=15,
            after_dedup=10,
        )

        # Load and verify
        canonical = load_canonical_findings(tmp_path)
        assert canonical is not None

        # Check counts match
        assert len(canonical.findings) == 10
        assert canonical.summary.after_verification == 10
        assert canonical.summary.confirmed == 10

    def test_severity_counts_match_findings(self, tmp_path):
        """Severity breakdown must match actual findings"""
        findings = [
            FindingV2(title="Critical 1", severity=SeverityV2.CRITICAL, target="x", url="https://x/1", source_tool="s", verification_status=VerificationStatusV2.CONFIRMED),
            FindingV2(title="Critical 2", severity=SeverityV2.CRITICAL, target="x", url="https://x/2", source_tool="s", verification_status=VerificationStatusV2.CONFIRMED),
            FindingV2(title="High 1", severity=SeverityV2.HIGH, target="x", url="https://x/3", source_tool="s", verification_status=VerificationStatusV2.CONFIRMED),
            FindingV2(title="Medium 1", severity=SeverityV2.MEDIUM, target="x", url="https://x/4", source_tool="s", verification_status=VerificationStatusV2.CONFIRMED),
            FindingV2(title="Medium 2", severity=SeverityV2.MEDIUM, target="x", url="https://x/5", source_tool="s", verification_status=VerificationStatusV2.CONFIRMED),
            FindingV2(title="Low 1", severity=SeverityV2.LOW, target="x", url="https://x/6", source_tool="s", verification_status=VerificationStatusV2.CONFIRMED),
        ]

        path = save_canonical_findings(
            findings=findings,
            output_dir=tmp_path,
            scan_id="test",
            target="x",
            total_raw=6,
            after_dedup=6,
        )

        canonical = load_canonical_findings(tmp_path)

        # Verify severity counts
        assert canonical.summary.by_severity["critical"] == 2
        assert canonical.summary.by_severity["high"] == 1
        assert canonical.summary.by_severity["medium"] == 2
        assert canonical.summary.by_severity["low"] == 1


# ============================================================================
# Deduplication Integrity Tests
# ============================================================================

class TestDeduplicationIntegrity:
    """Test deduplication produces unique fingerprints"""

    def test_no_duplicate_fingerprints(self):
        """No two findings should have same fingerprint after dedup"""
        # Create findings with some duplicates
        findings = [
            FindingV2(title="SQLi on login", severity=SeverityV2.HIGH, category=FindingCategory.INJECTION_SQLI, target="example.com", url="https://example.com/login", parameter="username", source_tool="sqlmap"),
            FindingV2(title="SQLi on login", severity=SeverityV2.HIGH, category=FindingCategory.INJECTION_SQLI, target="example.com", url="https://example.com/login", parameter="username", source_tool="nuclei"),  # Duplicate
            FindingV2(title="XSS on search", severity=SeverityV2.MEDIUM, category=FindingCategory.INJECTION_XSS, target="example.com", url="https://example.com/search", parameter="q", source_tool="nuclei"),
        ]

        deduplicator = Deduplicator()
        deduped = deduplicator.deduplicate(findings)

        # Check no duplicate fingerprints
        fingerprints = [f.fingerprint for f in deduped]
        assert len(fingerprints) == len(set(fingerprints)), "Duplicate fingerprints found after deduplication"

    def test_merge_preserves_best_status(self):
        """Merge should preserve the best verification status"""
        confirmed = FindingV2(
            title="Same Finding",
            severity=SeverityV2.HIGH,
            category=FindingCategory.INJECTION_SQLI,
            target="example.com",
            url="https://example.com/login",
            source_tool="scanner1",
            verification_status=VerificationStatusV2.CONFIRMED,
        )

        needs_review = FindingV2(
            title="Same Finding",
            severity=SeverityV2.HIGH,
            category=FindingCategory.INJECTION_SQLI,
            target="example.com",
            url="https://example.com/login",
            source_tool="scanner2",
            verification_status=VerificationStatusV2.NEEDS_REVIEW,
        )

        # Merge should keep CONFIRMED
        merged = merge_findings_v2(needs_review, confirmed)
        assert merged.verification_status == VerificationStatusV2.CONFIRMED

    def test_merge_keeps_highest_severity(self):
        """Merge should keep the highest severity"""
        high = FindingV2(
            title="Finding",
            severity=SeverityV2.HIGH,
            category=FindingCategory.OTHER,
            target="example.com",
            url="https://example.com/path",
            source_tool="scanner1",
        )

        critical = FindingV2(
            title="Finding",
            severity=SeverityV2.CRITICAL,
            category=FindingCategory.OTHER,
            target="example.com",
            url="https://example.com/path",
            source_tool="scanner2",
        )

        merged = merge_findings_v2(high, critical)
        assert merged.severity == SeverityV2.CRITICAL

    def test_dedup_stats_accurate(self):
        """Deduplication stats should be accurate"""
        findings = [
            FindingV2(title="F1", severity=SeverityV2.HIGH, target="x", url="https://x/1", source_tool="s"),
            FindingV2(title="F1", severity=SeverityV2.HIGH, target="x", url="https://x/1", source_tool="s"),  # Dup
            FindingV2(title="F2", severity=SeverityV2.LOW, target="x", url="https://x/2", source_tool="s"),
        ]

        deduplicator = Deduplicator()
        deduped = deduplicator.deduplicate(findings)
        stats = deduplicator.get_stats()

        assert stats.total_input == 3
        assert stats.total_output == 2
        assert stats.duplicates_merged == 1


# ============================================================================
# Tool Failure Tracking Tests
# ============================================================================

class TestToolFailureTracking:
    """Test that tool failures are properly represented"""

    def test_failed_tool_not_misleading(self):
        """Failed tools should show FAILED status, not misleading '0' findings"""
        tool_stats = ToolStats(
            tool_name="burp",
            status=ToolStatus.FAILED,
            finding_count=0,
            error="Connection refused",
        )

        assert tool_stats.status == ToolStatus.FAILED
        assert tool_stats.error is not None
        # The key is that status is FAILED, not that count is 0
        # This makes it clear the tool didn't run successfully

    def test_completed_tool_with_zero_findings(self):
        """Completed tools with 0 findings should show COMPLETED status"""
        tool_stats = ToolStats(
            tool_name="sslscan",
            status=ToolStatus.COMPLETED,
            finding_count=0,
            error=None,
        )

        assert tool_stats.status == ToolStatus.COMPLETED
        assert tool_stats.error is None
        # 0 findings is valid for completed tools (target might be secure)


# ============================================================================
# URL Normalization Tests
# ============================================================================

class TestURLNormalization:
    """Test URL normalization fixes double slashes"""

    def test_no_double_slashes(self):
        """URLs should not have double slashes in path"""
        test_cases = [
            ("https://example.com//path", "https://example.com/path"),
            ("https://example.com//path//sub", "https://example.com/path/sub"),
            ("https://example.com///triple", "https://example.com/triple"),
        ]

        for input_url, expected in test_cases:
            result = normalize_url(input_url, "example.com")
            assert "//" not in result.replace("https://", ""), f"Double slash found in {result}"

    def test_preserves_valid_urls(self):
        """Valid URLs should not be modified"""
        valid_url = "https://example.com/api/v1/users"
        result = normalize_url(valid_url, "example.com")
        assert result == valid_url


# ============================================================================
# Category Mapping Tests
# ============================================================================

class TestCategoryMapping:
    """Test vulnerability type to category mapping"""

    def test_tls_categorization(self):
        """TLS/SSL types should map to TLS_SSL category"""
        for vuln_type in ["ssl_weak_cipher", "TLS 1.0", "Heartbleed", "certificate_expired"]:
            category = categorize_vuln_type(vuln_type)
            assert category == FindingCategory.TLS_SSL, f"{vuln_type} should be TLS_SSL"

    def test_ssti_categorization(self):
        """SSTI types should map to INJECTION_SSTI category"""
        for vuln_type in ["ssti", "Template Injection", "SSTI_Jinja2"]:
            category = categorize_vuln_type(vuln_type)
            assert category == FindingCategory.INJECTION_SSTI, f"{vuln_type} should be INJECTION_SSTI"

    def test_sqli_categorization(self):
        """SQL injection types should map to INJECTION_SQLI category"""
        for vuln_type in ["sql_injection", "SQLi", "blind_sql"]:
            category = categorize_vuln_type(vuln_type)
            assert category == FindingCategory.INJECTION_SQLI, f"{vuln_type} should be INJECTION_SQLI"


# ============================================================================
# FindingV2 Serialization Tests
# ============================================================================

class TestFindingV2Serialization:
    """Test FindingV2 serialization/deserialization"""

    def test_roundtrip_serialization(self):
        """FindingV2 should survive JSON roundtrip"""
        finding = FindingV2(
            title="Test Finding",
            severity=SeverityV2.HIGH,
            category=FindingCategory.INJECTION_SQLI,
            vuln_type="sql_injection",
            target="example.com",
            url="https://example.com/api",
            parameter="id",
            method="POST",
            description="SQL injection in ID parameter",
            evidence="Error: SQL syntax",
            verification_status=VerificationStatusV2.CONFIRMED,
            source_tool="sqlmap",
            source_scanner_type=ScannerType.LOCAL,
            cve_ids=["CVE-2021-1234"],
        )

        # Serialize
        data = finding.to_dict()
        json_str = json.dumps(data)

        # Deserialize
        loaded_data = json.loads(json_str)
        restored = FindingV2.from_dict(loaded_data)

        # Verify
        assert restored.title == finding.title
        assert restored.severity == finding.severity
        assert restored.category == finding.category
        assert restored.verification_status == finding.verification_status
        assert restored.cve_ids == finding.cve_ids

    def test_severity_is_string_not_numeric(self):
        """Severity in dict should be string, not numeric"""
        finding = FindingV2(
            title="Test",
            severity=SeverityV2.HIGH,
            target="x",
            url="https://x/",
            source_tool="s",
        )

        data = finding.to_dict()
        assert isinstance(data["severity"], str)
        assert data["severity"] == "high"
        assert data["severity"] not in [0, 1, 2, 3, 4]  # Not numeric


# ============================================================================
# Run tests with: pytest tests/pipeline/test_findings_pipeline.py -v
# ============================================================================
