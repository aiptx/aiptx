"""
Unit tests for AIPTX WinPwn Integration Module.

Tests module instantiation, data classes, parsers, and configuration
without requiring actual Windows infrastructure or PowerShell execution.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime


# =============================================================================
# Test WinPwn Configuration
# =============================================================================

class TestWinPwnConfig:
    """Tests for winpwn_config.py"""

    def test_config_defaults(self):
        """Test WinPwnConfig has sensible defaults"""
        from aipt_v2.tools.winpwn import WinPwnConfig

        config = WinPwnConfig()
        assert config.bypass_amsi is True
        assert config.bypass_etw is True
        assert config.noninteractive is True
        assert config.timeout == 600

    def test_credentials_dataclass(self):
        """Test WinPwnCredentials can be instantiated"""
        from aipt_v2.tools.winpwn import WinPwnCredentials

        creds = WinPwnCredentials(
            username="testuser",
            password="testpass",
            domain="test.local"
        )
        assert creds.username == "testuser"
        assert creds.domain == "test.local"
        assert creds.has_credentials() is True

    def test_credentials_from_hash(self):
        """Test credentials with NTLM hash"""
        from aipt_v2.tools.winpwn import WinPwnCredentials

        creds = WinPwnCredentials(
            username="admin",
            domain="CORP",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert creds.has_credentials() is True
        assert creds.ntlm_hash.startswith("aad3b435")

    def test_credentials_empty(self):
        """Test empty credentials"""
        from aipt_v2.tools.winpwn import WinPwnCredentials

        creds = WinPwnCredentials()
        assert creds.has_credentials() is False

    def test_module_enum(self):
        """Test WinPwnModule enum values"""
        from aipt_v2.tools.winpwn import WinPwnModule

        assert WinPwnModule.LOCAL_RECON.value == "localrecon"
        assert WinPwnModule.KERBEROASTING.value == "kerberoasting"
        assert WinPwnModule.BLOODHOUND.value == "sharphound"
        assert WinPwnModule.LSASS_DUMP.value == "lsassdump"

    def test_execution_mode_enum(self):
        """Test WinPwnExecutionMode enum"""
        from aipt_v2.tools.winpwn import WinPwnExecutionMode

        assert WinPwnExecutionMode.LOCAL_SCRIPT.value == "local"
        assert WinPwnExecutionMode.REMOTE_REPO.value == "remote"
        assert WinPwnExecutionMode.CUSTOM_REPO.value == "custom"

    def test_get_winpwn_config(self):
        """Test get_winpwn_config factory function"""
        from aipt_v2.tools.winpwn import get_winpwn_config, WinPwnExecutionMode

        config = get_winpwn_config(
            script_path="/nonexistent/path.ps1",
            domain="corp.local",
            dc_ip="10.0.0.1",
            username="admin",
            password="secret"
        )

        assert config.domain == "corp.local"
        assert config.dc_ip == "10.0.0.1"
        assert config.credentials.username == "admin"
        # Since path doesn't exist, should be REMOTE_REPO
        assert config.execution_mode == WinPwnExecutionMode.REMOTE_REPO

    def test_validate_config_missing_script(self):
        """Test config validation with missing script"""
        from aipt_v2.tools.winpwn import (
            WinPwnConfig,
            WinPwnExecutionMode,
            validate_winpwn_config
        )

        config = WinPwnConfig(
            script_path="/nonexistent/script.ps1",
            execution_mode=WinPwnExecutionMode.LOCAL_SCRIPT
        )

        result = validate_winpwn_config(config)
        assert result["valid"] is False
        assert any("not found" in e for e in result["errors"])

    def test_validate_config_valid_remote(self):
        """Test config validation for remote mode"""
        from aipt_v2.tools.winpwn import (
            WinPwnConfig,
            WinPwnExecutionMode,
            validate_winpwn_config
        )

        config = WinPwnConfig(
            execution_mode=WinPwnExecutionMode.REMOTE_REPO
        )

        result = validate_winpwn_config(config)
        assert result["valid"] is True

    def test_get_module_command(self):
        """Test module command mapping"""
        from aipt_v2.tools.winpwn import WinPwnConfig, WinPwnModule

        config = WinPwnConfig()

        assert config.get_module_command(WinPwnModule.LOCAL_RECON) == "Localreconmodules"
        assert config.get_module_command(WinPwnModule.KERBEROASTING) == "Kerberoasting"
        assert config.get_module_command(WinPwnModule.BLOODHOUND) == "Sharphound"

    def test_requires_admin(self):
        """Test admin requirement check"""
        from aipt_v2.tools.winpwn import WinPwnConfig, WinPwnModule

        config = WinPwnConfig()

        # LSASS dump requires admin
        assert config.requires_admin(WinPwnModule.LSASS_DUMP) is True

        # Local recon doesn't require admin
        assert config.requires_admin(WinPwnModule.LOCAL_RECON) is False


# =============================================================================
# Test PowerShell Executor
# =============================================================================

class TestPowerShellExecutor:
    """Tests for powershell_executor.py"""

    def test_result_dataclass(self):
        """Test PowerShellResult dataclass"""
        from aipt_v2.tools.winpwn import PowerShellResult

        result = PowerShellResult(
            success=True,
            exit_code=0,
            stdout="Hello World",
            stderr="",
            execution_time=1.5,
            command="Write-Output 'Hello World'"
        )

        assert result.success is True
        assert result.exit_code == 0
        assert result.output == "Hello World"
        assert result.execution_time == 1.5

    def test_result_combined_output(self):
        """Test combined output property"""
        from aipt_v2.tools.winpwn import PowerShellResult

        result = PowerShellResult(
            success=False,
            exit_code=1,
            stdout="Output text",
            stderr="Error text",
            execution_time=0.5
        )

        assert "Output text" in result.output
        assert "Error text" in result.output

    def test_result_timestamp(self):
        """Test automatic timestamp"""
        from aipt_v2.tools.winpwn import PowerShellResult

        result = PowerShellResult(
            success=True,
            exit_code=0,
            stdout="",
            stderr="",
            execution_time=0
        )

        assert result.timestamp is not None
        assert "T" in result.timestamp  # ISO format

    def test_executor_instantiation(self):
        """Test PowerShellExecutor can be created"""
        from aipt_v2.tools.winpwn import PowerShellExecutor

        executor = PowerShellExecutor()
        assert executor.execution_policy == "Bypass"
        assert executor.encoding == "utf-8"

    def test_executor_custom_path(self):
        """Test executor with custom PowerShell path"""
        from aipt_v2.tools.winpwn import PowerShellExecutor

        executor = PowerShellExecutor(
            powershell_path="/custom/pwsh",
            use_pwsh_core=True,
            execution_policy="RemoteSigned"
        )

        # Custom path should be used
        assert executor.execution_policy == "RemoteSigned"


# =============================================================================
# Test WinPwn Output Parsers
# =============================================================================

class TestWinPwnParsers:
    """Tests for winpwn_parsers.py"""

    def test_finding_dataclass(self):
        """Test WinPwnFinding dataclass"""
        from aipt_v2.tools.winpwn import (
            WinPwnFinding,
            FindingSeverity,
            FindingCategory
        )

        finding = WinPwnFinding(
            title="Test Finding",
            category=FindingCategory.CREDENTIAL,
            severity=FindingSeverity.HIGH,
            description="A test finding",
            source_module="test"
        )

        assert finding.title == "Test Finding"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.category == FindingCategory.CREDENTIAL
        assert finding.timestamp is not None

    def test_finding_to_dict(self):
        """Test finding serialization"""
        from aipt_v2.tools.winpwn import (
            WinPwnFinding,
            FindingSeverity,
            FindingCategory
        )

        finding = WinPwnFinding(
            title="Test",
            category=FindingCategory.VULNERABILITY,
            severity=FindingSeverity.CRITICAL,
            description="Description",
            source_module="module"
        )

        data = finding.to_dict()
        assert data["title"] == "Test"
        assert data["severity"] == "critical"
        assert data["category"] == "vulnerability"

    def test_extracted_credential_dataclass(self):
        """Test ExtractedCredential dataclass"""
        from aipt_v2.tools.winpwn import ExtractedCredential

        cred = ExtractedCredential(
            username="admin",
            domain="CORP",
            ntlm_hash="aad3b435b51404ee:31d6cfe0d16ae931",
            source="sam_dump",
            credential_type="hash"
        )

        assert cred.username == "admin"
        assert cred.domain == "CORP"
        assert cred.credential_type == "hash"

    def test_severity_enum(self):
        """Test FindingSeverity enum values"""
        from aipt_v2.tools.winpwn import FindingSeverity

        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_category_enum(self):
        """Test FindingCategory enum values"""
        from aipt_v2.tools.winpwn import FindingCategory

        assert FindingCategory.CREDENTIAL.value == "credential"
        assert FindingCategory.PRIVILEGE.value == "privilege"
        assert FindingCategory.MISCONFIGURATION.value == "misconfiguration"

    def test_parser_instantiation(self):
        """Test WinPwnParser can be created"""
        from aipt_v2.tools.winpwn import WinPwnParser

        parser = WinPwnParser()
        assert parser is not None

    def test_parse_sam_dump(self):
        """Test SAM dump parsing"""
        from aipt_v2.tools.winpwn import WinPwnParser

        parser = WinPwnParser()

        # SAM output without leading newline
        sam_output = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"""

        credentials = parser.parse_sam_dump(sam_output)

        assert len(credentials) == 2
        assert credentials[0].username.strip() == "Administrator"
        assert credentials[0].lm_hash == "aad3b435b51404eeaad3b435b51404ee"
        assert credentials[0].ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_parse_kerberos_tickets(self):
        """Test Kerberos ticket parsing"""
        from aipt_v2.tools.winpwn import WinPwnParser

        parser = WinPwnParser()

        kerb_output = """
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local~1433*$abc123...
$krb5asrep$23$user@CORP.LOCAL:abc456...
"""

        findings = parser.parse_kerberos_tickets(kerb_output)

        assert len(findings) == 2

        # Check Kerberoast finding
        tgs_finding = [f for f in findings if "Kerberoastable" in f.title][0]
        assert "svc_sql" in tgs_finding.title
        assert tgs_finding.metadata.get("username") == "svc_sql"

        # Check AS-REP finding
        asrep_finding = [f for f in findings if "AS-REP" in f.title][0]
        assert "user" in asrep_finding.title or "user" in asrep_finding.metadata.get("username", "")

    def test_parse_privilege_check(self):
        """Test privilege enumeration parsing"""
        from aipt_v2.tools.winpwn import WinPwnParser

        parser = WinPwnParser()

        priv_output = """
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeDebugPrivilege              Debug programs                       Enabled
SeImpersonatePrivilege        Impersonate a client after auth      Enabled
"""

        findings = parser.parse_privilege_check(priv_output)

        assert len(findings) >= 2

        # Should find SeDebugPrivilege
        debug_priv = [f for f in findings if "SeDebugPrivilege" in f.title]
        assert len(debug_priv) == 1

        # Should find SeImpersonatePrivilege
        impersonate = [f for f in findings if "SeImpersonatePrivilege" in f.title]
        assert len(impersonate) == 1

    def test_parse_local_recon_alwayselevated(self):
        """Test AlwaysInstallElevated detection"""
        from aipt_v2.tools.winpwn import WinPwnParser

        parser = WinPwnParser()

        recon_output = """
[+] Checking AlwaysInstallElevated...
AlwaysInstallElevated    REG_DWORD    0x1
"""

        findings = parser.parse_local_recon(recon_output)

        elevated = [f for f in findings if "AlwaysInstallElevated" in f.title]
        assert len(elevated) == 1

    def test_parse_all(self):
        """Test combined parsing"""
        from aipt_v2.tools.winpwn import WinPwnParser

        parser = WinPwnParser()

        combined_output = """
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
$krb5tgs$23$*svc$CORP$test*$hash...
SeDebugPrivilege Enabled
"""

        findings, credentials = parser.parse_all(combined_output, module="test")

        assert len(credentials) >= 1
        assert len(findings) >= 2


# =============================================================================
# Test WinPwn Attacks Orchestrator
# =============================================================================

class TestWinPwnAttacks:
    """Tests for winpwn_attacks.py"""

    def test_module_result_dataclass(self):
        """Test ModuleResult dataclass"""
        from aipt_v2.tools.winpwn import ModuleResult, WinPwnModule

        result = ModuleResult(
            module=WinPwnModule.LOCAL_RECON,
            success=True,
            execution_time=5.0,
            raw_output="test output"
        )

        assert result.success is True
        assert result.module == WinPwnModule.LOCAL_RECON
        assert result.timestamp is not None

    def test_winpwn_result_dataclass(self):
        """Test WinPwnResult dataclass"""
        from aipt_v2.tools.winpwn import WinPwnResult

        result = WinPwnResult(
            status="completed",
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:05:00Z",
            duration=300.0,
            modules_run=["localrecon", "privesc"],
            module_results=[]
        )

        assert result.status == "completed"
        assert len(result.modules_run) == 2

    def test_result_summary(self):
        """Test result summary generation"""
        from aipt_v2.tools.winpwn import (
            WinPwnResult,
            WinPwnFinding,
            FindingSeverity,
            FindingCategory
        )

        finding = WinPwnFinding(
            title="Test",
            category=FindingCategory.CREDENTIAL,
            severity=FindingSeverity.HIGH,
            description="Test finding",
            source_module="test"
        )

        result = WinPwnResult(
            status="completed",
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:01:00Z",
            duration=60.0,
            modules_run=["localrecon"],
            module_results=[],
            all_findings=[finding]
        )

        summary = result.get_summary()

        assert summary["status"] == "completed"
        assert summary["total_findings"] == 1
        assert summary["findings_by_severity"]["high"] == 1

    def test_attacks_instantiation(self):
        """Test WinPwnAttacks can be created"""
        from aipt_v2.tools.winpwn import WinPwnAttacks, WinPwnConfig

        config = WinPwnConfig()
        attacks = WinPwnAttacks(config)

        assert attacks.config is not None
        assert attacks.executor is not None
        assert attacks.parser is not None


# =============================================================================
# Test Module Utilities
# =============================================================================

class TestModuleUtilities:
    """Tests for module utility functions"""

    def test_get_available_modules(self):
        """Test available modules listing"""
        from aipt_v2.tools.winpwn import get_available_modules

        modules = get_available_modules()

        assert "localrecon" in modules
        assert "kerberoasting" in modules
        assert "privesc" in modules
        assert len(modules) >= 15

    def test_get_module_info(self):
        """Test module info retrieval"""
        from aipt_v2.tools.winpwn import get_module_info

        info = get_module_info("localrecon")
        assert "Local" in info or "recon" in info.lower()

        # Unknown module
        info = get_module_info("nonexistent")
        assert "Unknown" in info

    def test_available_modules_constant(self):
        """Test AVAILABLE_MODULES constant"""
        from aipt_v2.tools.winpwn import AVAILABLE_MODULES

        assert isinstance(AVAILABLE_MODULES, dict)
        assert all(isinstance(k, str) for k in AVAILABLE_MODULES.keys())
        assert all(isinstance(v, str) for v in AVAILABLE_MODULES.values())


# =============================================================================
# Test Module Exports
# =============================================================================

class TestModuleExports:
    """Test that all expected exports are available"""

    def test_config_exports(self):
        """Test configuration exports"""
        from aipt_v2.tools.winpwn import (
            WinPwnConfig,
            WinPwnCredentials,
            WinPwnModule,
            WinPwnExecutionMode,
            get_winpwn_config,
            validate_winpwn_config,
        )

        assert WinPwnConfig is not None
        assert WinPwnCredentials is not None
        assert callable(get_winpwn_config)
        assert callable(validate_winpwn_config)

    def test_executor_exports(self):
        """Test executor exports"""
        from aipt_v2.tools.winpwn import (
            PowerShellExecutor,
            PowerShellResult,
            WinRMExecutor,
        )

        assert PowerShellExecutor is not None
        assert PowerShellResult is not None
        assert WinRMExecutor is not None

    def test_parser_exports(self):
        """Test parser exports"""
        from aipt_v2.tools.winpwn import (
            WinPwnParser,
            WinPwnFinding,
            ExtractedCredential,
            FindingSeverity,
            FindingCategory,
        )

        assert WinPwnParser is not None
        assert WinPwnFinding is not None
        assert ExtractedCredential is not None

    def test_attacks_exports(self):
        """Test attacks exports"""
        from aipt_v2.tools.winpwn import (
            WinPwnAttacks,
            WinPwnResult,
            ModuleResult,
            run_winpwn_assessment,
            quick_local_recon,
        )

        assert WinPwnAttacks is not None
        assert WinPwnResult is not None
        assert callable(run_winpwn_assessment)
        assert callable(quick_local_recon)


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
