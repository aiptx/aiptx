"""
Unit tests for AIPTX v5.0 Active Directory modules.

Tests module instantiation, data classes, and helper functions
without requiring actual AD infrastructure.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime


# =============================================================================
# Test AD Discovery Module
# =============================================================================

class TestADDiscovery:
    """Tests for recon/ad_discovery.py"""

    def test_config_defaults(self):
        """Test ADDiscoveryConfig has sensible defaults"""
        from aipt_v2.recon.ad_discovery import ADDiscoveryConfig

        config = ADDiscoveryConfig()
        assert config.enumerate_srv is True
        assert config.enumerate_trusts is True

    def test_domain_controller_dataclass(self):
        """Test DomainController can be instantiated"""
        from aipt_v2.recon.ad_discovery import DomainController

        dc = DomainController(
            hostname="DC01.test.local",
            ip="192.168.1.10",
            domain="test.local",
            is_gc=True,
            is_pdc=True
        )
        assert dc.hostname == "DC01.test.local"
        assert dc.ip == "192.168.1.10"
        assert dc.is_gc is True

    def test_domain_trust_dataclass(self):
        """Test DomainTrust dataclass"""
        from aipt_v2.recon.ad_discovery import DomainTrust

        trust = DomainTrust(
            source_domain="test.local",
            target_domain="child.test.local",
            trust_type="parent-child",
            trust_direction="bidirectional"
        )
        assert trust.source_domain == "test.local"
        assert trust.target_domain == "child.test.local"

    def test_discovery_result_dataclass(self):
        """Test ADDiscoveryResult can be instantiated"""
        from aipt_v2.recon.ad_discovery import ADDiscoveryResult, DomainController

        dc = DomainController(hostname="DC01.test.local", ip="192.168.1.10")
        result = ADDiscoveryResult(
            target_domain="test.local",
            domain_controllers=[dc]
        )
        assert result.target_domain == "test.local"
        assert len(result.domain_controllers) == 1


# =============================================================================
# Test AD User Enumeration Module
# =============================================================================

class TestADUserEnumeration:
    """Tests for recon/ad_users.py"""

    def test_enum_config_defaults(self):
        """Test ADUserEnumConfig has sensible defaults"""
        from aipt_v2.recon.ad_users import ADUserEnumConfig

        config = ADUserEnumConfig()
        assert config.use_kerberos is True
        assert config.use_rid_cycle is True
        assert config.use_ldap is True

    def test_ad_user_dataclass(self):
        """Test ADUser dataclass"""
        from aipt_v2.recon.ad_users import ADUser

        user = ADUser(
            username="jdoe",
            domain="test.local",
            sid="S-1-5-21-...",
            dn="CN=John Doe,CN=Users,DC=test,DC=local"
        )
        assert user.username == "jdoe"
        assert user.domain == "test.local"

    def test_enum_result(self):
        """Test ADUserEnumResult"""
        from aipt_v2.recon.ad_users import ADUserEnumResult, ADUser

        user = ADUser(username="test", domain="test.local")
        result = ADUserEnumResult(
            target_domain="test.local",
            dc_ip="192.168.1.10",
            users=[user],
            methods_used=["kerberos"],
            total_found=1
        )
        assert result.total_found == 1
        assert len(result.users) == 1


# =============================================================================
# Test AD Privesc Scanner Module
# =============================================================================

class TestADPrivescScanner:
    """Tests for scanners/ad_privesc_scanner.py"""

    def test_scanner_config(self):
        """Test ADPrivescConfig"""
        from aipt_v2.scanners.ad_privesc_scanner import ADPrivescConfig

        config = ADPrivescConfig(
            domain="test.local",
            dc_ip="192.168.1.10",
            username="scanner",
            password="secret"
        )
        assert config.domain == "test.local"

    def test_scanner_instantiation(self):
        """Test ADPrivescScanner can be created"""
        from aipt_v2.scanners.ad_privesc_scanner import ADPrivescScanner, ADPrivescConfig

        config = ADPrivescConfig(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="user",
            password="pass"
        )
        scanner = ADPrivescScanner(config)
        assert scanner.config.domain == "test.local"


# =============================================================================
# Test ADCS Scanner Module
# =============================================================================

class TestADCSScanner:
    """Tests for scanners/ad_adcs_scanner.py"""

    def test_scanner_config(self):
        """Test ADCSConfig"""
        from aipt_v2.scanners.ad_adcs_scanner import ADCSConfig

        config = ADCSConfig(
            domain="test.local",
            dc_ip="192.168.1.10",
            username="user",
            password="pass"
        )
        assert config.domain == "test.local"

    def test_certificate_template_dataclass(self):
        """Test CertificateTemplate dataclass"""
        from aipt_v2.scanners.ad_adcs_scanner import CertificateTemplate

        template = CertificateTemplate(
            name="User",
            display_name="User Certificate"
        )
        assert template.name == "User"
        assert template.display_name == "User Certificate"


# =============================================================================
# Test AD Credential Attacks Module
# =============================================================================

class TestADCredentialAttacks:
    """Tests for exploitation/ad_credentials.py"""

    def test_credential_config(self):
        """Test ADCredentialConfig"""
        from aipt_v2.exploitation.ad_credentials import ADCredentialConfig

        config = ADCredentialConfig(
            domain="test.local",
            dc_ip="192.168.1.10",
            username="attacker",
            password="password"
        )
        assert config.domain == "test.local"

    def test_extracted_credential_dataclass(self):
        """Test ExtractedCredential dataclass"""
        from aipt_v2.exploitation.ad_credentials import ExtractedCredential, CredentialType

        cred = ExtractedCredential(
            username="admin",
            domain="TEST",
            credential_type=CredentialType.NTLM_HASH,
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert cred.username == "admin"
        assert cred.credential_type == CredentialType.NTLM_HASH

    def test_relay_target_dataclass(self):
        """Test RelayTarget dataclass"""
        from aipt_v2.exploitation.ad_credentials import RelayTarget

        target = RelayTarget(
            host="192.168.1.10",
            port=636,
            protocol="ldaps",
            signing_required=False
        )
        assert target.protocol == "ldaps"
        assert target.host == "192.168.1.10"


# =============================================================================
# Test AD Delegation Attacks Module
# =============================================================================

class TestADDelegationAttacks:
    """Tests for exploitation/ad_delegation.py"""

    def test_delegation_config(self):
        """Test ADDelegationConfig"""
        from aipt_v2.exploitation.ad_delegation import ADDelegationConfig

        config = ADDelegationConfig(
            domain="test.local",
            dc_ip="192.168.1.10",
            username="attacker",
            password="password"
        )
        assert config.domain == "test.local"

    def test_delegation_type_enum(self):
        """Test DelegationType enum"""
        from aipt_v2.exploitation.ad_delegation import DelegationType

        assert DelegationType.UNCONSTRAINED.value == "unconstrained"
        assert DelegationType.CONSTRAINED.value == "constrained"
        assert DelegationType.RBCD.value == "rbcd"

    def test_kerberos_ticket_dataclass(self):
        """Test KerberosTicket dataclass"""
        from aipt_v2.exploitation.ad_delegation import KerberosTicket, TicketType

        ticket = KerberosTicket(
            ticket_type=TicketType.TGT,
            username="user",
            domain="TEST.LOCAL",
            target_service="krbtgt/TEST.LOCAL",
            ticket_b64="YII..."
        )
        assert ticket.ticket_type == TicketType.TGT
        assert ticket.username == "user"


# =============================================================================
# Test ADCS Exploitation Module
# =============================================================================

class TestADCSExploitation:
    """Tests for exploitation/ad_adcs.py"""

    def test_exploit_config(self):
        """Test ADCSExploitConfig"""
        from aipt_v2.exploitation.ad_adcs import ADCSExploitConfig

        config = ADCSExploitConfig(
            domain="test.local",
            ca_host="CA01.test.local",
            username="user",
            password="pass"
        )
        assert config.ca_host == "CA01.test.local"

    def test_issued_certificate_dataclass(self):
        """Test IssuedCertificate dataclass"""
        from aipt_v2.exploitation.ad_adcs import IssuedCertificate

        cert = IssuedCertificate(
            subject="CN=admin,DC=test,DC=local",
            issuer="CN=test-CA,DC=test,DC=local",
            serial_number="1234567890",
            pfx_file="/tmp/admin.pfx"
        )
        assert cert.subject == "CN=admin,DC=test,DC=local"
        assert cert.pfx_file == "/tmp/admin.pfx"


# =============================================================================
# Test AD Chain Templates Module
# =============================================================================

class TestADChainTemplates:
    """Tests for exploitation/ad_chain_templates.py"""

    def test_chain_templates_exist(self):
        """Test that AD attack chains are defined"""
        from aipt_v2.exploitation.ad_chain_templates import AD_ATTACK_CHAINS

        assert "kerberoast" in AD_ATTACK_CHAINS
        assert "asreproast" in AD_ATTACK_CHAINS
        assert "rbcd" in AD_ATTACK_CHAINS

    def test_get_ad_chain(self):
        """Test get_ad_chain function"""
        from aipt_v2.exploitation.ad_chain_templates import get_ad_chain

        chain = get_ad_chain("kerberoast")
        assert chain is not None

        # Non-existent chain
        assert get_ad_chain("nonexistent") is None

    def test_list_all_chains(self):
        """Test list_all_chains function"""
        from aipt_v2.exploitation.ad_chain_templates import list_all_chains

        chains = list_all_chains()
        assert len(chains) >= 7  # At least 7 chains defined
        assert "kerberoast" in chains

    def test_chain_difficulty_enum(self):
        """Test ADChainDifficulty enum"""
        from aipt_v2.exploitation.ad_chain_templates import ADChainDifficulty

        assert ADChainDifficulty.LOW.value == "low"
        assert ADChainDifficulty.HIGH.value == "high"
        assert ADChainDifficulty.ADVANCED.value == "advanced"


# =============================================================================
# Test AD Lateral Movement Module
# =============================================================================

class TestADLateralMovement:
    """Tests for lateral/ad_lateral.py"""

    def test_lateral_config(self):
        """Test ADLateralConfig"""
        from aipt_v2.lateral.ad_lateral import ADLateralConfig

        config = ADLateralConfig(
            domain="test.local",
            username="admin",
            password="password"
        )
        assert config.domain == "test.local"

    def test_exec_method_enum(self):
        """Test ExecMethod enum"""
        from aipt_v2.lateral.ad_lateral import ExecMethod

        assert ExecMethod.PSEXEC.value == "psexec"
        assert ExecMethod.WMIEXEC.value == "wmiexec"
        assert ExecMethod.DCOMEXEC.value == "dcomexec"
        assert ExecMethod.SMBEXEC.value == "smbexec"

    def test_exec_result_dataclass(self):
        """Test ExecResult dataclass"""
        from aipt_v2.lateral.ad_lateral import ExecResult, ExecMethod

        result = ExecResult(
            target="192.168.1.20",
            method=ExecMethod.WMIEXEC,
            command="whoami",
            stdout="TEST\\admin",
            success=True
        )
        assert result.success
        assert result.method == ExecMethod.WMIEXEC
        assert result.stdout == "TEST\\admin"


# =============================================================================
# Test AD Attack Planner Module
# =============================================================================

class TestADAttackPlanner:
    """Tests for intelligence/ad_attack_planner.py"""

    def test_attack_objective_enum(self):
        """Test AttackObjective enum"""
        from aipt_v2.intelligence.ad_attack_planner import AttackObjective

        assert AttackObjective.DOMAIN_ADMIN.value == "domain_admin"

    def test_ad_environment_dataclass(self):
        """Test ADEnvironment dataclass"""
        from aipt_v2.intelligence.ad_attack_planner import ADEnvironment

        env = ADEnvironment(
            domain="test.local",
            dc_ip="192.168.1.10"
        )
        assert env.domain == "test.local"

    def test_attack_step_dataclass(self):
        """Test AttackStep dataclass"""
        from aipt_v2.intelligence.ad_attack_planner import AttackStep, AttackPhase

        step = AttackStep(
            phase=AttackPhase.RECONNAISSANCE,
            action="Enumerate SPNs",
            description="Find service accounts with SPNs",
            tool="GetUserSPNs.py"
        )
        assert step.action == "Enumerate SPNs"
        assert "GetUserSPNs" in step.tool


# =============================================================================
# Test AD Evasion Module
# =============================================================================

class TestADEvasion:
    """Tests for evasion/ad_evasion.py"""

    def test_stealth_level_enum(self):
        """Test StealthLevel enum"""
        from aipt_v2.evasion.ad_evasion import StealthLevel

        assert StealthLevel.NONE.value == "none"
        assert StealthLevel.PARANOID.value == "paranoid"

    def test_evasion_config_defaults(self):
        """Test EvasionConfig defaults"""
        from aipt_v2.evasion.ad_evasion import EvasionConfig, StealthLevel

        config = EvasionConfig()
        assert config.stealth_level == StealthLevel.MEDIUM
        assert config.min_delay >= 0
        assert config.max_delay >= config.min_delay

    def test_stealth_profiles(self):
        """Test pre-configured stealth profiles"""
        from aipt_v2.evasion.ad_evasion import STEALTH_PROFILES, StealthLevel

        assert "fast" in STEALTH_PROFILES
        assert "balanced" in STEALTH_PROFILES
        assert "stealth" in STEALTH_PROFILES
        assert "paranoid" in STEALTH_PROFILES

        # Fast profile should have no stealth
        assert STEALTH_PROFILES["fast"].stealth_level == StealthLevel.NONE

        # Paranoid should have maximum stealth
        assert STEALTH_PROFILES["paranoid"].stealth_level == StealthLevel.PARANOID

    def test_get_evasion_profile(self):
        """Test get_evasion_profile function"""
        from aipt_v2.evasion.ad_evasion import get_evasion_profile, StealthLevel

        profile = get_evasion_profile("stealth")
        assert profile.stealth_level == StealthLevel.HIGH

        # Unknown profile should return balanced
        profile = get_evasion_profile("unknown")
        assert profile.stealth_level == StealthLevel.MEDIUM

    def test_create_stealth_wrapper(self):
        """Test create_stealth_wrapper convenience function"""
        from aipt_v2.evasion.ad_evasion import create_stealth_wrapper, StealthLevel

        wrapper = create_stealth_wrapper("paranoid")
        assert wrapper.config.stealth_level == StealthLevel.PARANOID

    @pytest.mark.asyncio
    async def test_delay_with_no_stealth(self):
        """Test delay returns 0 when stealth is disabled"""
        from aipt_v2.evasion.ad_evasion import ADEvasion, EvasionConfig, StealthLevel

        config = EvasionConfig(stealth_level=StealthLevel.NONE)
        evasion = ADEvasion(config)

        delay = await evasion.delay("test")
        assert delay == 0.0

    def test_is_business_hours_disabled(self):
        """Test business hours check when disabled"""
        from aipt_v2.evasion.ad_evasion import ADEvasion, EvasionConfig

        config = EvasionConfig(only_business_hours=False)
        evasion = ADEvasion(config)

        # Should always return True when disabled
        assert evasion.is_business_hours() is True

    def test_get_native_command(self):
        """Test native command selection"""
        from aipt_v2.evasion.ad_evasion import ADEvasion, EvasionConfig

        config = EvasionConfig(use_native_tools=True)
        evasion = ADEvasion(config)

        cmd = evasion.get_native_command("user_enum")
        assert cmd is not None
        assert any(x in cmd for x in ["net user", "dsquery", "wmic"])

    def test_get_stats(self):
        """Test statistics retrieval"""
        from aipt_v2.evasion.ad_evasion import ADEvasion, EvasionConfig

        evasion = ADEvasion(EvasionConfig())
        stats = evasion.get_stats()

        assert "total_operations" in stats
        assert "stealth_level" in stats
        assert stats["total_operations"] == 0


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
