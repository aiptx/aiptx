"""
AIPT Evasion Module - WAF Bypass and Request Obfuscation

Provides evasion techniques for authorized penetration testing:
- WAF bypass payload generation
- Request obfuscation and encoding
- User-Agent rotation
- TLS fingerprint randomization

WARNING: Use only for authorized security testing!

Usage:
    from aipt_v2.evasion import WAFBypass, RequestObfuscator, UARotator

    bypass = WAFBypass()
    payloads = bypass.generate_sqli_bypasses("' OR '1'='1")
"""

from aipt_v2.evasion.waf_bypass import (
    WAFBypass,
    BypassPayload,
    generate_bypass_payloads,
)

from aipt_v2.evasion.request_obfuscator import (
    RequestObfuscator,
    ObfuscationConfig,
    obfuscate_request,
)

from aipt_v2.evasion.ua_rotator import (
    UARotator,
    UserAgent,
    get_random_ua,
)

from aipt_v2.evasion.tls_fingerprint import (
    TLSFingerprint,
    randomize_tls,
)

# AD-specific evasion for stealth penetration testing
from aipt_v2.evasion.ad_evasion import (
    ADEvasion,
    EvasionConfig,
    EvasionStats,
    EvasionTechnique,
    StealthLevel,
    STEALTH_PROFILES,
    get_evasion_profile,
    create_stealth_wrapper,
)

__all__ = [
    # WAF Bypass
    "WAFBypass",
    "BypassPayload",
    "generate_bypass_payloads",
    # Obfuscation
    "RequestObfuscator",
    "ObfuscationConfig",
    "obfuscate_request",
    # User-Agent
    "UARotator",
    "UserAgent",
    "get_random_ua",
    # TLS
    "TLSFingerprint",
    "randomize_tls",
    # AD Evasion - Stealth techniques for AD testing
    "ADEvasion",
    "EvasionConfig",
    "EvasionStats",
    "EvasionTechnique",
    "StealthLevel",
    "STEALTH_PROFILES",
    "get_evasion_profile",
    "create_stealth_wrapper",
]
