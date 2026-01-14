"""
TLS Fingerprint Randomization

Randomizes TLS fingerprint (JA3/JA3S) to evade detection:
- Cipher suite ordering
- TLS extension manipulation
- ALPN protocol ordering
- Supported versions randomization

Usage:
    from aipt_v2.evasion import TLSFingerprint

    tls = TLSFingerprint()
    context = tls.get_randomized_context()
"""

import ssl
import random
from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class TLSProfile:
    """TLS connection profile."""
    name: str
    ciphers: List[str]
    protocols: List[str]
    extensions: List[str]
    alpn: List[str]
    ja3_hash: str = ""


class TLSFingerprint:
    """
    TLS Fingerprint Randomization.

    Modifies TLS connection parameters to evade
    JA3/JA3S fingerprint detection.
    """

    # Common cipher suites
    CIPHER_SUITES = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ]

    # Browser-like cipher ordering
    BROWSER_PROFILES = {
        "chrome": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ],
        "firefox": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ],
        "safari": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ],
    }

    # ALPN protocols
    ALPN_PROTOCOLS = ["h2", "http/1.1"]

    def __init__(self):
        """Initialize TLS fingerprint handler."""
        self.profiles = self._create_profiles()

    def _create_profiles(self) -> Dict[str, TLSProfile]:
        """Create TLS profiles for different browsers."""
        return {
            "chrome": TLSProfile(
                name="Chrome",
                ciphers=self.BROWSER_PROFILES["chrome"],
                protocols=["TLSv1.2", "TLSv1.3"],
                extensions=["server_name", "ec_point_formats", "supported_groups"],
                alpn=["h2", "http/1.1"]
            ),
            "firefox": TLSProfile(
                name="Firefox",
                ciphers=self.BROWSER_PROFILES["firefox"],
                protocols=["TLSv1.2", "TLSv1.3"],
                extensions=["server_name", "supported_groups", "ec_point_formats"],
                alpn=["h2", "http/1.1"]
            ),
            "safari": TLSProfile(
                name="Safari",
                ciphers=self.BROWSER_PROFILES["safari"],
                protocols=["TLSv1.2", "TLSv1.3"],
                extensions=["server_name", "ec_point_formats", "supported_groups"],
                alpn=["h2", "http/1.1"]
            ),
            "random": TLSProfile(
                name="Random",
                ciphers=self.CIPHER_SUITES.copy(),
                protocols=["TLSv1.2", "TLSv1.3"],
                extensions=["server_name"],
                alpn=["h2", "http/1.1"]
            ),
        }

    def get_profile(self, name: str = "random") -> TLSProfile:
        """
        Get TLS profile.

        Args:
            name: Profile name (chrome, firefox, safari, random)

        Returns:
            TLSProfile
        """
        return self.profiles.get(name, self.profiles["random"])

    def randomize_ciphers(self, base_ciphers: List[str] = None) -> List[str]:
        """
        Randomize cipher suite order.

        Args:
            base_ciphers: Base cipher list

        Returns:
            Randomized cipher list
        """
        ciphers = base_ciphers or self.CIPHER_SUITES.copy()

        # Keep TLS 1.3 ciphers at top but shuffle others
        tls13_ciphers = [c for c in ciphers if c.startswith("TLS_")]
        other_ciphers = [c for c in ciphers if not c.startswith("TLS_")]

        random.shuffle(other_ciphers)

        return tls13_ciphers + other_ciphers

    def randomize_alpn(self) -> List[str]:
        """
        Randomize ALPN protocol order.

        Returns:
            Randomized ALPN list
        """
        alpn = self.ALPN_PROTOCOLS.copy()
        if random.random() > 0.5:
            alpn.reverse()
        return alpn

    def create_ssl_context(
        self,
        profile: str = "random",
        verify: bool = True
    ) -> ssl.SSLContext:
        """
        Create SSL context with randomized fingerprint.

        Args:
            profile: TLS profile to use
            verify: Verify certificates

        Returns:
            Configured SSLContext
        """
        context = ssl.create_default_context()

        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Get profile
        tls_profile = self.get_profile(profile)

        # Set ciphers
        if profile == "random":
            ciphers = self.randomize_ciphers(tls_profile.ciphers)
        else:
            ciphers = tls_profile.ciphers

        try:
            cipher_string = ":".join(ciphers)
            context.set_ciphers(cipher_string)
        except ssl.SSLError:
            # Fall back to default if cipher setting fails
            pass

        # Set minimum TLS version
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set ALPN protocols
        try:
            alpn = self.randomize_alpn() if profile == "random" else tls_profile.alpn
            context.set_alpn_protocols(alpn)
        except (ssl.SSLError, AttributeError):
            pass

        return context

    def get_randomized_context(self, verify: bool = True) -> ssl.SSLContext:
        """
        Get SSL context with randomized fingerprint.

        Args:
            verify: Verify certificates

        Returns:
            Randomized SSLContext
        """
        # Randomly pick a browser profile
        profile = random.choice(["chrome", "firefox", "safari", "random"])
        return self.create_ssl_context(profile, verify)

    def get_cipher_string(self, profile: str = "random") -> str:
        """
        Get cipher string for requests/urllib3.

        Args:
            profile: TLS profile

        Returns:
            Cipher string
        """
        tls_profile = self.get_profile(profile)

        if profile == "random":
            ciphers = self.randomize_ciphers(tls_profile.ciphers)
        else:
            ciphers = tls_profile.ciphers

        return ":".join(ciphers)


def randomize_tls(verify: bool = True) -> ssl.SSLContext:
    """
    Get randomized TLS context.

    Args:
        verify: Verify certificates

    Returns:
        Randomized SSLContext
    """
    tls = TLSFingerprint()
    return tls.get_randomized_context(verify)


def get_browser_tls(browser: str = "chrome", verify: bool = True) -> ssl.SSLContext:
    """
    Get browser-like TLS context.

    Args:
        browser: Browser name (chrome, firefox, safari)
        verify: Verify certificates

    Returns:
        Browser-like SSLContext
    """
    tls = TLSFingerprint()
    return tls.create_ssl_context(browser, verify)
