"""
AIPT Payloads Module

Security testing payloads for various vulnerability classes:
- XSS (Cross-Site Scripting)
- SQL Injection
- Command Injection
- Path Traversal
- SSRF (Server-Side Request Forgery)
- Template Injection
"""

from .xss import XSSPayloads
from .sqli import SQLiPayloads
from .cmdi import CommandInjectionPayloads
from .traversal import PathTraversalPayloads
from .ssrf import SSRFPayloads
from .templates import TemplateInjectionPayloads

__all__ = [
    "XSSPayloads",
    "SQLiPayloads",
    "CommandInjectionPayloads",
    "PathTraversalPayloads",
    "SSRFPayloads",
    "TemplateInjectionPayloads",
]
