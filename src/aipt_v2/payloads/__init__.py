"""
AIPTX Payloads Module.

Security testing payloads for various vulnerability classes:
- XSS (Cross-Site Scripting)
- SQL Injection (comprehensive database with 6+ DB types)
- Command Injection
- Path Traversal
- SSRF (Server-Side Request Forgery)
- Template Injection
- XXE (XML External Entity Injection)

v5.2 Enhancement: Added comprehensive SQLInjectionDB with:
- 6 database types (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB)
- 6 injection techniques (error, union, blind boolean/time, stacked, OOB)
- WAF bypass variants with 7+ encoding methods
"""

from .cmdi import CommandInjectionPayloads
from .sqli import SQLiPayloads
from .sqli_payloads import (
    DBType,
    EncodingType,
    SQLInjectionDB,
    SQLInjectionFinding,
    SQLITechnique,
    SQLPayload,
)
from .ssrf import SSRFPayloads
from .templates import TemplateInjectionPayloads
from .traversal import PathTraversalPayloads
from .xss import XSSPayloads
from .xxe import XXEPayload, XXEPayloads, get_xxe_payloads

__all__ = [
    # XSS
    "XSSPayloads",
    # SQLi (legacy)
    "SQLiPayloads",
    # SQLi (v5.2 comprehensive database)
    "SQLInjectionDB",
    "DBType",
    "SQLITechnique",
    "EncodingType",
    "SQLPayload",
    "SQLInjectionFinding",
    # Command Injection
    "CommandInjectionPayloads",
    # Path Traversal
    "PathTraversalPayloads",
    # SSRF
    "SSRFPayloads",
    # Template Injection
    "TemplateInjectionPayloads",
    # XXE
    "XXEPayloads",
    "XXEPayload",
    "get_xxe_payloads",
]
