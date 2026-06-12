"""
PAT Detection Patterns

Comprehensive regex patterns and detection logic for each vulnerability type.
These patterns are used by the ResponseAnalyzer to identify successful exploitation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .config import DetectionMethod, VulnerabilityType


@dataclass
class DetectionPattern:
    """Detection pattern for vulnerability identification."""

    vuln_type: VulnerabilityType
    method: DetectionMethod
    patterns: list[str] = field(default_factory=list)  # Regex patterns
    keywords: list[str] = field(default_factory=list)  # Simple keyword matches
    time_threshold_ms: float = 5000.0  # For time-based
    content_diff_threshold: float = 0.3  # For content diff
    description: str = ""
    confidence_weight: float = 1.0  # Weight for confidence calc


# =============================================================================
# SQL Injection Detection Patterns
# =============================================================================

SQL_ERROR_PATTERNS = [
    # MySQL
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"Warning.*mysqli_",
    r"MySqlClient\.",
    r"com\.mysql\.jdbc",
    r"Syntax error.*MySQL",
    r"MySQL Query fail",
    r"You have an error in your SQL syntax",
    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"Warning.*PostgreSQL",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError",
    r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s+syntax error at or near",
    # Microsoft SQL Server
    r"Microsoft.*ODBC.*SQL Server",
    r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver",
    r"SqlClient",
    r"\bUnclosed quotation mark\b",
    r"'[^']*' contains the command",
    r"Procedure.*requires parameter",
    r"mssql_query\(",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Incorrect syntax near",
    r"SQL Server.*Driver",
    # Oracle
    r"ORA-\d{5}",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Warning.*ora_",
    r"oracle\.jdbc",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    # SQLite
    r"SQLite.*error",
    r"Warning.*sqlite_",
    r"Warning.*SQLite3::",
    r"SQLite3::SQLException",
    r"SQLITE_ERROR",
    r"\[SQLITE_ERROR\]",
    r"unrecognized token",
    # Generic
    r"SQL error",
    r"SQL syntax error",
    r"Syntax error in query",
    r"invalid query",
    r"SQL command failed",
    r"SQLSTATE\[",
    r"PDOException",
    r"Unexpected EOF in statement",
]

SQL_UNION_INDICATORS = [
    r"\d+\s*,\s*\d+\s*,\s*\d+",  # Column number output
    r"NULL,NULL,NULL",  # NULL column injection
    r"information_schema",  # Schema enumeration
    r"table_name.*column_name",  # Table enum result
]

SQL_BOOLEAN_KEYWORDS = [
    "login successful",
    "welcome back",
    "authentication successful",
    "you are now logged in",
    "access granted",
]


# =============================================================================
# XSS Detection Patterns
# =============================================================================

XSS_REFLECTION_CONTEXTS = [
    # Script tag contexts
    r"<script[^>]*>[^<]*{payload}",
    r"</script>.*{payload}.*<script",
    # Event handlers
    r"on\w+\s*=\s*['\"][^'\"]*{payload}",
    r"on\w+\s*=\s*{payload}",
    # JavaScript contexts
    r"javascript:[^'\"]*{payload}",
    r"href\s*=\s*['\"]javascript:[^'\"]*{payload}",
    # Data URL
    r"data:text/html[^'\"]*{payload}",
    # Style contexts
    r"style\s*=\s*['\"][^'\"]*expression\([^)]*{payload}",
    # Attribute injection
    r"<\w+[^>]*\s+\w+\s*=\s*['\"][^'\"]*{payload}",
]

XSS_DANGEROUS_TAGS = [
    r"<script\b",
    r"<img\b[^>]*\bonerror\b",
    r"<svg\b[^>]*\bonload\b",
    r"<body\b[^>]*\bonload\b",
    r"<iframe\b",
    r"<object\b",
    r"<embed\b",
    r"<link\b[^>]*\bhref\s*=",
    r"<base\b",
    r"<form\b[^>]*\baction\s*=",
]

XSS_EVENT_HANDLERS = [
    "onload",
    "onerror",
    "onclick",
    "onmouseover",
    "onfocus",
    "onblur",
    "onchange",
    "onsubmit",
    "onkeydown",
    "onkeyup",
    "onkeypress",
    "ondblclick",
    "onmousedown",
    "onmouseup",
    "onmousemove",
    "onmouseout",
    "onmouseenter",
    "onmouseleave",
    "oncontextmenu",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    "oninput",
    "oninvalid",
    "onreset",
    "onsearch",
    "onselect",
    "onwheel",
    "oncopy",
    "oncut",
    "onpaste",
    "onscroll",
    "ontoggle",
    "onanimationend",
    "onanimationiteration",
    "onanimationstart",
    "ontransitionend",
]


# =============================================================================
# Command Injection Detection Patterns
# =============================================================================

COMMAND_INJECTION_OUTPUT_PATTERNS = [
    # Linux/Unix identifiers
    r"root:.*:0:0:",  # /etc/passwd
    r"daemon:.*:\d+:\d+:",
    r"uid=\d+.*gid=\d+",  # id command output
    r"Linux\s+\S+\s+\d+\.\d+",  # uname output
    r"/bin/(ba)?sh",
    r"GNU/Linux",
    r"total\s+\d+\s+drwx",  # ls -la output
    # Windows identifiers
    r"Windows\s+(NT|2000|XP|Vista|7|8|10|11|Server)",
    r"\\Windows\\system32",
    r"Microsoft\s+Windows",
    r"Volume\s+Serial\s+Number",
    r"Directory\s+of\s+[A-Z]:\\",
    r"\[COMPUTERNAME\]",
    r"Administrator",
    r"DOMAIN\\",
    # Common command outputs
    r"PING\s+\S+\s+\(\d+\.\d+\.\d+\.\d+\)",  # ping output
    r"\d+\s+bytes\s+from\s+\d+\.\d+\.\d+\.\d+",
    r"ttl=\d+",
    r"rtt\s+min/avg/max",
]

COMMAND_INJECTION_TIME_PAYLOADS = [
    "sleep 5",
    "ping -c 5 127.0.0.1",
    "timeout /t 5",
    "&& sleep 5",
    "; sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
]


# =============================================================================
# SSRF Detection Patterns
# =============================================================================

SSRF_INTERNAL_INDICATORS = [
    # Internal IP responses
    r"^127\.\d+\.\d+\.\d+",
    r"^10\.\d+\.\d+\.\d+",
    r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
    r"^192\.168\.\d+\.\d+",
    r"localhost",
    r"0\.0\.0\.0",
    # Cloud metadata
    r"169\.254\.169\.254",  # AWS/GCP metadata
    r"ami-id",
    r"instance-id",
    r"availability-zone",
    r"iam/security-credentials",
    r"computeMetadata/v1",
    # Internal services
    r"Redis",
    r"Elasticsearch",
    r"MongoDB",
    r"Apache Tomcat",
    r"Jenkins",
    r"Kubernetes",
]

SSRF_FILE_PROTOCOL_INDICATORS = [
    r"root:.*:0:0:",  # file:///etc/passwd
    r"\\Windows\\win\.ini",  # file:///c:/windows/win.ini
    r"\[fonts\]",
    r"\[extensions\]",
]


# =============================================================================
# XXE Detection Patterns
# =============================================================================

XXE_FILE_DISCLOSURE_PATTERNS = [
    r"root:.*:0:0:",  # /etc/passwd
    r"daemon:.*:\d+:\d+:",
    r"\[boot loader\]",  # boot.ini
    r"\[operating systems\]",
    r"\[fonts\]",  # win.ini
    r"\[extensions\]",
    r"<!DOCTYPE",  # DTD reflection
    r"<!ENTITY",
]

XXE_ERROR_PATTERNS = [
    r"XML\s+parsing\s+error",
    r"XML\s+syntax\s+error",
    r"XML\s+declaration\s+not\s+finished",
    r"Start tag expected",
    r"EntityRef.*expecting",
    r"PCDATA invalid Char value",
    r"xmlParseEntityRef",
    r"SAXParseException",
    r"XMLReader",
    r"DOMDocument",
]


# =============================================================================
# LFI/Path Traversal Detection Patterns
# =============================================================================

LFI_FILE_CONTENT_PATTERNS = [
    # /etc/passwd
    r"root:.*:0:0:.*:/root:",
    r"daemon:.*:1:1:",
    r"bin:.*:2:2:",
    r"nobody:.*:65534:65534:",
    # Windows files
    r"\[boot loader\]",
    r"\[operating systems\]",
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[mci extensions\]",
    r"for 16-bit app support",
    # PHP wrappers
    r"<\?php",
    r"<\?=",
    # Common config files
    r"DB_PASSWORD",
    r"DATABASE_URL",
    r"SECRET_KEY",
    r"AWS_ACCESS_KEY",
]

LFI_ERROR_PATTERNS = [
    r"include\(.*\).*failed to open stream",
    r"require\(.*\).*failed to open stream",
    r"Warning.*include",
    r"Warning.*require",
    r"Warning.*file_get_contents",
    r"Warning.*fopen",
    r"No such file or directory",
    r"Failed opening.*for inclusion",
]


# =============================================================================
# NoSQL Injection Detection Patterns
# =============================================================================

NOSQL_ERROR_PATTERNS = [
    # MongoDB
    r"MongoError",
    r"MongoDB.*Error",
    r"BadValue",
    r"Command\s+failed\s+with\s+error",
    r"\$where",
    r"\$gt",
    r"\$ne",
    r"BSONObj",
    r"objectid",
    # CouchDB
    r"CouchDB",
    r"bad_request",
    r"invalid_json",
    # Cassandra
    r"CassandraException",
    r"InvalidQueryException",
]

NOSQL_BYPASS_KEYWORDS = [
    "login successful",
    "welcome",
    "dashboard",
    "profile",
    "logged in as",
]


# =============================================================================
# SSTI Detection Patterns
# =============================================================================

SSTI_REFLECTION_PATTERNS = [
    # Math expressions
    r"\b49\b",  # {{7*7}} -> 49
    r"\b7777777\b",  # {{7*'7'}} -> 7777777
    r"\b823543\b",  # {{7*7*'7'}} -> 823543
    # Jinja2/Flask
    r"<class.*subprocess\.Popen",
    r"<class.*os\.system",
    r"config\s*=\s*{",
    # Twig
    r"Twig_Error",
    r"Twig\\Error",
    # Freemarker
    r"freemarker\.template",
    r"FreeMarker template error",
    # Velocity
    r"VelocityException",
    r"org\.apache\.velocity",
]


# =============================================================================
# CRLF Injection Detection Patterns
# =============================================================================

CRLF_INDICATORS = [
    r"Set-Cookie:.*injected",  # Injected header
    r"X-Injected-Header:",
    r"Location:.*javascript:",
    r"Content-Type:.*text/html",
]


# =============================================================================
# Open Redirect Detection Patterns
# =============================================================================

OPEN_REDIRECT_INDICATORS = [
    r"^https?://evil\.com",
    r"^https?://attacker\.com",
    r"^//evil\.com",
    r"location:.*evil\.com",
]


# =============================================================================
# RFI (Remote File Inclusion) Detection Patterns
# =============================================================================

RFI_ERROR_PATTERNS = [
    # PHP include/require errors
    r"failed to open stream.*http",
    r"include\(\).*URL file-access is disabled",
    r"allow_url_include.*=.*Off",
    r"include\(\).*failed opening.*http",
    r"require\(\).*failed opening.*http",
    # Remote file access indicators
    r"URL file-access",
    r"allow_url_fopen",
    r"getaddrinfo failed",
    r"failed to open stream.*No such file",
    # Error messages indicating remote access attempt
    r"HTTP request failed",
    r"file_get_contents.*failed to open stream",
    r"Unable to access.*http",
]

RFI_SUCCESS_INDICATORS = [
    # Content from remote malicious file
    r"RFI_TEST_STRING_12345",
    r"REMOTE_FILE_INCLUDED",
    r"<\?php.*phpinfo\(\)",
    r"<\?php.*system\(",
]


# =============================================================================
# Insecure Deserialization Detection Patterns
# =============================================================================

DESERIALIZATION_ERROR_PATTERNS = [
    # PHP
    r"unserialize\(\).*failed",
    r"unserialize\(\).*error",
    r"O:\d+:\"[^\"]+\":\d+",  # PHP serialized object notation
    r"__wakeup\(\)",
    r"__destruct\(\)",
    r"allowed_classes",
    # Java
    r"java\.io\.ObjectInputStream",
    r"java\.lang\.ClassNotFoundException",
    r"InvalidClassException",
    r"java\.io\.NotSerializableException",
    r"Could not deserialize object",
    r"ClassCastException",
    r"ysoserial",
    r"CommonsCollections",
    r"InvokerTransformer",
    r"ChainedTransformer",
    # Python
    r"pickle\.loads",
    r"pickle\.load",
    r"_pickle\.UnpicklingError",
    r"cPickle",
    r"PyYAML",
    r"yaml\.load\(",
    r"yaml\.unsafe_load",
    # .NET
    r"BinaryFormatter",
    r"ObjectStateFormatter",
    r"LosFormatter",
    r"NetDataContractSerializer",
    r"TypeConfuseDelegate",
    r"System\.Runtime\.Serialization",
    # Node.js
    r"node-serialize",
    r"serialize.*function",
    r"_$$ND_FUNC$$_",
]

DESERIALIZATION_RCE_INDICATORS = [
    r"uid=\d+.*gid=\d+",  # Command execution output
    r"root:.*:0:0:",  # /etc/passwd content
    r"COMPUTERNAME=",  # Windows env
]


# =============================================================================
# JWT Attack Detection Patterns
# =============================================================================

JWT_ERROR_PATTERNS = [
    # Signature errors
    r"invalid signature",
    r"signature verification failed",
    r"JWT signature does not match",
    r"token signature is invalid",
    # Algorithm errors
    r"algorithm.*none.*not allowed",
    r"algorithm.*not supported",
    r"invalid algorithm",
    r"unsupported.*algorithm",
    # Token structure errors
    r"jwt.*expired",
    r"token.*expired",
    r"invalid.*token",
    r"malformed.*jwt",
    r"jwt.*malformed",
    r"Token is not valid",
    # Key errors
    r"kid.*not found",
    r"kid.*injection",
    r"key.*not found",
    r"invalid.*key",
    r"JWK.*error",
    r"jku.*error",
    # JWT specific
    r"io\.jsonwebtoken",
    r"com\.auth0\.jwt",
    r"pyjwt",
    r"jose\.jwt",
]

JWT_BYPASS_INDICATORS = [
    r"alg\s*:\s*['\"]?none",  # Algorithm none attack
    r"kid\s*:\s*['\"]?\.\./",  # KID path traversal
    r"jku\s*:\s*['\"]?http",  # JKU injection
]


# =============================================================================
# GraphQL Detection Patterns
# =============================================================================

GRAPHQL_ERROR_PATTERNS = [
    # Query errors
    r"GraphQL.*error",
    r"Cannot query field",
    r"Unknown field",
    r"Field.*is not defined",
    r"Syntax error.*GraphQL",
    r"Expected.*got",
    r"Parse error on",
    # Introspection indicators
    r"__schema",
    r"__type",
    r"__typename",
    r"queryType",
    r"mutationType",
    r"subscriptionType",
    r"introspectionQuery",
    # Mutation errors
    r"Mutation.*not found",
    r"Cannot perform mutation",
    # Type errors
    r"Expected type",
    r"Variable.*type mismatch",
    r"is not a valid.*type",
    # Common GraphQL frameworks
    r"apollo-server",
    r"graphql-yoga",
    r"graphene",
]

GRAPHQL_INTROSPECTION_SUCCESS = [
    r'"name"\s*:\s*"__schema"',
    r'"queryType"',
    r'"types"\s*:',
    r'"fields"\s*:\s*\[',
    r'"kind"\s*:\s*"OBJECT"',
]


# =============================================================================
# WebSocket Detection Patterns
# =============================================================================

WEBSOCKET_ERROR_PATTERNS = [
    # Connection errors
    r"WebSocket.*error",
    r"WebSocket.*failed",
    r"WebSocket connection.*closed",
    r"upgrade.*websocket.*failed",
    r"WebSocket handshake.*failed",
    # Protocol errors
    r"Invalid WebSocket frame",
    r"WebSocket.*protocol error",
    r"Sec-WebSocket-Accept",
    r"Sec-WebSocket-Key",
    # Common implementations
    r"socket\.io",
    r"ws://",
    r"wss://",
    r"sockjs",
]

WEBSOCKET_INJECTION_INDICATORS = [
    r"<script>.*</script>",  # XSS via WebSocket
    r"javascript:",
    r"'.*OR.*'.*=.*'",  # SQLi via WebSocket
]


# =============================================================================
# File Upload Detection Patterns
# =============================================================================

FILE_UPLOAD_SUCCESS_INDICATORS = [
    # Success messages
    r"file.*uploaded.*successfully",
    r"upload.*complete",
    r"upload.*success",
    r"file.*saved",
    r"stored.*uploads",
    r"uploaded to",
    # Path disclosure
    r"/uploads/[^/]+\.\w+",
    r"/media/[^/]+\.\w+",
    r"/files/[^/]+\.\w+",
    r"/assets/[^/]+\.\w+",
    # Dangerous file extensions in response
    r"\.(php|jsp|asp|aspx|exe|sh|py|pl|rb|cgi)(\"|'|$|\s)",
]

FILE_UPLOAD_EXECUTION_INDICATORS = [
    # PHP execution
    r"<\?php",
    r"phpinfo\(\)",
    r"PHP Version",
    r"System.*Linux",
    # JSP execution
    r"<%@",
    r"<jsp:",
    r"java\.lang",
    # ASP execution
    r"<%\s",
    r"Response\.Write",
    r"Server\.CreateObject",
]

FILE_UPLOAD_ERROR_PATTERNS = [
    r"file type.*not allowed",
    r"extension.*not permitted",
    r"invalid file type",
    r"mime type.*rejected",
    r"file too large",
    r"upload failed",
    r"UPLOAD_ERR_",
    r"move_uploaded_file.*failed",
]


# =============================================================================
# LDAP Injection Detection Patterns
# =============================================================================

LDAP_ERROR_PATTERNS = [
    r"LDAP.*error",
    r"Invalid.*LDAP.*filter",
    r"ldap_search.*failed",
    r"ldap_bind.*failed",
    r"Size limit exceeded",
    r"Bad search filter",
    r"Invalid DN syntax",
    r"javax\.naming\.NamingException",
    r"LDAPException",
]

LDAP_BYPASS_KEYWORDS = [
    "cn=",
    "dc=",
    "ou=",
    "uid=",
    "admin",
    "Administrator",
]


# =============================================================================
# XPath Injection Detection Patterns
# =============================================================================

XPATH_ERROR_PATTERNS = [
    r"XPath.*error",
    r"XPath.*syntax",
    r"Invalid XPath",
    r"XPATH.*query",
    r"XPathException",
    r"javax\.xml\.xpath",
    r"Missing closing quote",
    r"Unexpected token",
]


# =============================================================================
# NEW - CSRF Detection Patterns
# =============================================================================

CSRF_ERROR_PATTERNS = [
    r"csrf.*token.*missing",
    r"csrf.*token.*invalid",
    r"csrf.*token.*expired",
    r"invalid.*csrf",
    r"csrf.*mismatch",
    r"missing.*csrf.*token",
    r"state.*parameter.*missing",
    r"anti-forgery.*token",
    r"request.*forgery.*detected",
    r"cross-site request forgery",
]

CSRF_SUCCESS_INDICATORS = [
    r"action.*performed.*successfully",
    r"request.*completed",
    r"operation.*successful",
]


# =============================================================================
# NEW - IDOR Detection Patterns
# =============================================================================

IDOR_INDICATORS = [
    r"unauthorized.*access",
    r"access.*denied",
    r"permission.*denied",
    r"forbidden",
    r"not.*authorized",
    r"user_id.*mismatch",
    r"account.*not.*found",
]

IDOR_SUCCESS_INDICATORS = [
    # Different user data accessed
    r"\"user_id\":\s*\d+",
    r"\"account_id\":\s*\d+",
    r"email.*@.*\.com",
    r"\"name\":\s*\"[^\"]+\"",
]


# =============================================================================
# NEW - OAuth Misconfiguration Detection Patterns
# =============================================================================

OAUTH_ERROR_PATTERNS = [
    r"invalid.*redirect.*uri",
    r"redirect.*uri.*mismatch",
    r"invalid.*client.*id",
    r"invalid.*client.*secret",
    r"invalid.*grant",
    r"authorization.*code.*expired",
    r"state.*mismatch",
    r"invalid.*scope",
    r"OAuth.*error",
    r"access.*denied",
]

OAUTH_BYPASS_INDICATORS = [
    r"access_token",
    r"refresh_token",
    r"id_token",
    r"authorization_code",
    r"Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
]


# =============================================================================
# NEW - SAML Injection Detection Patterns
# =============================================================================

SAML_ERROR_PATTERNS = [
    r"SAML.*error",
    r"Invalid.*SAML.*response",
    r"Signature.*verification.*failed",
    r"Invalid.*assertion",
    r"SAML.*assertion.*expired",
    r"Invalid.*issuer",
    r"NameID.*not.*found",
    r"SAMLException",
]

SAML_BYPASS_INDICATORS = [
    r"<saml:Assertion",
    r"<saml:NameID",
    r"<saml:AuthnStatement",
    r"<saml:Conditions",
]


# =============================================================================
# NEW - HTTP Request Smuggling Detection Patterns
# =============================================================================

HTTP_SMUGGLING_INDICATORS = [
    r"HTTP/1\.1\s+400",
    r"Bad\s+Request",
    r"Invalid.*request.*line",
    r"Malformed.*HTTP",
    r"Transfer-Encoding.*error",
    r"Content-Length.*mismatch",
    r"Connection.*reset",
    r"chunk.*error",
    r"desync",
]

HTTP_SMUGGLING_SUCCESS_INDICATORS = [
    # Response splitting indicators
    r"HTTP/1\.[01]\s+\d{3}.*HTTP/1\.[01]",  # Double response
    r"smuggled.*request",
]


# =============================================================================
# NEW - HTTP Parameter Pollution Detection Patterns
# =============================================================================

HPP_INDICATORS = [
    r"duplicate.*parameter",
    r"multiple.*values",
    r"parameter.*pollution",
]

HPP_SUCCESS_INDICATORS = [
    r"parameter.*override",
    r"unexpected.*value",
]


# =============================================================================
# NEW - DNS Rebinding Detection Patterns
# =============================================================================

DNS_REBINDING_INDICATORS = [
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"internal.*service",
    r"192\.168\.\d+\.\d+",
    r"10\.\d+\.\d+\.\d+",
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
]


# =============================================================================
# NEW - CORS Misconfiguration Detection Patterns
# =============================================================================

CORS_ERROR_PATTERNS = [
    r"CORS.*error",
    r"blocked.*CORS.*policy",
    r"no.*access-control-allow-origin",
    r"Origin.*not.*allowed",
    r"Access-Control-Allow-Origin.*null",
]

CORS_MISCONFIG_INDICATORS = [
    r"Access-Control-Allow-Origin:\s*\*",
    r"Access-Control-Allow-Origin:\s*null",
    r"Access-Control-Allow-Credentials:\s*true",
    r"Access-Control-Allow-Origin:.*\.(evil|attacker)\.",
]


# =============================================================================
# NEW - Clickjacking Detection Patterns
# =============================================================================

CLICKJACKING_INDICATORS = [
    # Missing or weak frame protection
    r"X-Frame-Options:\s*ALLOWALL",
    r"frame-ancestors.*\*",
    r"frame-ancestors.*'none'",
]

CLICKJACKING_VULNERABLE_INDICATORS = [
    # No protection headers
    r"Content-Security-Policy",
    r"X-Frame-Options",
]


# =============================================================================
# NEW - Prototype Pollution Detection Patterns
# =============================================================================

PROTOTYPE_POLLUTION_INDICATORS = [
    r"__proto__",
    r"constructor\.prototype",
    r"Object\.prototype",
    r"prototype.*pollution",
    r"\[object Object\]",
]

PROTOTYPE_POLLUTION_SUCCESS = [
    r"polluted",
    r"isAdmin.*true",
    r"role.*admin",
]


# =============================================================================
# NEW - Cache Poisoning Detection Patterns
# =============================================================================

CACHE_POISONING_INDICATORS = [
    r"X-Cache.*HIT",
    r"X-Cache.*MISS",
    r"CF-Cache-Status",
    r"Age:\s*\d+",
    r"X-Served-By",
    r"X-Cache-Lookup",
    r"cached.*response",
]

CACHE_POISONING_SUCCESS = [
    r"poisoned.*cache",
    r"cache.*pollution",
]


# =============================================================================
# NEW - DOM Clobbering Detection Patterns
# =============================================================================

DOM_CLOBBERING_INDICATORS = [
    r"HTMLCollection",
    r"document\.getElementById",
    r"document\.forms",
    r"window\.",
    r"clobbered",
]


# =============================================================================
# NEW - CSV Injection Detection Patterns
# =============================================================================

CSV_INJECTION_INDICATORS = [
    r"^[=+\-@]",
    r"DDE",
    r"=cmd\|",
    r"HYPERLINK",
    r"=IMPORTXML",
    r"=IMPORTDATA",
]

CSV_INJECTION_ERROR = [
    r"formula.*not.*allowed",
    r"invalid.*cell.*content",
    r"macro.*blocked",
]


# =============================================================================
# NEW - Zip Slip Detection Patterns
# =============================================================================

ZIP_SLIP_INDICATORS = [
    r"\.\./",
    r"\.\.\\",
    r"path.*traversal",
    r"symlink",
    r"directory.*escape",
]

ZIP_SLIP_ERROR = [
    r"path.*outside.*allowed",
    r"illegal.*path",
    r"zip.*path.*error",
]


# =============================================================================
# NEW - Race Condition Detection Patterns
# =============================================================================

RACE_CONDITION_INDICATORS = [
    r"concurrent.*modification",
    r"optimistic.*locking",
    r"transaction.*conflict",
    r"deadlock",
    r"lock.*timeout",
    r"version.*mismatch",
]

RACE_CONDITION_SUCCESS = [
    r"double.*credit",
    r"duplicate.*entry",
    r"limit.*exceeded",
]


# =============================================================================
# NEW - Mass Assignment Detection Patterns
# =============================================================================

MASS_ASSIGNMENT_INDICATORS = [
    r"role.*changed",
    r"is_admin.*true",
    r"privilege.*escalation",
    r"permission.*changed",
    r"unpermitted.*parameter",
]


# =============================================================================
# NEW - Type Juggling Detection Patterns
# =============================================================================

TYPE_JUGGLING_INDICATORS = [
    r"0e\d+",
    r"loose.*comparison",
    r"==\s*true",
    r"strcmp.*0",
]

TYPE_JUGGLING_SUCCESS = [
    r"authentication.*successful",
    r"login.*success",
    r"bypass",
]


# =============================================================================
# NEW - LaTeX Injection Detection Patterns
# =============================================================================

LATEX_INJECTION_INDICATORS = [
    r"\\input\{",
    r"\\include\{",
    r"\\write18",
    r"\\immediate\\write",
    r"\\catcode",
    r"LaTeX.*Error",
]

LATEX_INJECTION_SUCCESS = [
    r"root:.*:0:0:",  # /etc/passwd via \input
    r"uid=\d+",
]


# =============================================================================
# NEW - SSI Injection Detection Patterns
# =============================================================================

SSI_INJECTION_INDICATORS = [
    r"<!--#",
    r"<!--#exec",
    r"<!--#include",
    r"<!--#echo",
    r"SSI.*error",
    r"SHTML",
]

SSI_INJECTION_SUCCESS = [
    r"root:.*:0:0:",
    r"uid=\d+",
    r"SERVER_SOFTWARE",
    r"DOCUMENT_ROOT",
]


# =============================================================================
# NEW - XSLT Injection Detection Patterns
# =============================================================================

XSLT_INJECTION_INDICATORS = [
    r"<xsl:stylesheet",
    r"<xsl:transform",
    r"document\(",
    r"system-property\(",
    r"XSLT.*error",
]

XSLT_INJECTION_SUCCESS = [
    r"root:.*:0:0:",
    r"java\.version",
    r"os\.name",
]


# =============================================================================
# NEW - Prompt Injection Detection Patterns
# =============================================================================

PROMPT_INJECTION_INDICATORS = [
    r"ignore.*previous.*instructions",
    r"disregard.*above",
    r"new.*instructions",
    r"system.*prompt",
    r"jailbreak",
]

PROMPT_INJECTION_SUCCESS = [
    r"I.*will.*ignore",
    r"Following.*new.*instructions",
    r"bypassed",
]


# =============================================================================
# NEW - ReDoS Detection Patterns
# =============================================================================

REGEX_DOS_INDICATORS = [
    r"regex.*timeout",
    r"catastrophic.*backtracking",
    r"maximum.*recursion",
    r"stack.*overflow",
    r"pcre.*limit",
]


# =============================================================================
# NEW - Git Exposure Detection Patterns
# =============================================================================

GIT_EXPOSURE_INDICATORS = [
    r"ref:\s*refs/heads/",
    r"\[core\]",
    r"\[remote.*origin\]",
    r"HEAD.*commit",
    r"COMMIT_EDITMSG",
    r"\.gitignore",
    r"objects/pack",
]


# =============================================================================
# NEW - API Key Leak Detection Patterns
# =============================================================================

API_KEY_LEAK_INDICATORS = [
    r"api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9-_]{16,}",
    r"AKIA[A-Z0-9]{16}",  # AWS Access Key
    r"sk-[A-Za-z0-9]{24,}",  # OpenAI
    r"ghp_[A-Za-z0-9]{36}",  # GitHub PAT
    r"AIza[A-Za-z0-9-_]{35}",  # Google API
    r"Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",  # JWT
]


# =============================================================================
# NEW - Secrets Exposure Detection Patterns
# =============================================================================

SECRETS_EXPOSURE_INDICATORS = [
    r"password\s*[=:]\s*['\"][^'\"]+['\"]",
    r"secret\s*[=:]\s*['\"][^'\"]+['\"]",
    r"private[_-]?key",
    r"BEGIN RSA PRIVATE KEY",
    r"BEGIN OPENSSH PRIVATE KEY",
    r"-----BEGIN.*PRIVATE KEY-----",
]


# =============================================================================
# NEW - Host Header Injection Detection Patterns
# =============================================================================

HOST_HEADER_INDICATORS = [
    r"X-Forwarded-Host",
    r"X-Original-URL",
    r"X-Rewrite-URL",
    r"Forwarded:.*host=",
]

HOST_HEADER_SUCCESS = [
    r"password.*reset.*link",
    r"forgot.*password",
    r"attacker\.com",
]


# =============================================================================
# NEW - HTTP Verb Tampering Detection Patterns
# =============================================================================

HTTP_VERB_TAMPERING_INDICATORS = [
    r"Method.*Not.*Allowed",
    r"405.*Method",
    r"Allow:\s*GET,\s*POST",
    r"Invalid.*request.*method",
]


# =============================================================================
# NEW - Subdomain Takeover Detection Patterns
# =============================================================================

SUBDOMAIN_TAKEOVER_INDICATORS = [
    r"NXDOMAIN",
    r"There isn't a GitHub Pages site here",
    r"NoSuchBucket",
    r"The specified bucket does not exist",
    r"Heroku.*no.*such.*app",
    r"The request could not be satisfied",
    r"Repository not found",
    r"Project not found",
]


# =============================================================================
# NEW - Admin Interface Detection Patterns
# =============================================================================

ADMIN_INTERFACE_INDICATORS = [
    r"admin.*login",
    r"administrator.*panel",
    r"dashboard.*admin",
    r"management.*console",
    r"phpMyAdmin",
    r"wp-admin",
]


# =============================================================================
# NEW - Java RMI Detection Patterns
# =============================================================================

JAVA_RMI_INDICATORS = [
    r"java\.rmi",
    r"RemoteException",
    r"ObjectInputStream",
    r"serialVersionUID",
    r"java\.io\.InvalidClassException",
    r"ClassNotFoundException",
]


# =============================================================================
# NEW - Insecure Randomness Detection Patterns
# =============================================================================

INSECURE_RANDOM_INDICATORS = [
    r"Math\.random",
    r"mt_rand",
    r"rand\(",
    r"srand\(",
    r"time\(\)",
    r"microtime",
    r"uniqid",
]


# =============================================================================
# NEW - Dependency Confusion Detection Patterns
# =============================================================================

DEPENDENCY_CONFUSION_INDICATORS = [
    r"package.*not.*found",
    r"module.*not.*found",
    r"could.*not.*resolve",
    r"404.*npm",
    r"404.*pypi",
]


# =============================================================================
# Pattern Registry
# =============================================================================


def get_detection_patterns(vuln_type: VulnerabilityType) -> list[DetectionPattern]:
    """Get detection patterns for a vulnerability type."""
    patterns_map = {
        VulnerabilityType.SQL_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.SQL_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=SQL_ERROR_PATTERNS,
                description="SQL error message detected",
                confidence_weight=0.9,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.SQL_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=SQL_UNION_INDICATORS,
                description="UNION injection output detected",
                confidence_weight=0.85,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.SQL_INJECTION,
                method=DetectionMethod.TIME_BASED,
                patterns=[],
                time_threshold_ms=5000.0,
                description="Time-based blind SQL injection",
                confidence_weight=0.8,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.SQL_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                keywords=SQL_BOOLEAN_KEYWORDS,
                content_diff_threshold=0.3,
                description="Boolean-based blind SQL injection",
                confidence_weight=0.7,
            ),
        ],
        VulnerabilityType.XSS: [
            DetectionPattern(
                vuln_type=VulnerabilityType.XSS,
                method=DetectionMethod.REFLECTION,
                patterns=XSS_DANGEROUS_TAGS,
                description="XSS payload reflected in dangerous context",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.XSS,
                method=DetectionMethod.REFLECTION,
                keywords=XSS_EVENT_HANDLERS,
                description="Event handler injection detected",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.COMMAND_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.COMMAND_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=COMMAND_INJECTION_OUTPUT_PATTERNS,
                description="Command execution output detected",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.COMMAND_INJECTION,
                method=DetectionMethod.TIME_BASED,
                patterns=[],
                time_threshold_ms=5000.0,
                description="Time-based command injection",
                confidence_weight=0.8,
            ),
        ],
        VulnerabilityType.SSRF: [
            DetectionPattern(
                vuln_type=VulnerabilityType.SSRF,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=SSRF_INTERNAL_INDICATORS,
                description="Internal service response detected",
                confidence_weight=0.9,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.SSRF,
                method=DetectionMethod.CALLBACK,
                patterns=[],
                description="Out-of-band callback received",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.XXE: [
            DetectionPattern(
                vuln_type=VulnerabilityType.XXE,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=XXE_FILE_DISCLOSURE_PATTERNS,
                description="File content disclosed via XXE",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.XXE,
                method=DetectionMethod.ERROR_BASED,
                patterns=XXE_ERROR_PATTERNS,
                description="XXE parsing error detected",
                confidence_weight=0.7,
            ),
        ],
        VulnerabilityType.LFI: [
            DetectionPattern(
                vuln_type=VulnerabilityType.LFI,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=LFI_FILE_CONTENT_PATTERNS,
                description="Local file content disclosed",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.LFI,
                method=DetectionMethod.ERROR_BASED,
                patterns=LFI_ERROR_PATTERNS,
                description="LFI error message detected",
                confidence_weight=0.6,
            ),
        ],
        VulnerabilityType.NOSQL_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.NOSQL_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=NOSQL_ERROR_PATTERNS,
                description="NoSQL error detected",
                confidence_weight=0.85,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.NOSQL_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                keywords=NOSQL_BYPASS_KEYWORDS,
                description="NoSQL authentication bypass",
                confidence_weight=0.75,
            ),
        ],
        VulnerabilityType.SSTI: [
            DetectionPattern(
                vuln_type=VulnerabilityType.SSTI,
                method=DetectionMethod.REFLECTION,
                patterns=SSTI_REFLECTION_PATTERNS,
                description="Template expression evaluated",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.CRLF_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CRLF_INJECTION,
                method=DetectionMethod.HEADER_BASED,
                patterns=CRLF_INDICATORS,
                description="CRLF header injection detected",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.OPEN_REDIRECT: [
            DetectionPattern(
                vuln_type=VulnerabilityType.OPEN_REDIRECT,
                method=DetectionMethod.HEADER_BASED,
                patterns=OPEN_REDIRECT_INDICATORS,
                description="Open redirect to external domain",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.RFI: [
            DetectionPattern(
                vuln_type=VulnerabilityType.RFI,
                method=DetectionMethod.ERROR_BASED,
                patterns=RFI_ERROR_PATTERNS,
                description="RFI error indicating remote file access attempt",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.RFI,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=RFI_SUCCESS_INDICATORS,
                description="Remote file content successfully included",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.INSECURE_DESERIALIZATION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                method=DetectionMethod.ERROR_BASED,
                patterns=DESERIALIZATION_ERROR_PATTERNS,
                description="Deserialization error or gadget chain indicator",
                confidence_weight=0.8,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=DESERIALIZATION_RCE_INDICATORS,
                description="Deserialization RCE achieved",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.JWT_ATTACKS: [
            DetectionPattern(
                vuln_type=VulnerabilityType.JWT_ATTACKS,
                method=DetectionMethod.ERROR_BASED,
                patterns=JWT_ERROR_PATTERNS,
                description="JWT validation error indicating weakness",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.JWT_ATTACKS,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=JWT_BYPASS_INDICATORS,
                description="JWT bypass technique successful",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.GRAPHQL: [
            DetectionPattern(
                vuln_type=VulnerabilityType.GRAPHQL,
                method=DetectionMethod.ERROR_BASED,
                patterns=GRAPHQL_ERROR_PATTERNS,
                description="GraphQL error revealing schema or structure",
                confidence_weight=0.75,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.GRAPHQL,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=GRAPHQL_INTROSPECTION_SUCCESS,
                description="GraphQL introspection query succeeded",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.WEBSOCKET: [
            DetectionPattern(
                vuln_type=VulnerabilityType.WEBSOCKET,
                method=DetectionMethod.ERROR_BASED,
                patterns=WEBSOCKET_ERROR_PATTERNS,
                description="WebSocket error revealing implementation",
                confidence_weight=0.6,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.WEBSOCKET,
                method=DetectionMethod.REFLECTION,
                patterns=WEBSOCKET_INJECTION_INDICATORS,
                description="Injection via WebSocket channel",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.FILE_UPLOAD: [
            DetectionPattern(
                vuln_type=VulnerabilityType.FILE_UPLOAD,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=FILE_UPLOAD_SUCCESS_INDICATORS,
                description="Dangerous file uploaded successfully",
                confidence_weight=0.8,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.FILE_UPLOAD,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=FILE_UPLOAD_EXECUTION_INDICATORS,
                description="Uploaded file executed on server",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.FILE_UPLOAD,
                method=DetectionMethod.ERROR_BASED,
                patterns=FILE_UPLOAD_ERROR_PATTERNS,
                description="File upload error revealing bypass opportunity",
                confidence_weight=0.5,
            ),
        ],
        VulnerabilityType.LDAP_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.LDAP_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=LDAP_ERROR_PATTERNS,
                description="LDAP injection error detected",
                confidence_weight=0.8,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.LDAP_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                keywords=LDAP_BYPASS_KEYWORDS,
                description="LDAP query manipulation successful",
                confidence_weight=0.7,
            ),
        ],
        VulnerabilityType.XPATH_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.XPATH_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=XPATH_ERROR_PATTERNS,
                description="XPath injection error detected",
                confidence_weight=0.8,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Authentication & Access Control
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.CSRF: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CSRF,
                method=DetectionMethod.ERROR_BASED,
                patterns=CSRF_ERROR_PATTERNS,
                description="CSRF token validation error",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.CSRF,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=CSRF_SUCCESS_INDICATORS,
                description="CSRF protection bypassed",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.IDOR: [
            DetectionPattern(
                vuln_type=VulnerabilityType.IDOR,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=IDOR_SUCCESS_INDICATORS,
                description="Unauthorized data access via IDOR",
                confidence_weight=0.9,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.IDOR,
                method=DetectionMethod.ERROR_BASED,
                patterns=IDOR_INDICATORS,
                description="Authorization check failure",
                confidence_weight=0.6,
            ),
        ],
        VulnerabilityType.OAUTH_MISCONFIG: [
            DetectionPattern(
                vuln_type=VulnerabilityType.OAUTH_MISCONFIG,
                method=DetectionMethod.ERROR_BASED,
                patterns=OAUTH_ERROR_PATTERNS,
                description="OAuth configuration error",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.OAUTH_MISCONFIG,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=OAUTH_BYPASS_INDICATORS,
                description="OAuth token leaked or bypassed",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.SAML_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.SAML_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=SAML_ERROR_PATTERNS,
                description="SAML validation error",
                confidence_weight=0.75,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.SAML_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=SAML_BYPASS_INDICATORS,
                description="SAML assertion manipulation successful",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.ACCOUNT_TAKEOVER: [
            DetectionPattern(
                vuln_type=VulnerabilityType.ACCOUNT_TAKEOVER,
                method=DetectionMethod.CONTENT_DIFF,
                keywords=["password reset", "token", "email sent", "verification code"],
                description="Account takeover vector identified",
                confidence_weight=0.8,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Protocol/Request Attacks
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.HTTP_SMUGGLING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.HTTP_SMUGGLING,
                method=DetectionMethod.ERROR_BASED,
                patterns=HTTP_SMUGGLING_INDICATORS,
                description="HTTP desync error detected",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.HTTP_SMUGGLING,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=HTTP_SMUGGLING_SUCCESS_INDICATORS,
                description="HTTP request smuggling confirmed",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.HTTP_SMUGGLING,
                method=DetectionMethod.TIME_BASED,
                patterns=[],
                time_threshold_ms=10000.0,
                description="HTTP smuggling via timing desync",
                confidence_weight=0.8,
            ),
        ],
        VulnerabilityType.HPP: [
            DetectionPattern(
                vuln_type=VulnerabilityType.HPP,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=HPP_SUCCESS_INDICATORS,
                description="HTTP parameter pollution successful",
                confidence_weight=0.75,
            ),
        ],
        VulnerabilityType.DNS_REBINDING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.DNS_REBINDING,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=DNS_REBINDING_INDICATORS,
                description="DNS rebinding accessing internal resources",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.CORS_MISCONFIG: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CORS_MISCONFIG,
                method=DetectionMethod.HEADER_BASED,
                patterns=CORS_MISCONFIG_INDICATORS,
                description="CORS misconfiguration allowing arbitrary origins",
                confidence_weight=0.9,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.CORS_MISCONFIG,
                method=DetectionMethod.ERROR_BASED,
                patterns=CORS_ERROR_PATTERNS,
                description="CORS error revealing configuration",
                confidence_weight=0.5,
            ),
        ],
        VulnerabilityType.TABNABBING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.TABNABBING,
                method=DetectionMethod.REFLECTION,
                patterns=[r"target\s*=\s*['\"]_blank['\"](?!.*rel.*noopener)"],
                description="Reverse tabnabbing vulnerability",
                confidence_weight=0.8,
            ),
        ],
        VulnerabilityType.CACHE_POISONING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CACHE_POISONING,
                method=DetectionMethod.HEADER_BASED,
                patterns=CACHE_POISONING_INDICATORS,
                description="Cache headers indicating poisoning potential",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.CACHE_POISONING,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=CACHE_POISONING_SUCCESS,
                description="Cache poisoning confirmed",
                confidence_weight=0.9,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Client-Side Attacks
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.DOM_CLOBBERING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.DOM_CLOBBERING,
                method=DetectionMethod.REFLECTION,
                patterns=DOM_CLOBBERING_INDICATORS,
                description="DOM clobbering attack vector",
                confidence_weight=0.8,
            ),
        ],
        VulnerabilityType.CLICKJACKING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CLICKJACKING,
                method=DetectionMethod.HEADER_BASED,
                patterns=CLICKJACKING_INDICATORS,
                description="Missing or weak frame protection",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.PROTOTYPE_POLLUTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.PROTOTYPE_POLLUTION,
                method=DetectionMethod.REFLECTION,
                patterns=PROTOTYPE_POLLUTION_INDICATORS,
                description="Prototype pollution injection point",
                confidence_weight=0.8,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.PROTOTYPE_POLLUTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=PROTOTYPE_POLLUTION_SUCCESS,
                description="Prototype pollution successful",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.CLIENT_PATH_TRAVERSAL: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CLIENT_PATH_TRAVERSAL,
                method=DetectionMethod.REFLECTION,
                patterns=[r"\.\./", r"\.\.\\\\", r"location\.(hash|search).*\.\./"],
                description="Client-side path traversal",
                confidence_weight=0.75,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - File & Data Attacks
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.CSV_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CSV_INJECTION,
                method=DetectionMethod.REFLECTION,
                patterns=CSV_INJECTION_INDICATORS,
                description="CSV/Formula injection payload reflected",
                confidence_weight=0.85,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.CSV_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=CSV_INJECTION_ERROR,
                description="CSV injection blocked but detectable",
                confidence_weight=0.5,
            ),
        ],
        VulnerabilityType.ZIP_SLIP: [
            DetectionPattern(
                vuln_type=VulnerabilityType.ZIP_SLIP,
                method=DetectionMethod.ERROR_BASED,
                patterns=ZIP_SLIP_ERROR,
                description="Zip slip path traversal detected",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.ZIP_SLIP,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=ZIP_SLIP_INDICATORS,
                description="Zip slip extraction successful",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.ORM_LEAK: [
            DetectionPattern(
                vuln_type=VulnerabilityType.ORM_LEAK,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=[r"\"password\"", r"\"secret\"", r"\"api_key\"", r"hashed_password"],
                description="ORM data leak exposing sensitive fields",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.API_KEY_LEAK: [
            DetectionPattern(
                vuln_type=VulnerabilityType.API_KEY_LEAK,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=API_KEY_LEAK_INDICATORS,
                description="API key/token exposed",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.GIT_EXPOSURE: [
            DetectionPattern(
                vuln_type=VulnerabilityType.GIT_EXPOSURE,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=GIT_EXPOSURE_INDICATORS,
                description="Git repository exposed",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.SECRETS_EXPOSURE: [
            DetectionPattern(
                vuln_type=VulnerabilityType.SECRETS_EXPOSURE,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=SECRETS_EXPOSURE_INDICATORS,
                description="Secrets/credentials exposed",
                confidence_weight=0.9,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Business Logic & Timing
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.RACE_CONDITION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.RACE_CONDITION,
                method=DetectionMethod.ERROR_BASED,
                patterns=RACE_CONDITION_INDICATORS,
                description="Race condition error detected",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.RACE_CONDITION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=RACE_CONDITION_SUCCESS,
                description="Race condition exploited",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.MASS_ASSIGNMENT: [
            DetectionPattern(
                vuln_type=VulnerabilityType.MASS_ASSIGNMENT,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=MASS_ASSIGNMENT_INDICATORS,
                description="Mass assignment vulnerability exploited",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.TYPE_JUGGLING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.TYPE_JUGGLING,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=TYPE_JUGGLING_INDICATORS,
                description="Type juggling pattern detected",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.TYPE_JUGGLING,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=TYPE_JUGGLING_SUCCESS,
                description="Type juggling bypass successful",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.BUSINESS_LOGIC: [
            DetectionPattern(
                vuln_type=VulnerabilityType.BUSINESS_LOGIC,
                method=DetectionMethod.CONTENT_DIFF,
                keywords=["negative", "overflow", "discount", "free", "unlimited"],
                description="Business logic flaw exploited",
                confidence_weight=0.75,
            ),
        ],
        VulnerabilityType.INSECURE_RANDOM: [
            DetectionPattern(
                vuln_type=VulnerabilityType.INSECURE_RANDOM,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=INSECURE_RANDOM_INDICATORS,
                description="Predictable randomness detected",
                confidence_weight=0.7,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Injection Variants
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.LATEX_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.LATEX_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=LATEX_INJECTION_INDICATORS,
                description="LaTeX injection error",
                confidence_weight=0.7,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.LATEX_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=LATEX_INJECTION_SUCCESS,
                description="LaTeX command injection successful",
                confidence_weight=0.95,
            ),
        ],
        VulnerabilityType.SSI_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.SSI_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=SSI_INJECTION_SUCCESS,
                description="SSI command execution successful",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.SSI_INJECTION,
                method=DetectionMethod.REFLECTION,
                patterns=SSI_INJECTION_INDICATORS,
                description="SSI directive reflected",
                confidence_weight=0.7,
            ),
        ],
        VulnerabilityType.XSLT_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.XSLT_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=XSLT_INJECTION_SUCCESS,
                description="XSLT injection successful",
                confidence_weight=0.95,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.XSLT_INJECTION,
                method=DetectionMethod.ERROR_BASED,
                patterns=XSLT_INJECTION_INDICATORS,
                description="XSLT processing error",
                confidence_weight=0.7,
            ),
        ],
        VulnerabilityType.PROMPT_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.PROMPT_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=PROMPT_INJECTION_SUCCESS,
                description="Prompt injection bypass successful",
                confidence_weight=0.85,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.PROMPT_INJECTION,
                method=DetectionMethod.REFLECTION,
                patterns=PROMPT_INJECTION_INDICATORS,
                description="Prompt injection attempt reflected",
                confidence_weight=0.6,
            ),
        ],
        VulnerabilityType.REGEX_DOS: [
            DetectionPattern(
                vuln_type=VulnerabilityType.REGEX_DOS,
                method=DetectionMethod.TIME_BASED,
                patterns=REGEX_DOS_INDICATORS,
                time_threshold_ms=5000.0,
                description="ReDoS causing significant delay",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.JAVA_RMI: [
            DetectionPattern(
                vuln_type=VulnerabilityType.JAVA_RMI,
                method=DetectionMethod.ERROR_BASED,
                patterns=JAVA_RMI_INDICATORS,
                description="Java RMI deserialization error",
                confidence_weight=0.8,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.JAVA_RMI,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=DESERIALIZATION_RCE_INDICATORS,
                description="Java RMI RCE achieved",
                confidence_weight=0.95,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Misconfiguration & Exposure
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.HIDDEN_PARAMS: [
            DetectionPattern(
                vuln_type=VulnerabilityType.HIDDEN_PARAMS,
                method=DetectionMethod.CONTENT_DIFF,
                keywords=["debug", "test", "admin", "internal", "verbose"],
                description="Hidden parameter discovered",
                confidence_weight=0.7,
            ),
        ],
        VulnerabilityType.ADMIN_INTERFACE: [
            DetectionPattern(
                vuln_type=VulnerabilityType.ADMIN_INTERFACE,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=ADMIN_INTERFACE_INDICATORS,
                description="Admin interface exposed",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.VIRTUAL_HOST: [
            DetectionPattern(
                vuln_type=VulnerabilityType.VIRTUAL_HOST,
                method=DetectionMethod.CONTENT_DIFF,
                keywords=["internal", "dev", "staging", "test", "admin"],
                description="Virtual host enumeration successful",
                confidence_weight=0.75,
            ),
        ],
        VulnerabilityType.REVERSE_PROXY: [
            DetectionPattern(
                vuln_type=VulnerabilityType.REVERSE_PROXY,
                method=DetectionMethod.HEADER_BASED,
                patterns=HOST_HEADER_INDICATORS,
                description="Reverse proxy misconfiguration",
                confidence_weight=0.8,
            ),
        ],
        VulnerabilityType.GWT_VULN: [
            DetectionPattern(
                vuln_type=VulnerabilityType.GWT_VULN,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=[r"\.nocache\.js", r"\.cache\.html", r"gwt\.xml"],
                description="GWT application exposed",
                confidence_weight=0.7,
            ),
        ],
        VulnerabilityType.DEPENDENCY_CONFUSION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.DEPENDENCY_CONFUSION,
                method=DetectionMethod.ERROR_BASED,
                patterns=DEPENDENCY_CONFUSION_INDICATORS,
                description="Dependency confusion vulnerability",
                confidence_weight=0.75,
            ),
        ],
        VulnerabilityType.CVE_EXPLOITS: [
            DetectionPattern(
                vuln_type=VulnerabilityType.CVE_EXPLOITS,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=[r"CVE-\d{4}-\d+", r"uid=\d+", r"root:.*:0:0:"],
                description="CVE exploit successful",
                confidence_weight=0.95,
            ),
        ],
        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Additional Edge Cases
        # ═══════════════════════════════════════════════════════════════════════
        VulnerabilityType.ENV_INJECTION: [
            DetectionPattern(
                vuln_type=VulnerabilityType.ENV_INJECTION,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=[r"PATH=", r"HOME=", r"USER=", r"LD_PRELOAD"],
                description="Environment variable manipulation",
                confidence_weight=0.85,
            ),
        ],
        VulnerabilityType.HEADLESS_BROWSER: [
            DetectionPattern(
                vuln_type=VulnerabilityType.HEADLESS_BROWSER,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=[r"puppeteer", r"playwright", r"chromium", r"headless"],
                description="Headless browser exploitation",
                confidence_weight=0.8,
            ),
        ],
        VulnerabilityType.ENCODING_BYPASS: [
            DetectionPattern(
                vuln_type=VulnerabilityType.ENCODING_BYPASS,
                method=DetectionMethod.REFLECTION,
                patterns=[r"%00", r"\\x00", r"\\u0000", r"charset="],
                description="Encoding-based filter bypass",
                confidence_weight=0.75,
            ),
        ],
        VulnerabilityType.HOST_HEADER: [
            DetectionPattern(
                vuln_type=VulnerabilityType.HOST_HEADER,
                method=DetectionMethod.HEADER_BASED,
                patterns=HOST_HEADER_INDICATORS,
                description="Host header injection",
                confidence_weight=0.8,
            ),
            DetectionPattern(
                vuln_type=VulnerabilityType.HOST_HEADER,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=HOST_HEADER_SUCCESS,
                description="Host header injection exploited",
                confidence_weight=0.9,
            ),
        ],
        VulnerabilityType.HTTP_VERB_TAMPERING: [
            DetectionPattern(
                vuln_type=VulnerabilityType.HTTP_VERB_TAMPERING,
                method=DetectionMethod.ERROR_BASED,
                patterns=HTTP_VERB_TAMPERING_INDICATORS,
                description="HTTP verb tampering potential",
                confidence_weight=0.6,
            ),
        ],
        VulnerabilityType.SUBDOMAIN_TAKEOVER: [
            DetectionPattern(
                vuln_type=VulnerabilityType.SUBDOMAIN_TAKEOVER,
                method=DetectionMethod.CONTENT_DIFF,
                patterns=SUBDOMAIN_TAKEOVER_INDICATORS,
                description="Subdomain takeover vulnerability",
                confidence_weight=0.9,
            ),
        ],
    }

    return patterns_map.get(vuln_type, [])


def compile_patterns(patterns: list[str]) -> list[re.Pattern]:
    """Compile regex patterns for performance."""
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
        except re.error:
            continue
    return compiled


# Pre-compiled pattern sets for performance
COMPILED_PATTERNS: dict[VulnerabilityType, list[re.Pattern]] = {}


def get_compiled_patterns(vuln_type: VulnerabilityType) -> list[re.Pattern]:
    """Get compiled regex patterns for a vulnerability type."""
    if vuln_type not in COMPILED_PATTERNS:
        detection_patterns = get_detection_patterns(vuln_type)
        all_patterns = []
        for dp in detection_patterns:
            all_patterns.extend(dp.patterns)
        COMPILED_PATTERNS[vuln_type] = compile_patterns(all_patterns)
    return COMPILED_PATTERNS[vuln_type]


def match_any_pattern(
    content: str,
    vuln_type: VulnerabilityType,
) -> tuple[bool, Optional[str], Optional[re.Match]]:
    """
    Check if content matches any pattern for a vulnerability type.

    Returns:
        Tuple of (matched, pattern_string, match_object)
    """
    compiled = get_compiled_patterns(vuln_type)
    for pattern in compiled:
        match = pattern.search(content)
        if match:
            return True, pattern.pattern, match
    return False, None, None
