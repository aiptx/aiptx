"""
Web Application Black-Box Testing Playbook.

Structured methodology for testing web applications without
source code access. Follows OWASP Testing Guide principles.
"""

from .base_playbook import BasePlaybook, Phase, PlaybookMode


class WebPlaybook(BasePlaybook):
    """
    Comprehensive web application penetration testing playbook.

    Covers OWASP Top 10 and common web vulnerabilities through
    a structured multi-phase approach.
    """

    name = "web"
    description = "Web Application Black-Box Penetration Testing"
    mode = PlaybookMode.ADAPTIVE
    target_type = "web"
    estimated_duration = 7200  # 2 hours

    phases = [
        # Phase 1: Discovery
        Phase(
            name="Discovery",
            objective="Map the application attack surface and understand technologies",
            techniques=[
                "Identify web technologies and frameworks using httpx/wappalyzer",
                "Crawl and spider the application to discover content",
                "Enumerate directories and files with ffuf/gobuster",
                "Identify API endpoints and their methods",
                "Map authentication and session mechanisms",
                "Discover hidden parameters with arjun/paramspider",
            ],
            required_tools=["httpx", "ffuf", "gobuster", "arjun", "katana"],
            mitre_techniques=["T1595.002", "T1592.002"],
            timeout=900,
            parallel_safe=True,
        ),
        # Phase 2: Authentication Testing
        Phase(
            name="Authentication",
            objective="Test authentication mechanisms for weaknesses",
            techniques=[
                "Test for default/weak credentials",
                "Analyze password policy enforcement",
                "Test account lockout mechanisms",
                "Check for authentication bypass vulnerabilities",
                "Test password reset functionality",
                "Analyze session token generation and handling",
                "Test for session fixation vulnerabilities",
                "Check remember-me functionality security",
            ],
            required_tools=["burp", "ffuf", "hydra"],
            mitre_techniques=["T1110", "T1078"],
            timeout=600,
            depends_on=["Discovery"],
        ),
        # Phase 3: Injection Testing
        Phase(
            name="Injection",
            objective="Test for injection vulnerabilities across all input vectors",
            techniques=[
                "Test for SQL injection (error-based, blind, time-based)",
                "Test for command injection in system calls",
                "Test for LDAP injection in directory queries",
                "Test for XPath injection in XML processing",
                "Test for Server-Side Template Injection (SSTI)",
                "Test for Server-Side Request Forgery (SSRF)",
                "Test for XML External Entity (XXE) injection",
                "Test for NoSQL injection in MongoDB/other",
            ],
            required_tools=["sqlmap", "commix", "tplmap", "nuclei"],
            mitre_techniques=["T1190", "T1059"],
            timeout=1200,
            depends_on=["Discovery"],
        ),
        # Phase 4: Business Logic
        Phase(
            name="Business Logic",
            objective="Test for business logic flaws and access control issues",
            techniques=[
                "Test for Insecure Direct Object References (IDOR)",
                "Test horizontal and vertical privilege escalation",
                "Test for race conditions in critical operations",
                "Test for price/quantity manipulation",
                "Test multi-step process bypass",
                "Test for function-level access control issues",
                "Analyze workflow sequences for bypass opportunities",
                "Test for mass assignment vulnerabilities",
            ],
            required_tools=["burp", "autorize"],
            mitre_techniques=["T1068", "T1548"],
            timeout=900,
            depends_on=["Authentication"],
        ),
        # Phase 5: Client-Side Testing
        Phase(
            name="Client-Side",
            objective="Test for client-side vulnerabilities",
            techniques=[
                "Test for Reflected Cross-Site Scripting (XSS)",
                "Test for Stored Cross-Site Scripting",
                "Test for DOM-based Cross-Site Scripting",
                "Test for Cross-Site Request Forgery (CSRF)",
                "Test for Clickjacking vulnerabilities",
                "Analyze JavaScript for sensitive data exposure",
                "Test for insecure postMessage handling",
                "Check Content Security Policy effectiveness",
            ],
            required_tools=["dalfox", "xsstrike", "nuclei"],
            mitre_techniques=["T1189", "T1185"],
            timeout=600,
            depends_on=["Discovery"],
            parallel_safe=True,
        ),
        # Phase 6: Data Exposure
        Phase(
            name="Data Exposure",
            objective="Identify sensitive data exposure and information leakage",
            techniques=[
                "Check for sensitive data in responses/errors",
                "Test for directory listing vulnerabilities",
                "Check for backup files and source code exposure",
                "Test for sensitive data in client-side storage",
                "Analyze caching headers for sensitive pages",
                "Check for information disclosure in headers",
                "Test for path traversal/LFI vulnerabilities",
                "Search for hardcoded secrets in JavaScript",
            ],
            required_tools=["nuclei", "ffuf", "secretfinder"],
            mitre_techniques=["T1552", "T1083"],
            timeout=600,
            depends_on=["Discovery"],
            parallel_safe=True,
        ),
        # Phase 7: Configuration & Deployment
        Phase(
            name="Configuration",
            objective="Test for security misconfigurations",
            techniques=[
                "Test for verbose error messages",
                "Check for unnecessary HTTP methods enabled",
                "Test for insecure CORS configuration",
                "Check security headers (HSTS, X-Frame-Options, etc.)",
                "Test for default pages and admin interfaces",
                "Check for outdated software versions (CVEs)",
                "Test for debug mode/development settings",
                "Analyze SSL/TLS configuration",
            ],
            required_tools=["nuclei", "nikto", "testssl"],
            mitre_techniques=["T1082"],
            timeout=600,
            depends_on=["Discovery"],
            parallel_safe=True,
        ),
    ]


class WebAPIPlaybook(BasePlaybook):
    """
    Focused playbook for REST/GraphQL API testing.

    Shorter and more targeted than full web playbook.
    """

    name = "web_api"
    description = "Web API Security Testing (REST/GraphQL)"
    mode = PlaybookMode.SEQUENTIAL
    target_type = "api"
    estimated_duration = 3600  # 1 hour

    phases = [
        Phase(
            name="API Discovery",
            objective="Discover and document API endpoints",
            techniques=[
                "Parse OpenAPI/Swagger documentation if available",
                "Fuzz for undocumented endpoints",
                "Identify API versioning patterns",
                "Map authentication mechanisms (JWT, OAuth, API keys)",
                "Discover GraphQL introspection endpoint",
            ],
            required_tools=["httpx", "ffuf", "graphql-cop"],
            mitre_techniques=["T1595.002"],
            timeout=600,
        ),
        Phase(
            name="API Authentication",
            objective="Test API authentication and authorization",
            techniques=[
                "Test for broken authentication",
                "Test JWT vulnerabilities (none algorithm, weak secret)",
                "Test OAuth flow vulnerabilities",
                "Test API key exposure and reuse",
                "Test for BOLA (Broken Object Level Authorization)",
                "Test for BFLA (Broken Function Level Authorization)",
            ],
            required_tools=["jwt_tool", "burp"],
            mitre_techniques=["T1078", "T1110"],
            timeout=600,
            depends_on=["API Discovery"],
        ),
        Phase(
            name="API Injection",
            objective="Test for injection vulnerabilities in API",
            techniques=[
                "Test for SQL injection in parameters",
                "Test for NoSQL injection",
                "Test for GraphQL injection and DoS",
                "Test for command injection",
                "Test for SSRF through API parameters",
            ],
            required_tools=["sqlmap", "nuclei"],
            mitre_techniques=["T1190"],
            timeout=600,
            depends_on=["API Discovery"],
        ),
        Phase(
            name="API Logic",
            objective="Test for business logic flaws in API",
            techniques=[
                "Test rate limiting effectiveness",
                "Test for mass assignment",
                "Test for excessive data exposure",
                "Test pagination vulnerabilities",
                "Test for resource exhaustion",
            ],
            required_tools=["burp"],
            mitre_techniques=["T1499"],
            timeout=600,
            depends_on=["API Authentication"],
        ),
    ]
