"""
AIPTX Java Security Rules

Security rules specific to Java code.
"""

from aipt_v2.sast.rules.base import Rule, RuleSet, RuleSeverity, RuleCategory


class JavaSecurityRules(RuleSet):
    """Java-specific security rules."""

    def __init__(self):
        super().__init__(language="java", name="java_security")
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """Initialize Java security rules."""

        # SQL Injection
        self.add_rule(Rule(
            id="JAVA001",
            name="SQL Statement Usage",
            description="Statement is vulnerable to SQL injection, use PreparedStatement",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=["java"],
            patterns=[
                r'createStatement\s*\(',
                r'Statement\s+\w+\s*=',
            ],
            cwe_ids=["CWE-89"],
            remediation="Use PreparedStatement with parameterized queries",
        ))

        self.add_rule(Rule(
            id="JAVA002",
            name="SQL String Concatenation",
            description="SQL query with string concatenation",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=["java"],
            patterns=[
                r'executeQuery\s*\(\s*["\'].*\+',
                r'executeUpdate\s*\(\s*["\'].*\+',
            ],
            cwe_ids=["CWE-89"],
            remediation="Use PreparedStatement with parameter placeholders",
        ))

        # Command Injection
        self.add_rule(Rule(
            id="JAVA003",
            name="Runtime.exec()",
            description="Runtime.exec() is vulnerable to command injection",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=["java"],
            pattern=r'Runtime\.getRuntime\(\)\.exec\s*\(',
            cwe_ids=["CWE-78"],
            remediation="Use ProcessBuilder with argument array",
        ))

        self.add_rule(Rule(
            id="JAVA004",
            name="ProcessBuilder",
            description="ProcessBuilder with string may be vulnerable",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            languages=["java"],
            pattern=r'new\s+ProcessBuilder\s*\([^)]*\+',
            cwe_ids=["CWE-78"],
            remediation="Use ProcessBuilder with List<String> arguments",
        ))

        # XXE
        self.add_rule(Rule(
            id="JAVA005",
            name="XXE in DocumentBuilder",
            description="XML parser may be vulnerable to XXE attacks",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.XXE,
            languages=["java"],
            patterns=[
                r'DocumentBuilderFactory\.newInstance\s*\(',
                r'SAXParserFactory\.newInstance\s*\(',
                r'XMLInputFactory\.newInstance\s*\(',
            ],
            cwe_ids=["CWE-611"],
            remediation="Disable external entities: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        ))

        # Deserialization
        self.add_rule(Rule(
            id="JAVA006",
            name="Unsafe Deserialization",
            description="ObjectInputStream can execute arbitrary code",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.DESERIALIZATION,
            languages=["java"],
            patterns=[
                r'ObjectInputStream',
                r'readObject\s*\(',
                r'XMLDecoder',
            ],
            cwe_ids=["CWE-502"],
            remediation="Use look-ahead deserialization or avoid native serialization",
        ))

        # Path Traversal
        self.add_rule(Rule(
            id="JAVA007",
            name="Path Traversal",
            description="File path with user input may allow traversal",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.PATH_TRAVERSAL,
            languages=["java"],
            patterns=[
                r'new\s+File\s*\([^)]*\+',
                r'new\s+FileInputStream\s*\([^)]*\+',
                r'Paths\.get\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-22"],
            remediation="Canonicalize paths and validate against allowed directories",
        ))

        # LDAP Injection
        self.add_rule(Rule(
            id="JAVA008",
            name="LDAP Injection",
            description="LDAP query with string concatenation",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=["java"],
            patterns=[
                r'search\s*\([^)]*\+.*\)',
                r'DirContext',
            ],
            cwe_ids=["CWE-90"],
            remediation="Use parameterized LDAP queries",
        ))

        # XSS
        self.add_rule(Rule(
            id="JAVA009",
            name="XSS via getParameter",
            description="Request parameter used without encoding",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.XSS,
            languages=["java"],
            patterns=[
                r'\.getParameter\s*\([^)]*\)',
                r'\.write\s*\([^)]*getParameter',
            ],
            cwe_ids=["CWE-79"],
            remediation="Encode output using OWASP Java Encoder",
        ))

        # SSRF
        self.add_rule(Rule(
            id="JAVA010",
            name="SSRF",
            description="URL with user input may be vulnerable to SSRF",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.SSRF,
            languages=["java"],
            patterns=[
                r'new\s+URL\s*\([^)]*\+',
                r'openConnection\s*\(',
            ],
            cwe_ids=["CWE-918"],
            remediation="Validate and whitelist allowed URLs/hosts",
        ))

        # Weak Cryptography
        self.add_rule(Rule(
            id="JAVA011",
            name="MD5 Hash",
            description="MD5 is cryptographically weak",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTO,
            languages=["java"],
            pattern=r'getInstance\s*\(\s*["\']MD5["\']',
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Use SHA-256 or stronger algorithms",
        ))

        self.add_rule(Rule(
            id="JAVA012",
            name="DES Encryption",
            description="DES is cryptographically weak",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CRYPTO,
            languages=["java"],
            pattern=r'getInstance\s*\(\s*["\']DES["\']',
            cwe_ids=["CWE-327"],
            remediation="Use AES-256 encryption",
        ))

        self.add_rule(Rule(
            id="JAVA013",
            name="Insecure Random",
            description="java.util.Random is not cryptographically secure",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTO,
            languages=["java"],
            pattern=r'new\s+Random\s*\(',
            negative_patterns=[r'SecureRandom'],
            cwe_ids=["CWE-330"],
            remediation="Use java.security.SecureRandom",
        ))

        # TLS Configuration
        self.add_rule(Rule(
            id="JAVA014",
            name="TLS Certificate Validation Disabled",
            description="SSL/TLS certificate validation is disabled",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.CONFIG,
            languages=["java"],
            patterns=[
                r'TrustAllCerts',
                r'ALLOW_ALL_HOSTNAME_VERIFIER',
                r'setHostnameVerifier.*ALLOW_ALL',
            ],
            cwe_ids=["CWE-295"],
            remediation="Use proper certificate validation",
        ))

        # Spring Security
        self.add_rule(Rule(
            id="JAVA015",
            name="Spring Security CSRF Disabled",
            description="CSRF protection is disabled",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CONFIG,
            languages=["java"],
            pattern=r'\.csrf\s*\(\s*\)\s*\.disable\s*\(',
            cwe_ids=["CWE-352"],
            remediation="Enable CSRF protection or use stateless authentication",
        ))

        # Logging Sensitive Data
        self.add_rule(Rule(
            id="JAVA016",
            name="Logging Sensitive Data",
            description="Sensitive data may be logged",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.LOGGING,
            languages=["java"],
            patterns=[
                r'log\.(info|debug|warn|error)\s*\([^)]*password',
                r'log\.(info|debug|warn|error)\s*\([^)]*token',
                r'log\.(info|debug|warn|error)\s*\([^)]*secret',
            ],
            cwe_ids=["CWE-532"],
            remediation="Never log sensitive data like passwords or tokens",
        ))

        # Hardcoded IP
        self.add_rule(Rule(
            id="JAVA017",
            name="Hardcoded IP Address",
            description="Hardcoded IP address in source code",
            severity=RuleSeverity.LOW,
            category=RuleCategory.CONFIG,
            languages=["java"],
            pattern=r'["\'][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}["\']',
            negative_patterns=[r'127\.0\.0\.1', r'0\.0\.0\.0', r'localhost'],
            cwe_ids=["CWE-547"],
            remediation="Use configuration files or environment variables",
        ))

        # Android specific
        self.add_rule(Rule(
            id="JAVA018",
            name="Android WebView JavaScript Enabled",
            description="WebView with JavaScript enabled may be vulnerable",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CONFIG,
            languages=["java"],
            pattern=r'setJavaScriptEnabled\s*\(\s*true',
            cwe_ids=["CWE-749"],
            remediation="Disable JavaScript if not needed, use content security policies",
        ))
