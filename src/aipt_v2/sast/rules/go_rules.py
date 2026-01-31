"""
AIPTX Go Security Rules

Security rules specific to Go code.
"""

from aipt_v2.sast.rules.base import Rule, RuleSet, RuleSeverity, RuleCategory


class GoSecurityRules(RuleSet):
    """Go-specific security rules."""

    def __init__(self):
        super().__init__(language="go", name="go_security")
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """Initialize Go security rules."""

        # SQL Injection
        self.add_rule(Rule(
            id="GO001",
            name="SQL String Formatting",
            description="SQL query with fmt.Sprintf is vulnerable to injection",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=["go"],
            patterns=[
                r'fmt\.Sprintf\s*\([^)]*SELECT',
                r'fmt\.Sprintf\s*\([^)]*INSERT',
                r'fmt\.Sprintf\s*\([^)]*UPDATE',
                r'fmt\.Sprintf\s*\([^)]*DELETE',
                r'db\.(Query|Exec)\s*\([^,)]*\+',
            ],
            cwe_ids=["CWE-89"],
            remediation="Use parameterized queries with $1, $2 placeholders",
        ))

        # Command Injection
        self.add_rule(Rule(
            id="GO002",
            name="Command Injection via exec.Command",
            description="exec.Command with user input is vulnerable",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=["go"],
            patterns=[
                r'exec\.Command\s*\([^)]*\+',
                r'exec\.CommandContext\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-78"],
            remediation="Validate/sanitize input, use argument arrays",
        ))

        # Path Traversal
        self.add_rule(Rule(
            id="GO003",
            name="Path Traversal",
            description="File path with user input may allow traversal",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.PATH_TRAVERSAL,
            languages=["go"],
            patterns=[
                r'os\.Open\s*\([^)]*\+',
                r'ioutil\.ReadFile\s*\([^)]*\+',
                r'os\.ReadFile\s*\([^)]*\+',
                r'filepath\.Join\s*\([^)]*\.\.',
            ],
            cwe_ids=["CWE-22"],
            remediation="Use filepath.Clean() and validate against base directory",
        ))

        # SSRF
        self.add_rule(Rule(
            id="GO004",
            name="SSRF",
            description="HTTP request with user-controlled URL",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.SSRF,
            languages=["go"],
            patterns=[
                r'http\.Get\s*\([^)]*\+',
                r'http\.Post\s*\([^)]*\+',
                r'http\.NewRequest\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-918"],
            remediation="Validate URLs against whitelist",
        ))

        # TLS Configuration
        self.add_rule(Rule(
            id="GO005",
            name="TLS Verification Disabled",
            description="TLS certificate verification is disabled",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.CONFIG,
            languages=["go"],
            pattern=r'InsecureSkipVerify:\s*true',
            cwe_ids=["CWE-295"],
            remediation="Enable TLS certificate verification",
        ))

        self.add_rule(Rule(
            id="GO006",
            name="Weak TLS Version",
            description="TLS 1.0/1.1 is insecure",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CONFIG,
            languages=["go"],
            patterns=[
                r'MinVersion:\s*tls\.VersionSSL',
                r'MinVersion:\s*tls\.VersionTLS10',
                r'MinVersion:\s*tls\.VersionTLS11',
            ],
            cwe_ids=["CWE-326"],
            remediation="Use tls.VersionTLS12 or tls.VersionTLS13",
        ))

        # Weak Cryptography
        self.add_rule(Rule(
            id="GO007",
            name="MD5 Hash",
            description="MD5 is cryptographically weak",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTO,
            languages=["go"],
            pattern=r'md5\.New\s*\(',
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Use sha256.New() or stronger",
        ))

        self.add_rule(Rule(
            id="GO008",
            name="SHA1 Hash",
            description="SHA1 is cryptographically weak",
            severity=RuleSeverity.LOW,
            category=RuleCategory.CRYPTO,
            languages=["go"],
            pattern=r'sha1\.New\s*\(',
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Use sha256.New() or stronger",
        ))

        self.add_rule(Rule(
            id="GO009",
            name="Weak Encryption",
            description="DES/RC4 are cryptographically weak",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CRYPTO,
            languages=["go"],
            patterns=[
                r'des\.NewCipher',
                r'rc4\.NewCipher',
            ],
            cwe_ids=["CWE-327"],
            remediation="Use AES encryption",
        ))

        # Template Injection
        self.add_rule(Rule(
            id="GO010",
            name="Template Injection",
            description="template.HTML bypasses escaping",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.XSS,
            languages=["go"],
            patterns=[
                r'template\.HTML\s*\(',
                r'template\.JS\s*\(',
                r'template\.URL\s*\(',
            ],
            cwe_ids=["CWE-79"],
            remediation="Sanitize user input before using template.HTML",
        ))

        # Race Conditions
        self.add_rule(Rule(
            id="GO011",
            name="Potential Race Condition",
            description="Goroutine accessing shared variable",
            severity=RuleSeverity.LOW,
            category=RuleCategory.RACE_CONDITION,
            languages=["go"],
            pattern=r'go\s+func\s*\(',
            cwe_ids=["CWE-362"],
            remediation="Use sync.Mutex, channels, or atomic operations",
        ))

        # Error Handling
        self.add_rule(Rule(
            id="GO012",
            name="Ignored Error",
            description="Error return value is ignored",
            severity=RuleSeverity.LOW,
            category=RuleCategory.ERROR_HANDLING,
            languages=["go"],
            patterns=[
                r'_\s*,?\s*=\s*\w+\(',
                r'defer\s+\w+\.Close\(\)',
            ],
            negative_patterns=[r'if\s+err\s*!=\s*nil'],
            cwe_ids=["CWE-754"],
            remediation="Always check error returns",
        ))

        # CORS
        self.add_rule(Rule(
            id="GO013",
            name="CORS Allow All",
            description="CORS configured to allow all origins",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CONFIG,
            languages=["go"],
            patterns=[
                r'AllowAllOrigins:\s*true',
                r'Access-Control-Allow-Origin.*\*',
            ],
            cwe_ids=["CWE-346"],
            remediation="Specify allowed origins explicitly",
        ))

        # Unsafe Package
        self.add_rule(Rule(
            id="GO014",
            name="Unsafe Package Usage",
            description="unsafe package bypasses type safety",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.MISCELLANEOUS,
            languages=["go"],
            pattern=r'"unsafe"',
            cwe_ids=["CWE-119"],
            remediation="Avoid unsafe package unless absolutely necessary",
        ))

        # SQL Injection via ORM
        self.add_rule(Rule(
            id="GO015",
            name="GORM Raw Query",
            description="GORM Raw() with user input is vulnerable",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            languages=["go"],
            patterns=[
                r'\.Raw\s*\([^)]*\+',
                r'\.Exec\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-89"],
            remediation="Use GORM's parameterized methods",
        ))

        # HTTP Response Writing
        self.add_rule(Rule(
            id="GO016",
            name="Unescaped HTTP Response",
            description="Direct write of user input to response",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.XSS,
            languages=["go"],
            patterns=[
                r'w\.Write\s*\(\s*\[\]byte\s*\([^)]*\+',
                r'fmt\.Fprintf\s*\([^,]*w\s*,[^)]*\+',
            ],
            cwe_ids=["CWE-79"],
            remediation="Use html/template for HTML output",
        ))
