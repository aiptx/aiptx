"""
AIPTX JavaScript Security Rules

Security rules specific to JavaScript and TypeScript code.
"""

from aipt_v2.sast.rules.base import Rule, RuleSet, RuleSeverity, RuleCategory


class JavaScriptSecurityRules(RuleSet):
    """JavaScript/TypeScript-specific security rules."""

    def __init__(self):
        super().__init__(language="javascript", name="javascript_security")
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """Initialize JavaScript security rules."""
        languages = ["javascript", "typescript"]

        # XSS - DOM Based
        self.add_rule(Rule(
            id="JS001",
            name="innerHTML Assignment",
            description="Setting innerHTML with user input can lead to XSS",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.XSS,
            languages=languages,
            pattern=r'\.innerHTML\s*=',
            cwe_ids=["CWE-79"],
            remediation="Use textContent or DOM manipulation methods instead",
        ))

        self.add_rule(Rule(
            id="JS002",
            name="document.write()",
            description="document.write() with user input can lead to XSS",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.XSS,
            languages=languages,
            pattern=r'document\.write\s*\(',
            cwe_ids=["CWE-79"],
            remediation="Use DOM manipulation methods instead",
        ))

        self.add_rule(Rule(
            id="JS003",
            name="React dangerouslySetInnerHTML",
            description="dangerouslySetInnerHTML bypasses React's XSS protection",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.XSS,
            languages=languages,
            pattern=r'dangerouslySetInnerHTML',
            cwe_ids=["CWE-79"],
            remediation="Sanitize HTML content with DOMPurify before using",
        ))

        # Code Execution
        self.add_rule(Rule(
            id="JS004",
            name="eval() Usage",
            description="eval() can execute arbitrary code",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=languages,
            pattern=r'\beval\s*\(',
            cwe_ids=["CWE-94", "CWE-95"],
            remediation="Use JSON.parse() for JSON, or safer alternatives",
        ))

        self.add_rule(Rule(
            id="JS005",
            name="new Function()",
            description="new Function() is equivalent to eval()",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=languages,
            pattern=r'new\s+Function\s*\(',
            cwe_ids=["CWE-94"],
            remediation="Avoid dynamic code generation",
        ))

        self.add_rule(Rule(
            id="JS006",
            name="setTimeout/setInterval with String",
            description="setTimeout/setInterval with string argument acts like eval",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            languages=languages,
            patterns=[
                r'setTimeout\s*\(\s*["\']',
                r'setInterval\s*\(\s*["\']',
            ],
            cwe_ids=["CWE-94"],
            remediation="Pass a function instead of a string",
        ))

        # Command Injection (Node.js)
        self.add_rule(Rule(
            id="JS007",
            name="child_process.exec()",
            description="exec() is vulnerable to command injection",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=languages,
            pattern=r'(?:child_process\.)?exec\s*\(',
            cwe_ids=["CWE-78"],
            remediation="Use execFile() with arguments array, or spawn()",
        ))

        # SQL Injection
        self.add_rule(Rule(
            id="JS008",
            name="SQL String Concatenation",
            description="SQL query built with string concatenation",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=languages,
            patterns=[
                r'\.query\s*\(\s*[`"\'].*\$\{',
                r'\.query\s*\(\s*["\'].*\+',
                r'\.execute\s*\(\s*[`"\'].*\$\{',
            ],
            cwe_ids=["CWE-89"],
            remediation="Use parameterized queries",
        ))

        # NoSQL Injection
        self.add_rule(Rule(
            id="JS009",
            name="MongoDB $where Operator",
            description="$where operator can execute JavaScript and is dangerous",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=languages,
            pattern=r'\$where\s*:',
            cwe_ids=["CWE-943"],
            remediation="Avoid $where, use standard query operators",
        ))

        # Path Traversal
        self.add_rule(Rule(
            id="JS010",
            name="Path Traversal",
            description="File path built with user input may allow traversal",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.PATH_TRAVERSAL,
            languages=languages,
            patterns=[
                r'fs\.(readFile|writeFile|readdir|unlink)\s*\([^)]*\+',
                r'path\.join\s*\([^)]*req\.',
                r'res\.sendFile\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-22"],
            remediation="Validate paths and use path.resolve() to check against allowed directories",
        ))

        # Open Redirect
        self.add_rule(Rule(
            id="JS011",
            name="Open Redirect",
            description="Redirect with user-controlled URL",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.MISCELLANEOUS,
            languages=languages,
            patterns=[
                r'res\.redirect\s*\([^)]*req\.',
                r'window\.location\s*=\s*[^"\']+',
                r'location\.href\s*=\s*[^"\']+',
            ],
            cwe_ids=["CWE-601"],
            remediation="Validate redirect URLs against a whitelist",
        ))

        # Prototype Pollution
        self.add_rule(Rule(
            id="JS012",
            name="Prototype Pollution",
            description="__proto__ access can lead to prototype pollution",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=languages,
            patterns=[
                r'__proto__',
                r'constructor\s*\[',
                r'Object\.assign\s*\([^,]+,\s*(?:req|request|body)',
            ],
            cwe_ids=["CWE-1321"],
            remediation="Use Object.create(null) for dictionaries, validate object keys",
        ))

        # Insecure Configuration
        self.add_rule(Rule(
            id="JS013",
            name="CORS Allow All Origins",
            description="CORS configured to allow all origins",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CONFIG,
            languages=languages,
            patterns=[
                r'cors\s*\(\s*\)',
                r'origin:\s*["\']\\*["\']',
                r'Access-Control-Allow-Origin.*\\*',
            ],
            cwe_ids=["CWE-346"],
            remediation="Specify allowed origins explicitly",
        ))

        self.add_rule(Rule(
            id="JS014",
            name="Insecure Cookie",
            description="Cookie without secure/httpOnly flags",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CONFIG,
            languages=languages,
            patterns=[
                r'secure:\s*false',
                r'httpOnly:\s*false',
            ],
            cwe_ids=["CWE-614", "CWE-1004"],
            remediation="Set secure: true and httpOnly: true for sensitive cookies",
        ))

        # SSRF
        self.add_rule(Rule(
            id="JS015",
            name="SSRF",
            description="HTTP request with user-controlled URL",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.SSRF,
            languages=languages,
            patterns=[
                r'axios\.(get|post|put|delete)\s*\([^)]*\+',
                r'fetch\s*\([^)]*\+',
                r'request\s*\([^)]*\+',
                r'http\.request\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-918"],
            remediation="Validate and whitelist allowed URLs/domains",
        ))

        # Weak Crypto
        self.add_rule(Rule(
            id="JS016",
            name="Weak Crypto Hash",
            description="MD5/SHA1 are cryptographically weak",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTO,
            languages=languages,
            patterns=[
                r'createHash\s*\(\s*["\']md5["\']',
                r'createHash\s*\(\s*["\']sha1["\']',
            ],
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Use SHA-256 or stronger algorithms",
        ))

        self.add_rule(Rule(
            id="JS017",
            name="Insecure Random",
            description="Math.random() is not cryptographically secure",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTO,
            languages=languages,
            pattern=r'Math\.random\s*\(',
            cwe_ids=["CWE-330"],
            remediation="Use crypto.randomBytes() or crypto.getRandomValues()",
        ))

        # JWT Verification
        self.add_rule(Rule(
            id="JS018",
            name="JWT Without Verification",
            description="JWT decoded without signature verification",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.AUTH,
            languages=languages,
            patterns=[
                r'jwt\.decode\s*\(',
                r'algorithms:\s*\[\s*["\']none["\']',
            ],
            cwe_ids=["CWE-347"],
            remediation="Always use jwt.verify() with algorithm specified",
        ))

        # Regular Expression DoS
        self.add_rule(Rule(
            id="JS019",
            name="Regex DoS",
            description="Complex regex patterns can cause catastrophic backtracking",
            severity=RuleSeverity.LOW,
            category=RuleCategory.MISCELLANEOUS,
            languages=languages,
            patterns=[
                r'new\s+RegExp\s*\([^)]*\+',  # Dynamic regex
                r'/\([^)]*\+\)\+/',           # Nested quantifiers
            ],
            cwe_ids=["CWE-1333"],
            remediation="Use safe-regex or validate regex patterns",
        ))

        # Express specific
        self.add_rule(Rule(
            id="JS020",
            name="Express Without Helmet",
            description="Express app should use helmet for security headers",
            severity=RuleSeverity.LOW,
            category=RuleCategory.CONFIG,
            languages=languages,
            pattern=r'express\s*\(\s*\)',
            negative_patterns=[r'helmet'],
            cwe_ids=["CWE-693"],
            remediation="Use helmet middleware for security headers",
        ))
