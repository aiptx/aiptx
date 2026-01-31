"""
AIPTX Python Security Rules

Security rules specific to Python code.
"""

from aipt_v2.sast.rules.base import Rule, RuleSet, RuleSeverity, RuleCategory


class PythonSecurityRules(RuleSet):
    """Python-specific security rules."""

    def __init__(self):
        super().__init__(language="python", name="python_security")
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """Initialize Python security rules."""

        # Code Execution
        self.add_rule(Rule(
            id="PY001",
            name="eval() Usage",
            description="eval() can execute arbitrary code and is dangerous with user input",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=["python"],
            pattern=r'\beval\s*\(',
            cwe_ids=["CWE-94", "CWE-95"],
            remediation="Use ast.literal_eval() for safe evaluation of literals, or avoid eval entirely",
        ))

        self.add_rule(Rule(
            id="PY002",
            name="exec() Usage",
            description="exec() can execute arbitrary code and is dangerous with user input",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=["python"],
            pattern=r'\bexec\s*\(',
            cwe_ids=["CWE-94"],
            remediation="Avoid exec(). Use safer alternatives like importing modules dynamically.",
        ))

        # Command Injection
        self.add_rule(Rule(
            id="PY003",
            name="os.system() Usage",
            description="os.system() is vulnerable to command injection",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=["python"],
            pattern=r'\bos\.system\s*\(',
            cwe_ids=["CWE-78"],
            remediation="Use subprocess.run() with shell=False and a list of arguments",
        ))

        self.add_rule(Rule(
            id="PY004",
            name="subprocess with shell=True",
            description="subprocess with shell=True is vulnerable to command injection",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            languages=["python"],
            pattern=r'subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
            cwe_ids=["CWE-78"],
            remediation="Use shell=False and pass command as a list",
        ))

        # SQL Injection
        self.add_rule(Rule(
            id="PY005",
            name="SQL String Formatting",
            description="SQL query built with string formatting is vulnerable to SQL injection",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=["python"],
            patterns=[
                r'execute\s*\(\s*["\'].*%[sd]',
                r'execute\s*\(\s*f["\']',
                r'execute\s*\(\s*["\'].*\.format\s*\(',
                r'cursor\.[a-z]+\s*\(\s*[^)]+\+',
            ],
            cwe_ids=["CWE-89"],
            remediation="Use parameterized queries with placeholders",
        ))

        self.add_rule(Rule(
            id="PY006",
            name="Django raw() Query",
            description="Django raw() queries can be vulnerable to SQL injection",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            languages=["python"],
            pattern=r'\.raw\s*\(\s*[^)]+[+%]',
            cwe_ids=["CWE-89"],
            remediation="Use Django ORM or parameterized queries",
        ))

        # Deserialization
        self.add_rule(Rule(
            id="PY007",
            name="Pickle Deserialization",
            description="pickle.load() can execute arbitrary code during deserialization",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.DESERIALIZATION,
            languages=["python"],
            patterns=[
                r'\bpickle\.loads?\s*\(',
                r'\bpickle\.Unpickler\s*\(',
                r'\bcPickle\.loads?\s*\(',
            ],
            cwe_ids=["CWE-502"],
            remediation="Use JSON or other safe serialization formats. Never unpickle untrusted data.",
        ))

        self.add_rule(Rule(
            id="PY008",
            name="YAML Unsafe Load",
            description="yaml.load() without Loader can execute arbitrary code",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.DESERIALIZATION,
            languages=["python"],
            pattern=r'\byaml\.load\s*\([^)]*\)',
            negative_patterns=[r'yaml\.load\s*\([^)]*Loader\s*='],
            cwe_ids=["CWE-502"],
            remediation="Use yaml.safe_load() or specify Loader=yaml.SafeLoader",
        ))

        # Path Traversal
        self.add_rule(Rule(
            id="PY009",
            name="Path Traversal in File Operations",
            description="File operation with user input may allow path traversal",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.PATH_TRAVERSAL,
            languages=["python"],
            patterns=[
                r'open\s*\([^)]*\+',
                r'os\.path\.join\s*\([^)]*request\.',
                r'send_file\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-22"],
            remediation="Validate and sanitize file paths. Use os.path.realpath() and check against allowed directories.",
        ))

        # XXE
        self.add_rule(Rule(
            id="PY010",
            name="XML External Entities",
            description="XML parsing without protection against XXE attacks",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.XXE,
            languages=["python"],
            patterns=[
                r'etree\.parse\s*\(',
                r'xml\.sax\.parse\s*\(',
                r'minidom\.parse\s*\(',
            ],
            negative_patterns=[r'defused'],
            cwe_ids=["CWE-611"],
            remediation="Use defusedxml library instead of standard xml libraries",
        ))

        # Weak Cryptography
        self.add_rule(Rule(
            id="PY011",
            name="MD5 Hash",
            description="MD5 is cryptographically weak and should not be used for security",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTO,
            languages=["python"],
            pattern=r'\bhashlib\.md5\s*\(',
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Use SHA-256 or stronger hash algorithms",
        ))

        self.add_rule(Rule(
            id="PY012",
            name="SHA1 Hash",
            description="SHA1 is cryptographically weak",
            severity=RuleSeverity.LOW,
            category=RuleCategory.CRYPTO,
            languages=["python"],
            pattern=r'\bhashlib\.sha1\s*\(',
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Use SHA-256 or stronger hash algorithms",
        ))

        # SSRF
        self.add_rule(Rule(
            id="PY013",
            name="SSRF via requests",
            description="HTTP request with dynamic URL may be vulnerable to SSRF",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.SSRF,
            languages=["python"],
            patterns=[
                r'requests\.(get|post|put|delete|head|patch)\s*\([^)]*\+',
                r'requests\.(get|post|put|delete|head|patch)\s*\([^)]*\.format',
                r'urllib\.request\.urlopen\s*\([^)]*\+',
            ],
            cwe_ids=["CWE-918"],
            remediation="Validate and whitelist allowed URLs/domains",
        ))

        # Flask/Django specific
        self.add_rule(Rule(
            id="PY014",
            name="Flask Debug Mode",
            description="Flask debug mode enabled in production",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CONFIG,
            languages=["python"],
            patterns=[
                r'app\.run\s*\([^)]*debug\s*=\s*True',
                r'DEBUG\s*=\s*True',
            ],
            cwe_ids=["CWE-489"],
            remediation="Disable debug mode in production",
        ))

        self.add_rule(Rule(
            id="PY015",
            name="Jinja2 Template Injection",
            description="render_template_string with user input can lead to SSTI",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.INJECTION,
            languages=["python"],
            pattern=r'render_template_string\s*\([^)]*\+',
            cwe_ids=["CWE-94"],
            remediation="Use render_template with static template files",
        ))

        # Assert in production
        self.add_rule(Rule(
            id="PY016",
            name="Assert Statement",
            description="Assert statements are removed in optimized mode (-O flag)",
            severity=RuleSeverity.LOW,
            category=RuleCategory.ERROR_HANDLING,
            languages=["python"],
            pattern=r'^\s*assert\s+',
            cwe_ids=["CWE-617"],
            remediation="Use if/raise for security checks instead of assert",
        ))

        # Binding to all interfaces
        self.add_rule(Rule(
            id="PY017",
            name="Binding to All Interfaces",
            description="Server bound to 0.0.0.0 exposes it to all network interfaces",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CONFIG,
            languages=["python"],
            pattern=r'(host|bind)\s*=\s*["\']0\.0\.0\.0["\']',
            cwe_ids=["CWE-284"],
            remediation="Bind to specific interface or localhost in development",
        ))

        # Random for security
        self.add_rule(Rule(
            id="PY018",
            name="Insecure Random",
            description="random module should not be used for security purposes",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.CRYPTO,
            languages=["python"],
            patterns=[
                r'\brandom\.random\s*\(',
                r'\brandom\.randint\s*\(',
                r'\brandom\.choice\s*\(',
            ],
            negative_patterns=[r'secrets\.', r'SystemRandom'],
            cwe_ids=["CWE-330"],
            remediation="Use secrets module for cryptographic randomness",
        ))
