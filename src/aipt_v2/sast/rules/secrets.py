"""
AIPTX Secret Detection Rules - Universal Secret Detection

Detects hardcoded secrets, API keys, passwords, and tokens
across all programming languages.
"""

from aipt_v2.sast.rules.base import Rule, RuleSet, RuleSeverity, RuleCategory


class SecretDetectionRules(RuleSet):
    """
    Universal secret detection rules.

    Detects:
    - API keys (AWS, GCP, Azure, etc.)
    - Passwords and passphrases
    - Private keys
    - Tokens (JWT, OAuth, etc.)
    - Connection strings
    """

    def __init__(self):
        super().__init__(
            language="*",  # All languages
            name="secret_detection",
        )
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """Initialize secret detection rules."""
        all_languages = ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"]

        # AWS Credentials
        self.add_rule(Rule(
            id="SEC001",
            name="AWS Access Key ID",
            description="Hardcoded AWS Access Key ID detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            cwe_ids=["CWE-798"],
            owasp_ids=["A3:2017"],
            remediation="Use environment variables or AWS IAM roles instead of hardcoded credentials",
            references=["https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html"],
        ))

        self.add_rule(Rule(
            id="SEC002",
            name="AWS Secret Access Key",
            description="Hardcoded AWS Secret Access Key detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']',
            cwe_ids=["CWE-798"],
            owasp_ids=["A3:2017"],
            remediation="Use environment variables or AWS IAM roles",
        ))

        # Google Cloud
        self.add_rule(Rule(
            id="SEC003",
            name="Google Cloud API Key",
            description="Hardcoded Google Cloud API key detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'AIza[0-9A-Za-z\-_]{35}',
            cwe_ids=["CWE-798"],
            remediation="Use environment variables or GCP service accounts",
        ))

        self.add_rule(Rule(
            id="SEC004",
            name="Google OAuth Token",
            description="Hardcoded Google OAuth token detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            cwe_ids=["CWE-798"],
            remediation="Store OAuth credentials securely",
        ))

        # GitHub
        self.add_rule(Rule(
            id="SEC005",
            name="GitHub Token",
            description="Hardcoded GitHub personal access token detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'ghp_[0-9a-zA-Z]{36}',  # Personal access token
                r'gho_[0-9a-zA-Z]{36}',  # OAuth token
                r'ghu_[0-9a-zA-Z]{36}',  # User token
                r'ghs_[0-9a-zA-Z]{36}',  # Server token
                r'ghr_[0-9a-zA-Z]{36}',  # Refresh token
            ],
            cwe_ids=["CWE-798"],
            remediation="Use GitHub Actions secrets or environment variables",
        ))

        # Slack
        self.add_rule(Rule(
            id="SEC006",
            name="Slack Token",
            description="Hardcoded Slack token detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
                r'xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24}',
            ],
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for Slack tokens",
        ))

        # Stripe
        self.add_rule(Rule(
            id="SEC007",
            name="Stripe API Key",
            description="Hardcoded Stripe API key detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'sk_live_[0-9a-zA-Z]{24}',
                r'rk_live_[0-9a-zA-Z]{24}',
            ],
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for Stripe keys",
        ))

        # Private Keys
        self.add_rule(Rule(
            id="SEC008",
            name="RSA Private Key",
            description="RSA private key detected in source code",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'-----BEGIN RSA PRIVATE KEY-----',
            cwe_ids=["CWE-321"],
            remediation="Store private keys in a secure key management system",
        ))

        self.add_rule(Rule(
            id="SEC009",
            name="SSH Private Key",
            description="SSH private key detected in source code",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'-----BEGIN OPENSSH PRIVATE KEY-----',
                r'-----BEGIN DSA PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----',
            ],
            cwe_ids=["CWE-321"],
            remediation="Never commit private keys. Use SSH key management.",
        ))

        # JWT
        self.add_rule(Rule(
            id="SEC010",
            name="JWT Token",
            description="Hardcoded JWT token detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            negative_patterns=[r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzdWIiOiIxMjM0NTY3ODkwIi'],  # Common example
            cwe_ids=["CWE-798"],
            remediation="Generate JWT tokens dynamically, don't hardcode them",
        ))

        # Generic Passwords
        self.add_rule(Rule(
            id="SEC011",
            name="Hardcoded Password",
            description="Potential hardcoded password detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'(?i)password\s*[=:]\s*["\'][^"\']{8,}["\']',
                r'(?i)passwd\s*[=:]\s*["\'][^"\']{8,}["\']',
                r'(?i)pwd\s*[=:]\s*["\'][^"\']{8,}["\']',
            ],
            negative_patterns=[
                r'(?i)password\s*[=:]\s*["\'](\$|%|{{|<|getenv|environ|env\()',
                r'(?i)password\s*[=:]\s*["\']["\']',  # Empty string
                r'(?i)password\s*[=:]\s*None',
            ],
            cwe_ids=["CWE-798", "CWE-259"],
            remediation="Use environment variables or a secrets manager",
        ))

        # API Keys (generic)
        self.add_rule(Rule(
            id="SEC012",
            name="Generic API Key",
            description="Potential hardcoded API key detected",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']',
                r'(?i)(secret_key|secretkey|secret-key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']',
            ],
            negative_patterns=[
                r'(?i)(api_key|secret_key)\s*[=:]\s*["\'](\$|%|{{|<|getenv|environ|env\()',
            ],
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for API keys",
        ))

        # Connection Strings
        self.add_rule(Rule(
            id="SEC013",
            name="Database Connection String",
            description="Database connection string with credentials detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'(?i)(mysql|postgres|postgresql|mongodb|redis|mssql)://\w+:[^@]+@',
                r'(?i)Server=.*;User\s*Id=.*;Password=.*',
            ],
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for database connection strings",
        ))

        # Twilio
        self.add_rule(Rule(
            id="SEC014",
            name="Twilio API Key",
            description="Hardcoded Twilio API key detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'SK[0-9a-fA-F]{32}',
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for Twilio credentials",
        ))

        # SendGrid
        self.add_rule(Rule(
            id="SEC015",
            name="SendGrid API Key",
            description="Hardcoded SendGrid API key detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for SendGrid API keys",
        ))

        # Azure
        self.add_rule(Rule(
            id="SEC016",
            name="Azure Storage Key",
            description="Hardcoded Azure storage key detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'(?i)AccountKey=[A-Za-z0-9+/=]{88}',
            cwe_ids=["CWE-798"],
            remediation="Use Azure Managed Identity or Key Vault",
        ))

        # Heroku
        self.add_rule(Rule(
            id="SEC017",
            name="Heroku API Key",
            description="Hardcoded Heroku API key detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for Heroku credentials",
        ))

        # npm
        self.add_rule(Rule(
            id="SEC018",
            name="NPM Token",
            description="Hardcoded NPM token detected",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-_]+',
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for NPM tokens",
        ))

        # Generic high-entropy strings
        self.add_rule(Rule(
            id="SEC019",
            name="High Entropy String",
            description="High entropy string that may be a secret",
            severity=RuleSeverity.LOW,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            patterns=[
                r'["\'][A-Za-z0-9+/]{40,}["\']',  # Base64-like
                r'["\'][0-9a-f]{32,}["\']',      # Hex
            ],
            negative_patterns=[
                r'sha256:',
                r'sha512:',
                r'hash',
                r'digest',
            ],
            cwe_ids=["CWE-798"],
            remediation="Review if this is a secret and move to secure storage",
        ))

        # OpenAI
        self.add_rule(Rule(
            id="SEC020",
            name="OpenAI API Key",
            description="Hardcoded OpenAI API key detected",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECRETS,
            languages=all_languages,
            pattern=r'sk-[A-Za-z0-9]{48}',
            cwe_ids=["CWE-798"],
            remediation="Use environment variables for OpenAI API keys",
        ))
