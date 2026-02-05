"""
PAT Payload Parser

Parses PayloadsAllTheThings markdown files to extract payloads.
Handles code blocks, inline code, and tables.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from .config import VulnerabilityType, PayloadTechnique, PayloadConfig

logger = logging.getLogger(__name__)


@dataclass
class ParsedPayload:
    """A parsed payload from PayloadsAllTheThings."""
    content: str                                # The actual payload string
    category: VulnerabilityType                 # SQL injection, XSS, etc.
    subcategory: str = ""                       # mysql, postgresql, reflected, etc.
    technique: PayloadTechnique = PayloadTechnique.DIRECT
    description: str = ""                       # What it does
    language: str = ""                          # sql, javascript, xml, etc.
    source_file: str = ""                       # Original markdown file
    requires_encoding: bool = False             # URL encode before use
    is_dangerous: bool = False                  # Destructive payload
    tags: list[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.content)

    def __eq__(self, other) -> bool:
        if isinstance(other, ParsedPayload):
            return self.content == other.content
        return False


# Mapping of PAT directory names to VulnerabilityType
# Full coverage of 67 PayloadsAllTheThings categories
DIRECTORY_MAPPING = {
    # ═══════════════════════════════════════════════════════════════════════════
    # EXISTING - Core Injection Types (23 mappings for 19 types)
    # ═══════════════════════════════════════════════════════════════════════════
    "SQL Injection": VulnerabilityType.SQL_INJECTION,
    "SQL injection": VulnerabilityType.SQL_INJECTION,
    "XSS Injection": VulnerabilityType.XSS,
    "XSS injection": VulnerabilityType.XSS,
    "Cross-Site Scripting": VulnerabilityType.XSS,
    "Command Injection": VulnerabilityType.COMMAND_INJECTION,
    "OS Command Injection": VulnerabilityType.COMMAND_INJECTION,
    "Server Side Request Forgery": VulnerabilityType.SSRF,
    "SSRF": VulnerabilityType.SSRF,
    "XXE Injection": VulnerabilityType.XXE,
    "XXE": VulnerabilityType.XXE,
    "XML External Entity": VulnerabilityType.XXE,
    "File Inclusion": VulnerabilityType.LFI,
    "File Inclusion - Path Traversal": VulnerabilityType.LFI,
    "Directory Traversal": VulnerabilityType.PATH_TRAVERSAL,
    "Path Traversal": VulnerabilityType.PATH_TRAVERSAL,
    "NoSQL Injection": VulnerabilityType.NOSQL_INJECTION,
    "NoSQL injection": VulnerabilityType.NOSQL_INJECTION,
    "LDAP Injection": VulnerabilityType.LDAP_INJECTION,
    "XPATH Injection": VulnerabilityType.XPATH_INJECTION,
    "XPath Injection": VulnerabilityType.XPATH_INJECTION,
    "CRLF Injection": VulnerabilityType.CRLF_INJECTION,
    "Open Redirect": VulnerabilityType.OPEN_REDIRECT,
    "Server Side Template Injection": VulnerabilityType.SSTI,
    "SSTI": VulnerabilityType.SSTI,
    "Insecure Deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
    "JWT Attacks": VulnerabilityType.JWT_ATTACKS,
    "JSON Web Token": VulnerabilityType.JWT_ATTACKS,
    "GraphQL Injection": VulnerabilityType.GRAPHQL,
    "GraphQL": VulnerabilityType.GRAPHQL,
    "Web Sockets": VulnerabilityType.WEBSOCKET,
    "Upload Insecure Files": VulnerabilityType.FILE_UPLOAD,
    "File Upload": VulnerabilityType.FILE_UPLOAD,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Authentication & Access Control
    # ═══════════════════════════════════════════════════════════════════════════
    "Cross-Site Request Forgery": VulnerabilityType.CSRF,
    "CSRF": VulnerabilityType.CSRF,
    "Insecure Direct Object References": VulnerabilityType.IDOR,
    "IDOR": VulnerabilityType.IDOR,
    "OAuth Misconfiguration": VulnerabilityType.OAUTH_MISCONFIG,
    "OAuth": VulnerabilityType.OAUTH_MISCONFIG,
    "SAML Injection": VulnerabilityType.SAML_INJECTION,
    "SAML": VulnerabilityType.SAML_INJECTION,
    "Account Takeover": VulnerabilityType.ACCOUNT_TAKEOVER,
    "2FA Bypass": VulnerabilityType.ACCOUNT_TAKEOVER,
    "Password Reset": VulnerabilityType.ACCOUNT_TAKEOVER,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Protocol/Request Attacks
    # ═══════════════════════════════════════════════════════════════════════════
    "HTTP Request Smuggling": VulnerabilityType.HTTP_SMUGGLING,
    "Request Smuggling": VulnerabilityType.HTTP_SMUGGLING,
    "HTTP Parameter Pollution": VulnerabilityType.HPP,
    "HPP": VulnerabilityType.HPP,
    "DNS Rebinding": VulnerabilityType.DNS_REBINDING,
    "CORS Misconfiguration": VulnerabilityType.CORS_MISCONFIG,
    "CORS": VulnerabilityType.CORS_MISCONFIG,
    "Tabnabbing": VulnerabilityType.TABNABBING,
    "Reverse Tabnabbing": VulnerabilityType.TABNABBING,
    "Web Cache Deception": VulnerabilityType.CACHE_POISONING,
    "Web Cache Poisoning": VulnerabilityType.CACHE_POISONING,
    "Cache Poisoning": VulnerabilityType.CACHE_POISONING,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Client-Side Attacks
    # ═══════════════════════════════════════════════════════════════════════════
    "DOM Clobbering": VulnerabilityType.DOM_CLOBBERING,
    "Clickjacking": VulnerabilityType.CLICKJACKING,
    "UI Redressing": VulnerabilityType.CLICKJACKING,
    "Prototype Pollution": VulnerabilityType.PROTOTYPE_POLLUTION,
    "Client Side Path Traversal": VulnerabilityType.CLIENT_PATH_TRAVERSAL,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - File & Data Attacks
    # ═══════════════════════════════════════════════════════════════════════════
    "CSV Injection": VulnerabilityType.CSV_INJECTION,
    "Formula Injection": VulnerabilityType.CSV_INJECTION,
    "Zip Slip": VulnerabilityType.ZIP_SLIP,
    "ORM Leak": VulnerabilityType.ORM_LEAK,
    "ORM Injection": VulnerabilityType.ORM_LEAK,
    "API Key Leaks": VulnerabilityType.API_KEY_LEAK,
    "API Key": VulnerabilityType.API_KEY_LEAK,
    "Insecure Source Code Management": VulnerabilityType.GIT_EXPOSURE,
    ".git": VulnerabilityType.GIT_EXPOSURE,
    "Secrets in Files": VulnerabilityType.SECRETS_EXPOSURE,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Business Logic & Timing
    # ═══════════════════════════════════════════════════════════════════════════
    "Race Condition": VulnerabilityType.RACE_CONDITION,
    "Mass Assignment": VulnerabilityType.MASS_ASSIGNMENT,
    "Type Juggling": VulnerabilityType.TYPE_JUGGLING,
    "PHP Type Juggling": VulnerabilityType.TYPE_JUGGLING,
    "Business Logic Errors": VulnerabilityType.BUSINESS_LOGIC,
    "Business Logic": VulnerabilityType.BUSINESS_LOGIC,
    "Insecure Randomness": VulnerabilityType.INSECURE_RANDOM,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Injection Variants
    # ═══════════════════════════════════════════════════════════════════════════
    "LaTeX Injection": VulnerabilityType.LATEX_INJECTION,
    "Server Side Include": VulnerabilityType.SSI_INJECTION,
    "SSI Injection": VulnerabilityType.SSI_INJECTION,
    "XSLT Injection": VulnerabilityType.XSLT_INJECTION,
    "Prompt Injection": VulnerabilityType.PROMPT_INJECTION,
    "AI Prompt Injection": VulnerabilityType.PROMPT_INJECTION,
    "Regular Expression": VulnerabilityType.REGEX_DOS,
    "ReDoS": VulnerabilityType.REGEX_DOS,
    "Java RMI": VulnerabilityType.JAVA_RMI,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Misconfiguration & Exposure
    # ═══════════════════════════════════════════════════════════════════════════
    "Hidden Parameters": VulnerabilityType.HIDDEN_PARAMS,
    "Insecure Management Interface": VulnerabilityType.ADMIN_INTERFACE,
    "Admin Interface": VulnerabilityType.ADMIN_INTERFACE,
    "Virtual Hosts": VulnerabilityType.VIRTUAL_HOST,
    "Reverse Proxy Misconfigurations": VulnerabilityType.REVERSE_PROXY,
    "Reverse Proxy": VulnerabilityType.REVERSE_PROXY,
    "Google Web Toolkit": VulnerabilityType.GWT_VULN,
    "GWT": VulnerabilityType.GWT_VULN,
    "Dependency Confusion": VulnerabilityType.DEPENDENCY_CONFUSION,
    "CVE Exploits": VulnerabilityType.CVE_EXPLOITS,

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW - Additional Edge Cases
    # ═══════════════════════════════════════════════════════════════════════════
    "External Variable Modification": VulnerabilityType.ENV_INJECTION,
    "Environment Variables": VulnerabilityType.ENV_INJECTION,
    "Headless Browser": VulnerabilityType.HEADLESS_BROWSER,
    "Encoding Transformations": VulnerabilityType.ENCODING_BYPASS,
    "Host Header Injection": VulnerabilityType.HOST_HEADER,
    "Host Header": VulnerabilityType.HOST_HEADER,
    "HTTP Verb Tampering": VulnerabilityType.HTTP_VERB_TAMPERING,
    "Subdomain Takeover": VulnerabilityType.SUBDOMAIN_TAKEOVER,
}

# Subcategory detection patterns
SUBCATEGORY_PATTERNS = {
    # ═══════════════════════════════════════════════════════════════════════════
    # Existing subcategories
    # ═══════════════════════════════════════════════════════════════════════════
    VulnerabilityType.SQL_INJECTION: {
        "mysql": ["MySQL", "mysql", "MariaDB"],
        "postgresql": ["PostgreSQL", "postgres", "Postgres"],
        "mssql": ["MSSQL", "SQL Server", "mssql"],
        "oracle": ["Oracle", "oracle", "ORA-"],
        "sqlite": ["SQLite", "sqlite"],
        "mongodb": ["MongoDB", "mongo"],  # Actually NoSQL
    },
    VulnerabilityType.XSS: {
        "reflected": ["reflected", "Reflected"],
        "stored": ["stored", "Stored", "persistent"],
        "dom": ["DOM", "dom-based", "DOM-based"],
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # New subcategories for extended vuln types
    # ═══════════════════════════════════════════════════════════════════════════
    VulnerabilityType.HTTP_SMUGGLING: {
        "cl_te": ["CL.TE", "cl.te", "Content-Length.*Transfer-Encoding"],
        "te_cl": ["TE.CL", "te.cl", "Transfer-Encoding.*Content-Length"],
        "te_te": ["TE.TE", "te.te", "obfuscation"],
        "h2c": ["H2C", "HTTP/2", "http2"],
    },
    VulnerabilityType.SSTI: {
        "jinja2": ["Jinja2", "jinja", "Flask"],
        "twig": ["Twig", "twig"],
        "freemarker": ["FreeMarker", "freemarker"],
        "velocity": ["Velocity", "velocity"],
        "mako": ["Mako", "mako"],
        "smarty": ["Smarty", "smarty"],
        "erb": ["ERB", "erb", "Ruby"],
    },
    VulnerabilityType.INSECURE_DESERIALIZATION: {
        "java": ["Java", "java", "ysoserial", "ObjectInputStream"],
        "php": ["PHP", "php", "unserialize"],
        "python": ["Python", "python", "pickle"],
        "dotnet": [".NET", "dotnet", "ObjectDataProvider"],
        "ruby": ["Ruby", "ruby", "Marshal"],
        "nodejs": ["Node.js", "nodejs", "node-serialize"],
    },
    VulnerabilityType.SSRF: {
        "aws": ["AWS", "169.254.169.254", "metadata"],
        "gcp": ["GCP", "metadata.google"],
        "azure": ["Azure", "169.254.169.254"],
        "kubernetes": ["Kubernetes", "k8s", "kube-"],
        "docker": ["Docker", "docker", "172.17.0.1"],
    },
    VulnerabilityType.OAUTH_MISCONFIG: {
        "authorization_code": ["authorization_code", "code"],
        "implicit": ["implicit", "token"],
        "pkce": ["PKCE", "code_verifier"],
        "state": ["state", "nonce"],
        "redirect_uri": ["redirect_uri", "callback"],
    },
    VulnerabilityType.JWT_ATTACKS: {
        "none_algorithm": ["none", "alg:none", "algorithm:none"],
        "key_confusion": ["RS256", "HS256", "key confusion"],
        "jwk_injection": ["JWK", "jwk", "jku"],
        "kid_injection": ["kid", "key id"],
    },
    VulnerabilityType.RACE_CONDITION: {
        "double_spending": ["double", "spend", "duplicate"],
        "limit_bypass": ["limit", "quota", "rate"],
        "toctou": ["TOCTOU", "time-of-check"],
    },
    VulnerabilityType.PROTOTYPE_POLLUTION: {
        "server_side": ["server", "Node.js", "express"],
        "client_side": ["client", "browser", "DOM"],
    },
    VulnerabilityType.CACHE_POISONING: {
        "web_cache_deception": ["deception", "WCD"],
        "web_cache_poisoning": ["poisoning", "WCP"],
        "cdn": ["CDN", "Cloudflare", "Akamai", "Fastly"],
    },
}

# Technique detection keywords
TECHNIQUE_KEYWORDS = {
    PayloadTechnique.ERROR_BASED: ["error", "Error-based", "error-based"],
    PayloadTechnique.UNION_BASED: ["UNION", "union", "Union-based"],
    PayloadTechnique.BOOLEAN_BASED: ["boolean", "Boolean", "blind boolean", "boolean-based"],
    PayloadTechnique.TIME_BASED: ["time", "Time-based", "sleep", "SLEEP", "WAITFOR", "benchmark", "time-based"],
    PayloadTechnique.STACKED_QUERIES: ["stacked", "Stacked", "multiple queries"],
    PayloadTechnique.OUT_OF_BAND: ["OOB", "out-of-band", "DNS", "HTTP callback"],
    PayloadTechnique.FILTER_BYPASS: ["bypass", "Bypass", "filter", "WAF", "waf"],
    PayloadTechnique.WAF_BYPASS: ["WAF", "waf", "firewall"],
    PayloadTechnique.ENCODING_BYPASS: ["encoding", "encode", "hex", "base64", "unicode"],
}

# Dangerous payload indicators (skip by default)
DANGEROUS_INDICATORS = [
    "DROP TABLE",
    "DROP DATABASE",
    "DELETE FROM",
    "TRUNCATE",
    "rm -rf",
    "del /f",
    "format c:",
    "shutdown",
    "reboot",
    ":(){:|:&};:",  # Fork bomb
    "mkfs",
    "> /dev/sda",
]


class PayloadParser:
    """
    Parser for PayloadsAllTheThings repository.

    Extracts payloads from markdown files and categorizes them
    by vulnerability type, technique, and subcategory.
    """

    def __init__(self, config: PayloadConfig):
        """
        Initialize parser.

        Args:
            config: Payload configuration
        """
        self.config = config
        self.repo_path = Path(config.repo_path).expanduser()

    def ensure_repository(self) -> bool:
        """
        Ensure PAT repository is cloned/updated.

        Returns:
            True if repository is available
        """
        if not self.repo_path.exists():
            return self._clone_repository()
        elif self.config.auto_update:
            return self._update_repository()
        return True

    def _clone_repository(self) -> bool:
        """Clone PAT repository."""
        logger.info(f"Cloning PayloadsAllTheThings to {self.repo_path}")
        self.repo_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", self.config.repo_url, str(self.repo_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                logger.info("PAT repository cloned successfully")
                return True
            else:
                logger.error(f"Failed to clone PAT: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("Clone operation timed out")
            return False
        except FileNotFoundError:
            logger.error("Git not found. Please install git.")
            return False

    def _update_repository(self) -> bool:
        """Update PAT repository."""
        logger.info("Updating PayloadsAllTheThings repository")
        try:
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Failed to update PAT: {e}")
            return False

    def get_category_directories(self) -> dict[VulnerabilityType, Path]:
        """
        Get mapping of vulnerability types to directories.

        Returns:
            Dict mapping VulnerabilityType to directory path
        """
        categories = {}

        if not self.repo_path.exists():
            return categories

        for item in self.repo_path.iterdir():
            if item.is_dir() and not item.name.startswith((".", "_")):
                # Check if directory name maps to a vuln type
                for name_pattern, vuln_type in DIRECTORY_MAPPING.items():
                    if name_pattern.lower() in item.name.lower():
                        categories[vuln_type] = item
                        break

        return categories

    def parse_directory(
        self,
        directory: Path,
        vuln_type: VulnerabilityType,
    ) -> Iterator[ParsedPayload]:
        """
        Parse all markdown files in a directory.

        Args:
            directory: Directory path
            vuln_type: Vulnerability type for this directory

        Yields:
            ParsedPayload objects
        """
        if not directory.exists():
            return

        # Find all markdown files
        md_files = list(directory.rglob("*.md"))
        logger.debug(f"Found {len(md_files)} markdown files in {directory}")

        for md_file in md_files:
            try:
                yield from self._parse_markdown_file(md_file, vuln_type)
            except Exception as e:
                logger.warning(f"Error parsing {md_file}: {e}")

    def _parse_markdown_file(
        self,
        file_path: Path,
        vuln_type: VulnerabilityType,
    ) -> Iterator[ParsedPayload]:
        """
        Parse a single markdown file.

        Args:
            file_path: Path to markdown file
            vuln_type: Vulnerability type

        Yields:
            ParsedPayload objects
        """
        content = file_path.read_text(encoding="utf-8", errors="replace")
        relative_path = str(file_path.relative_to(self.repo_path))

        # Detect subcategory from file path/name
        subcategory = self._detect_subcategory(file_path.name, content, vuln_type)

        # Parse different payload formats
        payloads = []

        # 1. Fenced code blocks (```lang ... ```)
        payloads.extend(self._extract_code_blocks(content, vuln_type, subcategory, relative_path))

        # 2. Inline code (`payload`)
        payloads.extend(self._extract_inline_code(content, vuln_type, subcategory, relative_path))

        # 3. Tables (| payload | description |)
        payloads.extend(self._extract_tables(content, vuln_type, subcategory, relative_path))

        # Deduplicate and filter
        seen = set()
        for payload in payloads:
            if payload.content not in seen:
                seen.add(payload.content)

                # Skip empty or too long payloads
                if not payload.content.strip():
                    continue
                if len(payload.content) > self.config.max_payload_length:
                    continue

                # Skip dangerous payloads unless explicitly allowed
                if not self.config.include_dangerous and payload.is_dangerous:
                    continue

                yield payload

    def _extract_code_blocks(
        self,
        content: str,
        vuln_type: VulnerabilityType,
        subcategory: str,
        source_file: str,
    ) -> list[ParsedPayload]:
        """Extract payloads from fenced code blocks."""
        payloads = []

        # Pattern for fenced code blocks with optional language
        pattern = r"```(\w*)\n(.*?)```"
        matches = re.findall(pattern, content, re.DOTALL)

        for language, code in matches:
            language = language.lower() if language else ""

            # Skip non-payload code blocks (e.g., python scripts, explanations)
            if language in ("python", "ruby", "java", "c", "cpp", "go", "rust"):
                # But include if it contains payload-like content
                if not self._looks_like_payload(code, vuln_type):
                    continue

            # Split multi-line code blocks into individual payloads
            lines = code.strip().split("\n")

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue

                technique = self._detect_technique(line, content)
                is_dangerous = self._is_dangerous_payload(line)

                payloads.append(ParsedPayload(
                    content=line,
                    category=vuln_type,
                    subcategory=subcategory,
                    technique=technique,
                    language=language,
                    source_file=source_file,
                    is_dangerous=is_dangerous,
                ))

        return payloads

    def _extract_inline_code(
        self,
        content: str,
        vuln_type: VulnerabilityType,
        subcategory: str,
        source_file: str,
    ) -> list[ParsedPayload]:
        """Extract payloads from inline code."""
        payloads = []

        # Pattern for inline code
        pattern = r"`([^`\n]{3,500})`"
        matches = re.findall(pattern, content)

        for code in matches:
            code = code.strip()

            # Filter out non-payloads (file paths, commands, etc.)
            if not self._looks_like_payload(code, vuln_type):
                continue

            technique = self._detect_technique(code, content)
            is_dangerous = self._is_dangerous_payload(code)

            payloads.append(ParsedPayload(
                content=code,
                category=vuln_type,
                subcategory=subcategory,
                technique=technique,
                source_file=source_file,
                is_dangerous=is_dangerous,
            ))

        return payloads

    def _extract_tables(
        self,
        content: str,
        vuln_type: VulnerabilityType,
        subcategory: str,
        source_file: str,
    ) -> list[ParsedPayload]:
        """Extract payloads from markdown tables."""
        payloads = []

        # Pattern for table rows
        pattern = r"\|([^|]+)\|([^|]+)\|"
        matches = re.findall(pattern, content)

        for col1, col2 in matches:
            col1 = col1.strip()
            col2 = col2.strip()

            # Skip header rows
            if "---" in col1 or "Payload" in col1 or "Description" in col1:
                continue

            # First column is usually the payload
            if self._looks_like_payload(col1, vuln_type):
                # Clean markdown formatting
                payload_content = re.sub(r"`([^`]+)`", r"\1", col1)

                technique = self._detect_technique(payload_content, content)
                is_dangerous = self._is_dangerous_payload(payload_content)

                payloads.append(ParsedPayload(
                    content=payload_content,
                    category=vuln_type,
                    subcategory=subcategory,
                    technique=technique,
                    description=col2,
                    source_file=source_file,
                    is_dangerous=is_dangerous,
                ))

        return payloads

    def _detect_subcategory(
        self,
        filename: str,
        content: str,
        vuln_type: VulnerabilityType,
    ) -> str:
        """Detect subcategory from filename or content."""
        patterns = SUBCATEGORY_PATTERNS.get(vuln_type, {})

        for subcategory, keywords in patterns.items():
            for keyword in keywords:
                if keyword.lower() in filename.lower() or keyword in content[:1000]:
                    return subcategory

        return ""

    def _detect_technique(self, payload: str, context: str) -> PayloadTechnique:
        """Detect the technique used by a payload."""
        combined = f"{payload} {context[:500]}".lower()

        for technique, keywords in TECHNIQUE_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in combined:
                    return technique

        return PayloadTechnique.DIRECT

    def _is_dangerous_payload(self, payload: str) -> bool:
        """Check if payload is potentially dangerous/destructive."""
        upper_payload = payload.upper()
        for indicator in DANGEROUS_INDICATORS:
            if indicator.upper() in upper_payload:
                return True
        return False

    def _looks_like_payload(self, text: str, vuln_type: VulnerabilityType) -> bool:
        """Check if text looks like a valid payload."""
        if len(text) < 3 or len(text) > 2000:
            return False

        # Skip pure prose/documentation
        if text.count(" ") > 20:
            return False

        # ═══════════════════════════════════════════════════════════════════════
        # Existing vuln type heuristics
        # ═══════════════════════════════════════════════════════════════════════
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            sql_keywords = ["SELECT", "UNION", "OR", "AND", "'", '"', "--", "#", "SLEEP", "BENCHMARK"]
            return any(kw in text.upper() for kw in sql_keywords)

        elif vuln_type == VulnerabilityType.XSS:
            xss_indicators = ["<", ">", "script", "onerror", "onload", "javascript:", "alert", "eval"]
            return any(ind in text.lower() for ind in xss_indicators)

        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            cmd_indicators = [";", "|", "&", "`", "$(", "&&", "||", "cat", "ls", "id", "whoami"]
            return any(ind in text for ind in cmd_indicators)

        elif vuln_type == VulnerabilityType.SSRF:
            ssrf_indicators = ["http://", "https://", "file://", "gopher://", "dict://", "@", "localhost"]
            return any(ind in text.lower() for ind in ssrf_indicators)

        elif vuln_type == VulnerabilityType.XXE:
            xxe_indicators = ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file://", "http://"]
            return any(ind in text for ind in xxe_indicators)

        elif vuln_type == VulnerabilityType.LFI:
            lfi_indicators = ["../", "..\\", "/etc/", "C:\\", "file://", "php://"]
            return any(ind in text for ind in lfi_indicators)

        elif vuln_type == VulnerabilityType.SSTI:
            ssti_indicators = ["{{", "}}", "${", "<%", "%>", "#{"]
            return any(ind in text for ind in ssti_indicators)

        elif vuln_type == VulnerabilityType.NOSQL_INJECTION:
            nosql_indicators = ["$gt", "$ne", "$where", "$regex", "true", "||", "'"]
            return any(ind in text for ind in nosql_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Authentication & Access Control
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.CSRF:
            csrf_indicators = ["<form", "<img", "csrf", "token", "XMLHttpRequest", "fetch("]
            return any(ind in text.lower() for ind in csrf_indicators)

        elif vuln_type == VulnerabilityType.IDOR:
            idor_indicators = ["id=", "user_id", "account_id", "order_id", "doc_id", "/users/", "/api/"]
            return any(ind in text.lower() for ind in idor_indicators)

        elif vuln_type == VulnerabilityType.OAUTH_MISCONFIG:
            oauth_indicators = ["redirect_uri", "state=", "code=", "access_token", "client_id", "response_type"]
            return any(ind in text.lower() for ind in oauth_indicators)

        elif vuln_type == VulnerabilityType.SAML_INJECTION:
            saml_indicators = ["<saml", "SAMLResponse", "Assertion", "Issuer", "NameID", "Signature"]
            return any(ind in text for ind in saml_indicators)

        elif vuln_type == VulnerabilityType.ACCOUNT_TAKEOVER:
            ato_indicators = ["password", "reset", "token", "otp", "2fa", "session", "email="]
            return any(ind in text.lower() for ind in ato_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Protocol/Request Attacks
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.HTTP_SMUGGLING:
            smuggle_indicators = ["Transfer-Encoding", "Content-Length", "chunked", "\r\n", "0\r\n\r\n"]
            return any(ind in text for ind in smuggle_indicators)

        elif vuln_type == VulnerabilityType.HPP:
            hpp_indicators = ["&", "?", "=", "param", "[]", "%26"]
            return any(ind in text for ind in hpp_indicators) and ("=" in text or "&" in text)

        elif vuln_type == VulnerabilityType.DNS_REBINDING:
            dns_indicators = ["localhost", "127.0.0.1", "0.0.0.0", "dns", "rebind", ".local"]
            return any(ind in text.lower() for ind in dns_indicators)

        elif vuln_type == VulnerabilityType.CORS_MISCONFIG:
            cors_indicators = ["Origin", "Access-Control", "null", "*.example.com", "withCredentials"]
            return any(ind in text for ind in cors_indicators)

        elif vuln_type == VulnerabilityType.TABNABBING:
            tabnab_indicators = ["target=", "_blank", "opener", "noopener", "noreferrer", "window.opener"]
            return any(ind in text.lower() for ind in tabnab_indicators)

        elif vuln_type == VulnerabilityType.CACHE_POISONING:
            cache_indicators = ["X-Forwarded", "X-Host", "X-Original-URL", "Cache-", "Vary:", "cb="]
            return any(ind in text for ind in cache_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Client-Side Attacks
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.DOM_CLOBBERING:
            dom_indicators = ["id=", "name=", "document.", "window.", "form", "HTMLCollection"]
            return any(ind in text for ind in dom_indicators)

        elif vuln_type == VulnerabilityType.CLICKJACKING:
            click_indicators = ["<iframe", "frame", "X-Frame-Options", "opacity:", "position:"]
            return any(ind in text.lower() for ind in click_indicators)

        elif vuln_type == VulnerabilityType.PROTOTYPE_POLLUTION:
            proto_indicators = ["__proto__", "constructor", "prototype", "Object.assign", "merge"]
            return any(ind in text for ind in proto_indicators)

        elif vuln_type == VulnerabilityType.CLIENT_PATH_TRAVERSAL:
            client_path_indicators = ["../", "location.", "window.location", "document.URL", "hash"]
            return any(ind in text for ind in client_path_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - File & Data Attacks
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.CSV_INJECTION:
            csv_indicators = ["=", "+", "-", "@", "|", "DDE", "HYPERLINK", "cmd"]
            return text.startswith(tuple(["=", "+", "-", "@"])) or "DDE" in text

        elif vuln_type == VulnerabilityType.ZIP_SLIP:
            zip_indicators = ["../", "..\\", "symlink", "absolute path"]
            return any(ind in text for ind in zip_indicators)

        elif vuln_type == VulnerabilityType.ORM_LEAK:
            orm_indicators = ["where", "select", "include", "join", "relation", "__"]
            return any(ind in text.lower() for ind in orm_indicators)

        elif vuln_type == VulnerabilityType.API_KEY_LEAK:
            api_indicators = ["api_key", "apikey", "secret", "token", "bearer", "authorization"]
            return any(ind in text.lower() for ind in api_indicators)

        elif vuln_type == VulnerabilityType.GIT_EXPOSURE:
            git_indicators = [".git", "HEAD", "config", "refs/", "objects/", "COMMIT_EDITMSG"]
            return any(ind in text for ind in git_indicators)

        elif vuln_type == VulnerabilityType.SECRETS_EXPOSURE:
            secrets_indicators = ["password", "secret", "key", "token", "credential", "aws_"]
            return any(ind in text.lower() for ind in secrets_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Business Logic & Timing
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.RACE_CONDITION:
            race_indicators = ["concurrent", "parallel", "atomic", "lock", "mutex", "async"]
            return any(ind in text.lower() for ind in race_indicators)

        elif vuln_type == VulnerabilityType.MASS_ASSIGNMENT:
            mass_indicators = ["role", "admin", "is_admin", "user[role]", "params", "permitted"]
            return any(ind in text.lower() for ind in mass_indicators)

        elif vuln_type == VulnerabilityType.TYPE_JUGGLING:
            juggle_indicators = ["==", "0e", "0x", "true", "false", "strcmp", "md5"]
            return any(ind in text.lower() for ind in juggle_indicators)

        elif vuln_type == VulnerabilityType.BUSINESS_LOGIC:
            logic_indicators = ["coupon", "discount", "price", "quantity", "negative", "overflow"]
            return any(ind in text.lower() for ind in logic_indicators)

        elif vuln_type == VulnerabilityType.INSECURE_RANDOM:
            random_indicators = ["rand", "random", "mt_rand", "Math.random", "time()", "seed"]
            return any(ind in text.lower() for ind in random_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Injection Variants
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.LATEX_INJECTION:
            latex_indicators = ["\\input", "\\include", "\\write18", "\\immediate", "\\catcode"]
            return any(ind in text for ind in latex_indicators)

        elif vuln_type == VulnerabilityType.SSI_INJECTION:
            ssi_indicators = ["<!--#", "exec cmd", "include virtual", "echo var", "config"]
            return any(ind in text.lower() for ind in ssi_indicators)

        elif vuln_type == VulnerabilityType.XSLT_INJECTION:
            xslt_indicators = ["<xsl:", "xslt", "transform", "stylesheet", "document("]
            return any(ind in text.lower() for ind in xslt_indicators)

        elif vuln_type == VulnerabilityType.PROMPT_INJECTION:
            prompt_indicators = ["ignore", "disregard", "forget", "system:", "assistant:", "user:"]
            return any(ind in text.lower() for ind in prompt_indicators)

        elif vuln_type == VulnerabilityType.REGEX_DOS:
            regex_indicators = ["*+", "++", ".*.*", "(a+)+", "(?:", "backtrack"]
            return any(ind in text for ind in regex_indicators)

        elif vuln_type == VulnerabilityType.JAVA_RMI:
            rmi_indicators = ["rmi://", "ObjectInputStream", "readObject", "ysoserial", "Transformer"]
            return any(ind in text for ind in rmi_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Misconfiguration & Exposure
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.HIDDEN_PARAMS:
            hidden_indicators = ["debug", "test", "admin", "_hidden", "internal", "verbose"]
            return any(ind in text.lower() for ind in hidden_indicators)

        elif vuln_type == VulnerabilityType.ADMIN_INTERFACE:
            admin_indicators = ["/admin", "/manager", "/console", "/dashboard", "/phpmyadmin"]
            return any(ind in text.lower() for ind in admin_indicators)

        elif vuln_type == VulnerabilityType.VIRTUAL_HOST:
            vhost_indicators = ["Host:", "vhost", "subdomain", "internal.", "dev.", "stage."]
            return any(ind in text.lower() for ind in vhost_indicators)

        elif vuln_type == VulnerabilityType.REVERSE_PROXY:
            proxy_indicators = ["X-Forwarded", "X-Real-IP", "X-Original", "proxy_pass", "backend"]
            return any(ind in text for ind in proxy_indicators)

        elif vuln_type == VulnerabilityType.GWT_VULN:
            gwt_indicators = ["gwt", "permutation", "serialization", "rpc", "remoteService"]
            return any(ind in text.lower() for ind in gwt_indicators)

        elif vuln_type == VulnerabilityType.DEPENDENCY_CONFUSION:
            dep_indicators = ["npm", "pip", "gem", "nuget", "package", "registry"]
            return any(ind in text.lower() for ind in dep_indicators)

        elif vuln_type == VulnerabilityType.CVE_EXPLOITS:
            cve_indicators = ["CVE-", "exploit", "poc", "payload", "gadget"]
            return any(ind in text for ind in cve_indicators)

        # ═══════════════════════════════════════════════════════════════════════
        # NEW - Additional Edge Cases
        # ═══════════════════════════════════════════════════════════════════════
        elif vuln_type == VulnerabilityType.ENV_INJECTION:
            env_indicators = ["$ENV", "${", "getenv", "putenv", "environ", "PATH="]
            return any(ind in text for ind in env_indicators)

        elif vuln_type == VulnerabilityType.HEADLESS_BROWSER:
            headless_indicators = ["puppeteer", "playwright", "selenium", "evaluate(", "goto("]
            return any(ind in text.lower() for ind in headless_indicators)

        elif vuln_type == VulnerabilityType.ENCODING_BYPASS:
            encoding_indicators = ["%", "\\x", "\\u", "&#", "base64", "unicode"]
            return any(ind in text for ind in encoding_indicators)

        elif vuln_type == VulnerabilityType.HOST_HEADER:
            host_indicators = ["Host:", "X-Forwarded-Host", "X-Host", "localhost", "127.0.0.1"]
            return any(ind in text for ind in host_indicators)

        elif vuln_type == VulnerabilityType.HTTP_VERB_TAMPERING:
            verb_indicators = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]
            return any(ind in text.upper() for ind in verb_indicators)

        elif vuln_type == VulnerabilityType.SUBDOMAIN_TAKEOVER:
            takeover_indicators = ["CNAME", "NXDOMAIN", "heroku", "s3", "cloudfront", "github.io"]
            return any(ind in text.lower() for ind in takeover_indicators)

        # Generic check - has special characters common in payloads
        special_chars = ["'", '"', "<", ">", "&", "|", ";", "{", "}", "$"]
        return sum(1 for c in special_chars if c in text) >= 2

    def parse_all(
        self,
        vuln_types: Optional[list[VulnerabilityType]] = None,
    ) -> dict[VulnerabilityType, list[ParsedPayload]]:
        """
        Parse all payloads from the repository.

        Args:
            vuln_types: Specific types to parse (None = all)

        Returns:
            Dict mapping vuln type to list of payloads
        """
        if not self.ensure_repository():
            return {}

        categories = self.get_category_directories()
        results: dict[VulnerabilityType, list[ParsedPayload]] = {}

        for vuln_type, directory in categories.items():
            if vuln_types and vuln_type not in vuln_types:
                continue

            payloads = list(self.parse_directory(directory, vuln_type))

            # Apply limit
            if len(payloads) > self.config.max_payloads_per_type:
                payloads = payloads[:self.config.max_payloads_per_type]

            results[vuln_type] = payloads
            logger.info(f"Parsed {len(payloads)} payloads for {vuln_type.value}")

        return results
