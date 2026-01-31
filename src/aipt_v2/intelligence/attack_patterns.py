"""
AIPTX Extended Attack Patterns
==============================

Comprehensive attack chain patterns covering:
- OWASP Top 10 2021
- API Security Top 10
- Cloud Security (AWS, Azure, GCP)
- Container/Kubernetes Attacks
- Authentication/Authorization Bypasses
- Business Logic Flaws
- Modern Web Application Attacks
- Lateral Movement & Privilege Escalation

Each pattern includes:
- MITRE ATT&CK technique mapping
- Detection keywords
- Recommended exploitation tools
- Risk scoring factors
"""

from dataclasses import dataclass, field
from typing import Set, List, Dict, Any
from enum import Enum

from .chain_analysis import (
    ChainPattern,
    ChainImpact,
    MitreTactic,
    MitreTechnique,
)


# ============================================================================
# Extended MITRE ATT&CK Technique Mappings
# ============================================================================

EXTENDED_TECHNIQUE_MAP = {
    # === Initial Access ===
    "sqli": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                           "SQL injection exploitation"),
    "xss_stored": MitreTechnique("T1189", "Drive-by Compromise", MitreTactic.INITIAL_ACCESS,
                                  "Stored XSS for persistent attack"),
    "xss_reflected": MitreTechnique("T1189", "Drive-by Compromise", MitreTactic.INITIAL_ACCESS,
                                     "Reflected XSS attack"),
    "xxe": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                          "XML External Entity injection"),
    "ssti": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                           "Server-Side Template Injection"),
    "ssrf": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                           "Server-Side Request Forgery"),
    "deserialization": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                                       "Insecure deserialization"),
    "rce": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                          "Remote Code Execution"),
    "file_upload": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                                   "Malicious file upload"),
    "command_injection": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                                         "OS Command Injection"),
    "path_traversal": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                                      "Path traversal attack"),
    "idor": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                           "Insecure Direct Object Reference"),
    "jwt_attack": MitreTechnique("T1078", "Valid Accounts", MitreTactic.INITIAL_ACCESS,
                                  "JWT token manipulation"),
    "oauth_flaw": MitreTechnique("T1078", "Valid Accounts", MitreTactic.INITIAL_ACCESS,
                                  "OAuth/OIDC implementation flaw"),
    "graphql_introspection": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                                             "GraphQL introspection attack"),
    "websocket_hijack": MitreTechnique("T1190", "Exploit Public-Facing Application", MitreTactic.INITIAL_ACCESS,
                                        "WebSocket hijacking"),

    # === Credential Access ===
    "credential_dump": MitreTechnique("T1003", "OS Credential Dumping", MitreTactic.CREDENTIAL_ACCESS,
                                       "Dumping credentials from system"),
    "kerberoasting": MitreTechnique("T1558.003", "Kerberoasting", MitreTactic.CREDENTIAL_ACCESS,
                                     "Kerberos ticket extraction"),
    "asreproasting": MitreTechnique("T1558.004", "AS-REP Roasting", MitreTactic.CREDENTIAL_ACCESS,
                                     "AS-REP Kerberos attack"),
    "password_spray": MitreTechnique("T1110.003", "Password Spraying", MitreTactic.CREDENTIAL_ACCESS,
                                      "Password spray attack"),
    "brute_force": MitreTechnique("T1110", "Brute Force", MitreTactic.CREDENTIAL_ACCESS,
                                   "Credential brute forcing"),
    "credential_stuffing": MitreTechnique("T1110.004", "Credential Stuffing", MitreTactic.CREDENTIAL_ACCESS,
                                           "Using leaked credentials"),
    "session_hijack": MitreTechnique("T1539", "Steal Web Session Cookie", MitreTactic.CREDENTIAL_ACCESS,
                                      "Session cookie theft"),
    "mfa_bypass": MitreTechnique("T1111", "Multi-Factor Authentication Interception", MitreTactic.CREDENTIAL_ACCESS,
                                  "MFA bypass techniques"),
    "api_key_leak": MitreTechnique("T1552.001", "Credentials In Files", MitreTactic.CREDENTIAL_ACCESS,
                                    "Exposed API keys"),
    "git_secrets": MitreTechnique("T1552.001", "Credentials In Files", MitreTactic.CREDENTIAL_ACCESS,
                                   "Secrets in git history"),

    # === Privilege Escalation ===
    "priv_esc": MitreTechnique("T1068", "Exploitation for Privilege Escalation", MitreTactic.PRIVILEGE_ESC,
                                "Generic privilege escalation"),
    "sudo_abuse": MitreTechnique("T1548.003", "Sudo and Sudo Caching", MitreTactic.PRIVILEGE_ESC,
                                  "Sudo misconfiguration abuse"),
    "suid_abuse": MitreTechnique("T1548.001", "Setuid and Setgid", MitreTactic.PRIVILEGE_ESC,
                                  "SUID binary exploitation"),
    "kernel_exploit": MitreTechnique("T1068", "Exploitation for Privilege Escalation", MitreTactic.PRIVILEGE_ESC,
                                      "Kernel vulnerability exploitation"),
    "container_escape": MitreTechnique("T1611", "Escape to Host", MitreTactic.PRIVILEGE_ESC,
                                        "Container escape to host"),
    "token_impersonation": MitreTechnique("T1134", "Access Token Manipulation", MitreTactic.PRIVILEGE_ESC,
                                           "Token impersonation attack"),
    "dll_hijack": MitreTechnique("T1574.001", "DLL Search Order Hijacking", MitreTactic.PRIVILEGE_ESC,
                                  "DLL hijacking for privilege escalation"),

    # === Lateral Movement ===
    "pass_the_hash": MitreTechnique("T1550.002", "Pass the Hash", MitreTactic.LATERAL_MOVEMENT,
                                     "NTLM hash relay"),
    "pass_the_ticket": MitreTechnique("T1550.003", "Pass the Ticket", MitreTactic.LATERAL_MOVEMENT,
                                       "Kerberos ticket reuse"),
    "lateral_ssh": MitreTechnique("T1021.004", "SSH", MitreTactic.LATERAL_MOVEMENT,
                                   "SSH lateral movement"),
    "lateral_smb": MitreTechnique("T1021.002", "SMB/Windows Admin Shares", MitreTactic.LATERAL_MOVEMENT,
                                   "SMB lateral movement"),
    "lateral_rdp": MitreTechnique("T1021.001", "Remote Desktop Protocol", MitreTactic.LATERAL_MOVEMENT,
                                   "RDP lateral movement"),
    "lateral_winrm": MitreTechnique("T1021.006", "Windows Remote Management", MitreTactic.LATERAL_MOVEMENT,
                                     "WinRM lateral movement"),
    "psexec": MitreTechnique("T1569.002", "Service Execution", MitreTactic.LATERAL_MOVEMENT,
                              "PsExec remote execution"),

    # === Discovery ===
    "network_scan": MitreTechnique("T1046", "Network Service Discovery", MitreTactic.DISCOVERY,
                                    "Network scanning"),
    "ad_enumeration": MitreTechnique("T1087.002", "Domain Account", MitreTactic.DISCOVERY,
                                      "Active Directory enumeration"),
    "cloud_enumeration": MitreTechnique("T1580", "Cloud Infrastructure Discovery", MitreTactic.DISCOVERY,
                                         "Cloud resource enumeration"),
    "container_discovery": MitreTechnique("T1613", "Container and Resource Discovery", MitreTactic.DISCOVERY,
                                           "Container enumeration"),

    # === Collection & Exfiltration ===
    "data_staging": MitreTechnique("T1074", "Data Staged", MitreTactic.COLLECTION,
                                    "Staging data for exfiltration"),
    "data_exfil_http": MitreTechnique("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                                       MitreTactic.EXFILTRATION, "HTTPS exfiltration"),
    "data_exfil_dns": MitreTechnique("T1048.003", "Exfiltration Over Alternative Protocol",
                                      MitreTactic.EXFILTRATION, "DNS exfiltration"),

    # === Persistence ===
    "webshell": MitreTechnique("T1505.003", "Web Shell", MitreTactic.PERSISTENCE,
                                "Web shell persistence"),
    "cron_persistence": MitreTechnique("T1053.003", "Cron", MitreTactic.PERSISTENCE,
                                        "Cron job persistence"),
    "ssh_key_persistence": MitreTechnique("T1098.004", "SSH Authorized Keys", MitreTactic.PERSISTENCE,
                                           "SSH key persistence"),
    "backdoor_user": MitreTechnique("T1136", "Create Account", MitreTactic.PERSISTENCE,
                                     "Backdoor account creation"),

    # === Impact ===
    "ransomware": MitreTechnique("T1486", "Data Encrypted for Impact", MitreTactic.IMPACT,
                                  "Ransomware encryption"),
    "defacement": MitreTechnique("T1491", "Defacement", MitreTactic.IMPACT,
                                  "Website defacement"),
    "dos": MitreTechnique("T1499", "Endpoint Denial of Service", MitreTactic.IMPACT,
                           "Denial of service"),
}


# ============================================================================
# Extended Attack Chain Patterns (50+ patterns)
# ============================================================================

EXTENDED_CHAIN_PATTERNS = [
    # =========================================================================
    # OWASP TOP 10 - INJECTION ATTACKS
    # =========================================================================

    ChainPattern(
        id="sqli_union_exfil",
        name="SQL Injection UNION-Based Data Exfiltration",
        description="Use UNION-based SQLi to extract database contents including credentials",
        entry_types={"sqli", "vuln", "injection"},
        intermediate_types={"database", "table", "column"},
        exit_types={"credential", "data_exfil", "pii"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION, MitreTactic.EXFILTRATION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"union", "select", "from", "sql", "injection", "database", "dump", "extract"},
    ),

    ChainPattern(
        id="sqli_blind_boolean",
        name="Blind SQL Injection Boolean-Based Extraction",
        description="Extract data through boolean-based blind SQLi using conditional responses",
        entry_types={"sqli", "vuln", "blind"},
        intermediate_types={"boolean", "conditional"},
        exit_types={"data_exfil", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"blind", "boolean", "true", "false", "and", "or", "conditional"},
    ),

    ChainPattern(
        id="sqli_time_based",
        name="Time-Based Blind SQL Injection",
        description="Extract data using time delays in SQL queries",
        entry_types={"sqli", "vuln", "time"},
        intermediate_types={"delay", "sleep", "benchmark"},
        exit_types={"data_exfil", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"sleep", "benchmark", "waitfor", "delay", "time-based", "blind"},
    ),

    ChainPattern(
        id="sqli_stacked_rce",
        name="Stacked SQL Injection to RCE",
        description="Execute OS commands via stacked SQL queries (MSSQL xp_cmdshell, MySQL INTO OUTFILE)",
        entry_types={"sqli", "vuln", "stacked"},
        intermediate_types={"command", "procedure"},
        exit_types={"rce", "shell", "command_exec"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"xp_cmdshell", "into outfile", "load_file", "stacked", "exec", "sp_", "procedure"},
    ),

    ChainPattern(
        id="nosql_injection",
        name="NoSQL Injection Attack",
        description="Bypass authentication or extract data via NoSQL injection",
        entry_types={"nosql", "mongodb", "injection"},
        intermediate_types={"operator", "query"},
        exit_types={"auth_bypass", "data_exfil"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"$ne", "$gt", "$regex", "$where", "mongodb", "nosql", "json", "bson"},
    ),

    ChainPattern(
        id="ldap_injection",
        name="LDAP Injection Attack",
        description="Bypass authentication or enumerate directory via LDAP injection",
        entry_types={"ldap", "injection", "vuln"},
        intermediate_types={"filter", "query"},
        exit_types={"auth_bypass", "enumeration", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"ldap", ")(", "cn=", "uid=", "filter", "directory", "injection"},
    ),

    ChainPattern(
        id="xpath_injection",
        name="XPath Injection Attack",
        description="Extract XML data or bypass authentication via XPath injection",
        entry_types={"xpath", "xml", "injection"},
        intermediate_types={"node", "query"},
        exit_types={"data_exfil", "auth_bypass"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.MEDIUM,
        keywords={"xpath", "xml", "//", "node", "contains", "text()"},
    ),

    ChainPattern(
        id="command_injection_rce",
        name="OS Command Injection to Shell",
        description="Execute arbitrary OS commands and obtain reverse shell",
        entry_types={"command", "os", "injection", "vuln"},
        intermediate_types={"pipe", "semicolon", "backtick"},
        exit_types={"rce", "shell", "reverse_shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={";", "|", "&&", "`", "$()", "ping", "curl", "wget", "bash", "sh", "cmd", "powershell"},
    ),

    # =========================================================================
    # OWASP TOP 10 - BROKEN ACCESS CONTROL
    # =========================================================================

    ChainPattern(
        id="idor_horizontal",
        name="Horizontal IDOR - Access Other Users' Data",
        description="Access resources belonging to other users at the same privilege level",
        entry_types={"idor", "bac", "access_control"},
        intermediate_types={"user_id", "reference", "parameter"},
        exit_types={"data_exfil", "pii", "unauthorized_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"id=", "user_id", "account", "profile", "document", "file", "idor"},
    ),

    ChainPattern(
        id="idor_vertical",
        name="Vertical IDOR - Privilege Escalation",
        description="Access admin or higher-privileged resources through IDOR",
        entry_types={"idor", "bac", "access_control"},
        intermediate_types={"role", "admin", "privilege"},
        exit_types={"priv_esc", "admin_access", "unauthorized_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"admin", "role", "privilege", "permission", "access_level", "is_admin"},
    ),

    ChainPattern(
        id="bola_api",
        name="Broken Object Level Authorization (BOLA)",
        description="API endpoint allows unauthorized access to objects by manipulating IDs",
        entry_types={"bola", "api", "authorization"},
        intermediate_types={"object_id", "uuid", "guid"},
        exit_types={"data_exfil", "unauthorized_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"api", "/v1/", "/v2/", "object", "uuid", "guid", "resource"},
    ),

    ChainPattern(
        id="bfla_api",
        name="Broken Function Level Authorization (BFLA)",
        description="Access admin API endpoints without proper authorization",
        entry_types={"bfla", "api", "authorization"},
        intermediate_types={"function", "endpoint", "method"},
        exit_types={"admin_access", "priv_esc"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"admin", "api", "delete", "update", "create", "management", "internal"},
    ),

    ChainPattern(
        id="path_traversal_lfi",
        name="Path Traversal to Local File Inclusion",
        description="Read sensitive files through directory traversal",
        entry_types={"lfi", "path_traversal", "vuln"},
        intermediate_types={"../", "file", "path"},
        exit_types={"config_leak", "credential", "source_code"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"../", "..\\", "passwd", "etc", "config", "file=", "path=", "include"},
    ),

    ChainPattern(
        id="lfi_log_poison_rce",
        name="LFI Log Poisoning to RCE",
        description="Poison log files via User-Agent/headers then include for code execution",
        entry_types={"lfi", "path_traversal"},
        intermediate_types={"log", "access_log", "error_log"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"log", "access.log", "error.log", "proc/self", "php://", "user-agent"},
    ),

    ChainPattern(
        id="lfi_php_wrapper_rce",
        name="LFI PHP Wrapper to RCE",
        description="Use PHP wrappers (expect, input, filter) to achieve code execution",
        entry_types={"lfi", "php", "wrapper"},
        intermediate_types={"php://", "filter", "input"},
        exit_types={"rce", "shell", "source_code"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"php://filter", "php://input", "expect://", "data://", "base64", "convert"},
    ),

    # =========================================================================
    # OWASP TOP 10 - XSS ATTACKS
    # =========================================================================

    ChainPattern(
        id="xss_stored_admin",
        name="Stored XSS to Admin Account Takeover",
        description="Store malicious script to steal admin session when they view the content",
        entry_types={"xss", "stored", "vuln"},
        intermediate_types={"script", "payload", "storage"},
        exit_types={"session_hijack", "admin_access", "account_takeover"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"stored", "persistent", "xss", "script", "document.cookie", "admin", "session"},
    ),

    ChainPattern(
        id="xss_dom_based",
        name="DOM-Based XSS Attack",
        description="Exploit client-side JavaScript to execute malicious code",
        entry_types={"xss", "dom", "client"},
        intermediate_types={"document", "window", "location"},
        exit_types={"session_hijack", "keylogger", "phishing"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"dom", "innerhtml", "document.write", "location.hash", "window.name", "eval"},
    ),

    ChainPattern(
        id="xss_to_csrf",
        name="XSS to CSRF Chain",
        description="Use XSS to perform authenticated actions on behalf of victim",
        entry_types={"xss", "vuln"},
        intermediate_types={"ajax", "fetch", "xmlhttprequest"},
        exit_types={"csrf", "state_change", "data_modification"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.IMPACT],
        base_impact=ChainImpact.HIGH,
        keywords={"xss", "fetch", "xmlhttprequest", "ajax", "csrf", "token"},
    ),

    ChainPattern(
        id="xss_keylogger",
        name="XSS Keylogger Deployment",
        description="Deploy JavaScript keylogger via XSS to capture credentials",
        entry_types={"xss", "stored", "vuln"},
        intermediate_types={"keylogger", "event", "listener"},
        exit_types={"credential", "keystrokes"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"keylogger", "onkeypress", "onkeydown", "addeventlistener", "keycode"},
    ),

    # =========================================================================
    # SSRF ATTACKS
    # =========================================================================

    ChainPattern(
        id="ssrf_cloud_metadata",
        name="SSRF to Cloud Metadata Exploitation",
        description="Access cloud metadata service to steal credentials (AWS/GCP/Azure)",
        entry_types={"ssrf", "vuln"},
        intermediate_types={"metadata", "169.254.169.254"},
        exit_types={"credential", "cloud_access", "api_key"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.CRITICAL,
        keywords={"169.254.169.254", "metadata", "aws", "gcp", "azure", "iam", "role"},
    ),

    ChainPattern(
        id="ssrf_internal_scan",
        name="SSRF Internal Network Reconnaissance",
        description="Use SSRF to scan and discover internal network services",
        entry_types={"ssrf", "vuln"},
        intermediate_types={"internal", "localhost", "10.", "172.", "192.168"},
        exit_types={"discovery", "internal_access", "port_scan"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.DISCOVERY],
        base_impact=ChainImpact.HIGH,
        keywords={"localhost", "127.0.0.1", "internal", "10.0", "172.16", "192.168", "intranet"},
    ),

    ChainPattern(
        id="ssrf_internal_exploit",
        name="SSRF to Internal Service Exploitation",
        description="Exploit vulnerable internal services via SSRF (Redis, Memcached, etc.)",
        entry_types={"ssrf", "vuln"},
        intermediate_types={"redis", "memcached", "elasticsearch", "internal"},
        exit_types={"rce", "data_exfil", "internal_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION, MitreTactic.LATERAL_MOVEMENT],
        base_impact=ChainImpact.CRITICAL,
        keywords={"redis", "memcached", "elasticsearch", "mongodb", "gopher://", "dict://"},
    ),

    ChainPattern(
        id="ssrf_file_read",
        name="SSRF to Local File Read",
        description="Use file:// protocol via SSRF to read local files",
        entry_types={"ssrf", "vuln"},
        intermediate_types={"file://", "local"},
        exit_types={"file_read", "config_leak", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"file://", "file:", "/etc/passwd", "config", "credential"},
    ),

    # =========================================================================
    # XXE ATTACKS
    # =========================================================================

    ChainPattern(
        id="xxe_file_read",
        name="XXE Local File Disclosure",
        description="Read local files using XML External Entity injection",
        entry_types={"xxe", "xml", "vuln"},
        intermediate_types={"entity", "dtd", "external"},
        exit_types={"file_read", "config_leak", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"<!entity", "<!doctype", "system", "file://", "xxe", "dtd", "external"},
    ),

    ChainPattern(
        id="xxe_ssrf",
        name="XXE to SSRF",
        description="Use XXE to perform SSRF attacks against internal services",
        entry_types={"xxe", "xml"},
        intermediate_types={"http://", "https://", "entity"},
        exit_types={"ssrf", "internal_access", "discovery"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.DISCOVERY],
        base_impact=ChainImpact.HIGH,
        keywords={"xxe", "entity", "http://", "https://", "internal", "metadata"},
    ),

    ChainPattern(
        id="xxe_blind_oob",
        name="Blind XXE Out-of-Band Exfiltration",
        description="Exfiltrate data via DNS/HTTP out-of-band channels",
        entry_types={"xxe", "blind", "xml"},
        intermediate_types={"oob", "dns", "http"},
        exit_types={"data_exfil", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXFILTRATION],
        base_impact=ChainImpact.HIGH,
        keywords={"blind", "oob", "burpcollaborator", "dnslog", "webhook", "exfil"},
    ),

    ChainPattern(
        id="xxe_rce",
        name="XXE to Remote Code Execution",
        description="Achieve RCE via XXE using expect:// or PHP wrappers",
        entry_types={"xxe", "xml"},
        intermediate_types={"expect", "php", "wrapper"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"xxe", "expect://", "php://", "rce", "command", "exec"},
    ),

    # =========================================================================
    # SSTI ATTACKS
    # =========================================================================

    ChainPattern(
        id="ssti_jinja2_rce",
        name="Jinja2 SSTI to RCE",
        description="Exploit Jinja2 template injection for Python code execution",
        entry_types={"ssti", "template", "jinja"},
        intermediate_types={"{{", "}}", "config", "class"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"{{", "}}", "__class__", "__mro__", "__subclasses__", "jinja", "flask", "config"},
    ),

    ChainPattern(
        id="ssti_twig_rce",
        name="Twig SSTI to RCE",
        description="Exploit Twig template injection for PHP code execution",
        entry_types={"ssti", "template", "twig"},
        intermediate_types={"{{", "}}", "filter"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"twig", "{{", "}}", "_self", "env", "filter", "symfony"},
    ),

    ChainPattern(
        id="ssti_freemarker_rce",
        name="FreeMarker SSTI to RCE",
        description="Exploit FreeMarker template injection for Java code execution",
        entry_types={"ssti", "template", "freemarker"},
        intermediate_types={"${", "}", "new"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"freemarker", "${", "}", "exec", "runtime", "processbuilder", "java"},
    ),

    # =========================================================================
    # DESERIALIZATION ATTACKS
    # =========================================================================

    ChainPattern(
        id="java_deserial_rce",
        name="Java Deserialization RCE",
        description="Exploit insecure Java deserialization for remote code execution",
        entry_types={"deserialization", "java", "vuln"},
        intermediate_types={"gadget", "chain", "payload"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"aced0005", "rO0", "objectinputstream", "ysoserial", "gadget", "commons-collections"},
    ),

    ChainPattern(
        id="php_deserial_rce",
        name="PHP Deserialization RCE",
        description="Exploit PHP unserialize() for code execution via POP chains",
        entry_types={"deserialization", "php", "vuln"},
        intermediate_types={"__wakeup", "__destruct", "phar"},
        exit_types={"rce", "shell", "file_write"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"unserialize", "O:", "a:", "__wakeup", "__destruct", "phar://", "phpggc"},
    ),

    ChainPattern(
        id="python_pickle_rce",
        name="Python Pickle Deserialization RCE",
        description="Exploit Python pickle.loads() for code execution",
        entry_types={"deserialization", "python", "pickle"},
        intermediate_types={"__reduce__", "payload"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"pickle", "unpickle", "__reduce__", "cPickle", "loads", "gASV"},
    ),

    ChainPattern(
        id="dotnet_deserial_rce",
        name=".NET Deserialization RCE",
        description="Exploit .NET deserialization vulnerabilities (BinaryFormatter, etc.)",
        entry_types={"deserialization", "dotnet", "vuln"},
        intermediate_types={"binaryformatter", "objectstateformatter"},
        exit_types={"rce", "shell"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"viewstate", "binaryformatter", "objectstateformatter", "ysoserial.net", "aaeaaad"},
    ),

    # =========================================================================
    # AUTHENTICATION/AUTHORIZATION ATTACKS
    # =========================================================================

    ChainPattern(
        id="jwt_none_alg",
        name="JWT Algorithm None Attack",
        description="Bypass JWT signature verification using 'none' algorithm",
        entry_types={"jwt", "auth", "token"},
        intermediate_types={"header", "algorithm"},
        exit_types={"auth_bypass", "priv_esc"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.DEFENSE_EVASION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"jwt", "alg", "none", "hs256", "rs256", "header", "bearer"},
    ),

    ChainPattern(
        id="jwt_key_confusion",
        name="JWT Algorithm Confusion (RS256 to HS256)",
        description="Exploit algorithm confusion to sign tokens with public key",
        entry_types={"jwt", "auth", "crypto"},
        intermediate_types={"algorithm", "key", "public"},
        exit_types={"auth_bypass", "token_forge"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.CRITICAL,
        keywords={"jwt", "rs256", "hs256", "algorithm", "confusion", "public_key"},
    ),

    ChainPattern(
        id="jwt_secret_bruteforce",
        name="JWT Secret Key Brute Force",
        description="Brute force weak JWT HMAC secret to forge tokens",
        entry_types={"jwt", "auth", "weak"},
        intermediate_types={"secret", "bruteforce"},
        exit_types={"token_forge", "auth_bypass"},
        tactics=[MitreTactic.CREDENTIAL_ACCESS, MitreTactic.INITIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"jwt", "secret", "bruteforce", "hashcat", "john", "weak"},
    ),

    ChainPattern(
        id="oauth_redirect_theft",
        name="OAuth Redirect URI Token Theft",
        description="Steal OAuth tokens via redirect_uri manipulation",
        entry_types={"oauth", "redirect", "vuln"},
        intermediate_types={"uri", "token", "code"},
        exit_types={"token_theft", "account_takeover"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"redirect_uri", "oauth", "code", "token", "callback", "state"},
    ),

    ChainPattern(
        id="mfa_bypass_backup",
        name="MFA Bypass via Backup Codes",
        description="Bypass MFA using leaked or brute-forced backup codes",
        entry_types={"mfa", "2fa", "auth"},
        intermediate_types={"backup", "code", "recovery"},
        exit_types={"auth_bypass", "account_takeover"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"mfa", "2fa", "backup", "recovery", "code", "otp"},
    ),

    ChainPattern(
        id="password_reset_token",
        name="Password Reset Token Exploitation",
        description="Exploit weak password reset tokens for account takeover",
        entry_types={"reset", "token", "auth"},
        intermediate_types={"predictable", "leaked", "enum"},
        exit_types={"account_takeover", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"reset", "forgot", "token", "password", "recovery", "email"},
    ),

    ChainPattern(
        id="session_fixation",
        name="Session Fixation Attack",
        description="Force victim to use attacker-known session ID",
        entry_types={"session", "fixation", "auth"},
        intermediate_types={"cookie", "sessionid"},
        exit_types={"session_hijack", "account_takeover"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"session", "fixation", "cookie", "sessionid", "jsessionid", "phpsessid"},
    ),

    # =========================================================================
    # API SECURITY ATTACKS
    # =========================================================================

    ChainPattern(
        id="graphql_introspection_enum",
        name="GraphQL Introspection to Schema Dump",
        description="Use GraphQL introspection to enumerate all queries, mutations, and types",
        entry_types={"graphql", "api", "introspection"},
        intermediate_types={"schema", "query", "mutation"},
        exit_types={"enumeration", "discovery"},
        tactics=[MitreTactic.RECONNAISSANCE, MitreTactic.DISCOVERY],
        base_impact=ChainImpact.MEDIUM,
        keywords={"__schema", "__type", "introspection", "graphql", "query", "mutation"},
    ),

    ChainPattern(
        id="graphql_batching_dos",
        name="GraphQL Batching/Nested Query DoS",
        description="Exhaust server resources via deeply nested or batched queries",
        entry_types={"graphql", "api", "dos"},
        intermediate_types={"nested", "batch", "complexity"},
        exit_types={"dos", "resource_exhaustion"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.IMPACT],
        base_impact=ChainImpact.MEDIUM,
        keywords={"graphql", "batch", "nested", "depth", "complexity", "alias"},
    ),

    ChainPattern(
        id="api_mass_assignment",
        name="API Mass Assignment Vulnerability",
        description="Modify unauthorized fields via mass assignment in API requests",
        entry_types={"api", "mass_assignment", "vuln"},
        intermediate_types={"field", "parameter", "binding"},
        exit_types={"priv_esc", "data_modification"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.HIGH,
        keywords={"role", "admin", "isadmin", "privilege", "binding", "assignment"},
    ),

    ChainPattern(
        id="api_rate_limit_bypass",
        name="API Rate Limiting Bypass",
        description="Bypass rate limiting to perform brute force or enumeration attacks",
        entry_types={"api", "rate_limit", "bypass"},
        intermediate_types={"header", "ip", "rotation"},
        exit_types={"brute_force", "enumeration"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.MEDIUM,
        keywords={"rate", "limit", "x-forwarded-for", "x-real-ip", "429", "retry"},
    ),

    ChainPattern(
        id="api_version_exploit",
        name="Deprecated API Version Exploitation",
        description="Exploit vulnerabilities in older, deprecated API versions",
        entry_types={"api", "version", "deprecated"},
        intermediate_types={"/v1/", "/v2/", "legacy"},
        exit_types={"vuln_exploit", "auth_bypass"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.DEFENSE_EVASION],
        base_impact=ChainImpact.HIGH,
        keywords={"v1", "v2", "deprecated", "legacy", "old", "version"},
    ),

    # =========================================================================
    # CLOUD SECURITY ATTACKS
    # =========================================================================

    ChainPattern(
        id="aws_metadata_to_s3",
        name="AWS Metadata to S3 Bucket Access",
        description="Use stolen IAM credentials from metadata to access S3 buckets",
        entry_types={"ssrf", "aws", "metadata"},
        intermediate_types={"iam", "role", "credential"},
        exit_types={"s3_access", "data_exfil", "cloud_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"169.254.169.254", "iam", "role", "s3", "bucket", "aws"},
    ),

    ChainPattern(
        id="s3_bucket_takeover",
        name="S3 Bucket Takeover",
        description="Take over unclaimed S3 bucket referenced by application",
        entry_types={"s3", "bucket", "cloud"},
        intermediate_types={"dns", "reference", "unclaimed"},
        exit_types={"takeover", "supply_chain"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PERSISTENCE],
        base_impact=ChainImpact.HIGH,
        keywords={"s3", "bucket", "nosuchbucket", "accessdenied", "takeover"},
    ),

    ChainPattern(
        id="azure_metadata_to_keyvault",
        name="Azure Metadata to Key Vault Access",
        description="Use managed identity from metadata to access Azure Key Vault secrets",
        entry_types={"ssrf", "azure", "metadata"},
        intermediate_types={"identity", "token", "keyvault"},
        exit_types={"secret_access", "credential"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.CRITICAL,
        keywords={"169.254.169.254", "azure", "identity", "keyvault", "secret", "managed"},
    ),

    ChainPattern(
        id="gcp_metadata_to_storage",
        name="GCP Metadata to Cloud Storage Access",
        description="Use service account token from metadata to access GCS buckets",
        entry_types={"ssrf", "gcp", "metadata"},
        intermediate_types={"service_account", "token"},
        exit_types={"storage_access", "data_exfil"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"metadata.google", "computemetadata", "service-account", "gcs", "storage"},
    ),

    # =========================================================================
    # CONTAINER/KUBERNETES ATTACKS
    # =========================================================================

    ChainPattern(
        id="container_escape_privileged",
        name="Privileged Container Escape",
        description="Escape from privileged container to host system",
        entry_types={"container", "docker", "privileged"},
        intermediate_types={"mount", "device", "host"},
        exit_types={"container_escape", "host_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"privileged", "docker", "container", "mount", "/dev", "escape"},
    ),

    ChainPattern(
        id="k8s_api_unauth",
        name="Kubernetes API Unauthenticated Access",
        description="Access unauthenticated Kubernetes API server",
        entry_types={"kubernetes", "api", "unauth"},
        intermediate_types={"apiserver", "kubectl"},
        exit_types={"cluster_access", "secret_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.DISCOVERY],
        base_impact=ChainImpact.CRITICAL,
        keywords={"kubernetes", "k8s", "apiserver", "kubectl", "anonymous", "6443", "8443"},
    ),

    ChainPattern(
        id="k8s_etcd_secret_dump",
        name="Kubernetes etcd Secret Dump",
        description="Access etcd to dump all Kubernetes secrets",
        entry_types={"kubernetes", "etcd", "unauth"},
        intermediate_types={"secret", "configmap"},
        exit_types={"credential", "secret_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.CRITICAL,
        keywords={"etcd", "2379", "2380", "secret", "kubernetes", "k8s"},
    ),

    ChainPattern(
        id="k8s_serviceaccount_abuse",
        name="Kubernetes Service Account Token Abuse",
        description="Use mounted service account token for cluster enumeration/exploitation",
        entry_types={"kubernetes", "serviceaccount", "token"},
        intermediate_types={"rbac", "permission"},
        exit_types={"priv_esc", "cluster_access"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.HIGH,
        keywords={"serviceaccount", "token", "rbac", "clusterrole", "rolebinding"},
    ),

    # =========================================================================
    # FILE UPLOAD ATTACKS
    # =========================================================================

    ChainPattern(
        id="file_upload_webshell",
        name="File Upload to Web Shell",
        description="Upload malicious file to gain web shell access",
        entry_types={"upload", "file", "vuln"},
        intermediate_types={"extension", "mime", "validation"},
        exit_types={"webshell", "rce"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PERSISTENCE, MitreTactic.EXECUTION],
        base_impact=ChainImpact.CRITICAL,
        keywords={"upload", "file", "webshell", "php", "jsp", "aspx", "extension"},
    ),

    ChainPattern(
        id="file_upload_xxe",
        name="File Upload XXE via SVG/DOCX",
        description="Upload SVG/DOCX with XXE payload to read files or SSRF",
        entry_types={"upload", "xxe", "svg"},
        intermediate_types={"xml", "entity", "docx"},
        exit_types={"file_read", "ssrf"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COLLECTION],
        base_impact=ChainImpact.HIGH,
        keywords={"svg", "docx", "xlsx", "xxe", "entity", "upload"},
    ),

    ChainPattern(
        id="file_upload_polyglot",
        name="Polyglot File Upload Bypass",
        description="Use polyglot files to bypass upload filters (e.g., GIFAR, PHAR+JPEG)",
        entry_types={"upload", "polyglot", "bypass"},
        intermediate_types={"magic_bytes", "header"},
        exit_types={"webshell", "rce"},
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.DEFENSE_EVASION, MitreTactic.EXECUTION],
        base_impact=ChainImpact.HIGH,
        keywords={"polyglot", "gif89a", "phar", "magic", "bypass", "filter"},
    ),

    # =========================================================================
    # LATERAL MOVEMENT & PRIVILEGE ESCALATION
    # =========================================================================

    ChainPattern(
        id="kerberoasting_crack",
        name="Kerberoasting to Domain Compromise",
        description="Extract and crack service account tickets for lateral movement",
        entry_types={"kerberos", "spn", "ticket"},
        intermediate_types={"tgs", "hash", "crack"},
        exit_types={"credential", "lateral_move", "domain_admin"},
        tactics=[MitreTactic.CREDENTIAL_ACCESS, MitreTactic.LATERAL_MOVEMENT],
        base_impact=ChainImpact.CRITICAL,
        keywords={"kerberos", "spn", "tgs", "ticket", "hashcat", "kerberoast"},
    ),

    ChainPattern(
        id="asreproast_crack",
        name="AS-REP Roasting to Account Compromise",
        description="Request and crack AS-REP hashes for accounts without pre-auth",
        entry_types={"kerberos", "asrep", "no_preauth"},
        intermediate_types={"hash", "crack"},
        exit_types={"credential", "account_access"},
        tactics=[MitreTactic.CREDENTIAL_ACCESS],
        base_impact=ChainImpact.HIGH,
        keywords={"asrep", "roast", "preauth", "kerberos", "hash", "crack"},
    ),

    ChainPattern(
        id="dcsync_ntds",
        name="DCSync to NTDS.dit Dump",
        description="Use DCSync to replicate domain credentials including krbtgt",
        entry_types={"dcsync", "replication", "ad"},
        intermediate_types={"drsuapi", "ntds"},
        exit_types={"credential", "domain_admin", "golden_ticket"},
        tactics=[MitreTactic.CREDENTIAL_ACCESS, MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"dcsync", "drsuapi", "ntds", "krbtgt", "replication", "mimikatz"},
    ),

    ChainPattern(
        id="linux_sudo_privesc",
        name="Linux Sudo Misconfiguration Privilege Escalation",
        description="Exploit sudo misconfigurations for root access",
        entry_types={"sudo", "linux", "privesc"},
        intermediate_types={"nopasswd", "env", "gtfobins"},
        exit_types={"root", "priv_esc"},
        tactics=[MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"sudo", "nopasswd", "gtfobins", "vim", "less", "find", "awk"},
    ),

    ChainPattern(
        id="linux_suid_privesc",
        name="Linux SUID Binary Privilege Escalation",
        description="Exploit SUID binaries for privilege escalation",
        entry_types={"suid", "linux", "binary"},
        intermediate_types={"gtfobins", "exploit"},
        exit_types={"root", "priv_esc"},
        tactics=[MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.HIGH,
        keywords={"suid", "4000", "gtfobins", "find", "nmap", "vim", "python"},
    ),

    ChainPattern(
        id="windows_token_impersonation",
        name="Windows Token Impersonation",
        description="Impersonate privileged tokens for local privilege escalation",
        entry_types={"token", "windows", "impersonation"},
        intermediate_types={"seimpersonate", "potato"},
        exit_types={"system", "priv_esc"},
        tactics=[MitreTactic.PRIVILEGE_ESC],
        base_impact=ChainImpact.CRITICAL,
        keywords={"seimpersonate", "potato", "token", "impersonate", "juicy", "rotten"},
    ),

    ChainPattern(
        id="windows_unquoted_service",
        name="Windows Unquoted Service Path Exploitation",
        description="Exploit unquoted service paths for privilege escalation",
        entry_types={"service", "windows", "unquoted"},
        intermediate_types={"path", "binary"},
        exit_types={"system", "priv_esc"},
        tactics=[MitreTactic.PRIVILEGE_ESC, MitreTactic.PERSISTENCE],
        base_impact=ChainImpact.HIGH,
        keywords={"unquoted", "service", "path", "program files", "hijack"},
    ),
]


# ============================================================================
# Tool Recommendations by Attack Type
# ============================================================================

ATTACK_TOOL_RECOMMENDATIONS: Dict[str, List[str]] = {
    # Injection attacks
    "sqli": ["sqlmap", "burp", "ghauri", "havij"],
    "nosql": ["nosqlmap", "burp"],
    "command_injection": ["commix", "burp"],
    "ssti": ["tplmap", "burp", "sstimap"],
    "xxe": ["burp", "xxeinjector"],

    # Access control
    "idor": ["burp", "autorize", "ffuf"],
    "bola": ["burp", "autorize"],
    "bfla": ["burp"],
    "lfi": ["burp", "ffuf", "lfimap"],
    "path_traversal": ["dotdotpwn", "burp"],

    # XSS
    "xss": ["dalfox", "xsstrike", "burp"],

    # SSRF
    "ssrf": ["burp", "ssrfmap", "gopherus"],

    # Authentication
    "jwt": ["jwt_tool", "burp"],
    "oauth": ["burp"],
    "session": ["burp"],
    "mfa": ["burp"],

    # API
    "graphql": ["graphqlmap", "inql", "burp"],
    "api": ["burp", "postman", "ffuf"],

    # Deserialization
    "java_deserial": ["ysoserial", "burp"],
    "php_deserial": ["phpggc", "burp"],
    "python_deserial": ["custom"],
    "dotnet_deserial": ["ysoserial.net"],

    # Cloud
    "aws": ["pacu", "awscli", "cloudfox"],
    "azure": ["azurehound", "roadtools"],
    "gcp": ["gcp_scanner"],

    # Container/K8s
    "container": ["deepce", "cdkexec"],
    "kubernetes": ["kube-hunter", "kubectl", "kubesploit"],

    # File upload
    "upload": ["burp", "fuxploider"],

    # Active Directory
    "kerberos": ["impacket", "rubeus", "mimikatz"],
    "ad": ["bloodhound", "ldapdomaindump", "crackmapexec"],

    # Lateral movement
    "lateral_ssh": ["ssh", "plink"],
    "lateral_smb": ["crackmapexec", "psexec", "impacket"],
    "lateral_rdp": ["xfreerdp", "rdesktop"],
    "lateral_winrm": ["evil-winrm", "crackmapexec"],

    # Privilege escalation
    "linux_privesc": ["linpeas", "linenum", "linux-exploit-suggester"],
    "windows_privesc": ["winpeas", "powerup", "windows-exploit-suggester"],
}


# ============================================================================
# Helper Functions
# ============================================================================

def get_all_patterns() -> List[ChainPattern]:
    """Get all attack chain patterns including extended patterns."""
    from .chain_analysis import CHAIN_PATTERNS
    return CHAIN_PATTERNS + EXTENDED_CHAIN_PATTERNS


def get_patterns_by_tactic(tactic: MitreTactic) -> List[ChainPattern]:
    """Get patterns that involve a specific MITRE tactic."""
    all_patterns = get_all_patterns()
    return [p for p in all_patterns if tactic in p.tactics]


def get_patterns_by_impact(impact: ChainImpact) -> List[ChainPattern]:
    """Get patterns with a specific impact level."""
    all_patterns = get_all_patterns()
    return [p for p in all_patterns if p.base_impact == impact]


def get_patterns_by_keywords(keywords: Set[str]) -> List[ChainPattern]:
    """Find patterns matching any of the given keywords."""
    all_patterns = get_all_patterns()
    matched = []
    keywords_lower = {k.lower() for k in keywords}

    for pattern in all_patterns:
        if pattern.keywords & keywords_lower:
            matched.append(pattern)

    return matched


def get_recommended_tools(attack_type: str) -> List[str]:
    """Get recommended tools for a specific attack type."""
    # Check exact match
    if attack_type in ATTACK_TOOL_RECOMMENDATIONS:
        return ATTACK_TOOL_RECOMMENDATIONS[attack_type]

    # Check partial match
    for key, tools in ATTACK_TOOL_RECOMMENDATIONS.items():
        if key in attack_type.lower() or attack_type.lower() in key:
            return tools

    return ["burp", "manual"]  # Default


def get_technique_for_attack(attack_type: str) -> MitreTechnique:
    """Get MITRE technique for an attack type."""
    return EXTENDED_TECHNIQUE_MAP.get(attack_type.lower())


# Pattern statistics
def get_pattern_statistics() -> Dict[str, Any]:
    """Get statistics about available attack patterns."""
    all_patterns = get_all_patterns()

    by_impact = {}
    for impact in ChainImpact:
        by_impact[impact.value] = len([p for p in all_patterns if p.base_impact == impact])

    by_tactic = {}
    for tactic in MitreTactic:
        by_tactic[tactic.value] = len([p for p in all_patterns if tactic in p.tactics])

    return {
        "total_patterns": len(all_patterns),
        "by_impact": by_impact,
        "by_tactic": by_tactic,
        "unique_keywords": len(set().union(*[p.keywords for p in all_patterns])),
    }
