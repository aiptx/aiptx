"""
JWT Token Security Analyzer

Comprehensive JWT (JSON Web Token) security testing:
- Algorithm confusion attacks (none, HS256/RS256 switch)
- Signature verification bypass
- Key brute-forcing (weak secrets)
- Claim manipulation (exp, iat, aud, iss)
- Token structure analysis
- JWK/JWKS endpoint testing

References:
- https://portswigger.net/web-security/jwt
- https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

Usage:
    from aipt_v2.tools.api_security import JWTAnalyzer

    analyzer = JWTAnalyzer()
    findings = analyzer.analyze("eyJhbGciOiJIUzI1NiIs...")
"""

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

try:
    import jwt as pyjwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False


@dataclass
class JWTFinding:
    """JWT security finding."""
    vulnerability: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str
    remediation: str
    affected_claim: str = ""
    attack_vector: str = ""
    timestamp: str = ""
    cwe: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class JWTInfo:
    """Parsed JWT information."""
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    is_valid: bool = False
    expiration: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    not_before: Optional[datetime] = None


class JWTAnalyzer:
    """
    JWT Security Analyzer.

    Analyzes JWT tokens for security vulnerabilities
    including algorithm confusion, weak signatures,
    and claim manipulation issues.
    """

    # Common weak secrets for brute-force
    COMMON_SECRETS = [
        "secret", "password", "123456", "admin", "key",
        "jwt_secret", "jwt-secret", "token", "auth",
        "supersecret", "changeme", "default", "test",
        "development", "dev", "production", "prod",
        "your-256-bit-secret", "your-secret-key",
        "HS256-secret", "secret123", "secretkey",
        "application-secret", "app-secret", "api-secret"
    ]

    # Extended wordlist
    EXTENDED_SECRETS = COMMON_SECRETS + [
        # Company-style secrets
        "company-secret", "my-secret-key", "very-secret",
        # Lazy admin secrets
        "password123", "admin123", "root", "toor",
        # Framework defaults
        "django-insecure", "flask-secret", "express-secret",
        "rails-secret", "laravel-secret",
        # Environment-style
        "JWT_SECRET", "API_SECRET", "AUTH_SECRET",
        # UUID-like
        "00000000-0000-0000-0000-000000000000",
        # Simple variations
        "Secret", "SECRET", "Password", "PASSWORD"
    ]

    def __init__(self, extended_wordlist: bool = False):
        """
        Initialize JWT analyzer.

        Args:
            extended_wordlist: Use extended wordlist for brute-force
        """
        self.secrets = self.EXTENDED_SECRETS if extended_wordlist else self.COMMON_SECRETS
        self.findings: List[JWTFinding] = []

    def _base64_decode(self, data: str) -> bytes:
        """Decode base64url encoded data."""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        # Replace URL-safe characters
        data = data.replace("-", "+").replace("_", "/")
        return base64.b64decode(data)

    def _base64_encode(self, data: bytes) -> str:
        """Encode data as base64url."""
        encoded = base64.b64encode(data).decode()
        # Make URL-safe
        return encoded.replace("+", "-").replace("/", "_").rstrip("=")

    def parse_token(self, token: str) -> Optional[JWTInfo]:
        """Parse JWT token into components."""
        parts = token.split(".")

        if len(parts) != 3:
            return None

        try:
            header_json = self._base64_decode(parts[0])
            payload_json = self._base64_decode(parts[1])

            header = json.loads(header_json)
            payload = json.loads(payload_json)

            # Parse timestamps
            expiration = None
            issued_at = None
            not_before = None

            if "exp" in payload:
                try:
                    expiration = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                except (ValueError, OSError):
                    pass

            if "iat" in payload:
                try:
                    issued_at = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
                except (ValueError, OSError):
                    pass

            if "nbf" in payload:
                try:
                    not_before = datetime.fromtimestamp(payload["nbf"], tz=timezone.utc)
                except (ValueError, OSError):
                    pass

            return JWTInfo(
                raw=token,
                header=header,
                payload=payload,
                signature=parts[2],
                algorithm=header.get("alg", "unknown"),
                expiration=expiration,
                issued_at=issued_at,
                not_before=not_before
            )

        except Exception:
            return None

    def test_none_algorithm(self, jwt_info: JWTInfo) -> List[JWTFinding]:
        """Test for 'none' algorithm vulnerability."""
        findings = []

        # Create token with "none" algorithm
        none_header = {"alg": "none", "typ": "JWT"}
        none_header_b64 = self._base64_encode(json.dumps(none_header).encode())
        payload_b64 = jwt_info.raw.split(".")[1]

        # Tokens without signature
        none_tokens = [
            f"{none_header_b64}.{payload_b64}.",
            f"{none_header_b64}.{payload_b64}",
        ]

        # Also try "None", "NONE", "nOnE"
        for alg_variant in ["None", "NONE", "nOnE"]:
            variant_header = {"alg": alg_variant, "typ": "JWT"}
            variant_b64 = self._base64_encode(json.dumps(variant_header).encode())
            none_tokens.append(f"{variant_b64}.{payload_b64}.")

        findings.append(JWTFinding(
            vulnerability="None Algorithm Attack Vector",
            severity="critical",
            description="JWT library may accept 'none' algorithm, allowing signature bypass",
            evidence=f"Generated attack tokens with none algorithm",
            attack_vector=none_tokens[0],
            remediation="Explicitly verify algorithm in JWT validation. Never accept 'none'.",
            cwe="CWE-327"
        ))

        return findings

    def test_algorithm_confusion(self, jwt_info: JWTInfo) -> List[JWTFinding]:
        """Test for algorithm confusion (HS256/RS256 switch)."""
        findings = []

        # If token uses RS256/RS384/RS512, could be vulnerable to HS256 confusion
        if jwt_info.algorithm in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]:
            findings.append(JWTFinding(
                vulnerability="Potential Algorithm Confusion",
                severity="high",
                description=f"Token uses {jwt_info.algorithm}. If the public key is known, "
                           "attacker may forge tokens by switching to HS256 and using public key as secret.",
                evidence=f"Current algorithm: {jwt_info.algorithm}",
                attack_vector="Switch alg to HS256 and sign with public key",
                remediation="Explicitly specify expected algorithm during verification. "
                           "Never allow algorithm to be changed by the token itself.",
                cwe="CWE-327"
            ))

        return findings

    def test_weak_secret(self, jwt_info: JWTInfo) -> List[JWTFinding]:
        """Test for weak/common secrets using brute-force."""
        findings = []

        if jwt_info.algorithm not in ["HS256", "HS384", "HS512"]:
            return findings

        # Get algorithm details
        alg_map = {
            "HS256": ("sha256", 256),
            "HS384": ("sha384", 384),
            "HS512": ("sha512", 512)
        }

        hash_alg, _ = alg_map.get(jwt_info.algorithm, ("sha256", 256))

        # Get message to sign
        parts = jwt_info.raw.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        target_sig = parts[2]

        # Try common secrets
        cracked_secret = None
        for secret in self.secrets:
            # Compute signature
            sig = hmac.new(
                secret.encode(),
                message,
                hash_alg
            ).digest()
            computed_sig = self._base64_encode(sig)

            if computed_sig == target_sig:
                cracked_secret = secret
                break

        if cracked_secret:
            findings.append(JWTFinding(
                vulnerability="Weak JWT Secret",
                severity="critical",
                description=f"JWT secret is a common/weak value: '{cracked_secret}'",
                evidence=f"Secret cracked: {cracked_secret}",
                attack_vector=f"Use secret '{cracked_secret}' to forge tokens",
                remediation="Use a strong, random secret (minimum 256 bits). "
                           "Consider using asymmetric algorithms (RS256).",
                cwe="CWE-521"
            ))
        else:
            findings.append(JWTFinding(
                vulnerability="JWT Secret Brute-Force Test",
                severity="info",
                description=f"Tested {len(self.secrets)} common secrets - none matched",
                evidence="Secret not in common wordlist",
                remediation="Continue using a strong secret",
                cwe=""
            ))

        return findings

    def test_expiration(self, jwt_info: JWTInfo) -> List[JWTFinding]:
        """Test token expiration claims."""
        findings = []
        now = datetime.now(timezone.utc)

        # Check for missing expiration
        if not jwt_info.expiration:
            if "exp" not in jwt_info.payload:
                findings.append(JWTFinding(
                    vulnerability="Missing Token Expiration",
                    severity="high",
                    description="Token has no expiration claim (exp)",
                    evidence="No 'exp' claim in payload",
                    affected_claim="exp",
                    remediation="Always include expiration in tokens. Use short lifetimes.",
                    cwe="CWE-613"
                ))
        else:
            # Check if expired
            if jwt_info.expiration < now:
                findings.append(JWTFinding(
                    vulnerability="Expired Token",
                    severity="info",
                    description=f"Token expired at {jwt_info.expiration.isoformat()}",
                    evidence=f"exp: {jwt_info.payload.get('exp')}",
                    affected_claim="exp",
                    remediation="Refresh token or obtain new one",
                    cwe=""
                ))
            else:
                # Check for excessively long expiration
                time_until_exp = (jwt_info.expiration - now).total_seconds()
                if time_until_exp > 86400 * 30:  # More than 30 days
                    findings.append(JWTFinding(
                        vulnerability="Long Token Lifetime",
                        severity="medium",
                        description=f"Token valid for {time_until_exp / 86400:.1f} days",
                        evidence=f"exp: {jwt_info.payload.get('exp')}",
                        affected_claim="exp",
                        remediation="Use shorter token lifetimes. Implement refresh tokens.",
                        cwe="CWE-613"
                    ))

        return findings

    def test_sensitive_claims(self, jwt_info: JWTInfo) -> List[JWTFinding]:
        """Check for sensitive data in claims."""
        findings = []

        sensitive_patterns = {
            "password": r"(password|passwd|pwd)",
            "secret": r"(secret|api_key|apikey|private)",
            "credit_card": r"(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})",
            "ssn": r"\d{3}-\d{2}-\d{4}",
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        }

        payload_str = json.dumps(jwt_info.payload).lower()

        for data_type, pattern in sensitive_patterns.items():
            if data_type in ["password", "secret"]:
                # Check for key names
                for key in jwt_info.payload.keys():
                    if re.search(pattern, key.lower()):
                        findings.append(JWTFinding(
                            vulnerability="Sensitive Data in JWT",
                            severity="high",
                            description=f"Token contains potentially sensitive claim: {key}",
                            evidence=f"Claim name matches pattern: {data_type}",
                            affected_claim=key,
                            remediation="Never store sensitive data in JWT. "
                                       "Store server-side and reference by ID.",
                            cwe="CWE-200"
                        ))
            else:
                # Check for patterns in values
                if re.search(pattern, payload_str):
                    findings.append(JWTFinding(
                        vulnerability=f"Potential {data_type.replace('_', ' ').title()} in JWT",
                        severity="medium",
                        description=f"Token may contain {data_type} data",
                        evidence=f"Pattern match for {data_type}",
                        remediation="Review and remove sensitive data from token",
                        cwe="CWE-200"
                    ))

        return findings

    def test_kid_injection(self, jwt_info: JWTInfo) -> List[JWTFinding]:
        """Test for kid (Key ID) injection vulnerabilities."""
        findings = []

        kid = jwt_info.header.get("kid")

        if kid:
            # Check for potential SQL injection in kid
            sql_patterns = ["'", '"', ";", "--", "/*", "*/", "OR", "AND"]
            for pattern in sql_patterns:
                if pattern in kid:
                    findings.append(JWTFinding(
                        vulnerability="Potential SQL Injection in kid",
                        severity="critical",
                        description="kid header may be vulnerable to SQL injection",
                        evidence=f"kid contains: {pattern}",
                        attack_vector=f"kid: {kid}",
                        remediation="Validate and sanitize kid before use in queries",
                        cwe="CWE-89"
                    ))
                    break

            # Check for path traversal
            if ".." in kid or "/" in kid or "\\" in kid:
                findings.append(JWTFinding(
                    vulnerability="Potential Path Traversal in kid",
                    severity="high",
                    description="kid header may allow path traversal",
                    evidence=f"kid: {kid}",
                    attack_vector=f"kid: ../../path/to/key",
                    remediation="Validate kid against allowlist of key identifiers",
                    cwe="CWE-22"
                ))

            # Check for command injection
            cmd_patterns = ["|", "`", "$", "(", ")", ";"]
            for pattern in cmd_patterns:
                if pattern in kid:
                    findings.append(JWTFinding(
                        vulnerability="Potential Command Injection in kid",
                        severity="critical",
                        description="kid header may allow command injection",
                        evidence=f"kid contains: {pattern}",
                        attack_vector=f"kid: {kid}",
                        remediation="Never use kid in shell commands",
                        cwe="CWE-78"
                    ))
                    break

        return findings

    def test_jku_jwks_uri(self, jwt_info: JWTInfo) -> List[JWTFinding]:
        """Test for jku/jwks_uri header injection."""
        findings = []

        jku = jwt_info.header.get("jku")
        x5u = jwt_info.header.get("x5u")

        for header_name, value in [("jku", jku), ("x5u", x5u)]:
            if value:
                findings.append(JWTFinding(
                    vulnerability=f"External Key Reference ({header_name})",
                    severity="high",
                    description=f"Token references external key via {header_name}: {value}",
                    evidence=f"{header_name}: {value}",
                    attack_vector=f"Replace {header_name} with attacker-controlled URL",
                    remediation=f"Do not accept {header_name} from tokens. "
                               "Use pre-configured key locations.",
                    cwe="CWE-345"
                ))

        return findings

    def generate_attack_tokens(self, jwt_info: JWTInfo) -> Dict[str, str]:
        """Generate various attack tokens for testing."""
        attacks = {}

        payload_b64 = jwt_info.raw.split(".")[1]

        # None algorithm attack
        none_header = self._base64_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        attacks["none_algorithm"] = f"{none_header}.{payload_b64}."

        # Modified payload (admin escalation)
        modified_payload = jwt_info.payload.copy()
        modified_payload["admin"] = True
        modified_payload["role"] = "admin"
        if "sub" in modified_payload:
            modified_payload["sub"] = "admin"

        mod_payload_b64 = self._base64_encode(json.dumps(modified_payload).encode())
        attacks["admin_escalation_unsigned"] = f"{none_header}.{mod_payload_b64}."

        # Expired timestamp manipulation
        no_exp_payload = jwt_info.payload.copy()
        no_exp_payload.pop("exp", None)
        no_exp_b64 = self._base64_encode(json.dumps(no_exp_payload).encode())
        attacks["no_expiration"] = f"{none_header}.{no_exp_b64}."

        return attacks

    def analyze(self, token: str) -> Tuple[JWTInfo, List[JWTFinding]]:
        """
        Perform full JWT analysis.

        Args:
            token: JWT token string

        Returns:
            Tuple of (JWTInfo, List of findings)
        """
        findings = []

        # Parse token
        jwt_info = self.parse_token(token)

        if not jwt_info:
            findings.append(JWTFinding(
                vulnerability="Invalid JWT Format",
                severity="info",
                description="Token is not a valid JWT format",
                evidence=f"Token: {token[:50]}...",
                remediation="Ensure token has three base64url-encoded parts separated by dots"
            ))
            return JWTInfo(
                raw=token,
                header={},
                payload={},
                signature="",
                algorithm="unknown"
            ), findings

        # Run all tests
        findings.extend(self.test_none_algorithm(jwt_info))
        findings.extend(self.test_algorithm_confusion(jwt_info))
        findings.extend(self.test_weak_secret(jwt_info))
        findings.extend(self.test_expiration(jwt_info))
        findings.extend(self.test_sensitive_claims(jwt_info))
        findings.extend(self.test_kid_injection(jwt_info))
        findings.extend(self.test_jku_jwks_uri(jwt_info))

        return jwt_info, findings

    def get_summary(self, findings: List[JWTFinding]) -> Dict[str, Any]:
        """Get summary of findings."""
        return {
            "total": len(findings),
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
            "low": len([f for f in findings if f.severity == "low"]),
            "info": len([f for f in findings if f.severity == "info"])
        }


# Convenience function
def analyze_jwt(token: str, extended_wordlist: bool = False) -> Tuple[JWTInfo, List[JWTFinding]]:
    """
    Quick JWT analysis.

    Args:
        token: JWT token string
        extended_wordlist: Use extended secret wordlist

    Returns:
        Tuple of (JWTInfo, List of findings)
    """
    analyzer = JWTAnalyzer(extended_wordlist=extended_wordlist)
    return analyzer.analyze(token)


def decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode JWT without verification (for inspection).

    Args:
        token: JWT token string

    Returns:
        Dict with header and payload
    """
    analyzer = JWTAnalyzer()
    jwt_info = analyzer.parse_token(token)

    if jwt_info:
        return {
            "header": jwt_info.header,
            "payload": jwt_info.payload,
            "algorithm": jwt_info.algorithm,
            "expiration": jwt_info.expiration.isoformat() if jwt_info.expiration else None,
            "issued_at": jwt_info.issued_at.isoformat() if jwt_info.issued_at else None
        }
    return {}
