"""
Request Obfuscator

Mutates HTTP requests to evade detection:
- Header manipulation
- Parameter encoding
- Request body obfuscation
- HTTP method alternatives

Usage:
    from aipt_v2.evasion import RequestObfuscator

    obfuscator = RequestObfuscator()
    modified = obfuscator.obfuscate(request)
"""

import random
import string
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ObfuscationConfig:
    """Configuration for request obfuscation."""
    encode_parameters: bool = True
    randomize_case: bool = True
    add_junk_headers: bool = True
    add_junk_parameters: bool = False
    pad_content_length: bool = False
    use_http_methods_override: bool = False


@dataclass
class ObfuscatedRequest:
    """Obfuscated HTTP request."""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    params: Dict[str, str]
    modifications: List[str]


class RequestObfuscator:
    """
    HTTP Request Obfuscator.

    Applies various obfuscation techniques to HTTP requests
    to evade detection and bypass security controls.
    """

    # Junk headers that are typically ignored
    JUNK_HEADERS = [
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
        "X-Client-IP", "CF-Connecting-IP", "True-Client-IP",
        "X-Custom-Header", "X-Debug", "X-Request-ID",
        "X-Correlation-ID", "X-Trace-ID"
    ]

    # Content-Type variations
    CONTENT_TYPES = [
        "application/json",
        "application/x-www-form-urlencoded",
        "text/plain",
        "application/xml",
        "multipart/form-data"
    ]

    def __init__(self, config: Optional[ObfuscationConfig] = None):
        """Initialize obfuscator."""
        self.config = config or ObfuscationConfig()

    def _random_string(self, length: int = 8) -> str:
        """Generate random string."""
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def _random_ip(self) -> str:
        """Generate random IP address."""
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def encode_parameter(self, value: str, encoding: str = "url") -> str:
        """
        Encode parameter value.

        Args:
            value: Original value
            encoding: Encoding type (url, double_url, unicode)

        Returns:
            Encoded value
        """
        if encoding == "url":
            return urllib.parse.quote(value, safe="")
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")
        elif encoding == "unicode":
            return "".join(f"%u00{ord(c):02x}" if c.isalpha() else c for c in value)
        return value

    def randomize_header_case(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Randomize header name case."""
        new_headers = {}
        for name, value in headers.items():
            # Random case for header name
            new_name = "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in name
            )
            new_headers[new_name] = value
        return new_headers

    def add_junk_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Add junk/decoy headers."""
        new_headers = headers.copy()

        # Add random IP headers
        ip_headers = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP"]
        for header in random.sample(ip_headers, random.randint(1, 2)):
            new_headers[header] = self._random_ip()

        # Add random custom headers
        for _ in range(random.randint(1, 3)):
            header_name = f"X-{self._random_string(6)}"
            new_headers[header_name] = self._random_string(12)

        return new_headers

    def add_junk_parameters(self, params: Dict[str, str]) -> Dict[str, str]:
        """Add junk parameters to request."""
        new_params = params.copy()

        for _ in range(random.randint(1, 3)):
            param_name = self._random_string(6)
            new_params[param_name] = self._random_string(8)

        return new_params

    def obfuscate_url(self, url: str) -> str:
        """Obfuscate URL path."""
        # Add path segments that resolve to same path
        path_tricks = [
            "/./",      # Current directory
            "/../..",   # Parent then back
            "//",       # Double slash
        ]

        # Random insertion point
        if "/" in url:
            parts = url.split("/")
            if len(parts) > 2:
                insert_idx = random.randint(1, len(parts) - 1)
                trick = random.choice(path_tricks)
                parts.insert(insert_idx, trick.strip("/"))
                url = "/".join(parts)

        return url

    def use_method_override(
        self,
        method: str,
        headers: Dict[str, str]
    ) -> tuple:
        """
        Use HTTP method override headers.

        Some applications accept X-HTTP-Method-Override
        to change the actual method.
        """
        override_headers = [
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
            "_method"
        ]

        new_headers = headers.copy()

        # Use POST with override header
        header_name = random.choice(override_headers)
        new_headers[header_name] = method

        return "POST", new_headers

    def obfuscate(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        params: Dict[str, str] = None,
        body: str = None
    ) -> ObfuscatedRequest:
        """
        Obfuscate HTTP request.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            params: Query parameters
            body: Request body

        Returns:
            ObfuscatedRequest
        """
        headers = headers or {}
        params = params or {}
        modifications = []

        # Encode parameters
        if self.config.encode_parameters and params:
            encoded_params = {}
            for key, value in params.items():
                encoding = random.choice(["url", "double_url", "unicode"])
                encoded_params[key] = self.encode_parameter(value, encoding)
            params = encoded_params
            modifications.append("parameter_encoding")

        # Randomize header case
        if self.config.randomize_case:
            headers = self.randomize_header_case(headers)
            modifications.append("header_case_randomization")

        # Add junk headers
        if self.config.add_junk_headers:
            headers = self.add_junk_headers(headers)
            modifications.append("junk_headers_added")

        # Add junk parameters
        if self.config.add_junk_parameters:
            params = self.add_junk_parameters(params)
            modifications.append("junk_parameters_added")

        # Method override
        if self.config.use_http_methods_override and method in ["PUT", "DELETE", "PATCH"]:
            method, headers = self.use_method_override(method, headers)
            modifications.append("method_override")

        return ObfuscatedRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            params=params,
            modifications=modifications
        )


# Convenience function
def obfuscate_request(
    method: str,
    url: str,
    headers: Dict[str, str] = None,
    params: Dict[str, str] = None,
    body: str = None
) -> ObfuscatedRequest:
    """
    Obfuscate HTTP request.

    Args:
        method: HTTP method
        url: Request URL
        headers: Request headers
        params: Query parameters
        body: Request body

    Returns:
        ObfuscatedRequest
    """
    obfuscator = RequestObfuscator()
    return obfuscator.obfuscate(method, url, headers, params, body)
