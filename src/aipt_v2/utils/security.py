"""
AIPTX Security Utilities

Provides functions for handling sensitive data safely in logs and outputs:
- Path masking for SSH keys, credentials files
- Error message sanitization
- API key redaction
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


# Patterns that indicate sensitive file paths
SENSITIVE_PATH_PATTERNS = [
    r"\.pem$",
    r"\.key$",
    r"id_rsa",
    r"id_ed25519",
    r"id_ecdsa",
    r"id_dsa",
    r"\.ppk$",
    r"credentials",
    r"\.env$",
    r"secrets?\.ya?ml$",
    r"apikey",
    r"token",
]

# Compiled patterns for efficiency
_SENSITIVE_PATH_RE = re.compile("|".join(SENSITIVE_PATH_PATTERNS), re.IGNORECASE)


def mask_path(path: str | Path | None, show_filename: bool = True) -> str:
    """
    Mask a potentially sensitive file path.

    For sensitive files (SSH keys, credentials), shows only the filename
    with a masked directory prefix to protect full path exposure.

    Args:
        path: The file path to mask.
        show_filename: If True, show the filename. If False, show just ***.

    Returns:
        Masked path string.

    Examples:
        >>> mask_path("/Users/john/Downloads/vps.pem")
        '~/.../vps.pem'
        >>> mask_path("/home/user/.ssh/id_rsa")
        '~/.../id_rsa'
        >>> mask_path("/var/log/app.log")
        '/var/log/app.log'  # Not sensitive, returned as-is
    """
    if path is None:
        return "<not set>"

    path_str = str(path)

    # Check if path contains sensitive patterns
    if not _SENSITIVE_PATH_RE.search(path_str):
        return path_str

    # Extract filename
    try:
        filename = Path(path_str).name
    except Exception:
        filename = path_str.split("/")[-1] if "/" in path_str else path_str

    if show_filename:
        return f"~/.../{ filename}"
    else:
        return "~/.../***"


def mask_api_key(key: str | None, visible_chars: int = 4) -> str:
    """
    Mask an API key, showing only the first few characters.

    Args:
        key: The API key to mask.
        visible_chars: Number of characters to show.

    Returns:
        Masked key string.

    Examples:
        >>> mask_api_key("sk-abc123456789")
        'sk-a****'
        >>> mask_api_key(None)
        '<not set>'
    """
    if not key:
        return "<not set>"

    if len(key) <= visible_chars:
        return "****"

    return key[:visible_chars] + "****"


def sanitize_error_message(
    error: str | Exception,
    max_length: int = 500,
    redact_paths: bool = True,
) -> str:
    """
    Sanitize an error message for user display.

    This function:
    - Truncates long messages
    - Removes full file paths
    - Strips internal implementation details
    - Redacts potential secrets

    Args:
        error: The error or error message to sanitize.
        max_length: Maximum length of the output.
        redact_paths: If True, mask sensitive paths.

    Returns:
        Sanitized error message.
    """
    message = str(error)

    # Remove ANSI color codes
    message = re.sub(r"\x1b\[[0-9;]*m", "", message)

    # Redact full file paths (keep just filename)
    if redact_paths:
        # Match Unix paths
        message = re.sub(
            r"(/[a-zA-Z0-9_.\-/]+/)([\w.\-]+\.(pem|key|env|json|yaml|yml))",
            r"~/.../\2",
            message,
        )
        # Match Windows paths
        message = re.sub(
            r"([A-Za-z]:\\[^:\s]+\\)([\w.\-]+\.(pem|key|env|json|yaml|yml))",
            r"...\\\2",
            message,
        )

    # Redact potential API keys (common patterns)
    message = re.sub(
        r"(sk-|api[-_]?key[=:]\s*|token[=:]\s*|bearer\s+)([a-zA-Z0-9\-_]{10,})",
        r"\1****",
        message,
        flags=re.IGNORECASE,
    )

    # Redact IP addresses (except localhost and private ranges optionally)
    # This helps avoid exposing internal infrastructure
    message = re.sub(
        r"\b(?!127\.0\.0\.1|localhost)(\d{1,3}\.){3}\d{1,3}(:\d+)?\b",
        "[REDACTED_IP]",
        message,
    )

    # Remove stack traces (Python specific)
    message = re.sub(
        r'File ".*?", line \d+, in \w+',
        "[stack frame]",
        message,
    )

    # Truncate if too long
    if len(message) > max_length:
        message = message[:max_length - 3] + "..."

    return message.strip()


def redact_dict_secrets(data: dict[str, Any], keys_to_redact: list[str] | None = None) -> dict[str, Any]:
    """
    Create a copy of a dict with sensitive values redacted.

    Args:
        data: Dictionary to redact.
        keys_to_redact: List of key patterns to redact. Default includes common patterns.

    Returns:
        New dictionary with sensitive values masked.
    """
    if keys_to_redact is None:
        keys_to_redact = [
            "key", "token", "secret", "password", "credential",
            "auth", "api_key", "apikey", "access_key", "private",
        ]

    result = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Check if this key should be redacted
        should_redact = any(pattern in key_lower for pattern in keys_to_redact)

        if should_redact and isinstance(value, str) and value:
            result[key] = mask_api_key(value)
        elif isinstance(value, dict):
            result[key] = redact_dict_secrets(value, keys_to_redact)
        elif isinstance(value, list):
            result[key] = [
                redact_dict_secrets(item, keys_to_redact) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def is_path_sensitive(path: str | Path) -> bool:
    """
    Check if a path points to a potentially sensitive file.

    Args:
        path: The path to check.

    Returns:
        True if the path appears to be sensitive.
    """
    return bool(_SENSITIVE_PATH_RE.search(str(path)))
