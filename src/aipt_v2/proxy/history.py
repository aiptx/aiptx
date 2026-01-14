"""
AIPT Proxy History

Traffic history management and analysis.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from .interceptor import InterceptedRequest, InterceptedResponse


@dataclass
class HistoryEntry:
    """A request/response pair"""
    request: InterceptedRequest
    response: Optional[InterceptedResponse] = None

    # Analysis
    has_parameters: bool = False
    has_cookies: bool = False
    has_auth: bool = False
    interesting: bool = False
    notes: str = ""

    # Security indicators
    security_flags: list[str] = field(default_factory=list)

    def analyze(self) -> None:
        """Analyze entry for security-relevant features"""
        self.has_parameters = bool(
            self.request.query_params or
            self.request.is_form or
            self.request.is_json
        )
        self.has_cookies = bool(self.request.cookies)
        self.has_auth = "authorization" in [h.lower() for h in self.request.headers.keys()]

        # Check for interesting patterns
        self._check_security_flags()

    def _check_security_flags(self) -> None:
        """Check for security-relevant patterns"""
        flags = []

        # Request analysis
        url_lower = self.request.url.lower()

        # Potential admin endpoints
        if any(p in url_lower for p in ["/admin", "/manage", "/dashboard", "/config"]):
            flags.append("admin_endpoint")

        # API endpoints
        if "/api/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
            flags.append("api_endpoint")

        # Authentication endpoints
        if any(p in url_lower for p in ["/login", "/auth", "/signin", "/token"]):
            flags.append("auth_endpoint")

        # File operations
        if any(p in url_lower for p in ["/upload", "/download", "/file", "/export"]):
            flags.append("file_operation")

        # Potential SQL injection points (numeric IDs)
        if re.search(r"/\d+(/|$|\?)", url_lower):
            flags.append("numeric_id")

        # Check request body for interesting patterns
        body_text = self.request.get_body_text().lower()
        if body_text:
            if "password" in body_text or "passwd" in body_text:
                flags.append("contains_password")
            if "token" in body_text or "key" in body_text:
                flags.append("contains_secret")

        # Response analysis
        if self.response:
            resp_body = self.response.get_body_text().lower()

            # Error messages that might leak info
            if "error" in resp_body or "exception" in resp_body:
                flags.append("error_response")

            # Stack traces
            if "traceback" in resp_body or "stack trace" in resp_body:
                flags.append("stack_trace")

            # SQL errors
            if "sql" in resp_body and ("syntax" in resp_body or "error" in resp_body):
                flags.append("sql_error")

            # Interesting status codes
            if self.response.status_code in [401, 403]:
                flags.append("auth_required")
            elif self.response.status_code >= 500:
                flags.append("server_error")

        self.security_flags = flags
        self.interesting = len(flags) > 0

    def to_dict(self) -> dict:
        return {
            "request": self.request.to_dict(),
            "response": self.response.to_dict() if self.response else None,
            "has_parameters": self.has_parameters,
            "has_cookies": self.has_cookies,
            "has_auth": self.has_auth,
            "interesting": self.interesting,
            "security_flags": self.security_flags,
            "notes": self.notes,
        }


class ProxyHistory:
    """
    Proxy traffic history manager.

    Features:
    - Traffic storage and retrieval
    - Filtering and search
    - Security analysis
    - Export capabilities

    Example:
        history = ProxyHistory()
        history.add(request, response)

        # Find interesting entries
        interesting = history.get_interesting()

        # Search
        api_calls = history.search(path_contains="/api/")
    """

    def __init__(self):
        self._entries: list[HistoryEntry] = []
        self._by_host: dict[str, list[HistoryEntry]] = {}

    def add(
        self,
        request: InterceptedRequest,
        response: Optional[InterceptedResponse] = None,
    ) -> HistoryEntry:
        """Add request/response to history"""
        entry = HistoryEntry(request=request, response=response)
        entry.analyze()

        self._entries.append(entry)

        # Index by host
        host = request.host
        if host not in self._by_host:
            self._by_host[host] = []
        self._by_host[host].append(entry)

        return entry

    def get_all(self) -> list[HistoryEntry]:
        """Get all entries"""
        return self._entries.copy()

    def get_by_host(self, host: str) -> list[HistoryEntry]:
        """Get entries for a specific host"""
        return self._by_host.get(host, [])

    def get_hosts(self) -> list[str]:
        """Get all unique hosts"""
        return list(self._by_host.keys())

    def get_interesting(self) -> list[HistoryEntry]:
        """Get entries flagged as interesting"""
        return [e for e in self._entries if e.interesting]

    def get_with_parameters(self) -> list[HistoryEntry]:
        """Get entries with parameters (potential injection points)"""
        return [e for e in self._entries if e.has_parameters]

    def get_authenticated(self) -> list[HistoryEntry]:
        """Get entries with authentication"""
        return [e for e in self._entries if e.has_auth]

    def get_by_flag(self, flag: str) -> list[HistoryEntry]:
        """Get entries with specific security flag"""
        return [e for e in self._entries if flag in e.security_flags]

    def search(
        self,
        method: Optional[str] = None,
        host_contains: Optional[str] = None,
        path_contains: Optional[str] = None,
        status_code: Optional[int] = None,
        content_type: Optional[str] = None,
        body_contains: Optional[str] = None,
    ) -> list[HistoryEntry]:
        """Search history with filters"""
        results = []

        for entry in self._entries:
            # Method filter
            if method and entry.request.method != method.upper():
                continue

            # Host filter
            if host_contains and host_contains.lower() not in entry.request.host.lower():
                continue

            # Path filter
            if path_contains and path_contains.lower() not in entry.request.path.lower():
                continue

            # Status code filter
            if status_code and entry.response and entry.response.status_code != status_code:
                continue

            # Content type filter
            if content_type:
                req_ct = entry.request.content_type.lower()
                resp_ct = entry.response.content_type.lower() if entry.response else ""
                if content_type.lower() not in req_ct and content_type.lower() not in resp_ct:
                    continue

            # Body content filter
            if body_contains:
                body_lower = body_contains.lower()
                req_body = entry.request.get_body_text().lower()
                resp_body = entry.response.get_body_text().lower() if entry.response else ""
                if body_lower not in req_body and body_lower not in resp_body:
                    continue

            results.append(entry)

        return results

    def get_unique_endpoints(self) -> list[dict]:
        """Get unique endpoints (method + path, no query params)"""
        seen = set()
        endpoints = []

        for entry in self._entries:
            parsed = urlparse(entry.request.url)
            key = (entry.request.method, parsed.netloc, parsed.path)

            if key not in seen:
                seen.add(key)
                endpoints.append({
                    "method": entry.request.method,
                    "host": parsed.netloc,
                    "path": parsed.path,
                    "count": 1,
                })
            else:
                # Increment count
                for ep in endpoints:
                    if (ep["method"], ep["host"], ep["path"]) == key:
                        ep["count"] += 1
                        break

        return sorted(endpoints, key=lambda x: x["count"], reverse=True)

    def get_parameter_map(self) -> dict[str, list[str]]:
        """Get map of endpoints to their parameters"""
        param_map = {}

        for entry in self._entries:
            if not entry.has_parameters:
                continue

            endpoint = f"{entry.request.method} {entry.request.path}"
            if endpoint not in param_map:
                param_map[endpoint] = []

            # Extract parameter names
            for key in entry.request.query_params.keys():
                if key not in param_map[endpoint]:
                    param_map[endpoint].append(key)

            # From form/JSON body
            if entry.request.is_json:
                body_json = entry.request.get_body_json()
                if body_json and isinstance(body_json, dict):
                    for key in body_json.keys():
                        if key not in param_map[endpoint]:
                            param_map[endpoint].append(key)

        return param_map

    def get_statistics(self) -> dict:
        """Get history statistics"""
        methods = {}
        status_codes = {}
        content_types = {}

        for entry in self._entries:
            # Methods
            method = entry.request.method
            methods[method] = methods.get(method, 0) + 1

            # Status codes
            if entry.response:
                code = entry.response.status_code
                status_codes[code] = status_codes.get(code, 0) + 1

                # Content types
                ct = entry.response.content_type.split(";")[0]
                content_types[ct] = content_types.get(ct, 0) + 1

        return {
            "total_entries": len(self._entries),
            "unique_hosts": len(self._by_host),
            "interesting_count": len(self.get_interesting()),
            "with_parameters": len(self.get_with_parameters()),
            "methods": methods,
            "status_codes": status_codes,
            "content_types": content_types,
            "security_flags": self._get_flag_counts(),
        }

    def _get_flag_counts(self) -> dict[str, int]:
        """Count security flags"""
        counts = {}
        for entry in self._entries:
            for flag in entry.security_flags:
                counts[flag] = counts.get(flag, 0) + 1
        return counts

    def export_json(self, filepath: str) -> bool:
        """Export history to JSON"""
        try:
            data = {
                "exported_at": datetime.utcnow().isoformat(),
                "statistics": self.get_statistics(),
                "entries": [e.to_dict() for e in self._entries],
            }
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception:
            return False

    def clear(self) -> None:
        """Clear all history"""
        self._entries.clear()
        self._by_host.clear()

    def __len__(self) -> int:
        return len(self._entries)
