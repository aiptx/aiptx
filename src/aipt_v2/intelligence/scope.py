"""
AIPT Scope Enforcement Module

Ensures all testing activities stay within authorized scope.
This is CRITICAL for legitimate penetration testing.

Features:
- Domain/IP allowlist enforcement
- Path exclusion patterns
- Rate limiting
- Out-of-scope detection and alerting
- Audit logging for compliance
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


class ScopeDecision(Enum):
    """Decision about whether a target is in scope"""
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED = "excluded"
    RATE_LIMITED = "rate_limited"
    UNKNOWN = "unknown"


@dataclass
class ScopeViolation:
    """Record of an attempted scope violation"""
    timestamp: datetime
    url: str
    reason: str
    decision: ScopeDecision
    tool: str
    blocked: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "url": self.url,
            "reason": self.reason,
            "decision": self.decision.value,
            "tool": self.tool,
            "blocked": self.blocked,
        }


@dataclass
class ScopeConfig:
    """Configuration defining authorized scope"""
    # Included targets (allowlist)
    included_domains: list[str] = field(default_factory=list)
    included_ips: list[str] = field(default_factory=list)  # CIDR notation supported
    included_urls: list[str] = field(default_factory=list)  # Specific URL patterns

    # Excluded targets (denylist - always blocked even if in allowlist)
    excluded_domains: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)  # Regex patterns
    excluded_keywords: list[str] = field(default_factory=list)  # e.g., "production", "prod"

    # Rate limiting
    max_requests_per_second: int = 10
    max_requests_per_minute: int = 300

    # Safety settings
    block_out_of_scope: bool = True  # If False, just log but don't block
    allow_subdomains: bool = True  # Allow *.example.com if example.com is in scope

    # Audit settings
    log_all_requests: bool = True
    alert_on_violation: bool = True

    # Authorization metadata
    engagement_id: str = ""
    client_name: str = ""
    authorized_by: str = ""
    start_date: str = ""
    end_date: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScopeConfig":
        """Create config from dictionary"""
        return cls(
            included_domains=data.get("included_domains", []),
            included_ips=data.get("included_ips", []),
            included_urls=data.get("included_urls", []),
            excluded_domains=data.get("excluded_domains", []),
            excluded_paths=data.get("excluded_paths", []),
            excluded_keywords=data.get("excluded_keywords", []),
            max_requests_per_second=data.get("max_requests_per_second", 10),
            max_requests_per_minute=data.get("max_requests_per_minute", 300),
            block_out_of_scope=data.get("block_out_of_scope", True),
            allow_subdomains=data.get("allow_subdomains", True),
            engagement_id=data.get("engagement_id", ""),
            client_name=data.get("client_name", ""),
            authorized_by=data.get("authorized_by", ""),
            start_date=data.get("start_date", ""),
            end_date=data.get("end_date", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "included_domains": self.included_domains,
            "included_ips": self.included_ips,
            "included_urls": self.included_urls,
            "excluded_domains": self.excluded_domains,
            "excluded_paths": self.excluded_paths,
            "excluded_keywords": self.excluded_keywords,
            "max_requests_per_second": self.max_requests_per_second,
            "max_requests_per_minute": self.max_requests_per_minute,
            "block_out_of_scope": self.block_out_of_scope,
            "allow_subdomains": self.allow_subdomains,
            "engagement_id": self.engagement_id,
            "client_name": self.client_name,
            "authorized_by": self.authorized_by,
            "start_date": self.start_date,
            "end_date": self.end_date,
        }


class ScopeEnforcer:
    """
    Enforces authorized testing scope.

    This class is essential for legitimate penetration testing.
    It ensures all requests stay within the authorized scope
    and logs all activity for compliance and audit purposes.

    Example:
        config = ScopeConfig(
            included_domains=["example.com", "api.example.com"],
            excluded_paths=["/admin/delete", "/production/*"],
            client_name="ACME Corp",
            engagement_id="PT-2024-001",
        )
        enforcer = ScopeEnforcer(config)

        # Check before making requests
        if enforcer.is_in_scope("https://example.com/api/users"):
            # Safe to test
            pass
        else:
            # Do not test - out of scope
            pass
    """

    def __init__(self, config: ScopeConfig):
        self.config = config
        self._violations: list[ScopeViolation] = []
        self._request_timestamps: list[datetime] = []

        # Compile regex patterns for performance
        self._excluded_path_patterns = [
            re.compile(p) for p in config.excluded_paths
        ]

        # Parse IP networks
        self._included_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for ip_str in config.included_ips:
            try:
                network = ipaddress.ip_network(ip_str, strict=False)
                self._included_networks.append(network)
            except ValueError as e:
                logger.warning(f"Invalid IP/CIDR in scope: {ip_str}: {e}")

        logger.info(
            f"Scope enforcer initialized: {len(config.included_domains)} domains, "
            f"{len(self._included_networks)} IP ranges"
        )

    def is_in_scope(
        self,
        url: str,
        tool: str = "unknown",
    ) -> bool:
        """
        Check if a URL is within authorized scope.

        Args:
            url: URL to check
            tool: Name of tool making the request (for logging)

        Returns:
            True if in scope, False otherwise
        """
        decision, reason = self._check_scope(url)

        # Log the check
        if self.config.log_all_requests:
            logger.debug(f"Scope check: {url} -> {decision.value} ({reason})")

        # Record violation if out of scope
        if decision in [ScopeDecision.OUT_OF_SCOPE, ScopeDecision.EXCLUDED]:
            violation = ScopeViolation(
                timestamp=datetime.utcnow(),
                url=url,
                reason=reason,
                decision=decision,
                tool=tool,
                blocked=self.config.block_out_of_scope,
            )
            self._violations.append(violation)

            if self.config.alert_on_violation:
                logger.warning(
                    f"SCOPE VIOLATION: {tool} attempted to access {url} - {reason}"
                )

            return not self.config.block_out_of_scope

        return decision == ScopeDecision.IN_SCOPE

    def _check_scope(self, url: str) -> tuple[ScopeDecision, str]:
        """Internal scope checking logic"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0].lower()  # Remove port
            path = parsed.path

            # Check excluded keywords first (highest priority)
            url_lower = url.lower()
            for keyword in self.config.excluded_keywords:
                if keyword.lower() in url_lower:
                    return ScopeDecision.EXCLUDED, f"Contains excluded keyword: {keyword}"

            # Check excluded paths
            for pattern in self._excluded_path_patterns:
                if pattern.search(path):
                    return ScopeDecision.EXCLUDED, f"Matches excluded path pattern"

            # Check excluded domains
            for domain in self.config.excluded_domains:
                if self._domain_matches(host, domain):
                    return ScopeDecision.EXCLUDED, f"Domain explicitly excluded: {domain}"

            # Check if IP is in scope
            try:
                ip = ipaddress.ip_address(host)
                for network in self._included_networks:
                    if ip in network:
                        return ScopeDecision.IN_SCOPE, f"IP in authorized range: {network}"
            except ValueError:
                pass  # Not an IP address, check domain

            # Check included domains
            for domain in self.config.included_domains:
                if self._domain_matches(host, domain):
                    return ScopeDecision.IN_SCOPE, f"Domain in scope: {domain}"

            # Check included URL patterns
            for url_pattern in self.config.included_urls:
                if url.startswith(url_pattern) or re.match(url_pattern, url):
                    return ScopeDecision.IN_SCOPE, f"URL matches pattern: {url_pattern}"

            return ScopeDecision.OUT_OF_SCOPE, "Not in authorized scope"

        except Exception as e:
            logger.error(f"Error checking scope for {url}: {e}")
            return ScopeDecision.UNKNOWN, f"Error: {str(e)}"

    def _domain_matches(self, host: str, scope_domain: str) -> bool:
        """Check if a host matches a scope domain"""
        scope_domain = scope_domain.lower()

        # Exact match
        if host == scope_domain:
            return True

        # Subdomain match (if allowed)
        if self.config.allow_subdomains:
            if host.endswith("." + scope_domain):
                return True

        # Wildcard match
        if scope_domain.startswith("*."):
            base = scope_domain[2:]
            if host == base or host.endswith("." + base):
                return True

        return False

    def check_rate_limit(self) -> bool:
        """
        Check if request rate is within limits.

        Returns:
            True if within limits, False if rate limited
        """
        now = datetime.utcnow()

        # Clean old timestamps
        one_minute_ago = now.timestamp() - 60
        self._request_timestamps = [
            ts for ts in self._request_timestamps
            if ts.timestamp() > one_minute_ago
        ]

        # Check per-minute limit
        if len(self._request_timestamps) >= self.config.max_requests_per_minute:
            logger.warning("Rate limit exceeded (per minute)")
            return False

        # Check per-second limit
        one_second_ago = now.timestamp() - 1
        recent = sum(1 for ts in self._request_timestamps if ts.timestamp() > one_second_ago)
        if recent >= self.config.max_requests_per_second:
            logger.warning("Rate limit exceeded (per second)")
            return False

        # Record this request
        self._request_timestamps.append(now)
        return True

    def record_request(self, url: str, tool: str = "unknown") -> None:
        """Record a request for rate limiting and audit"""
        self._request_timestamps.append(datetime.utcnow())

    def get_violations(self) -> list[ScopeViolation]:
        """Get all recorded scope violations"""
        return self._violations.copy()

    def get_violation_count(self) -> int:
        """Get count of scope violations"""
        return len(self._violations)

    def get_audit_log(self) -> dict[str, Any]:
        """Get audit log for compliance reporting"""
        return {
            "engagement_id": self.config.engagement_id,
            "client_name": self.config.client_name,
            "authorized_by": self.config.authorized_by,
            "start_date": self.config.start_date,
            "end_date": self.config.end_date,
            "scope_config": self.config.to_dict(),
            "violations": [v.to_dict() for v in self._violations],
            "violation_count": len(self._violations),
            "generated_at": datetime.utcnow().isoformat(),
        }

    def validate_scope_config(self) -> list[str]:
        """
        Validate scope configuration for common issues.

        Returns:
            List of validation warnings/errors
        """
        issues = []

        # Check for empty scope
        if not self.config.included_domains and not self.config.included_ips:
            issues.append("WARNING: No targets in scope - nothing will be tested")

        # Check for overly broad scope
        for domain in self.config.included_domains:
            if domain in ["*", "*.com", "*.net", "*.org"]:
                issues.append(f"DANGER: Overly broad scope: {domain}")

        # Check for missing engagement metadata
        if not self.config.engagement_id:
            issues.append("INFO: No engagement ID set - recommended for tracking")

        if not self.config.authorized_by:
            issues.append("WARNING: No authorizer specified - document authorization")

        # Check for common sensitive paths not excluded
        sensitive_paths = ["/admin", "/backup", "/production", "/prod"]
        for path in sensitive_paths:
            excluded = any(
                path in ep for ep in self.config.excluded_paths
            )
            if not excluded:
                issues.append(f"INFO: Consider excluding {path} if not in scope")

        return issues

    def generate_scope_summary(self) -> str:
        """Generate human-readable scope summary"""
        lines = [
            "=" * 60,
            "AUTHORIZED TESTING SCOPE",
            "=" * 60,
            f"Engagement ID: {self.config.engagement_id or 'Not specified'}",
            f"Client: {self.config.client_name or 'Not specified'}",
            f"Authorized by: {self.config.authorized_by or 'Not specified'}",
            f"Period: {self.config.start_date} to {self.config.end_date}",
            "",
            "IN-SCOPE TARGETS:",
        ]

        for domain in self.config.included_domains:
            subdomain_note = " (including subdomains)" if self.config.allow_subdomains else ""
            lines.append(f"  • {domain}{subdomain_note}")

        for ip in self.config.included_ips:
            lines.append(f"  • {ip}")

        if self.config.excluded_paths:
            lines.append("")
            lines.append("EXCLUDED PATHS:")
            for path in self.config.excluded_paths:
                lines.append(f"  ✗ {path}")

        if self.config.excluded_keywords:
            lines.append("")
            lines.append("EXCLUDED KEYWORDS:")
            for keyword in self.config.excluded_keywords:
                lines.append(f"  ✗ {keyword}")

        lines.append("")
        lines.append(f"Rate Limit: {self.config.max_requests_per_second}/sec, {self.config.max_requests_per_minute}/min")
        lines.append(f"Block Out-of-Scope: {'Yes' if self.config.block_out_of_scope else 'No (log only)'}")
        lines.append("=" * 60)

        return "\n".join(lines)


def create_scope_from_target(target: str) -> ScopeConfig:
    """
    Create a basic scope config from a single target URL.

    This is a convenience function for simple scans where
    the scope is just the target domain.
    """
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0]

    return ScopeConfig(
        included_domains=[host],
        allow_subdomains=True,
        excluded_keywords=["production", "prod", "live"],
    )
