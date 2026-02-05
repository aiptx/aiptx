"""
PAT Request Generator

Generates HTTP requests with payloads injected at various injection points.
Handles URL parameters, POST body, headers, cookies, and more.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterator, Optional
from copy import deepcopy

from .config import (
    InjectionPoint,
    VulnerabilityType,
    PATScanConfig,
    EnhancedPATScanConfig,
)
from .payload_parser import ParsedPayload

# Lazy imports for mutation engines to avoid circular imports
_sqli_mutator = None
_xss_mutator = None
_cmd_mutator = None
_http_smuggling_mutator = None
_prototype_pollution_mutator = None
_cache_poison_mutator = None
_hpp_mutator = None
_ssrf_mutator = None
_ssti_mutator = None
_nosql_mutator = None
_cors_mutator = None
_race_condition_mutator = None


def _get_sqli_mutator(dbms: str = "mysql"):
    """Lazy-load SQLi mutator."""
    global _sqli_mutator
    if _sqli_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.sqli_mutations import SQLiMutator
            _sqli_mutator = SQLiMutator
        except ImportError:
            return None
    return _sqli_mutator(dbms)


def _get_xss_mutator(context: str = "html_body"):
    """Lazy-load XSS mutator."""
    global _xss_mutator
    if _xss_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.xss_mutations import XSSMutator
            _xss_mutator = XSSMutator
        except ImportError:
            return None
    return _xss_mutator(context)


def _get_cmd_mutator(os_type: str = "linux"):
    """Lazy-load CMD mutator."""
    global _cmd_mutator
    if _cmd_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.cmd_mutations import CMDMutator
            _cmd_mutator = CMDMutator
        except ImportError:
            return None
    return _cmd_mutator(os_type)


def _get_http_smuggling_mutator():
    """Lazy-load HTTP Smuggling mutator."""
    global _http_smuggling_mutator
    if _http_smuggling_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import HTTPSmugglingMutator
            _http_smuggling_mutator = HTTPSmugglingMutator
        except ImportError:
            return None
    return _http_smuggling_mutator()


def _get_prototype_pollution_mutator():
    """Lazy-load Prototype Pollution mutator."""
    global _prototype_pollution_mutator
    if _prototype_pollution_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import PrototypePollutionMutator
            _prototype_pollution_mutator = PrototypePollutionMutator
        except ImportError:
            return None
    return _prototype_pollution_mutator()


def _get_cache_poison_mutator():
    """Lazy-load Cache Poison mutator."""
    global _cache_poison_mutator
    if _cache_poison_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import CachePoisonMutator
            _cache_poison_mutator = CachePoisonMutator
        except ImportError:
            return None
    return _cache_poison_mutator()


def _get_hpp_mutator():
    """Lazy-load HTTP Parameter Pollution mutator."""
    global _hpp_mutator
    if _hpp_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import HPPMutator
            _hpp_mutator = HPPMutator
        except ImportError:
            return None
    return _hpp_mutator()


def _get_ssrf_mutator():
    """Lazy-load SSRF mutator."""
    global _ssrf_mutator
    if _ssrf_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import SSRFMutator
            _ssrf_mutator = SSRFMutator
        except ImportError:
            return None
    return _ssrf_mutator()


def _get_ssti_mutator(engine: str = "jinja2"):
    """Lazy-load SSTI mutator."""
    global _ssti_mutator
    if _ssti_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import SSTIMutator
            _ssti_mutator = SSTIMutator
        except ImportError:
            return None
    return _ssti_mutator(engine)


def _get_nosql_mutator():
    """Lazy-load NoSQL Injection mutator."""
    global _nosql_mutator
    if _nosql_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import NoSQLMutator
            _nosql_mutator = NoSQLMutator
        except ImportError:
            return None
    return _nosql_mutator()


def _get_cors_mutator():
    """Lazy-load CORS mutator."""
    global _cors_mutator
    if _cors_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import CORSMutator
            _cors_mutator = CORSMutator
        except ImportError:
            return None
    return _cors_mutator()


def _get_race_condition_mutator():
    """Lazy-load Race Condition mutator."""
    global _race_condition_mutator
    if _race_condition_mutator is None:
        try:
            from aipt_v2.exploitation.mutations.specialized_mutations import RaceConditionMutator
            _race_condition_mutator = RaceConditionMutator
        except ImportError:
            return None
    return _race_condition_mutator()

logger = logging.getLogger(__name__)


@dataclass
class InjectionRequest:
    """An HTTP request with a payload injected."""
    # Request details
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: dict[str, str] = field(default_factory=dict)

    # Injection metadata
    payload: Optional[ParsedPayload] = None
    injection_point: InjectionPoint = InjectionPoint.URL_PARAM
    parameter_name: str = ""              # Which parameter was injected
    original_value: str = ""              # Value that was replaced

    # Request settings
    timeout: float = 30.0
    follow_redirects: bool = True

    def to_curl(self) -> str:
        """Generate curl command for this request."""
        parts = ["curl", "-X", self.method]

        # Add headers
        for key, value in self.headers.items():
            parts.extend(["-H", f"'{key}: {value}'"])

        # Add cookies
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            parts.extend(["-H", f"'Cookie: {cookie_str}'"])

        # Add body
        if self.body:
            parts.extend(["-d", f"'{self.body}'"])

        # Add URL (quoted)
        parts.append(f"'{self.url}'")

        return " ".join(parts)


class RequestGenerator:
    """
    Generates HTTP requests with payloads injected.

    Supports multiple injection points:
    - URL parameters (?id=PAYLOAD)
    - URL path segments (/api/PAYLOAD/endpoint)
    - POST form data (field=PAYLOAD)
    - POST JSON body ({"field": "PAYLOAD"})
    - HTTP headers (X-Custom: PAYLOAD)
    - Cookies (session=PAYLOAD)
    - XML body injection
    """

    # Encoding functions for different contexts
    ENCODINGS = {
        "url": lambda x: urllib.parse.quote(x, safe=""),
        "url_plus": lambda x: urllib.parse.quote_plus(x),
        "html": lambda x: x.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"),
        "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x, safe=""), safe=""),
        "none": lambda x: x,
    }

    def __init__(self, config: Optional[PATScanConfig] = None):
        """
        Initialize request generator.

        Args:
            config: Scanner configuration
        """
        self.config = config or PATScanConfig()

    def generate_requests(
        self,
        target_url: str,
        payloads: list[ParsedPayload],
        parameters: Optional[list[str]] = None,
        injection_points: Optional[list[InjectionPoint]] = None,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Iterator[InjectionRequest]:
        """
        Generate injection requests for all combinations.

        Args:
            target_url: Base URL to test
            payloads: List of payloads to inject
            parameters: Parameter names to test (auto-detected if None)
            injection_points: Which injection points to test
            method: HTTP method
            headers: Base headers
            cookies: Base cookies
            body: Request body template

        Yields:
            InjectionRequest objects
        """
        # Use config defaults if not specified
        injection_points = injection_points or self.config.injection_points
        headers = headers or self.config.headers.copy()
        cookies = cookies or self.config.cookies.copy()

        # Detect parameters if not specified
        if not parameters:
            parameters = self._detect_parameters(target_url, body)

        logger.debug(f"Generating requests for {len(payloads)} payloads × {len(parameters)} params × {len(injection_points)} points")

        for payload in payloads:
            for param in parameters:
                for injection_point in injection_points:
                    # Skip incompatible combinations
                    if not self._is_compatible(injection_point, method, body):
                        continue

                    request = self._generate_single_request(
                        target_url=target_url,
                        payload=payload,
                        parameter=param,
                        injection_point=injection_point,
                        method=method,
                        headers=headers,
                        cookies=cookies,
                        body=body,
                    )

                    if request:
                        yield request

    def _generate_single_request(
        self,
        target_url: str,
        payload: ParsedPayload,
        parameter: str,
        injection_point: InjectionPoint,
        method: str,
        headers: dict[str, str],
        cookies: dict[str, str],
        body: Optional[str],
    ) -> Optional[InjectionRequest]:
        """Generate a single injection request."""
        # Deep copy to avoid mutation
        headers = deepcopy(headers)
        cookies = deepcopy(cookies)

        # Determine encoding based on context
        encoding = self._get_encoding(injection_point, payload.category)
        encoded_payload = self.ENCODINGS.get(encoding, self.ENCODINGS["none"])(payload.content)

        original_value = ""
        new_url = target_url
        new_body = body

        if injection_point == InjectionPoint.URL_PARAM:
            new_url, original_value = self._inject_url_param(target_url, parameter, encoded_payload)

        elif injection_point == InjectionPoint.URL_PATH:
            new_url, original_value = self._inject_url_path(target_url, parameter, encoded_payload)

        elif injection_point == InjectionPoint.POST_FORM:
            if body:
                new_body, original_value = self._inject_form_data(body, parameter, encoded_payload)
            else:
                new_body = f"{parameter}={encoded_payload}"
                original_value = ""
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        elif injection_point == InjectionPoint.POST_JSON:
            if body:
                new_body, original_value = self._inject_json(body, parameter, payload.content)
            else:
                new_body = json.dumps({parameter: payload.content})
                original_value = ""
            headers["Content-Type"] = "application/json"

        elif injection_point == InjectionPoint.HEADER:
            original_value = headers.get(parameter, "")
            headers[parameter] = payload.content

        elif injection_point == InjectionPoint.COOKIE:
            original_value = cookies.get(parameter, "")
            cookies[parameter] = encoded_payload

        elif injection_point == InjectionPoint.XML_BODY:
            if body:
                new_body, original_value = self._inject_xml(body, parameter, payload.content)
            headers["Content-Type"] = "application/xml"

        return InjectionRequest(
            method=method,
            url=new_url,
            headers=headers,
            body=new_body,
            cookies=cookies,
            payload=payload,
            injection_point=injection_point,
            parameter_name=parameter,
            original_value=original_value,
            timeout=self.config.executor.timeout,
            follow_redirects=self.config.executor.follow_redirects,
        )

    def _detect_parameters(self, url: str, body: Optional[str]) -> list[str]:
        """Auto-detect parameters from URL and body."""
        parameters = []

        # URL query parameters
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            parameters.extend(params.keys())

        # Form body parameters
        if body:
            # Try URL-encoded form
            try:
                form_params = urllib.parse.parse_qs(body)
                parameters.extend(form_params.keys())
            except Exception:
                pass

            # Try JSON body
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    parameters.extend(json_data.keys())
            except Exception:
                pass

        # Remove duplicates while preserving order
        seen = set()
        unique_params = []
        for param in parameters:
            if param not in seen:
                seen.add(param)
                unique_params.append(param)

        return unique_params

    def _inject_url_param(
        self,
        url: str,
        param: str,
        payload: str,
    ) -> tuple[str, str]:
        """Inject payload into URL parameter."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        original_value = params.get(param, [""])[0]
        params[param] = [payload]

        # Rebuild query string
        query = urllib.parse.urlencode(params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query,
            parsed.fragment,
        ))

        return new_url, original_value

    def _inject_url_path(
        self,
        url: str,
        param: str,
        payload: str,
    ) -> tuple[str, str]:
        """Inject payload into URL path segment."""
        parsed = urllib.parse.urlparse(url)
        path_segments = parsed.path.split("/")

        original_value = ""
        for i, segment in enumerate(path_segments):
            if segment == param or segment == f"{{{param}}}":
                original_value = segment
                path_segments[i] = payload
                break

        new_path = "/".join(path_segments)
        new_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            new_path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))

        return new_url, original_value

    def _inject_form_data(
        self,
        body: str,
        param: str,
        payload: str,
    ) -> tuple[str, str]:
        """Inject payload into form data."""
        params = urllib.parse.parse_qs(body, keep_blank_values=True)
        original_value = params.get(param, [""])[0]
        params[param] = [payload]
        new_body = urllib.parse.urlencode(params, doseq=True)
        return new_body, original_value

    def _inject_json(
        self,
        body: str,
        param: str,
        payload: str,
    ) -> tuple[str, str]:
        """Inject payload into JSON body."""
        try:
            data = json.loads(body)
            original_value = str(data.get(param, ""))

            # Handle nested paths (e.g., "user.name")
            if "." in param:
                self._set_nested_value(data, param.split("."), payload)
            else:
                data[param] = payload

            return json.dumps(data), original_value
        except json.JSONDecodeError:
            return body, ""

    def _set_nested_value(self, data: dict, path: list[str], value: str) -> None:
        """Set a nested value in a dictionary."""
        for key in path[:-1]:
            if key not in data:
                data[key] = {}
            data = data[key]
        data[path[-1]] = value

    def _inject_xml(
        self,
        body: str,
        param: str,
        payload: str,
    ) -> tuple[str, str]:
        """Inject payload into XML body."""
        # Simple regex-based injection for XML elements
        pattern = rf"<{param}>([^<]*)</{param}>"
        match = re.search(pattern, body)

        if match:
            original_value = match.group(1)
            new_body = re.sub(pattern, f"<{param}>{payload}</{param}>", body)
            return new_body, original_value

        # Try attribute injection
        attr_pattern = rf'{param}="([^"]*)"'
        attr_match = re.search(attr_pattern, body)

        if attr_match:
            original_value = attr_match.group(1)
            new_body = re.sub(attr_pattern, f'{param}="{payload}"', body)
            return new_body, original_value

        return body, ""

    def _is_compatible(
        self,
        injection_point: InjectionPoint,
        method: str,
        body: Optional[str],
    ) -> bool:
        """Check if injection point is compatible with method/body."""
        # GET requests typically don't have body injection points
        if method == "GET" and injection_point in (
            InjectionPoint.POST_BODY,
            InjectionPoint.POST_FORM,
            InjectionPoint.POST_JSON,
            InjectionPoint.XML_BODY,
            InjectionPoint.MULTIPART,
        ):
            return False

        # Body injection points need a body or will create one
        if injection_point in (InjectionPoint.POST_JSON, InjectionPoint.XML_BODY):
            # These can be created from scratch
            return True

        return True

    def _get_encoding(
        self,
        injection_point: InjectionPoint,
        vuln_type: VulnerabilityType,
    ) -> str:
        """Determine appropriate encoding for context."""
        # URL parameters need URL encoding
        if injection_point == InjectionPoint.URL_PARAM:
            return "url"

        # URL path needs more aggressive encoding
        if injection_point == InjectionPoint.URL_PATH:
            return "url"

        # Form data needs URL encoding
        if injection_point == InjectionPoint.POST_FORM:
            return "url_plus"

        # JSON and headers typically don't need encoding
        return "none"

    def generate_baseline_requests(
        self,
        target_url: str,
        count: int = 3,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> list[InjectionRequest]:
        """
        Generate baseline requests without payloads.

        Used for comparison in response analysis.

        Args:
            target_url: Target URL
            count: Number of baseline requests
            method: HTTP method
            headers: Request headers
            body: Request body

        Returns:
            List of baseline requests
        """
        requests = []
        for _ in range(count):
            requests.append(InjectionRequest(
                method=method,
                url=target_url,
                headers=headers or {},
                body=body,
                timeout=self.config.executor.timeout,
                follow_redirects=self.config.executor.follow_redirects,
            ))
        return requests

    def create_time_based_request(
        self,
        base_request: InjectionRequest,
        delay_seconds: int = 5,
    ) -> InjectionRequest:
        """
        Create a time-based injection request variant.

        Modifies the payload to include time delay commands.

        Args:
            base_request: Original request
            delay_seconds: Desired delay in seconds

        Returns:
            Modified request with time-based payload
        """
        time_payloads = {
            VulnerabilityType.SQL_INJECTION: {
                "mysql": f"' OR SLEEP({delay_seconds})-- ",
                "postgresql": f"'; SELECT pg_sleep({delay_seconds});-- ",
                "mssql": f"'; WAITFOR DELAY '00:00:{delay_seconds:02d}';-- ",
                "default": f"' OR SLEEP({delay_seconds})-- ",
            },
            VulnerabilityType.COMMAND_INJECTION: {
                "default": f"; sleep {delay_seconds}",
            },
        }

        if base_request.payload:
            vuln_type = base_request.payload.category
            subcategory = base_request.payload.subcategory or "default"

            time_payload_map = time_payloads.get(vuln_type, {})
            time_payload = time_payload_map.get(subcategory, time_payload_map.get("default", ""))

            if time_payload:
                # Create new request with time-based payload
                new_request = deepcopy(base_request)
                if new_request.payload:
                    new_request.payload = ParsedPayload(
                        content=time_payload,
                        category=new_request.payload.category,
                        subcategory=new_request.payload.subcategory,
                        technique=new_request.payload.technique,
                    )
                return new_request

        return base_request


class EnhancedRequestGenerator(RequestGenerator):
    """
    Enhanced request generator with mutation engine integration.

    Generates 20x more payload variants by applying mutation engines:
    - SQLi: whitespace, case, comments, encoding mutations
    - XSS: tag alternatives, event handlers, encoding mutations
    - CMD: separators, space alternatives, encoding mutations

    Example:
        config = EnhancedPATScanConfig(
            enable_mutations=True,
            max_mutations_per_payload=10,
        )
        generator = EnhancedRequestGenerator(config)
        requests = list(generator.generate_mutated_requests(
            target_url="https://example.com/api",
            payloads=payloads,
            parameters=["id"],
        ))
    """

    def __init__(self, config: EnhancedPATScanConfig):
        """
        Initialize enhanced request generator.

        Args:
            config: Enhanced scanner configuration with mutation settings
        """
        super().__init__(config)
        self.enhanced_config = config
        self._seen_payloads: set[str] = set()  # For deduplication

    def generate_mutated_requests(
        self,
        target_url: str,
        payloads: list[ParsedPayload],
        parameters: Optional[list[str]] = None,
        injection_points: Optional[list[InjectionPoint]] = None,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Iterator[InjectionRequest]:
        """
        Generate injection requests with mutation variants.

        For each payload, generates:
        1. Original payload request
        2. Up to max_mutations_per_payload mutated variants

        Args:
            target_url: Base URL to test
            payloads: List of payloads to inject
            parameters: Parameter names to test
            injection_points: Which injection points to test
            method: HTTP method
            headers: Base headers
            cookies: Base cookies
            body: Request body template

        Yields:
            InjectionRequest objects (original + mutations)
        """
        if not self.enhanced_config.enable_mutations:
            # Fall back to base behavior
            yield from self.generate_requests(
                target_url=target_url,
                payloads=payloads,
                parameters=parameters,
                injection_points=injection_points,
                method=method,
                headers=headers,
                cookies=cookies,
                body=body,
            )
            return

        # Clear deduplication set for new scan
        self._seen_payloads.clear()

        for payload in payloads:
            # Get all variants (original + mutations)
            all_variants = self._get_payload_variants(payload)

            for variant_payload in all_variants:
                # Deduplicate if enabled
                if self.enhanced_config.deduplicate_payloads:
                    payload_hash = self._hash_payload(variant_payload.content)
                    if payload_hash in self._seen_payloads:
                        continue
                    self._seen_payloads.add(payload_hash)

                # Generate requests for this variant
                yield from self.generate_requests(
                    target_url=target_url,
                    payloads=[variant_payload],
                    parameters=parameters,
                    injection_points=injection_points,
                    method=method,
                    headers=headers,
                    cookies=cookies,
                    body=body,
                )

    def _get_payload_variants(self, payload: ParsedPayload) -> list[ParsedPayload]:
        """
        Generate mutated variants of a payload.

        Args:
            payload: Original payload

        Returns:
            List of payload variants (original first, then mutations)
        """
        variants = [payload]  # Always include original

        vuln_type = payload.category
        max_mutations = self.enhanced_config.max_mutations_per_payload

        # Get mutator based on vulnerability type
        mutations = self._mutate_for_vuln_type(payload.content, vuln_type)

        # Add mutated variants (up to limit)
        for mutated_content, mutation_name in mutations[:max_mutations]:
            variant = ParsedPayload(
                content=mutated_content,
                category=payload.category,
                subcategory=payload.subcategory,
                technique=payload.technique,
                source_file=f"{payload.source_file}+{mutation_name}" if payload.source_file else mutation_name,
                tags=payload.tags + [mutation_name] if payload.tags else [mutation_name],
            )
            variants.append(variant)

        logger.debug(
            f"Generated {len(variants)} variants for payload "
            f"({payload.category.value}): {payload.content[:50]}..."
        )

        return variants

    def _mutate_for_vuln_type(
        self,
        payload_content: str,
        vuln_type: VulnerabilityType,
    ) -> list[tuple[str, str]]:
        """
        Apply appropriate mutations based on vulnerability type.

        Supports all 64 vulnerability types with intelligent mutator mapping:
        - Core injection: SQLi, XSS, CMD use dedicated mutators
        - Protocol attacks: HTTP Smuggling, HPP, Cache Poisoning
        - Client-side: Prototype Pollution, CORS, DOM Clobbering
        - Server-side: SSRF, SSTI, NoSQL, XXE, LDAP, XPath
        - File attacks: LFI, RFI, Path Traversal, File Upload
        - Business logic: Race Condition, IDOR, Mass Assignment

        Args:
            payload_content: Original payload content
            vuln_type: Vulnerability type

        Returns:
            List of (mutated_payload, mutation_name) tuples
        """
        mutations = []

        # ===== CORE INJECTION TYPES =====
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            mutator = _get_sqli_mutator(self.enhanced_config.mutation_dbms)
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.XSS:
            mutator = _get_xss_mutator(self.enhanced_config.mutation_xss_context)
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            mutator = _get_cmd_mutator(self.enhanced_config.mutation_os)
            if mutator:
                mutations = mutator.mutate(payload_content)

        # ===== NOSQL & DATABASE VARIANTS =====
        elif vuln_type == VulnerabilityType.NOSQL_INJECTION:
            mutator = _get_nosql_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.LDAP_INJECTION:
            # LDAP uses SQLi-like encoding mutations
            mutator = _get_sqli_mutator("generic")
            if mutator:
                all_mutations = mutator.mutate(payload_content)
                mutations = [m for m in all_mutations if "encode" in m[1].lower()]

        elif vuln_type == VulnerabilityType.XPATH_INJECTION:
            # XPath uses SQLi-like mutations
            mutator = _get_sqli_mutator("generic")
            if mutator:
                all_mutations = mutator.mutate(payload_content)
                mutations = [m for m in all_mutations if "encode" in m[1].lower() or "comment" in m[1].lower()]

        # ===== TEMPLATE INJECTION =====
        elif vuln_type == VulnerabilityType.SSTI:
            mutator = _get_ssti_mutator(getattr(self.enhanced_config, 'mutation_template_engine', 'jinja2'))
            if mutator:
                mutations = mutator.mutate(payload_content)

        # ===== PROTOCOL ATTACKS =====
        elif vuln_type == VulnerabilityType.HTTP_SMUGGLING:
            mutator = _get_http_smuggling_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.HPP:
            mutator = _get_hpp_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.CACHE_POISONING:
            mutator = _get_cache_poison_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.DNS_REBINDING:
            # DNS rebinding uses SSRF mutations for IP obfuscation
            mutator = _get_ssrf_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        # ===== CLIENT-SIDE ATTACKS =====
        elif vuln_type == VulnerabilityType.PROTOTYPE_POLLUTION:
            mutator = _get_prototype_pollution_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.CORS_MISCONFIG:
            mutator = _get_cors_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.DOM_CLOBBERING:
            # DOM Clobbering uses XSS mutations
            mutator = _get_xss_mutator("html_body")
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.CLICKJACKING:
            # Clickjacking doesn't need payload mutations (header-based)
            mutations = []

        elif vuln_type == VulnerabilityType.TABNABBING:
            # Tabnabbing uses XSS-like mutations
            mutator = _get_xss_mutator("html_attr")
            if mutator:
                all_mutations = mutator.mutate(payload_content)
                mutations = [m for m in all_mutations if "encode" in m[1].lower()]

        elif vuln_type == VulnerabilityType.CLIENT_PATH_TRAVERSAL:
            mutations = self._path_traversal_mutations(payload_content)

        # ===== SERVER-SIDE ATTACKS =====
        elif vuln_type == VulnerabilityType.SSRF:
            mutator = _get_ssrf_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.XXE:
            # XXE uses encoding mutations
            import urllib.parse
            mutations = [
                (urllib.parse.quote(payload_content, safe=""), "url_encode"),
                (payload_content.replace("SYSTEM", "PUBLIC"), "public_entity"),
                (payload_content.replace("file://", "php://filter/read=convert.base64-encode/resource="), "php_filter"),
            ]

        # ===== FILE & PATH ATTACKS =====
        elif vuln_type in (VulnerabilityType.LFI, VulnerabilityType.PATH_TRAVERSAL):
            mutations = self._path_traversal_mutations(payload_content)

        elif vuln_type == VulnerabilityType.RFI:
            # RFI uses SSRF-like mutations
            mutator = _get_ssrf_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.FILE_UPLOAD:
            # File upload uses encoding mutations
            import urllib.parse
            mutations = [
                (payload_content + "%00.jpg", "null_byte_ext"),
                (payload_content.replace(".php", ".pHp"), "case_variation"),
                (payload_content.replace(".php", ".php5"), "alt_extension"),
                (payload_content.replace(".php", ".phtml"), "phtml_ext"),
                (payload_content + "/.jpg", "path_confusion"),
            ]

        elif vuln_type == VulnerabilityType.ZIP_SLIP:
            mutations = self._path_traversal_mutations(payload_content)

        # ===== DATA & INJECTION VARIANTS =====
        elif vuln_type == VulnerabilityType.CSV_INJECTION:
            # CSV injection uses encoding to bypass filters
            mutations = [
                (payload_content.replace("=", "\t="), "tab_prefix"),
                (payload_content.replace("=", "'="), "quote_prefix"),
                ("'" + payload_content, "single_quote_prefix"),
                (payload_content.replace("+", "%2B"), "plus_encode"),
            ]

        elif vuln_type == VulnerabilityType.CRLF:
            import urllib.parse
            mutations = [
                (payload_content.replace("\r\n", "%0d%0a"), "percent_encode"),
                (payload_content.replace("\r\n", "%0D%0A"), "upper_percent"),
                (payload_content.replace("\r\n", "%%0d%%0a"), "double_percent"),
                (payload_content.replace("\r\n", "%E5%98%8A%E5%98%8D"), "unicode_crlf"),
            ]

        elif vuln_type == VulnerabilityType.OPEN_REDIRECT:
            mutator = _get_ssrf_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        # ===== INJECTION VARIANTS =====
        elif vuln_type == VulnerabilityType.LATEX_INJECTION:
            # LaTeX uses encoding mutations
            import urllib.parse
            mutations = [
                (urllib.parse.quote(payload_content, safe=""), "url_encode"),
                (payload_content.replace("\\", "\\\\"), "double_backslash"),
            ]

        elif vuln_type == VulnerabilityType.SSI_INJECTION:
            # SSI uses HTML encoding mutations
            mutator = _get_xss_mutator("html_body")
            if mutator:
                all_mutations = mutator.mutate(payload_content)
                mutations = [m for m in all_mutations if "encode" in m[1].lower()]

        elif vuln_type == VulnerabilityType.XSLT_INJECTION:
            # XSLT uses XML-like mutations
            import urllib.parse
            mutations = [
                (urllib.parse.quote(payload_content, safe=""), "url_encode"),
                (payload_content.replace("&", "&amp;"), "xml_entity"),
            ]

        elif vuln_type == VulnerabilityType.PROMPT_INJECTION:
            # Prompt injection uses various delimiters
            mutations = [
                (payload_content.replace("```", "'''"), "alt_code_block"),
                ("\n\n" + payload_content, "newline_prefix"),
                ("IGNORE PREVIOUS INSTRUCTIONS. " + payload_content, "override_prefix"),
                (payload_content.replace(" ", "\u00a0"), "nbsp_spaces"),
            ]

        elif vuln_type == VulnerabilityType.JAVA_RMI:
            # Java RMI uses serialization mutations
            import base64
            mutations = [
                (base64.b64encode(payload_content.encode()).decode(), "base64_encode"),
            ]

        elif vuln_type == VulnerabilityType.REGEX_DOS:
            # ReDoS pattern mutations
            mutations = [
                (payload_content + "a" * 100, "long_suffix"),
                (payload_content * 5, "pattern_repeat"),
            ]

        # ===== BUSINESS LOGIC =====
        elif vuln_type == VulnerabilityType.RACE_CONDITION:
            mutator = _get_race_condition_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.IDOR:
            # IDOR uses numeric/encoding variations
            mutations = [
                (payload_content + "1", "increment"),
                (str(int(payload_content) - 1) if payload_content.isdigit() else payload_content, "decrement"),
                (payload_content.zfill(10) if payload_content.isdigit() else payload_content, "zero_pad"),
            ]

        elif vuln_type == VulnerabilityType.MASS_ASSIGNMENT:
            # Mass assignment doesn't need payload mutations (structural)
            mutations = []

        elif vuln_type == VulnerabilityType.TYPE_JUGGLING:
            # Type juggling uses PHP-style comparisons
            mutations = [
                ("0", "zero_string"),
                ("0e123", "scientific_zero"),
                ("true", "bool_true"),
                ("[]", "empty_array"),
                ("null", "null_value"),
            ]

        elif vuln_type == VulnerabilityType.INSECURE_RANDOM:
            # Insecure randomness doesn't need mutations
            mutations = []

        elif vuln_type == VulnerabilityType.BUSINESS_LOGIC:
            # Business logic doesn't need standard mutations
            mutations = []

        # ===== AUTHENTICATION & ACCESS =====
        elif vuln_type == VulnerabilityType.CSRF:
            # CSRF doesn't need payload mutations (token-based)
            mutations = []

        elif vuln_type == VulnerabilityType.OAUTH_MISCONFIG:
            # OAuth uses URL encoding mutations
            mutator = _get_ssrf_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.SAML_INJECTION:
            # SAML uses XML encoding mutations
            import urllib.parse
            mutations = [
                (urllib.parse.quote(payload_content, safe=""), "url_encode"),
                (payload_content.replace("&", "&amp;"), "xml_entity"),
            ]

        elif vuln_type == VulnerabilityType.ACCOUNT_TAKEOVER:
            # Account takeover doesn't need standard mutations
            mutations = []

        # ===== MISCONFIGURATION =====
        elif vuln_type == VulnerabilityType.GIT_EXPOSURE:
            mutations = self._path_traversal_mutations(payload_content)

        elif vuln_type == VulnerabilityType.HIDDEN_PARAMS:
            # Hidden params don't need mutations
            mutations = []

        elif vuln_type == VulnerabilityType.ADMIN_INTERFACE:
            mutations = self._path_traversal_mutations(payload_content)

        elif vuln_type == VulnerabilityType.VIRTUAL_HOST:
            # Virtual host uses domain mutations
            mutations = [
                (payload_content.replace(".", "-"), "dash_subdomain"),
                ("admin." + payload_content, "admin_prefix"),
                ("internal." + payload_content, "internal_prefix"),
            ]

        elif vuln_type == VulnerabilityType.REVERSE_PROXY:
            mutator = _get_http_smuggling_mutator()
            if mutator:
                mutations = mutator.mutate(payload_content)

        elif vuln_type == VulnerabilityType.GWT_VULN:
            # GWT uses base64/serialization mutations
            import base64
            mutations = [
                (base64.b64encode(payload_content.encode()).decode(), "base64_encode"),
            ]

        elif vuln_type == VulnerabilityType.DEPENDENCY_CONFUSION:
            # Dependency confusion doesn't need standard mutations
            mutations = []

        elif vuln_type == VulnerabilityType.CVE_EXPLOITS:
            # CVE exploits use encoding mutations
            import urllib.parse
            mutations = [
                (urllib.parse.quote(payload_content, safe=""), "url_encode"),
            ]

        elif vuln_type == VulnerabilityType.API_KEY_LEAK:
            # API key leak doesn't need mutations
            mutations = []

        elif vuln_type == VulnerabilityType.SECRETS_EXPOSURE:
            # Secrets exposure doesn't need mutations
            mutations = []

        # ===== FALLBACK =====
        else:
            # For any unhandled types, apply basic encoding mutations
            import urllib.parse
            mutations = [
                (urllib.parse.quote(payload_content, safe=""), "url_encode"),
                (urllib.parse.quote(urllib.parse.quote(payload_content, safe=""), safe=""), "double_url_encode"),
            ]

        return mutations

    def _path_traversal_mutations(self, payload: str) -> list[tuple[str, str]]:
        """Generate path traversal mutations."""
        mutations = []

        # URL encoding
        import urllib.parse
        mutations.append((urllib.parse.quote(payload, safe=""), "url_encode"))

        # Double URL encoding
        mutations.append((urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""), "double_url_encode"))

        # Dot alternatives
        if ".." in payload:
            mutations.append((payload.replace("..", "..%c0%af"), "unicode_dot"))
            mutations.append((payload.replace("..", "..%252f"), "double_encoded_slash"))
            mutations.append((payload.replace("..", "....//"), "double_dot_slash"))
            mutations.append((payload.replace("..", "..;/"), "semicolon_bypass"))

        # Null byte
        mutations.append((payload + "%00", "null_byte"))

        return mutations

    def _ssrf_mutations(self, payload: str) -> list[tuple[str, str]]:
        """Generate SSRF mutations."""
        mutations = []
        import urllib.parse

        # URL encoding
        mutations.append((urllib.parse.quote(payload, safe=":/"), "url_encode"))

        # IP obfuscation if localhost or internal IP
        if "127.0.0.1" in payload:
            mutations.append((payload.replace("127.0.0.1", "2130706433"), "decimal_ip"))
            mutations.append((payload.replace("127.0.0.1", "0x7f000001"), "hex_ip"))
            mutations.append((payload.replace("127.0.0.1", "0177.0.0.1"), "octal_ip"))
            mutations.append((payload.replace("127.0.0.1", "127.1"), "short_ip"))

        if "localhost" in payload:
            mutations.append((payload.replace("localhost", "localtest.me"), "dns_rebind"))
            mutations.append((payload.replace("localhost", "[::1]"), "ipv6_localhost"))

        # Protocol variations
        if payload.startswith("http://"):
            mutations.append((payload.replace("http://", "http://test@"), "userinfo_bypass"))

        return mutations

    def _hash_payload(self, payload: str) -> str:
        """Generate hash for payload deduplication."""
        import hashlib
        return hashlib.md5(payload.encode()).hexdigest()

    def get_mutation_stats(self) -> dict:
        """Get statistics about mutations applied."""
        return {
            "unique_payloads_generated": len(self._seen_payloads),
            "deduplication_enabled": self.enhanced_config.deduplicate_payloads,
            "max_mutations_per_payload": self.enhanced_config.max_mutations_per_payload,
        }
