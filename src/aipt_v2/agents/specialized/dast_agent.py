"""
AIPTX DAST Agent - Dynamic Application Security Testing

Tests running applications for vulnerabilities:
- SQL injection
- XSS (reflected, stored, DOM)
- SSRF
- Command injection
- Authentication bypasses
- Authorization flaws
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from aipt_v2.agents.specialized.base_specialized import (
    SpecializedAgent,
    AgentCapability,
    AgentConfig,
)
from aipt_v2.agents.shared.finding_repository import (
    Finding,
    FindingSeverity,
    VulnerabilityType,
    Evidence,
)

logger = logging.getLogger(__name__)


class DASTAgent(SpecializedAgent):
    """
    Dynamic Application Security Testing agent.

    Tests running applications for:
    - Injection vulnerabilities (SQL, XSS, Command)
    - Authentication/authorization flaws
    - Server-side vulnerabilities (SSRF, XXE)
    - Configuration issues
    """

    name = "DASTAgent"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._session = None
        self._discovered_endpoints: list[dict] = []

    def get_capabilities(self) -> list[AgentCapability]:
        return [
            AgentCapability.INJECTION_TESTING,
            AgentCapability.AUTH_TESTING,
            AgentCapability.XSS_TESTING,
            AgentCapability.FUZZING,
            AgentCapability.API_TESTING,
        ]

    async def run(self) -> dict[str, Any]:
        """Execute DAST testing."""
        await self.initialize()
        self._progress.status = "running"

        results = {
            "endpoints_tested": 0,
            "injection_tests": 0,
            "auth_tests": 0,
            "findings_count": 0,
            "success": True,
        }

        try:
            # Phase 1: Crawl/discover endpoints (20%)
            await self.update_progress("Discovering endpoints", 0)
            endpoints = await self._discover_endpoints()
            results["endpoints_tested"] = len(endpoints)

            # Phase 2: Test for SQL injection (40%)
            self.check_cancelled()
            await self.update_progress("Testing SQL injection", 20)
            await self._test_sql_injection(endpoints)
            results["injection_tests"] += len(endpoints)

            # Phase 3: Test for XSS (55%)
            self.check_cancelled()
            await self.update_progress("Testing XSS", 40)
            await self._test_xss(endpoints)

            # Phase 4: Test for SSRF (70%)
            self.check_cancelled()
            await self.update_progress("Testing SSRF", 55)
            await self._test_ssrf(endpoints)

            # Phase 5: Test authentication (85%)
            self.check_cancelled()
            await self.update_progress("Testing authentication", 70)
            await self._test_authentication(endpoints)
            results["auth_tests"] = len(endpoints)

            # Phase 6: Run external tools (100%)
            self.check_cancelled()
            await self.update_progress("Running external scanners", 85)
            await self._run_external_scanners()

            await self.update_progress("Complete", 100)
            results["findings_count"] = self._findings_count

        except asyncio.CancelledError:
            logger.info("DASTAgent cancelled")
            results["success"] = False
            results["error"] = "Cancelled"
        except Exception as e:
            logger.error(f"DASTAgent error: {e}", exc_info=True)
            results["success"] = False
            results["error"] = str(e)
        finally:
            if self._session:
                await self._session.close()
            await self.cleanup()

        return results

    async def _discover_endpoints(self) -> list[dict]:
        """Discover endpoints via crawling or from recon data."""
        endpoints = []

        # Get base URL
        base_url = self.target

        # Check for endpoints shared by ReconAgent
        try:
            from aipt_v2.agents.shared.message_bus import get_message_bus
            bus = get_message_bus()
            history = await bus.get_history(topic="coordination.*", limit=100)

            for msg in history:
                if msg.content and isinstance(msg.content, dict):
                    if "directories" in msg.content:
                        for path in msg.content.get("directories", [])[:50]:
                            endpoints.append({
                                "url": urljoin(base_url, path),
                                "method": "GET",
                                "params": [],
                            })
        except Exception:
            pass

        # Add base endpoint
        endpoints.append({
            "url": base_url,
            "method": "GET",
            "params": [],
        })

        # Try to crawl for more
        try:
            crawled = await self._crawl_target(base_url)
            endpoints.extend(crawled)
        except Exception as e:
            logger.warning(f"Crawling failed: {e}")

        return endpoints[:100]  # Limit to prevent overload

    async def _crawl_target(self, base_url: str) -> list[dict]:
        """Crawl target to discover endpoints."""
        endpoints = []

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, timeout=10) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        endpoints = self._extract_endpoints_from_html(html, base_url)
        except Exception as e:
            logger.warning(f"Crawl error: {e}")

        return endpoints

    def _extract_endpoints_from_html(self, html: str, base_url: str) -> list[dict]:
        """Extract endpoints from HTML content."""
        import re

        endpoints = []
        parsed_base = urlparse(base_url)

        # Find forms
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*'
        for match in re.finditer(form_pattern, html, re.IGNORECASE):
            action = match.group(1)
            if action:
                url = urljoin(base_url, action)
                if urlparse(url).netloc == parsed_base.netloc:
                    endpoints.append({
                        "url": url,
                        "method": "POST",
                        "params": self._extract_form_params(html, action),
                    })

        # Find links with parameters
        link_pattern = r'href=["\']([^"\']*\?[^"\']*)["\']'
        for match in re.finditer(link_pattern, html, re.IGNORECASE):
            url = urljoin(base_url, match.group(1))
            if urlparse(url).netloc == parsed_base.netloc:
                params = self._extract_url_params(url)
                endpoints.append({
                    "url": url.split("?")[0],
                    "method": "GET",
                    "params": params,
                })

        return endpoints

    def _extract_form_params(self, html: str, form_action: str) -> list[dict]:
        """Extract form parameters."""
        import re
        params = []

        # Find input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*'
        for match in re.finditer(input_pattern, html, re.IGNORECASE):
            params.append({
                "name": match.group(1),
                "type": "input",
            })

        return params

    def _extract_url_params(self, url: str) -> list[dict]:
        """Extract URL query parameters."""
        from urllib.parse import parse_qs, urlparse

        params = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        for name, values in query_params.items():
            params.append({
                "name": name,
                "type": "query",
                "value": values[0] if values else "",
            })

        return params

    async def _test_sql_injection(self, endpoints: list[dict]) -> None:
        """Test endpoints for SQL injection."""
        sqli_payloads = [
            ("'", "Single quote"),
            ("\"", "Double quote"),
            ("' OR '1'='1", "Boolean-based"),
            ("1' AND '1'='1", "Boolean-based AND"),
            ("1' WAITFOR DELAY '0:0:5'--", "Time-based MSSQL"),
            ("1' AND SLEEP(5)--", "Time-based MySQL"),
            ("1'; WAITFOR DELAY '0:0:5'--", "Stacked queries"),
            ("1 UNION SELECT NULL--", "UNION-based"),
        ]

        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"pg_query\(\) :",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"SQLite\/",
            r"sqlite_",
            r"sqlite3\.",
            r"Microsoft OLE DB Provider for SQL Server",
            r"ODBC SQL Server Driver",
            r"mssql_query\(\)",
            r"Unclosed quotation mark",
        ]

        import aiohttp
        import re

        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                self.check_cancelled()

                for param in endpoint.get("params", []):
                    for payload, description in sqli_payloads:
                        try:
                            # Build test request
                            test_url = endpoint["url"]
                            test_params = {param["name"]: payload}

                            async with session.get(
                                test_url,
                                params=test_params if endpoint["method"] == "GET" else None,
                                data=test_params if endpoint["method"] == "POST" else None,
                                timeout=10,
                                allow_redirects=False,
                            ) as resp:
                                body = await resp.text()

                                # Check for SQL errors
                                for pattern in error_patterns:
                                    if re.search(pattern, body, re.IGNORECASE):
                                        finding = Finding(
                                            vuln_type=VulnerabilityType.SQLI,
                                            title=f"SQL Injection in {param['name']}",
                                            description=f"SQL error detected using {description} payload",
                                            severity=FindingSeverity.CRITICAL,
                                            target=self.target,
                                            url=endpoint["url"],
                                            parameter=param["name"],
                                            payload=payload,
                                            evidence=Evidence(
                                                request=f"{endpoint['method']} {test_url}",
                                                response=body[:500],
                                            ),
                                            tags=["dast", "sqli"],
                                        )
                                        await self.add_finding(finding)
                                        break

                        except asyncio.TimeoutError:
                            # Timeout could indicate time-based SQLi
                            if "SLEEP" in payload or "WAITFOR" in payload:
                                finding = Finding(
                                    vuln_type=VulnerabilityType.SQLI,
                                    title=f"Time-based SQL Injection in {param['name']}",
                                    description="Request timed out with time-based payload",
                                    severity=FindingSeverity.CRITICAL,
                                    target=self.target,
                                    url=endpoint["url"],
                                    parameter=param["name"],
                                    payload=payload,
                                    tags=["dast", "sqli", "time-based"],
                                )
                                await self.add_finding(finding)
                        except Exception:
                            pass

    async def _test_xss(self, endpoints: list[dict]) -> None:
        """Test endpoints for XSS vulnerabilities."""
        xss_payloads = [
            ("<script>alert('XSS')</script>", "Basic script tag"),
            ("'\"><script>alert('XSS')</script>", "Quote escape + script"),
            ("<img src=x onerror=alert('XSS')>", "IMG onerror"),
            ("javascript:alert('XSS')", "JavaScript protocol"),
            ("<svg onload=alert('XSS')>", "SVG onload"),
            ("'\"><img src=x onerror=alert(1)>", "Quote escape + img"),
        ]

        import aiohttp

        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                self.check_cancelled()

                for param in endpoint.get("params", []):
                    for payload, description in xss_payloads:
                        try:
                            test_url = endpoint["url"]
                            test_params = {param["name"]: payload}

                            async with session.get(
                                test_url,
                                params=test_params if endpoint["method"] == "GET" else None,
                                data=test_params if endpoint["method"] == "POST" else None,
                                timeout=10,
                            ) as resp:
                                body = await resp.text()

                                # Check if payload is reflected
                                if payload in body:
                                    # Check if it's actually executable (not encoded)
                                    if "<script" in body or "onerror=" in body or "onload=" in body:
                                        finding = Finding(
                                            vuln_type=VulnerabilityType.XSS,
                                            title=f"Reflected XSS in {param['name']}",
                                            description=f"XSS payload reflected without encoding: {description}",
                                            severity=FindingSeverity.HIGH,
                                            target=self.target,
                                            url=endpoint["url"],
                                            parameter=param["name"],
                                            payload=payload,
                                            evidence=Evidence(
                                                request=f"{endpoint['method']} {test_url}",
                                                response=body[:500],
                                            ),
                                            tags=["dast", "xss", "reflected"],
                                        )
                                        await self.add_finding(finding)
                                        break

                        except Exception:
                            pass

    async def _test_ssrf(self, endpoints: list[dict]) -> None:
        """Test endpoints for SSRF vulnerabilities."""
        # Use callback server if available
        ssrf_payloads = [
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
            ("http://metadata.google.internal/", "GCP metadata"),
            ("http://localhost:22", "Local SSH"),
            ("http://127.0.0.1:80", "Local web"),
            ("file:///etc/passwd", "File protocol"),
        ]

        url_params = ["url", "uri", "link", "redirect", "return", "next",
                      "callback", "fetch", "load", "src", "href"]

        import aiohttp

        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                self.check_cancelled()

                for param in endpoint.get("params", []):
                    # Only test likely URL parameters
                    if not any(u in param["name"].lower() for u in url_params):
                        continue

                    for payload, description in ssrf_payloads:
                        try:
                            test_url = endpoint["url"]
                            test_params = {param["name"]: payload}

                            async with session.get(
                                test_url,
                                params=test_params,
                                timeout=10,
                                allow_redirects=False,
                            ) as resp:
                                body = await resp.text()

                                # Check for SSRF indicators
                                ssrf_indicators = [
                                    "ami-id", "instance-id",  # AWS
                                    "computeMetadata",  # GCP
                                    "root:x:0:0",  # /etc/passwd
                                    "SSH-2.0",  # SSH banner
                                ]

                                for indicator in ssrf_indicators:
                                    if indicator in body:
                                        finding = Finding(
                                            vuln_type=VulnerabilityType.SSRF,
                                            title=f"SSRF in {param['name']}",
                                            description=f"SSRF to {description} confirmed",
                                            severity=FindingSeverity.CRITICAL,
                                            target=self.target,
                                            url=endpoint["url"],
                                            parameter=param["name"],
                                            payload=payload,
                                            evidence=Evidence(
                                                response=body[:500],
                                            ),
                                            tags=["dast", "ssrf"],
                                        )
                                        await self.add_finding(finding)
                                        break

                        except Exception:
                            pass

    async def _test_authentication(self, endpoints: list[dict]) -> None:
        """Test authentication mechanisms."""
        # Test for common auth bypasses
        bypass_headers = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
        ]

        import aiohttp

        async with aiohttp.ClientSession() as session:
            # Find admin/protected endpoints
            admin_paths = ["/admin", "/dashboard", "/api/admin", "/management"]

            for path in admin_paths:
                self.check_cancelled()
                test_url = urljoin(self.target, path)

                for header_name, header_value in bypass_headers:
                    try:
                        async with session.get(
                            test_url,
                            headers={header_name: header_value},
                            timeout=10,
                        ) as resp:
                            if resp.status == 200:
                                body = await resp.text()

                                # Check if we actually got admin content
                                if any(word in body.lower() for word in
                                       ["admin", "dashboard", "management", "settings"]):
                                    finding = Finding(
                                        vuln_type=VulnerabilityType.AUTH_BYPASS,
                                        title=f"Authentication bypass via {header_name}",
                                        description=f"Admin page accessible using {header_name} header",
                                        severity=FindingSeverity.CRITICAL,
                                        target=self.target,
                                        url=test_url,
                                        evidence=Evidence(
                                            request=f"GET {test_url}\n{header_name}: {header_value}",
                                        ),
                                        tags=["dast", "auth-bypass"],
                                    )
                                    await self.add_finding(finding)

                    except Exception:
                        pass

    async def _run_external_scanners(self) -> None:
        """Run external DAST tools like Nuclei, Nikto."""
        try:
            from aipt_v2.execution.tool_registry import get_registry
            registry = get_registry()

            # Run Nuclei
            if await registry.is_tool_available("nuclei"):
                result = await self._run_tool("nuclei", [
                    "-u", self.target,
                    "-severity", "critical,high,medium",
                    "-json",
                    "-silent"
                ], timeout=300)

                if result.get("output"):
                    await self._parse_nuclei_output(result["output"])

            # Run Nikto
            if await registry.is_tool_available("nikto"):
                result = await self._run_tool("nikto", [
                    "-h", self.target,
                    "-Format", "json",
                    "-o", "-"
                ], timeout=300)

                if result.get("output"):
                    await self._parse_nikto_output(result["output"])

        except Exception as e:
            logger.warning(f"External scanner error: {e}")

    async def _parse_nuclei_output(self, output: str) -> None:
        """Parse Nuclei JSON output."""
        import json

        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }

        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = Finding(
                    vuln_type=VulnerabilityType.OTHER,
                    title=data.get("info", {}).get("name", "Nuclei Finding"),
                    description=data.get("info", {}).get("description", ""),
                    severity=severity_map.get(
                        data.get("info", {}).get("severity", "info"),
                        FindingSeverity.INFO
                    ),
                    target=self.target,
                    url=data.get("matched-at", self.target),
                    cve_id=data.get("info", {}).get("classification", {}).get("cve-id"),
                    tags=["dast", "nuclei"] + data.get("info", {}).get("tags", []),
                )
                await self.add_finding(finding)
            except json.JSONDecodeError:
                pass

    async def _parse_nikto_output(self, output: str) -> None:
        """Parse Nikto output."""
        import json

        try:
            data = json.loads(output)
            for vuln in data.get("vulnerabilities", []):
                finding = Finding(
                    vuln_type=VulnerabilityType.MISCONFIGURATION,
                    title=vuln.get("msg", "Nikto Finding"),
                    description=vuln.get("description", ""),
                    severity=FindingSeverity.MEDIUM,
                    target=self.target,
                    url=vuln.get("url", self.target),
                    tags=["dast", "nikto"],
                )
                await self.add_finding(finding)
        except json.JSONDecodeError:
            pass

    async def _run_tool(
        self,
        tool_name: str,
        args: list[str],
        timeout: int = 60,
    ) -> dict:
        """Run a DAST tool."""
        try:
            from aipt_v2.execution.tool_runner import ToolRunner
            runner = ToolRunner()
            return await runner.run(
                tool_name=tool_name,
                args=args,
                timeout=timeout,
            )
        except Exception as e:
            logger.warning(f"Tool {tool_name} failed: {e}")
            return {"output": "", "error": str(e)}
