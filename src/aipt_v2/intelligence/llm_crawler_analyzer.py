"""
AIPTX LLM-Powered Crawler Analyzer
===================================

Uses LLM intelligence to analyze webcrawler discoveries (endpoints, forms, parameters)
and intelligently prioritize attacks BEFORE running exploitation tools.

This enables:
- Smart parameter classification by vulnerability type (SQLi, XSS, IDOR, LFI, SSRF)
- Form purpose detection (login, registration, upload, payment)
- Attack chain generation based on discovered attack surface
- Priority scoring to focus on high-value targets first

Example:
    analyzer = LLMCrawlerAnalyzer()
    result = await analyzer.analyze_attack_surface(
        endpoints=discovered_endpoints,
        forms=discovered_forms,
        parameters=discovered_parameters,
        tech_stack=["PHP", "MySQL", "WordPress"]
    )

    # Get prioritized attack targets
    for target in result.get_high_priority_targets():
        print(f"[P{target.priority}] {target.url} - {target.attack_type}")
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AttackType(str, Enum):
    """Types of attacks to test."""
    SQLI = "sql_injection"
    XSS = "cross_site_scripting"
    IDOR = "insecure_direct_object_reference"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    SSRF = "server_side_request_forgery"
    RCE = "remote_code_execution"
    AUTH_BYPASS = "authentication_bypass"
    BOLA = "broken_object_level_auth"
    FILE_UPLOAD = "unrestricted_file_upload"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "cross_site_request_forgery"
    XXE = "xml_external_entity"
    BUSINESS_LOGIC = "business_logic"
    RATE_LIMIT = "rate_limiting"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class ParameterTarget:
    """A parameter identified for testing."""
    name: str
    url: str
    method: str  # GET, POST
    attack_types: list[AttackType]
    priority: int  # 1-5 (5 = highest)
    reasoning: str
    suggested_payloads: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "method": self.method,
            "attack_types": [a.value for a in self.attack_types],
            "priority": self.priority,
            "reasoning": self.reasoning,
            "suggested_payloads": self.suggested_payloads,
        }


@dataclass
class FormTarget:
    """A form identified for testing."""
    action: str
    method: str
    purpose: str  # login, registration, search, upload, payment, contact
    inputs: list[dict[str, str]]
    attack_types: list[AttackType]
    priority: int
    attack_strategy: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "purpose": self.purpose,
            "inputs": self.inputs,
            "attack_types": [a.value for a in self.attack_types],
            "priority": self.priority,
            "attack_strategy": self.attack_strategy,
        }


@dataclass
class AttackChainRecommendation:
    """A recommended attack chain based on discovered surface."""
    name: str
    steps: list[dict[str, str]]
    entry_point: str
    final_impact: str
    likelihood: str  # high, medium, low
    difficulty: str  # easy, medium, hard

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "steps": self.steps,
            "entry_point": self.entry_point,
            "final_impact": self.final_impact,
            "likelihood": self.likelihood,
            "difficulty": self.difficulty,
        }


@dataclass
class CrawlerAnalysisResult:
    """Complete result of LLM crawler analysis."""
    high_priority_parameters: list[ParameterTarget]
    high_priority_forms: list[FormTarget]
    attack_chains: list[AttackChainRecommendation]
    endpoint_categories: dict[str, list[str]]  # category -> endpoints
    technology_inferences: list[str]
    attack_surface_summary: str
    recommended_tool_order: list[str]
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    llm_model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "high_priority_parameters": [p.to_dict() for p in self.high_priority_parameters],
            "high_priority_forms": [f.to_dict() for f in self.high_priority_forms],
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "endpoint_categories": self.endpoint_categories,
            "technology_inferences": self.technology_inferences,
            "attack_surface_summary": self.attack_surface_summary,
            "recommended_tool_order": self.recommended_tool_order,
            "analyzed_at": self.analyzed_at.isoformat(),
            "llm_model": self.llm_model,
        }

    def get_high_priority_targets(self) -> list[ParameterTarget]:
        """Get parameters with priority >= 4."""
        return [p for p in self.high_priority_parameters if p.priority >= 4]

    def get_sqli_targets(self) -> list[ParameterTarget]:
        """Get parameters likely vulnerable to SQL injection."""
        return [p for p in self.high_priority_parameters if AttackType.SQLI in p.attack_types]

    def get_idor_targets(self) -> list[ParameterTarget]:
        """Get parameters likely vulnerable to IDOR/BOLA."""
        return [p for p in self.high_priority_parameters
                if AttackType.IDOR in p.attack_types or AttackType.BOLA in p.attack_types]

    def get_login_forms(self) -> list[FormTarget]:
        """Get forms identified as login forms."""
        return [f for f in self.high_priority_forms if f.purpose == "login"]

    def get_upload_forms(self) -> list[FormTarget]:
        """Get forms identified as file upload forms."""
        return [f for f in self.high_priority_forms if f.purpose == "upload"]

    def get_xss_targets(self) -> list[ParameterTarget]:
        """Get parameters likely vulnerable to XSS (Cross-Site Scripting)."""
        return [p for p in self.high_priority_parameters if AttackType.XSS in p.attack_types]

    def get_lfi_targets(self) -> list[ParameterTarget]:
        """Get parameters likely vulnerable to LFI (Local File Inclusion)."""
        return [p for p in self.high_priority_parameters if AttackType.LFI in p.attack_types]

    def get_ssrf_targets(self) -> list[ParameterTarget]:
        """Get parameters likely vulnerable to SSRF (Server-Side Request Forgery)."""
        return [p for p in self.high_priority_parameters if AttackType.SSRF in p.attack_types]

    def get_search_forms(self) -> list[FormTarget]:
        """Get forms identified as search forms (SQLi/XSS targets)."""
        return [f for f in self.high_priority_forms if f.purpose == "search"]


# LLM Prompts for Analysis
PARAMETER_ANALYSIS_PROMPT = """You are an elite penetration tester analyzing discovered parameters for vulnerability testing.

## Discovered Parameters (120 total)
```json
{parameters_json}
```

## Target Context
- **Target**: {target}
- **Technology Stack**: {tech_stack}
- **Endpoints Count**: {endpoint_count}
- **Forms Count**: {form_count}

## Your Task
Analyze each parameter and classify by vulnerability likelihood. Focus on:

### High Priority Indicators (Priority 5)
- `id`, `user_id`, `uid`, `account_id`, `customer_id` → IDOR/BOLA
- `file`, `path`, `document`, `download`, `include` → LFI/RFI
- `url`, `redirect`, `next`, `return`, `callback`, `ref` → SSRF/Open Redirect
- `cmd`, `exec`, `command`, `run`, `shell` → RCE
- `xml`, `data`, `config` → XXE

### Medium Priority Indicators (Priority 3-4)
- `search`, `query`, `q`, `keyword`, `filter`, `sort`, `order` → SQLi/XSS
- `email`, `password`, `username`, `login`, `token` → Auth attacks
- `name`, `title`, `description`, `comment`, `message` → XSS
- `page`, `limit`, `offset`, `size` → SQLi

### Business Logic Indicators (Priority 3)
- `amount`, `price`, `quantity`, `total`, `discount` → Business logic
- `role`, `admin`, `level`, `permission` → Privilege escalation

## Output Format (JSON)
```json
{{
    "high_priority_params": [
        {{
            "name": "user_id",
            "url": "https://example.com/api/user",
            "method": "GET",
            "attack_types": ["idor", "bola"],
            "priority": 5,
            "reasoning": "User ID parameter in API endpoint - classic IDOR target",
            "suggested_payloads": ["1", "2", "0", "-1", "admin"]
        }}
    ],
    "technology_inferences": ["PHP detected from .php extensions", "MySQL likely from error patterns"],
    "attack_surface_summary": "Large attack surface with 15 high-priority parameters..."
}}
```

Return ONLY the top 20 highest-priority parameters to focus testing efforts."""


FORM_ANALYSIS_PROMPT = """You are an elite penetration tester analyzing discovered forms for vulnerability testing.

## Discovered Forms ({form_count} total)
```json
{forms_json}
```

## Target Context
- **Target**: {target}
- **Technology Stack**: {tech_stack}

## Your Task
Analyze each form and determine:
1. **Purpose**: login, registration, search, upload, payment, contact, admin, api, other
2. **Attack Vectors**: What vulnerabilities to test
3. **Priority**: 1-5 based on impact
4. **Strategy**: Specific attack approach

### Form Purpose Detection
- Login form: Has username/password or email/password fields
- Registration: Has email, password, confirm_password fields
- File Upload: Has file input type
- Search: Has search/query field with GET method
- Payment: Has amount, card, cvv fields
- Contact: Has name, email, message fields
- Admin: URL contains /admin, /dashboard, /manage

### Attack Priority by Form Type
- Login form → Auth bypass, brute force, credential stuffing (Priority 5)
- File upload → Unrestricted upload, RCE (Priority 5)
- Admin form → Privilege escalation (Priority 5)
- Registration → Mass registration, duplicate accounts (Priority 4)
- Search → SQLi, XSS (Priority 4)
- Payment → Business logic, price manipulation (Priority 4)
- API form → All injection types (Priority 3)

## Output Format (JSON)
```json
{{
    "forms": [
        {{
            "action": "https://example.com/login",
            "method": "POST",
            "purpose": "login",
            "inputs": [{{"name": "username", "type": "text"}}, {{"name": "password", "type": "password"}}],
            "attack_types": ["auth_bypass", "brute_force", "sqli"],
            "priority": 5,
            "attack_strategy": "1. Test SQLi in username field, 2. Try admin'-- bypass, 3. Brute force common creds"
        }}
    ],
    "high_value_forms_summary": "Found 3 login forms and 1 file upload - high exploitation potential"
}}
```"""


ATTACK_CHAIN_PROMPT = """You are an elite penetration tester designing attack chains based on discovered attack surface.

## High Priority Parameters
```json
{priority_params_json}
```

## High Priority Forms
```json
{priority_forms_json}
```

## Target Context
- **Target**: {target}
- **Technology Stack**: {tech_stack}
- **Total Endpoints**: {endpoint_count}
- **Total Parameters**: {param_count}

## Your Task
Design realistic attack chains that combine discovered targets for maximum impact.

### Chain Types to Consider
1. **SQLi → Data Exfiltration → Credential Dump → Admin Access**
2. **Auth Bypass → User Enumeration → IDOR → Data Theft**
3. **File Upload → Webshell → RCE → Privilege Escalation**
4. **SSRF → Internal Network Access → Cloud Metadata → Secret Extraction**
5. **XSS → Session Hijacking → Account Takeover → Admin Access**
6. **IDOR → PII Disclosure → Mass Data Extraction**

### Prioritize Chains That:
- Start with easily exploitable vulnerabilities
- Lead to high business impact
- Have clear, actionable steps
- Use discovered parameters/forms as entry points

## Output Format (JSON)
```json
{{
    "attack_chains": [
        {{
            "name": "SQLi to Full Database Compromise",
            "steps": [
                {{"action": "Test SQLi in 'search' parameter", "tool": "sqlmap", "outcome": "Confirm injection point"}},
                {{"action": "Extract database schema", "tool": "sqlmap", "outcome": "Map all tables"}},
                {{"action": "Dump users table", "tool": "sqlmap", "outcome": "Extract credentials"}},
                {{"action": "Crack password hashes", "tool": "hashcat", "outcome": "Plain text passwords"}},
                {{"action": "Login as admin", "tool": "browser", "outcome": "Admin panel access"}}
            ],
            "entry_point": "https://example.com/search?q=FUZZ",
            "final_impact": "Full database access and admin account compromise",
            "likelihood": "high",
            "difficulty": "easy"
        }}
    ],
    "recommended_tool_order": ["sqlmap", "xsstrike", "burp-intruder", "nuclei"]
}}
```"""


class LLMCrawlerAnalyzer:
    """
    LLM-powered crawler analysis for intelligent attack orchestration.

    Analyzes webcrawler discoveries (endpoints, forms, parameters) to:
    - Classify parameters by vulnerability type
    - Identify form purposes and attack strategies
    - Generate attack chain recommendations
    - Prioritize testing for maximum efficiency

    Example:
        analyzer = LLMCrawlerAnalyzer()
        result = await analyzer.analyze_attack_surface(
            endpoints=["https://example.com/api/users/1"],
            forms=[{"action": "/login", "inputs": [{"name": "username"}, {"name": "password"}]}],
            parameters=[{"name": "user_id", "url": "/api/user", "method": "GET"}],
            target="example.com",
            tech_stack=["PHP", "MySQL"]
        )

        # Get prioritized SQLi targets
        for target in result.get_sqli_targets():
            print(f"Test SQLi: {target.url}?{target.name}=PAYLOAD")
    """

    def __init__(
        self,
        llm_provider: str = "anthropic",
        llm_model: str = "claude-3-5-sonnet-20241022",
    ):
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self._llm = None

    async def _get_llm(self):
        """Get or create LLM client."""
        if self._llm is None:
            try:
                import litellm
                self._llm = litellm
            except ImportError:
                logger.warning("litellm not installed - falling back to heuristic analysis")
                return None
        return self._llm

    async def analyze_attack_surface(
        self,
        endpoints: list[str],
        forms: list[dict[str, Any]],
        parameters: list[dict[str, Any]],
        target: str = "",
        tech_stack: list[str] = None,
    ) -> CrawlerAnalysisResult:
        """
        Analyze webcrawler discoveries to prioritize attacks.

        Args:
            endpoints: List of discovered endpoint URLs
            forms: List of discovered forms with inputs
            parameters: List of discovered parameters
            target: Target domain/URL
            tech_stack: Detected technologies

        Returns:
            CrawlerAnalysisResult with prioritized targets and attack chains
        """
        tech_stack = tech_stack or []

        llm = await self._get_llm()

        if llm is None:
            # Fall back to heuristic analysis
            return self._heuristic_analysis(endpoints, forms, parameters, target, tech_stack)

        try:
            # Analyze parameters
            param_result = await self._analyze_parameters(parameters, target, tech_stack, len(endpoints), len(forms))

            # Analyze forms
            form_result = await self._analyze_forms(forms, target, tech_stack)

            # Generate attack chains
            chain_result = await self._generate_attack_chains(
                param_result.get("high_priority_params", []),
                form_result.get("forms", []),
                target,
                tech_stack,
                len(endpoints),
                len(parameters)
            )

            # Categorize endpoints
            endpoint_categories = self._categorize_endpoints(endpoints)

            return CrawlerAnalysisResult(
                high_priority_parameters=[
                    ParameterTarget(
                        name=p["name"],
                        url=p.get("url", target),
                        method=p.get("method", "GET"),
                        attack_types=[AttackType(a) for a in p.get("attack_types", []) if a in [e.value for e in AttackType]],
                        priority=p.get("priority", 3),
                        reasoning=p.get("reasoning", ""),
                        suggested_payloads=p.get("suggested_payloads", []),
                    )
                    for p in param_result.get("high_priority_params", [])
                ],
                high_priority_forms=[
                    FormTarget(
                        action=f.get("action", ""),
                        method=f.get("method", "POST"),
                        purpose=f.get("purpose", "unknown"),
                        inputs=f.get("inputs", []),
                        attack_types=[AttackType(a) for a in f.get("attack_types", []) if a in [e.value for e in AttackType]],
                        priority=f.get("priority", 3),
                        attack_strategy=f.get("attack_strategy", ""),
                    )
                    for f in form_result.get("forms", [])
                ],
                attack_chains=[
                    AttackChainRecommendation(
                        name=c.get("name", ""),
                        steps=c.get("steps", []),
                        entry_point=c.get("entry_point", ""),
                        final_impact=c.get("final_impact", ""),
                        likelihood=c.get("likelihood", "medium"),
                        difficulty=c.get("difficulty", "medium"),
                    )
                    for c in chain_result.get("attack_chains", [])
                ],
                endpoint_categories=endpoint_categories,
                technology_inferences=param_result.get("technology_inferences", []),
                attack_surface_summary=param_result.get("attack_surface_summary", ""),
                recommended_tool_order=chain_result.get("recommended_tool_order", ["sqlmap", "xsstrike", "nuclei"]),
                llm_model=self.llm_model,
            )

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}, falling back to heuristic")
            return self._heuristic_analysis(endpoints, forms, parameters, target, tech_stack)

    async def _analyze_parameters(
        self,
        parameters: list[dict[str, Any]],
        target: str,
        tech_stack: list[str],
        endpoint_count: int,
        form_count: int,
    ) -> dict[str, Any]:
        """Analyze parameters using LLM."""
        llm = await self._get_llm()

        prompt = PARAMETER_ANALYSIS_PROMPT.format(
            parameters_json=json.dumps(parameters[:50], indent=2),  # Limit to 50 for token efficiency
            target=target,
            tech_stack=", ".join(tech_stack) if tech_stack else "Unknown",
            endpoint_count=endpoint_count,
            form_count=form_count,
        )

        try:
            response = await llm.acompletion(
                model=self.llm_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=4000,
            )

            result_text = response.choices[0].message.content

            # Extract JSON from response
            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', result_text)
            if json_match:
                return json.loads(json_match.group(1))

            # Try to parse entire response as JSON
            return json.loads(result_text)

        except Exception as e:
            logger.error(f"Parameter analysis failed: {e}")
            return {"high_priority_params": [], "technology_inferences": [], "attack_surface_summary": "Analysis failed"}

    async def _analyze_forms(
        self,
        forms: list[dict[str, Any]],
        target: str,
        tech_stack: list[str],
    ) -> dict[str, Any]:
        """Analyze forms using LLM."""
        llm = await self._get_llm()

        prompt = FORM_ANALYSIS_PROMPT.format(
            forms_json=json.dumps(forms[:30], indent=2),  # Limit to 30
            form_count=len(forms),
            target=target,
            tech_stack=", ".join(tech_stack) if tech_stack else "Unknown",
        )

        try:
            response = await llm.acompletion(
                model=self.llm_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=3000,
            )

            result_text = response.choices[0].message.content

            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', result_text)
            if json_match:
                return json.loads(json_match.group(1))

            return json.loads(result_text)

        except Exception as e:
            logger.error(f"Form analysis failed: {e}")
            return {"forms": [], "high_value_forms_summary": "Analysis failed"}

    async def _generate_attack_chains(
        self,
        priority_params: list[dict[str, Any]],
        priority_forms: list[dict[str, Any]],
        target: str,
        tech_stack: list[str],
        endpoint_count: int,
        param_count: int,
    ) -> dict[str, Any]:
        """Generate attack chain recommendations using LLM."""
        llm = await self._get_llm()

        prompt = ATTACK_CHAIN_PROMPT.format(
            priority_params_json=json.dumps(priority_params[:15], indent=2),
            priority_forms_json=json.dumps(priority_forms[:10], indent=2),
            target=target,
            tech_stack=", ".join(tech_stack) if tech_stack else "Unknown",
            endpoint_count=endpoint_count,
            param_count=param_count,
        )

        try:
            response = await llm.acompletion(
                model=self.llm_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5,  # Slightly higher for creativity
                max_tokens=3000,
            )

            result_text = response.choices[0].message.content

            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', result_text)
            if json_match:
                return json.loads(json_match.group(1))

            return json.loads(result_text)

        except Exception as e:
            logger.error(f"Attack chain generation failed: {e}")
            return {"attack_chains": [], "recommended_tool_order": ["sqlmap", "xsstrike", "nuclei"]}

    def _categorize_endpoints(self, endpoints: list[str]) -> dict[str, list[str]]:
        """Categorize endpoints by type."""
        categories = {
            "api": [],
            "admin": [],
            "auth": [],
            "user": [],
            "upload": [],
            "search": [],
            "other": [],
        }

        for endpoint in endpoints:
            ep_lower = endpoint.lower()

            if "/api/" in ep_lower or "/v1/" in ep_lower or "/v2/" in ep_lower:
                categories["api"].append(endpoint)
            elif "/admin" in ep_lower or "/dashboard" in ep_lower or "/manage" in ep_lower:
                categories["admin"].append(endpoint)
            elif "/login" in ep_lower or "/auth" in ep_lower or "/signin" in ep_lower or "/signup" in ep_lower:
                categories["auth"].append(endpoint)
            elif "/user" in ep_lower or "/profile" in ep_lower or "/account" in ep_lower:
                categories["user"].append(endpoint)
            elif "/upload" in ep_lower or "/file" in ep_lower or "/media" in ep_lower:
                categories["upload"].append(endpoint)
            elif "/search" in ep_lower or "?q=" in ep_lower or "?query=" in ep_lower:
                categories["search"].append(endpoint)
            else:
                categories["other"].append(endpoint)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v}

    def _heuristic_analysis(
        self,
        endpoints: list[str],
        forms: list[dict[str, Any]],
        parameters: list[dict[str, Any]],
        target: str,
        tech_stack: list[str],
    ) -> CrawlerAnalysisResult:
        """
        Fallback heuristic analysis when LLM is unavailable.

        Uses pattern matching to classify parameters and forms.
        """
        # Heuristic parameter patterns
        param_patterns = {
            AttackType.IDOR: ["id", "user_id", "uid", "account_id", "customer_id", "order_id", "doc_id"],
            AttackType.LFI: ["file", "path", "document", "download", "include", "template", "page"],
            AttackType.SSRF: ["url", "redirect", "next", "return", "callback", "ref", "link", "site"],
            AttackType.RCE: ["cmd", "exec", "command", "run", "shell", "code", "eval"],
            AttackType.SQLI: ["search", "query", "q", "keyword", "filter", "sort", "order", "id"],
            AttackType.XSS: ["name", "title", "description", "comment", "message", "content", "text"],
            AttackType.BUSINESS_LOGIC: ["amount", "price", "quantity", "total", "discount", "qty"],
        }

        high_priority_params = []

        for param in parameters:
            param_name = param.get("name", "").lower()

            for attack_type, patterns in param_patterns.items():
                if any(p in param_name for p in patterns):
                    priority = 5 if attack_type in [AttackType.IDOR, AttackType.LFI, AttackType.RCE] else 4
                    high_priority_params.append(ParameterTarget(
                        name=param.get("name", ""),
                        url=param.get("url", target),
                        method=param.get("method", "GET"),
                        attack_types=[attack_type],
                        priority=priority,
                        reasoning=f"Parameter name '{param_name}' matches {attack_type.value} pattern",
                    ))
                    break

        # Sort by priority
        high_priority_params.sort(key=lambda x: x.priority, reverse=True)

        # Heuristic form analysis
        high_priority_forms = []

        for form in forms:
            inputs = form.get("inputs", [])
            input_names = [i.get("name", "").lower() for i in inputs]
            input_types = [i.get("type", "").lower() for i in inputs]

            purpose = "other"
            attack_types = []
            priority = 3

            if "password" in input_names or "pass" in input_names:
                if "username" in input_names or "email" in input_names or "login" in input_names:
                    purpose = "login"
                    attack_types = [AttackType.AUTH_BYPASS, AttackType.SQLI]
                    priority = 5
                elif "confirm" in " ".join(input_names) or "register" in str(form.get("action", "")).lower():
                    purpose = "registration"
                    attack_types = [AttackType.SQLI, AttackType.XSS]
                    priority = 4

            if "file" in input_types:
                purpose = "upload"
                attack_types = [AttackType.FILE_UPLOAD, AttackType.RCE]
                priority = 5

            if "search" in input_names or "q" in input_names or "query" in input_names:
                purpose = "search"
                attack_types = [AttackType.SQLI, AttackType.XSS]
                priority = 4

            if attack_types:
                high_priority_forms.append(FormTarget(
                    action=form.get("action", ""),
                    method=form.get("method", "POST"),
                    purpose=purpose,
                    inputs=inputs,
                    attack_types=attack_types,
                    priority=priority,
                    attack_strategy=f"Test {', '.join([a.value for a in attack_types])} on {purpose} form",
                ))

        high_priority_forms.sort(key=lambda x: x.priority, reverse=True)

        return CrawlerAnalysisResult(
            high_priority_parameters=high_priority_params[:20],
            high_priority_forms=high_priority_forms[:10],
            attack_chains=[],  # Heuristic doesn't generate chains
            endpoint_categories=self._categorize_endpoints(endpoints),
            technology_inferences=tech_stack,
            attack_surface_summary=f"Heuristic analysis: {len(high_priority_params)} priority params, {len(high_priority_forms)} priority forms",
            recommended_tool_order=["sqlmap", "xsstrike", "nuclei", "burp"],
            llm_model="heuristic",
        )


# Demo function
async def demo():
    """Demonstrate the LLM Crawler Analyzer."""
    analyzer = LLMCrawlerAnalyzer()

    # Example data similar to webcrawler output
    endpoints = [
        "https://example.com/api/users/1",
        "https://example.com/api/orders",
        "https://example.com/admin/dashboard",
        "https://example.com/search?q=test",
        "https://example.com/upload",
    ]

    forms = [
        {
            "action": "https://example.com/login",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"},
            ]
        },
        {
            "action": "https://example.com/upload",
            "method": "POST",
            "inputs": [
                {"name": "file", "type": "file"},
                {"name": "description", "type": "text"},
            ]
        }
    ]

    parameters = [
        {"name": "user_id", "url": "https://example.com/api/user", "method": "GET"},
        {"name": "search", "url": "https://example.com/search", "method": "GET"},
        {"name": "file", "url": "https://example.com/download", "method": "GET"},
        {"name": "redirect", "url": "https://example.com/redirect", "method": "GET"},
    ]

    result = await analyzer.analyze_attack_surface(
        endpoints=endpoints,
        forms=forms,
        parameters=parameters,
        target="example.com",
        tech_stack=["PHP", "MySQL", "Apache"],
    )

    print("=== LLM Crawler Analysis Result ===\n")
    print(f"High Priority Parameters: {len(result.high_priority_parameters)}")
    for param in result.get_high_priority_targets():
        print(f"  [P{param.priority}] {param.name} @ {param.url} - {[a.value for a in param.attack_types]}")

    print(f"\nHigh Priority Forms: {len(result.high_priority_forms)}")
    for form in result.high_priority_forms:
        print(f"  [P{form.priority}] {form.purpose} form @ {form.action}")

    print(f"\nRecommended Tool Order: {result.recommended_tool_order}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(demo())
