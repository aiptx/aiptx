"""
AIPTX AI Checkpoint Manager
===========================

Orchestrates AI checkpoints between pipeline phases.
Manages LLM interactions, fallbacks, and result parsing.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .ollama_client import OllamaCheckpointClient, OllamaConfig
from .checkpoint_prompts import get_prompt, SYSTEM_PROMPT
from .checkpoint_summarizers import (
    ReconSummarizer,
    ScanSummarizer,
    ExploitSummarizer,
    SummarizationConfig,
)

logger = logging.getLogger(__name__)


class CheckpointType(Enum):
    """Types of AI checkpoints."""

    POST_RECON = "post_recon"
    POST_SCAN = "post_scan"
    POST_EXPLOIT = "post_exploit"


@dataclass
class CheckpointResult:
    """Result of an AI checkpoint analysis."""

    checkpoint_type: CheckpointType
    success: bool
    recommendations: Dict[str, Any]
    raw_response: str = ""
    model_used: str = ""
    tokens_used: int = 0
    duration_seconds: float = 0.0
    source: str = "llm"  # "llm" or "rule_based"
    confidence: float = 1.0
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "checkpoint_type": self.checkpoint_type.value,
            "success": self.success,
            "recommendations": self.recommendations,
            "model_used": self.model_used,
            "source": self.source,
            "confidence": self.confidence,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }


class CheckpointError(Exception):
    """Base exception for checkpoint errors."""
    pass


class OllamaUnavailableError(CheckpointError):
    """Ollama service not running or unreachable."""
    pass


class ModelNotFoundError(CheckpointError):
    """Requested model not pulled in Ollama."""
    pass


class ContextOverflowError(CheckpointError):
    """Input exceeds model context window."""
    pass


class AICheckpointManager:
    """
    Manages AI checkpoints with graceful fallbacks.

    This is the main orchestrator for AI-powered phase analysis.
    Handles LLM interactions, error recovery, and rule-based fallbacks.

    Example:
        config = AICheckpointSettings(...)
        manager = AICheckpointManager(config)

        # After recon phase
        result = await manager.post_recon_checkpoint(findings)
        if result.success:
            strategy = result.recommendations
            # Apply scan strategy...

        # After scan phase
        result = await manager.post_scan_checkpoint(findings)
        if result.success:
            exploit_plan = result.recommendations
            # Execute exploitation plan...
    """

    # Model recommendations per checkpoint type
    MODEL_RECOMMENDATIONS = {
        CheckpointType.POST_RECON: {
            "default": "mistral:7b",
            "alternatives": ["llama3:8b", "qwen2:7b", "phi-3:3.8b"],
            "min_context": 4096,
        },
        CheckpointType.POST_SCAN: {
            "default": "deepseek-coder:6.7b",
            "alternatives": ["codellama:13b", "mistral:7b", "llama3:8b"],
            "min_context": 8192,
        },
        CheckpointType.POST_EXPLOIT: {
            "default": "mistral:7b",
            "alternatives": ["phi-3:3.8b", "llama3:8b"],
            "min_context": 4096,
        },
    }

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        post_recon_model: str = "mistral:7b",
        post_scan_model: str = "deepseek-coder:6.7b",
        post_exploit_model: str = "mistral:7b",
        max_context_tokens: int = 8192,
        response_timeout: int = 300,
        enable_streaming: bool = True,
        fallback_to_rules: bool = True,
        show_reasoning: bool = True,
    ):
        """Initialize the checkpoint manager."""
        self.ollama_url = ollama_base_url
        self.models = {
            CheckpointType.POST_RECON: post_recon_model,
            CheckpointType.POST_SCAN: post_scan_model,
            CheckpointType.POST_EXPLOIT: post_exploit_model,
        }
        self.max_context = max_context_tokens
        self.timeout = response_timeout
        self.enable_streaming = enable_streaming
        self.fallback_to_rules = fallback_to_rules
        self.show_reasoning = show_reasoning

        # Initialize components
        self._ollama_client: Optional[OllamaCheckpointClient] = None
        self._recon_summarizer = ReconSummarizer()
        self._scan_summarizer = ScanSummarizer()
        self._exploit_summarizer = ExploitSummarizer()

        # Callbacks
        self.on_token: Optional[Callable[[str], None]] = None
        self.on_progress: Optional[Callable[[str, float], None]] = None

    def _get_client(self, model: str) -> OllamaCheckpointClient:
        """Get or create Ollama client for model."""
        config = OllamaConfig(
            base_url=self.ollama_url,
            model=model,
            timeout=self.timeout,
            context_length=self.max_context,
        )
        return OllamaCheckpointClient(config)

    async def check_ollama_health(self) -> bool:
        """Check if Ollama is running and healthy."""
        client = self._get_client(self.models[CheckpointType.POST_RECON])
        return await client.health_check()

    async def post_recon_checkpoint(
        self,
        findings: List[Dict[str, Any]],
        on_token: Optional[Callable[[str], None]] = None,
    ) -> CheckpointResult:
        """
        AI checkpoint after RECON phase.

        Analyzes reconnaissance results and recommends scan strategy.

        Args:
            findings: List of recon findings
            on_token: Optional callback for streaming tokens

        Returns:
            CheckpointResult with scan strategy recommendations
        """
        import time
        start_time = time.time()

        try:
            # Summarize findings
            summary = self._recon_summarizer.summarize(findings)
            attack_surface = self._recon_summarizer.get_attack_surface(findings)

            # Get model and prompt
            model = self.models[CheckpointType.POST_RECON]
            client = self._get_client(model)
            context_size = client.get_context_size(model)

            system_prompt, prompt_template = get_prompt("post_recon", context_size)
            prompt = prompt_template.format(recon_summary=summary)

            # Check context budget
            estimated_tokens = client.estimate_tokens(system_prompt + prompt)
            if estimated_tokens > self.max_context * 0.8:
                # Compress further
                summary = self._compress_summary(summary, target_tokens=self.max_context // 2)
                prompt = prompt_template.format(recon_summary=summary)

            # Check Ollama health
            if not await client.health_check():
                if self.fallback_to_rules:
                    return self._rule_based_post_recon(findings, attack_surface, start_time)
                raise OllamaUnavailableError("Ollama not available")

            # Generate response
            if self.enable_streaming and on_token:
                response = await client.analyze_with_streaming(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    on_token=on_token or self.on_token,
                )
            else:
                ollama_response = await client.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                )
                response = ollama_response.content

            # Parse JSON response
            recommendations = self._parse_json_response(response)

            return CheckpointResult(
                checkpoint_type=CheckpointType.POST_RECON,
                success=True,
                recommendations=recommendations,
                raw_response=response,
                model_used=model,
                tokens_used=client.estimate_tokens(response),
                duration_seconds=time.time() - start_time,
                source="llm",
            )

        except Exception as e:
            logger.error(f"Post-recon checkpoint failed: {e}")

            if self.fallback_to_rules:
                return self._rule_based_post_recon(
                    findings,
                    self._recon_summarizer.get_attack_surface(findings),
                    start_time,
                )

            return CheckpointResult(
                checkpoint_type=CheckpointType.POST_RECON,
                success=False,
                recommendations={},
                error=str(e),
                duration_seconds=time.time() - start_time,
            )

    async def post_scan_checkpoint(
        self,
        findings: List[Dict[str, Any]],
        on_token: Optional[Callable[[str], None]] = None,
    ) -> CheckpointResult:
        """
        AI checkpoint after SCAN phase.

        Analyzes vulnerabilities and plans exploitation.

        Args:
            findings: List of vulnerability findings
            on_token: Optional callback for streaming tokens

        Returns:
            CheckpointResult with exploitation plan
        """
        import time
        start_time = time.time()

        try:
            # Summarize findings
            vuln_summary = self._scan_summarizer.summarize(findings)
            compact_findings = self._scan_summarizer.get_exploitable_findings(findings)

            # Build attack surface string
            attack_surface_lines = []
            for cf in compact_findings[:10]:
                attack_surface_lines.append(cf.to_compact_str())
            attack_surface = "\n".join(attack_surface_lines) if attack_surface_lines else "No high-value findings"

            # Get model and prompt
            model = self.models[CheckpointType.POST_SCAN]
            client = self._get_client(model)
            context_size = client.get_context_size(model)

            system_prompt, prompt_template = get_prompt("post_scan", context_size)
            prompt = prompt_template.format(
                vuln_summary=vuln_summary,
                attack_surface=attack_surface,
            )

            # Check Ollama health
            if not await client.health_check():
                if self.fallback_to_rules:
                    return self._rule_based_post_scan(findings, compact_findings, start_time)
                raise OllamaUnavailableError("Ollama not available")

            # Generate response
            if self.enable_streaming and on_token:
                response = await client.analyze_with_streaming(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    on_token=on_token or self.on_token,
                )
            else:
                ollama_response = await client.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                )
                response = ollama_response.content

            # Parse JSON response
            recommendations = self._parse_json_response(response)

            return CheckpointResult(
                checkpoint_type=CheckpointType.POST_SCAN,
                success=True,
                recommendations=recommendations,
                raw_response=response,
                model_used=model,
                tokens_used=client.estimate_tokens(response),
                duration_seconds=time.time() - start_time,
                source="llm",
            )

        except Exception as e:
            logger.error(f"Post-scan checkpoint failed: {e}")

            if self.fallback_to_rules:
                return self._rule_based_post_scan(
                    findings,
                    self._scan_summarizer.get_exploitable_findings(findings),
                    start_time,
                )

            return CheckpointResult(
                checkpoint_type=CheckpointType.POST_SCAN,
                success=False,
                recommendations={},
                error=str(e),
                duration_seconds=time.time() - start_time,
            )

    async def post_exploit_checkpoint(
        self,
        target: str,
        vuln_type: str,
        tool: str,
        command: str,
        exit_code: int,
        output: str,
        previous_attempts: List[Dict[str, Any]] = None,
        findings_exploited: int = 0,
        total_findings: int = 0,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> CheckpointResult:
        """
        AI checkpoint after EXPLOIT attempt.

        Evaluates exploitation result and recommends next action.

        Args:
            target: Target URL/host
            vuln_type: Type of vulnerability
            tool: Tool used
            command: Command executed
            exit_code: Exit code
            output: Tool output
            previous_attempts: Previous exploitation attempts
            findings_exploited: Count of exploited findings
            total_findings: Total findings count
            on_token: Optional callback for streaming tokens

        Returns:
            CheckpointResult with next action recommendation
        """
        import time
        start_time = time.time()

        try:
            # Summarize attempt
            attempt_summary = self._exploit_summarizer.summarize_attempt(
                target=target,
                vuln_type=vuln_type,
                tool=tool,
                command=command,
                exit_code=exit_code,
                output=output,
                previous_attempts=previous_attempts or [],
            )
            attempt_summary["findings_exploited"] = str(findings_exploited)
            attempt_summary["total_findings"] = str(total_findings)

            # Get model and prompt
            model = self.models[CheckpointType.POST_EXPLOIT]
            client = self._get_client(model)
            context_size = client.get_context_size(model)

            system_prompt, prompt_template = get_prompt("post_exploit", context_size)
            prompt = prompt_template.format(**attempt_summary)

            # Check Ollama health
            if not await client.health_check():
                if self.fallback_to_rules:
                    return self._rule_based_post_exploit(
                        exit_code, output, vuln_type, start_time
                    )
                raise OllamaUnavailableError("Ollama not available")

            # Generate response
            if self.enable_streaming and on_token:
                response = await client.analyze_with_streaming(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    on_token=on_token or self.on_token,
                )
            else:
                ollama_response = await client.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                )
                response = ollama_response.content

            # Parse JSON response
            recommendations = self._parse_json_response(response)

            return CheckpointResult(
                checkpoint_type=CheckpointType.POST_EXPLOIT,
                success=True,
                recommendations=recommendations,
                raw_response=response,
                model_used=model,
                tokens_used=client.estimate_tokens(response),
                duration_seconds=time.time() - start_time,
                source="llm",
            )

        except Exception as e:
            logger.error(f"Post-exploit checkpoint failed: {e}")

            if self.fallback_to_rules:
                return self._rule_based_post_exploit(exit_code, output, vuln_type, start_time)

            return CheckpointResult(
                checkpoint_type=CheckpointType.POST_EXPLOIT,
                success=False,
                recommendations={},
                error=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from LLM response."""
        # Try to extract JSON from response
        response = response.strip()

        # Try direct parsing
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to find JSON block
        json_start = response.find("{")
        json_end = response.rfind("}") + 1

        if json_start >= 0 and json_end > json_start:
            try:
                return json.loads(response[json_start:json_end])
            except json.JSONDecodeError:
                pass

        # Fallback: return raw response in a wrapper
        return {"raw_response": response, "parse_error": True}

    def _compress_summary(self, summary: str, target_tokens: int) -> str:
        """Compress summary to fit target token budget."""
        lines = summary.split("\n")
        result = []
        current_tokens = 0

        for line in lines:
            line_tokens = len(line) // 4
            if current_tokens + line_tokens <= target_tokens:
                result.append(line)
                current_tokens += line_tokens
            else:
                break

        return "\n".join(result)

    # Rule-based fallbacks

    def _rule_based_post_recon(
        self,
        findings: List[Dict[str, Any]],
        attack_surface: Dict[str, Any],
        start_time: float,
    ) -> CheckpointResult:
        """Rule-based fallback for post-recon checkpoint."""
        import time

        # Determine scan priorities based on attack surface
        priorities = []

        if attack_surface.get("web_servers", 0) > 0:
            priorities.extend(["nuclei", "nikto", "ffuf"])

        if attack_surface.get("databases", 0) > 0:
            priorities.append("sqlmap")

        if attack_surface.get("api_endpoints", 0) > 0:
            priorities.append("nuclei")

        if not priorities:
            priorities = ["nuclei", "nmap"]

        recommendations = {
            "scan_priority": priorities,
            "high_value_targets": [
                {"url": t, "reason": "auto-detected", "suggested_tests": ["vuln_scan"]}
                for t in attack_surface.get("high_value_targets", [])[:5]
            ],
            "reasoning": "Rule-based strategy: prioritizing based on detected services",
        }

        return CheckpointResult(
            checkpoint_type=CheckpointType.POST_RECON,
            success=True,
            recommendations=recommendations,
            source="rule_based",
            confidence=0.6,
            duration_seconds=time.time() - start_time,
        )

    def _rule_based_post_scan(
        self,
        findings: List[Dict[str, Any]],
        compact_findings: List,
        start_time: float,
    ) -> CheckpointResult:
        """Rule-based fallback for post-scan checkpoint."""
        import time

        # Sort by severity
        severity_order = {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}
        sorted_findings = sorted(
            compact_findings,
            key=lambda f: severity_order.get(f.severity, 5)
        )

        # Build exploitation order
        exploit_order = []
        for cf in sorted_findings[:10]:
            tool = "nuclei"  # Default
            if "sqli" in cf.type:
                tool = "sqlmap"
            elif "xss" in cf.type:
                tool = "dalfox"
            elif "rce" in cf.type or "command" in cf.type:
                tool = "manual"

            exploit_order.append({
                "finding_id": cf.id,
                "vulnerability": cf.type,
                "target": cf.target,
                "tool": tool,
            })

        recommendations = {
            "exploitation_order": exploit_order,
            "attack_chains": [],
            "reasoning": "Rule-based: exploiting by severity order",
        }

        return CheckpointResult(
            checkpoint_type=CheckpointType.POST_SCAN,
            success=True,
            recommendations=recommendations,
            source="rule_based",
            confidence=0.7,
            duration_seconds=time.time() - start_time,
        )

    def _rule_based_post_exploit(
        self,
        exit_code: int,
        output: str,
        vuln_type: str,
        start_time: float,
    ) -> CheckpointResult:
        """Rule-based fallback for post-exploit checkpoint."""
        import time

        # Simple success detection
        indicators = self._exploit_summarizer.extract_success_indicators(output, vuln_type)
        success = exit_code == 0 and len(indicators) > 0

        if success:
            next_action = "post_exploit"
        elif exit_code == 0:
            next_action = "retry"
        else:
            next_action = "skip"

        recommendations = {
            "success": success,
            "confidence": 0.6 if indicators else 0.4,
            "evidence_of_success": indicators,
            "next_action": next_action,
            "reasoning": f"Rule-based: exit_code={exit_code}, indicators={len(indicators)}",
        }

        return CheckpointResult(
            checkpoint_type=CheckpointType.POST_EXPLOIT,
            success=True,
            recommendations=recommendations,
            source="rule_based",
            confidence=0.5,
            duration_seconds=time.time() - start_time,
        )
