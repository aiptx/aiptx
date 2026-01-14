"""
AIPT Memory Manager - Context compression and management

Prevents context overflow in long pentest sessions.
Inspired by: Strix's memory compression (100K limit, 15 recent, 90% compress)
"""
from __future__ import annotations

from typing import Optional, Any
from dataclasses import dataclass, field
import json
from datetime import datetime


@dataclass
class MemoryConfig:
    """Memory configuration"""
    max_tokens: int = 32000      # Context window limit
    compress_at: float = 0.8     # Compress when 80% full
    recent_keep: int = 10        # Always keep last N messages
    summary_max_tokens: int = 500  # Max tokens for summary


class MemoryManager:
    """
    Manages conversation context with automatic compression.

    Key features:
    - Tracks token usage
    - Compresses old messages when approaching limit
    - Preserves recent messages for context continuity
    - Maintains compressed summary of older interactions
    """

    def __init__(
        self,
        llm: Any = None,
        config: Optional[MemoryConfig] = None,
    ):
        self.llm = llm
        self.config = config or MemoryConfig()
        self.messages: list[dict] = []
        self.compressed_summary: str = ""
        self._total_tokens: int = 0
        self._compression_count: int = 0

    @property
    def total_tokens(self) -> int:
        """Current token count"""
        return self._total_tokens

    @property
    def compression_count(self) -> int:
        """Number of compressions performed"""
        return self._compression_count

    def add_system(self, content: str) -> None:
        """Add system message (always kept at position 0)"""
        # Remove existing system message if any
        self.messages = [m for m in self.messages if m["role"] != "system"]
        self.messages.insert(0, {"role": "system", "content": content})
        self._recalculate_tokens()

    def add_user(self, content: str) -> None:
        """Add user message"""
        self._add_message("user", content)

    def add_assistant(self, content: str) -> None:
        """Add assistant message"""
        self._add_message("assistant", content)

    def add_tool_result(self, tool_name: str, result: str, truncate: int = 5000) -> None:
        """Add tool execution result"""
        if len(result) > truncate:
            result = result[:truncate] + f"\n... [truncated at {truncate} chars]"
        content = f"[Tool: {tool_name}]\n{result}"
        self._add_message("user", content)

    def add_finding(self, finding_type: str, description: str, severity: str = "info") -> None:
        """Add a security finding to memory"""
        content = f"[Finding: {finding_type.upper()}] [{severity.upper()}] {description}"
        self._add_message("user", content)

    def _add_message(self, role: str, content: str) -> None:
        """Add message and check for compression"""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
        })
        self._total_tokens += self._count_tokens(content)

        # Check if compression needed
        if self._total_tokens > self.config.max_tokens * self.config.compress_at:
            self._compress()

    def _compress(self) -> None:
        """
        Compress older messages into a summary.

        Strategy:
        1. Keep system message (first)
        2. Keep last N messages (recent_keep)
        3. Summarize everything in between
        """
        if len(self.messages) <= self.config.recent_keep + 1:
            return  # Not enough to compress

        # Separate messages
        system_msg = None
        if self.messages and self.messages[0]["role"] == "system":
            system_msg = self.messages[0]
            other_messages = self.messages[1:]
        else:
            other_messages = self.messages

        # Split into old (to compress) and recent (to keep)
        split_point = len(other_messages) - self.config.recent_keep
        old_messages = other_messages[:split_point]
        recent_messages = other_messages[split_point:]

        if not old_messages:
            return  # Nothing to compress

        # Generate summary of old messages
        summary = self._summarize(old_messages)
        self._compression_count += 1

        # Rebuild messages list
        self.messages = []
        if system_msg:
            self.messages.append(system_msg)

        # Add compressed summary as context
        if summary or self.compressed_summary:
            combined_summary = f"{self.compressed_summary}\n\n{summary}".strip()
            self.compressed_summary = combined_summary[-4000:]  # Keep last 4000 chars
            self.messages.append({
                "role": "user",
                "content": f"[Previous Session Summary]\n{self.compressed_summary}"
            })

        # Add recent messages
        self.messages.extend(recent_messages)

        # Recalculate tokens
        self._recalculate_tokens()

    def _summarize(self, messages: list[dict]) -> str:
        """Generate concise summary of messages"""
        if not messages:
            return ""

        # If no LLM available, use simple extraction
        if not self.llm:
            return self._simple_summarize(messages)

        # Format messages for summarization
        formatted = "\n".join([
            f"{m['role'].upper()}: {m['content'][:500]}"
            for m in messages
        ])

        summary_prompt = [
            {
                "role": "system",
                "content": "Summarize the following pentest session concisely. "
                          "Focus on: discovered hosts, open ports, vulnerabilities found, "
                          "credentials obtained, and actions taken. Be brief but complete."
            },
            {
                "role": "user",
                "content": f"Summarize this session:\n\n{formatted[:8000]}"
            }
        ]

        try:
            response = self.llm.invoke(summary_prompt, max_tokens=self.config.summary_max_tokens)
            return response.content
        except Exception as e:
            return self._simple_summarize(messages) + f" [LLM summarization failed: {e}]"

    def _simple_summarize(self, messages: list[dict]) -> str:
        """Simple extraction-based summarization without LLM"""
        findings = []
        actions = []

        for msg in messages:
            content = msg.get("content", "")

            # Extract findings
            if "[Finding:" in content or "vuln" in content.lower():
                findings.append(content[:200])

            # Extract tool executions
            if "[Tool:" in content:
                tool_line = content.split("\n")[0]
                actions.append(tool_line)

        summary_parts = []
        if findings:
            summary_parts.append(f"Findings ({len(findings)}): " + "; ".join(findings[:3]))
        if actions:
            summary_parts.append(f"Actions ({len(actions)}): " + "; ".join(actions[:5]))

        return " | ".join(summary_parts) if summary_parts else f"[{len(messages)} messages compressed]"

    def _count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        if self.llm and hasattr(self.llm, 'count_tokens'):
            return self.llm.count_tokens(text)
        return len(text) // 4  # Approximate

    def _recalculate_tokens(self) -> None:
        """Recalculate total tokens"""
        self._total_tokens = sum(
            self._count_tokens(m.get("content", "")) for m in self.messages
        )

    def get_messages(self, include_timestamps: bool = False) -> list[dict]:
        """Get current message list for LLM"""
        if include_timestamps:
            return self.messages.copy()

        # Strip timestamps for LLM calls
        return [
            {"role": m["role"], "content": m["content"]}
            for m in self.messages
        ]

    def get_context_for_prompt(self) -> str:
        """Get formatted context string"""
        parts = []

        if self.compressed_summary:
            parts.append(f"## Previous Findings\n{self.compressed_summary}")

        # Add recent non-system messages
        for msg in self.messages:
            if msg["role"] == "system":
                continue
            role = "Assistant" if msg["role"] == "assistant" else "User/Tool"
            content = msg["content"][:1000]
            parts.append(f"**{role}**: {content}")

        return "\n\n".join(parts)

    def get_findings_summary(self) -> dict:
        """Extract summary of findings from memory"""
        findings = {"hosts": [], "ports": [], "vulns": [], "creds": []}

        for msg in self.messages:
            content = msg.get("content", "").lower()

            if "host" in content and "discovered" in content:
                findings["hosts"].append(content[:100])
            if "port" in content and "open" in content:
                findings["ports"].append(content[:100])
            if "vuln" in content or "cve-" in content:
                findings["vulns"].append(content[:100])
            if "credential" in content or "password" in content:
                findings["creds"].append(content[:100])

        return findings

    def clear(self) -> None:
        """Clear all messages (keeps system message)"""
        system_msg = None
        if self.messages and self.messages[0]["role"] == "system":
            system_msg = self.messages[0]

        self.messages = []
        if system_msg:
            self.messages.append(system_msg)

        self.compressed_summary = ""
        self._recalculate_tokens()

    def save_state(self) -> dict:
        """Export state for persistence"""
        return {
            "messages": self.messages,
            "compressed_summary": self.compressed_summary,
            "total_tokens": self._total_tokens,
            "compression_count": self._compression_count,
        }

    def load_state(self, state: dict) -> None:
        """Import state from persistence"""
        self.messages = state.get("messages", [])
        self.compressed_summary = state.get("compressed_summary", "")
        self._total_tokens = state.get("total_tokens", 0)
        self._compression_count = state.get("compression_count", 0)

    def to_json(self) -> str:
        """Export to JSON string"""
        return json.dumps(self.save_state(), indent=2, default=str)

    @classmethod
    def from_json(cls, json_str: str, llm: Any = None) -> "MemoryManager":
        """Create from JSON string"""
        state = json.loads(json_str)
        manager = cls(llm=llm)
        manager.load_state(state)
        return manager
