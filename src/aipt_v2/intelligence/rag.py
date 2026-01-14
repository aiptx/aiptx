"""
AIPT RAG Tool Selection - BGE-based tool retrieval and ranking
Selects the optimal security tool for each objective.

Inspired by: PentestAssistant's proven scoring formula
Score = 0.5 * description_similarity + 0.5 * sample_similarity + 2.0 * keyword_match
"""

import json
import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

import numpy as np


@dataclass
class ToolMatch:
    """A matched tool with its score"""
    name: str
    score: float
    tool: dict


class ToolRAG:
    """
    RAG-based tool selection using BGE embeddings.

    Features:
    - Semantic search via sentence-transformers
    - Keyword boosting for exact matches
    - Phase filtering for context-aware selection
    - Lazy loading of embeddings for fast startup
    """

    # Scoring weights (from PentestAssistant)
    WEIGHT_DESCRIPTION = 0.5
    WEIGHT_SAMPLES = 0.5
    WEIGHT_KEYWORDS = 2.0  # Keyword matches are heavily weighted

    def __init__(
        self,
        tools_path: Optional[str] = None,
        embedding_model: str = "BAAI/bge-large-en-v1.5",
        lazy_load: bool = True,
    ):
        self.tools_path = tools_path or self._default_tools_path()
        self.embedding_model_name = embedding_model
        self.tools: list[dict] = []
        self._embedder = None
        self._embeddings_cache: dict = {}

        # Load tools
        self._load_tools()

        # Optionally pre-compute embeddings
        if not lazy_load:
            self._ensure_embedder()
            self._precompute_embeddings()

    def _default_tools_path(self) -> str:
        """Get default tools.json path"""
        return str(Path(__file__).parent / "tools.json")

    def _load_tools(self) -> None:
        """Load tool definitions from JSON"""
        try:
            with open(self.tools_path, "r") as f:
                self.tools = json.load(f)
        except FileNotFoundError:
            # Initialize with empty list if file doesn't exist yet
            self.tools = []

    def _ensure_embedder(self) -> None:
        """Lazy-load the embedding model"""
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer(self.embedding_model_name)
            except ImportError:
                raise ImportError(
                    "sentence-transformers required. Install with: pip install sentence-transformers"
                )

    def _precompute_embeddings(self) -> None:
        """Pre-compute embeddings for all tools"""
        self._ensure_embedder()

        for tool in self.tools:
            name = tool.get("name", "")
            if name not in self._embeddings_cache:
                desc = tool.get("description", "")
                samples = " ".join(tool.get("samples", []))

                self._embeddings_cache[name] = {
                    "desc": self._embedder.encode(desc, normalize_embeddings=True),
                    "samples": self._embedder.encode(samples, normalize_embeddings=True) if samples else None,
                }

    def search(
        self,
        query: str,
        phase: Optional[str] = None,
        top_k: int = 5,
    ) -> list[dict]:
        """
        Search for tools matching the query.

        Args:
            query: Natural language description of what to do
            phase: Optional phase filter (recon, enum, exploit, post)
            top_k: Number of results to return

        Returns:
            List of tool dictionaries, sorted by relevance
        """
        if not self.tools:
            return []

        self._ensure_embedder()

        # Encode query
        query_embedding = self._embedder.encode(query, normalize_embeddings=True)

        # Filter by phase if specified
        candidates = self.tools
        if phase:
            candidates = [t for t in self.tools if t.get("phase") == phase or not t.get("phase")]

        # Score all candidates
        scored_tools: list[ToolMatch] = []

        for tool in candidates:
            score = self._score_tool(query, query_embedding, tool)
            scored_tools.append(ToolMatch(
                name=tool.get("name", "unknown"),
                score=score,
                tool=tool,
            ))

        # Sort by score (descending)
        scored_tools.sort(key=lambda x: x.score, reverse=True)

        # Return top_k
        return [match.tool for match in scored_tools[:top_k]]

    def _score_tool(
        self,
        query: str,
        query_embedding: np.ndarray,
        tool: dict,
    ) -> float:
        """
        Score a tool against the query using the proven formula:
        score = 0.5 * desc_sim + 0.5 * sample_sim + 2.0 * keyword_match
        """
        name = tool.get("name", "")

        # Get or compute embeddings
        if name in self._embeddings_cache:
            cached = self._embeddings_cache[name]
            desc_emb = cached["desc"]
            sample_emb = cached.get("samples")
        else:
            desc = tool.get("description", "")
            samples = " ".join(tool.get("samples", []))

            desc_emb = self._embedder.encode(desc, normalize_embeddings=True)
            sample_emb = self._embedder.encode(samples, normalize_embeddings=True) if samples else None

            # Cache for future use
            self._embeddings_cache[name] = {"desc": desc_emb, "samples": sample_emb}

        # Compute similarities
        desc_score = self._cosine_similarity(query_embedding, desc_emb)
        sample_score = self._cosine_similarity(query_embedding, sample_emb) if sample_emb is not None else 0.0

        # Keyword matching
        keyword_score = self._keyword_match(query, tool)

        # Combined score (the magic formula from PentestAssistant)
        score = (
            self.WEIGHT_DESCRIPTION * desc_score +
            self.WEIGHT_SAMPLES * sample_score +
            self.WEIGHT_KEYWORDS * keyword_score
        )

        return float(score)

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors"""
        if a is None or b is None:
            return 0.0
        return float(np.dot(a, b))  # Already normalized

    def _keyword_match(self, query: str, tool: dict) -> float:
        """
        Compute keyword match score.
        Higher weight for exact keyword matches.
        """
        query_lower = query.lower()
        keywords = tool.get("keywords", [])

        if not keywords:
            return 0.0

        # Count matches
        matches = sum(1 for kw in keywords if kw.lower() in query_lower)

        # Also check tool name
        if tool.get("name", "").lower() in query_lower:
            matches += 2  # Bonus for mentioning tool by name

        # Normalize to 0-1
        return min(matches / max(len(keywords), 1), 1.0)

    def get_tool_by_name(self, name: str) -> Optional[dict]:
        """Get a specific tool by name"""
        for tool in self.tools:
            if tool.get("name", "").lower() == name.lower():
                return tool
        return None

    def get_tools_by_phase(self, phase: str) -> list[dict]:
        """Get all tools for a specific phase"""
        return [t for t in self.tools if t.get("phase") == phase]

    def add_tool(self, tool: dict) -> None:
        """Add a custom tool to the registry"""
        self.tools.append(tool)
        # Clear cache for re-computation
        name = tool.get("name", "")
        if name in self._embeddings_cache:
            del self._embeddings_cache[name]

    def list_tools(self) -> list[str]:
        """List all available tool names"""
        return [t.get("name", "unknown") for t in self.tools]
