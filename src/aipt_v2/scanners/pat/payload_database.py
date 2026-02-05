"""
PAT Payload Database

Stores and retrieves parsed payloads with caching support.
Provides efficient querying by vulnerability type, technique, and subcategory.
"""
from __future__ import annotations

import json
import logging
import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .config import VulnerabilityType, PayloadTechnique, PayloadConfig
from .payload_parser import PayloadParser, ParsedPayload

logger = logging.getLogger(__name__)


@dataclass
class PayloadStats:
    """Statistics about loaded payloads."""
    total_payloads: int = 0
    by_category: dict[str, int] = None
    by_technique: dict[str, int] = None
    last_updated: Optional[str] = None

    def __post_init__(self):
        if self.by_category is None:
            self.by_category = {}
        if self.by_technique is None:
            self.by_technique = {}


class PayloadDatabase:
    """
    Database for PayloadsAllTheThings payloads.

    Provides:
    - Automatic parsing and caching of PAT repository
    - Efficient querying by vulnerability type, technique, subcategory
    - Deduplication and filtering
    - JSON persistence for fast loading
    """

    def __init__(self, config: Optional[PayloadConfig] = None):
        """
        Initialize payload database.

        Args:
            config: Payload configuration (uses defaults if None)
        """
        self.config = config or PayloadConfig()
        self._payloads: dict[VulnerabilityType, list[ParsedPayload]] = {}
        self._loaded = False
        self._parser = PayloadParser(self.config)

        # Ensure cache directory exists
        self.config.cache_dir.mkdir(parents=True, exist_ok=True)

    @property
    def cache_file(self) -> Path:
        """Get path to cache file."""
        return self.config.cache_dir / "payloads.json"

    @property
    def metadata_file(self) -> Path:
        """Get path to metadata file."""
        return self.config.cache_dir / "metadata.json"

    def load(self, force_refresh: bool = False) -> bool:
        """
        Load payloads from cache or parse from repository.

        Args:
            force_refresh: Force re-parsing even if cache exists

        Returns:
            True if payloads loaded successfully
        """
        if self._loaded and not force_refresh:
            return True

        # Try loading from cache first
        if not force_refresh and self._load_from_cache():
            logger.info(f"Loaded {self.stats.total_payloads} payloads from cache")
            self._loaded = True
            return True

        # Parse from repository
        logger.info("Parsing PayloadsAllTheThings repository...")
        self._payloads = self._parser.parse_all()

        if self._payloads:
            self._save_to_cache()
            self._loaded = True
            logger.info(f"Parsed and cached {self.stats.total_payloads} payloads")
            return True

        logger.warning("No payloads loaded")
        return False

    def _load_from_cache(self) -> bool:
        """Load payloads from JSON cache."""
        if not self.cache_file.exists():
            return False

        # Check cache age
        metadata = self._load_metadata()
        if metadata:
            last_updated = datetime.fromisoformat(metadata.get("last_updated", "2000-01-01"))
            age_hours = (datetime.now(timezone.utc) - last_updated.replace(tzinfo=timezone.utc)).total_seconds() / 3600
            if age_hours > self.config.cache_ttl_hours:
                logger.info(f"Cache expired ({age_hours:.1f}h old)")
                return False

        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._payloads = {}
            for vuln_type_str, payloads_list in data.items():
                try:
                    vuln_type = VulnerabilityType(vuln_type_str)
                    self._payloads[vuln_type] = [
                        ParsedPayload(
                            content=p["content"],
                            category=VulnerabilityType(p["category"]),
                            subcategory=p.get("subcategory", ""),
                            technique=PayloadTechnique(p.get("technique", "direct")),
                            description=p.get("description", ""),
                            language=p.get("language", ""),
                            source_file=p.get("source_file", ""),
                            requires_encoding=p.get("requires_encoding", False),
                            is_dangerous=p.get("is_dangerous", False),
                            tags=p.get("tags", []),
                        )
                        for p in payloads_list
                    ]
                except (ValueError, KeyError) as e:
                    logger.warning(f"Error loading category {vuln_type_str}: {e}")

            return bool(self._payloads)

        except Exception as e:
            logger.warning(f"Error loading cache: {e}")
            return False

    def _save_to_cache(self) -> None:
        """Save payloads to JSON cache."""
        try:
            data = {}
            for vuln_type, payloads in self._payloads.items():
                data[vuln_type.value] = [
                    {
                        "content": p.content,
                        "category": p.category.value,
                        "subcategory": p.subcategory,
                        "technique": p.technique.value,
                        "description": p.description,
                        "language": p.language,
                        "source_file": p.source_file,
                        "requires_encoding": p.requires_encoding,
                        "is_dangerous": p.is_dangerous,
                        "tags": p.tags,
                    }
                    for p in payloads
                ]

            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            # Save metadata
            self._save_metadata({
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "total_payloads": self.stats.total_payloads,
                "repo_path": str(self.config.repo_path),
            })

            logger.debug(f"Saved {self.stats.total_payloads} payloads to cache")

        except Exception as e:
            logger.warning(f"Error saving cache: {e}")

    def _load_metadata(self) -> Optional[dict]:
        """Load cache metadata."""
        if not self.metadata_file.exists():
            return None
        try:
            with open(self.metadata_file, "r") as f:
                return json.load(f)
        except Exception:
            return None

    def _save_metadata(self, metadata: dict) -> None:
        """Save cache metadata."""
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.warning(f"Error saving metadata: {e}")

    @property
    def stats(self) -> PayloadStats:
        """Get payload statistics."""
        stats = PayloadStats()

        for vuln_type, payloads in self._payloads.items():
            count = len(payloads)
            stats.total_payloads += count
            stats.by_category[vuln_type.value] = count

            for payload in payloads:
                technique = payload.technique.value
                stats.by_technique[technique] = stats.by_technique.get(technique, 0) + 1

        metadata = self._load_metadata()
        if metadata:
            stats.last_updated = metadata.get("last_updated")

        return stats

    def get_payloads(
        self,
        vuln_type: VulnerabilityType,
        technique: Optional[PayloadTechnique] = None,
        subcategory: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[ParsedPayload]:
        """
        Get payloads for a vulnerability type.

        Args:
            vuln_type: Vulnerability type to get payloads for
            technique: Filter by technique (optional)
            subcategory: Filter by subcategory (optional)
            limit: Maximum payloads to return (optional)

        Returns:
            List of ParsedPayload objects
        """
        if not self._loaded:
            self.load()

        payloads = self._payloads.get(vuln_type, [])

        # Apply filters
        if technique:
            payloads = [p for p in payloads if p.technique == technique]

        if subcategory:
            payloads = [p for p in payloads if p.subcategory == subcategory]

        # Apply limit
        if limit and len(payloads) > limit:
            payloads = payloads[:limit]

        return payloads

    def get_all_payloads(
        self,
        vuln_types: Optional[list[VulnerabilityType]] = None,
    ) -> Iterator[ParsedPayload]:
        """
        Iterate over all payloads.

        Args:
            vuln_types: Filter by vulnerability types (optional)

        Yields:
            ParsedPayload objects
        """
        if not self._loaded:
            self.load()

        for vuln_type, payloads in self._payloads.items():
            if vuln_types and vuln_type not in vuln_types:
                continue
            yield from payloads

    def search(
        self,
        query: str,
        vuln_types: Optional[list[VulnerabilityType]] = None,
        limit: int = 50,
    ) -> list[ParsedPayload]:
        """
        Search payloads by content.

        Args:
            query: Search query (substring match)
            vuln_types: Filter by vulnerability types
            limit: Maximum results

        Returns:
            Matching payloads
        """
        if not self._loaded:
            self.load()

        query_lower = query.lower()
        results = []

        for payload in self.get_all_payloads(vuln_types):
            if query_lower in payload.content.lower():
                results.append(payload)
                if len(results) >= limit:
                    break

        return results

    def get_payload_hash(self, payload: ParsedPayload) -> str:
        """Get unique hash for a payload."""
        content = f"{payload.category.value}:{payload.content}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get_techniques(self, vuln_type: VulnerabilityType) -> list[PayloadTechnique]:
        """Get available techniques for a vulnerability type."""
        if not self._loaded:
            self.load()

        payloads = self._payloads.get(vuln_type, [])
        techniques = set(p.technique for p in payloads)
        return list(techniques)

    def get_subcategories(self, vuln_type: VulnerabilityType) -> list[str]:
        """Get available subcategories for a vulnerability type."""
        if not self._loaded:
            self.load()

        payloads = self._payloads.get(vuln_type, [])
        subcategories = set(p.subcategory for p in payloads if p.subcategory)
        return list(subcategories)

    def get_categories(self) -> list[VulnerabilityType]:
        """Get all available vulnerability categories."""
        if not self._loaded:
            self.load()
        return list(self._payloads.keys())

    def clear_cache(self) -> None:
        """Clear the cache files."""
        if self.cache_file.exists():
            self.cache_file.unlink()
        if self.metadata_file.exists():
            self.metadata_file.unlink()
        self._payloads = {}
        self._loaded = False
        logger.info("Cache cleared")

    def refresh(self) -> bool:
        """Force refresh payloads from repository."""
        self.clear_cache()
        return self.load(force_refresh=True)

    def load_custom_payloads(
        self,
        file_path: str,
        variables: Optional[dict[str, str]] = None,
        merge: bool = True,
    ) -> int:
        """
        Load custom payloads from YAML/JSON file.

        Args:
            file_path: Path to custom payload file
            variables: Variable overrides for templating
            merge: If True, merge with existing; if False, replace

        Returns:
            Number of payloads loaded
        """
        try:
            from .custom_payloads import CustomPayloadLoader

            loader = CustomPayloadLoader()
            result = loader.load_file(file_path, variables)

            if not merge:
                self._payloads[result.vuln_type] = []

            if result.vuln_type not in self._payloads:
                self._payloads[result.vuln_type] = []

            self._payloads[result.vuln_type].extend(result.payloads)
            self._loaded = True

            logger.info(f"Loaded {len(result.payloads)} custom payloads from {file_path}")
            return len(result.payloads)

        except ImportError as e:
            logger.warning(f"Custom payload loader not available: {e}")
            return 0
        except Exception as e:
            logger.error(f"Failed to load custom payloads from {file_path}: {e}")
            return 0

    def load_custom_payloads_directory(
        self,
        directory: str,
        pattern: str = "*.yaml",
        variables: Optional[dict[str, str]] = None,
        merge: bool = True,
    ) -> int:
        """
        Load all custom payload files from directory.

        Args:
            directory: Directory containing payload files
            pattern: Glob pattern for files
            variables: Variable overrides
            merge: If True, merge with existing

        Returns:
            Total number of payloads loaded
        """
        try:
            from .custom_payloads import CustomPayloadLoader

            loader = CustomPayloadLoader()
            results = loader.load_directory(directory, pattern, variables=variables)

            total_loaded = 0
            for result in results:
                if not merge:
                    self._payloads[result.vuln_type] = []

                if result.vuln_type not in self._payloads:
                    self._payloads[result.vuln_type] = []

                self._payloads[result.vuln_type].extend(result.payloads)
                total_loaded += len(result.payloads)

            self._loaded = True
            logger.info(f"Loaded {total_loaded} custom payloads from {directory}")
            return total_loaded

        except ImportError as e:
            logger.warning(f"Custom payload loader not available: {e}")
            return 0
        except Exception as e:
            logger.error(f"Failed to load custom payloads from {directory}: {e}")
            return 0

    def add_payload(
        self,
        vuln_type: VulnerabilityType,
        content: str,
        technique: PayloadTechnique = PayloadTechnique.DIRECT,
        **kwargs,
    ) -> bool:
        """
        Add a single payload programmatically.

        Args:
            vuln_type: Vulnerability type
            content: Payload content
            technique: Payload technique
            **kwargs: Additional payload fields

        Returns:
            True if added successfully
        """
        payload = ParsedPayload(
            content=content,
            category=vuln_type,
            technique=technique,
            subcategory=kwargs.get("subcategory", ""),
            description=kwargs.get("description", ""),
            source_file=kwargs.get("source_file", "programmatic"),
            tags=kwargs.get("tags", []),
        )

        if vuln_type not in self._payloads:
            self._payloads[vuln_type] = []

        self._payloads[vuln_type].append(payload)
        return True

    def add_payloads_bulk(
        self,
        vuln_type: VulnerabilityType,
        payloads: list[str],
        technique: PayloadTechnique = PayloadTechnique.DIRECT,
    ) -> int:
        """
        Add multiple payloads at once.

        Args:
            vuln_type: Vulnerability type
            payloads: List of payload strings
            technique: Payload technique

        Returns:
            Number of payloads added
        """
        count = 0
        for content in payloads:
            if self.add_payload(vuln_type, content, technique):
                count += 1
        return count

    def remove_duplicate_payloads(self) -> int:
        """
        Remove duplicate payloads across all categories.

        Returns:
            Number of duplicates removed
        """
        total_removed = 0

        for vuln_type in self._payloads:
            seen = set()
            unique = []

            for payload in self._payloads[vuln_type]:
                payload_hash = self.get_payload_hash(payload)
                if payload_hash not in seen:
                    seen.add(payload_hash)
                    unique.append(payload)
                else:
                    total_removed += 1

            self._payloads[vuln_type] = unique

        if total_removed > 0:
            logger.info(f"Removed {total_removed} duplicate payloads")

        return total_removed

    def export_payloads(
        self,
        output_file: Path,
        vuln_types: Optional[list[VulnerabilityType]] = None,
        format: str = "json",
    ) -> int:
        """
        Export payloads to file.

        Args:
            output_file: Output file path
            vuln_types: Filter by vulnerability types
            format: Output format (json, txt)

        Returns:
            Number of payloads exported
        """
        if not self._loaded:
            self.load()

        payloads = list(self.get_all_payloads(vuln_types))

        if format == "json":
            data = [
                {
                    "content": p.content,
                    "category": p.category.value,
                    "technique": p.technique.value,
                    "subcategory": p.subcategory,
                }
                for p in payloads
            ]
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

        elif format == "txt":
            with open(output_file, "w", encoding="utf-8") as f:
                for p in payloads:
                    f.write(f"{p.content}\n")

        logger.info(f"Exported {len(payloads)} payloads to {output_file}")
        return len(payloads)


# Global database instance for convenience
_global_db: Optional[PayloadDatabase] = None


def get_payload_database(config: Optional[PayloadConfig] = None) -> PayloadDatabase:
    """Get or create global payload database instance."""
    global _global_db
    if _global_db is None:
        _global_db = PayloadDatabase(config)
    return _global_db


def get_payloads_for_vuln(
    vuln_type: VulnerabilityType,
    limit: int = 50,
) -> list[ParsedPayload]:
    """
    Quick helper to get payloads for a vulnerability type.

    Args:
        vuln_type: Vulnerability type
        limit: Maximum payloads

    Returns:
        List of payloads
    """
    db = get_payload_database()
    db.load()
    return db.get_payloads(vuln_type, limit=limit)
