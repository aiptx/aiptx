"""
AIPTX Offline Data Manager
==========================

Manages offline databases, wordlists, and templates for fully offline operation.
Handles downloading, caching, and updating of security data.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OfflineDataConfig:
    """Configuration for offline data storage."""

    base_path: Path = field(default_factory=lambda: Path.home() / ".aiptx" / "data")
    wordlist_path: Optional[Path] = None
    template_path: Optional[Path] = None
    cve_path: Optional[Path] = None
    exploitdb_path: Optional[Path] = None

    # Update settings
    auto_update: bool = True
    update_interval_days: int = 7

    # Download settings
    download_timeout: int = 300
    max_retries: int = 3

    def __post_init__(self):
        """Set default paths based on base_path."""
        if self.wordlist_path is None:
            self.wordlist_path = self.base_path / "wordlists"
        if self.template_path is None:
            self.template_path = self.base_path / "nuclei-templates"
        if self.cve_path is None:
            self.cve_path = self.base_path / "cve"
        if self.exploitdb_path is None:
            self.exploitdb_path = self.base_path / "exploitdb"


@dataclass
class DataSourceInfo:
    """Information about a data source."""

    name: str
    path: Path
    last_updated: Optional[datetime] = None
    file_count: int = 0
    size_bytes: int = 0
    is_available: bool = False
    needs_update: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "file_count": self.file_count,
            "size_mb": round(self.size_bytes / (1024 * 1024), 2),
            "is_available": self.is_available,
            "needs_update": self.needs_update,
        }


class OfflineDataManager:
    """
    Manages offline databases and wordlists for AIPTX.

    Responsibilities:
    - Directory structure creation and verification
    - Data source download and updates
    - Integrity checking
    - Path resolution for tools

    Example:
        manager = OfflineDataManager()
        await manager.initialize()

        # Get wordlist path
        wordlist = manager.get_wordlist("directories", "common.txt")

        # Update all data sources
        await manager.update_all()
    """

    # Data source definitions
    DATA_SOURCES = {
        "nuclei_templates": {
            "name": "Nuclei Templates",
            "subdir": "nuclei-templates",
            "update_command": "nuclei -ut -ud {path}",
            "min_files": 5000,
            "critical": True,
        },
        "wordlists": {
            "name": "Wordlists (SecLists)",
            "subdir": "wordlists",
            "download_url": "https://github.com/danielmiessler/SecLists/archive/master.zip",
            "min_files": 100,
            "critical": True,
        },
        "exploitdb": {
            "name": "ExploitDB",
            "subdir": "exploitdb",
            "update_command": "searchsploit -u",
            "min_files": 40000,
            "critical": False,
        },
        "cve_database": {
            "name": "CVE Database",
            "subdir": "cve",
            "min_files": 1,
            "critical": False,
        },
        "trivy_db": {
            "name": "Trivy Database",
            "subdir": "trivy",
            "update_command": "trivy image --download-db-only --cache-dir {path}",
            "min_files": 1,
            "critical": False,
        },
        "grype_db": {
            "name": "Grype Database",
            "subdir": "grype",
            "update_command": "grype db update -c {path}",
            "min_files": 1,
            "critical": False,
        },
        "wpscan_db": {
            "name": "WPScan Database",
            "subdir": "wpscan",
            "update_command": "wpscan --update --cache-dir {path}",
            "min_files": 1,
            "critical": False,
        },
    }

    def __init__(self, config: Optional[OfflineDataConfig] = None):
        """Initialize the offline data manager."""
        self.config = config or OfflineDataConfig()
        self._initialized = False
        self._metadata_file = self.config.base_path / ".metadata.json"
        self._metadata: Dict[str, Any] = {}

    async def initialize(self) -> bool:
        """
        Initialize the offline data manager.

        Creates directory structure and loads metadata.

        Returns:
            True if initialization successful
        """
        try:
            # Create base directory structure
            await self._create_directory_structure()

            # Load existing metadata
            self._load_metadata()

            self._initialized = True
            logger.info(f"Offline data manager initialized at {self.config.base_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize offline data manager: {e}")
            return False

    async def _create_directory_structure(self) -> None:
        """Create the required directory structure."""
        directories = [
            self.config.base_path,
            self.config.wordlist_path,
            self.config.template_path,
            self.config.cve_path,
            self.config.exploitdb_path,
            self.config.base_path / "trivy",
            self.config.base_path / "grype",
            self.config.base_path / "wpscan",
            self.config.base_path / "nikto",
            self.config.base_path / "hashcat",
            self.config.base_path / "cache",
        ]

        # Create wordlist subdirectories
        wordlist_subdirs = ["directories", "passwords", "usernames", "dns", "fuzzing"]
        for subdir in wordlist_subdirs:
            directories.append(self.config.wordlist_path / subdir)

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def _load_metadata(self) -> None:
        """Load metadata from file."""
        if self._metadata_file.exists():
            try:
                with open(self._metadata_file) as f:
                    self._metadata = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load metadata: {e}")
                self._metadata = {}

    def _save_metadata(self) -> None:
        """Save metadata to file."""
        try:
            with open(self._metadata_file, "w") as f:
                json.dump(self._metadata, f, indent=2, default=str)
        except IOError as e:
            logger.error(f"Failed to save metadata: {e}")

    def get_data_source_info(self, source_key: str) -> DataSourceInfo:
        """
        Get information about a data source.

        Args:
            source_key: Key from DATA_SOURCES

        Returns:
            DataSourceInfo object
        """
        if source_key not in self.DATA_SOURCES:
            raise ValueError(f"Unknown data source: {source_key}")

        source = self.DATA_SOURCES[source_key]
        path = self.config.base_path / source["subdir"]

        # Get metadata
        meta = self._metadata.get(source_key, {})
        last_updated = None
        if "last_updated" in meta:
            last_updated = datetime.fromisoformat(meta["last_updated"])

        # Check availability and file count
        file_count = 0
        size_bytes = 0
        is_available = False

        if path.exists():
            try:
                files = list(path.rglob("*"))
                file_count = len([f for f in files if f.is_file()])
                size_bytes = sum(f.stat().st_size for f in files if f.is_file())
                is_available = file_count >= source.get("min_files", 1)
            except Exception as e:
                logger.warning(f"Error checking {source_key}: {e}")

        # Check if update needed
        needs_update = False
        if last_updated and self.config.auto_update:
            update_threshold = datetime.now() - timedelta(days=self.config.update_interval_days)
            needs_update = last_updated < update_threshold

        return DataSourceInfo(
            name=source["name"],
            path=path,
            last_updated=last_updated,
            file_count=file_count,
            size_bytes=size_bytes,
            is_available=is_available,
            needs_update=needs_update or not is_available,
        )

    def check_data_freshness(self) -> Dict[str, DataSourceInfo]:
        """
        Check freshness of all data sources.

        Returns:
            Dictionary of source_key -> DataSourceInfo
        """
        results = {}
        for source_key in self.DATA_SOURCES:
            results[source_key] = self.get_data_source_info(source_key)
        return results

    async def download_data_source(
        self,
        source_key: str,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """
        Download a data source.

        Args:
            source_key: Key from DATA_SOURCES
            progress_callback: Optional callback(message, progress_percent)

        Returns:
            True if download successful
        """
        if source_key not in self.DATA_SOURCES:
            raise ValueError(f"Unknown data source: {source_key}")

        source = self.DATA_SOURCES[source_key]
        path = self.config.base_path / source["subdir"]

        try:
            # Use update command if available
            if "update_command" in source:
                return await self._run_update_command(source_key, source, path, progress_callback)

            # Use download URL if available
            if "download_url" in source:
                return await self._download_and_extract(
                    source_key, source["download_url"], path, progress_callback
                )

            logger.warning(f"No download method for {source_key}")
            return False

        except Exception as e:
            logger.error(f"Failed to download {source_key}: {e}")
            return False

    async def _run_update_command(
        self,
        source_key: str,
        source: dict,
        path: Path,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """Run update command for a data source."""
        command = source["update_command"].format(path=path)

        if progress_callback:
            progress_callback(f"Running: {command}", 0.0)

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.download_timeout
            )

            if process.returncode == 0:
                # Update metadata
                self._metadata[source_key] = {
                    "last_updated": datetime.now().isoformat(),
                    "method": "command",
                }
                self._save_metadata()

                if progress_callback:
                    progress_callback(f"Updated {source['name']}", 100.0)
                return True
            else:
                logger.error(f"Update command failed: {stderr.decode()}")
                return False

        except asyncio.TimeoutError:
            logger.error(f"Update command timed out for {source_key}")
            return False

    async def _download_and_extract(
        self,
        source_key: str,
        url: str,
        path: Path,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """Download and extract a zip file."""
        zip_path = self.config.base_path / "cache" / f"{source_key}.zip"

        try:
            if progress_callback:
                progress_callback(f"Downloading {url}...", 0.0)

            # Download file
            async with httpx.AsyncClient(timeout=self.config.download_timeout) as client:
                async with client.stream("GET", url, follow_redirects=True) as response:
                    response.raise_for_status()

                    total_size = int(response.headers.get("content-length", 0))
                    downloaded = 0

                    with open(zip_path, "wb") as f:
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)

                            if progress_callback and total_size > 0:
                                percent = (downloaded / total_size) * 50  # 50% for download
                                progress_callback(f"Downloading...", percent)

            if progress_callback:
                progress_callback("Extracting...", 50.0)

            # Extract zip file
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                # Get total files for progress
                total_files = len(zip_ref.namelist())

                for i, member in enumerate(zip_ref.namelist()):
                    zip_ref.extract(member, path)

                    if progress_callback:
                        percent = 50 + (i / total_files) * 50
                        progress_callback(f"Extracting {member}...", percent)

            # Clean up zip file
            zip_path.unlink()

            # Update metadata
            self._metadata[source_key] = {
                "last_updated": datetime.now().isoformat(),
                "method": "download",
                "url": url,
            }
            self._save_metadata()

            if progress_callback:
                progress_callback("Complete!", 100.0)

            return True

        except Exception as e:
            logger.error(f"Download failed for {source_key}: {e}")
            if zip_path.exists():
                zip_path.unlink()
            return False

    async def update_all(
        self,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> Dict[str, bool]:
        """
        Update all data sources.

        Returns:
            Dictionary of source_key -> success status
        """
        results = {}
        total_sources = len(self.DATA_SOURCES)

        for i, source_key in enumerate(self.DATA_SOURCES):
            info = self.get_data_source_info(source_key)

            if not info.needs_update:
                results[source_key] = True
                continue

            if progress_callback:
                overall_percent = (i / total_sources) * 100
                progress_callback(f"Updating {info.name}...", overall_percent)

            results[source_key] = await self.download_data_source(source_key)

        return results

    def get_wordlist(self, category: str, name: str) -> Optional[Path]:
        """
        Get path to a specific wordlist.

        Args:
            category: Category (directories, passwords, usernames, dns, fuzzing)
            name: Wordlist filename

        Returns:
            Path to wordlist or None if not found
        """
        # Try direct path first
        direct_path = self.config.wordlist_path / category / name
        if direct_path.exists():
            return direct_path

        # Try without category (for SecLists structure)
        seclists_paths = [
            self.config.wordlist_path / "SecLists-master" / "Discovery" / "Web-Content" / name,
            self.config.wordlist_path / "SecLists-master" / "Passwords" / name,
            self.config.wordlist_path / "SecLists-master" / "Usernames" / name,
            self.config.wordlist_path / "SecLists-master" / "Discovery" / "DNS" / name,
            self.config.wordlist_path / "SecLists-master" / "Fuzzing" / name,
        ]

        for path in seclists_paths:
            if path.exists():
                return path

        # Glob search as fallback
        matches = list(self.config.wordlist_path.rglob(name))
        if matches:
            return matches[0]

        logger.warning(f"Wordlist not found: {category}/{name}")
        return None

    def get_template_path(self, category: Optional[str] = None) -> Path:
        """
        Get path to nuclei templates.

        Args:
            category: Optional category subdirectory

        Returns:
            Path to templates directory
        """
        if category:
            return self.config.template_path / category
        return self.config.template_path

    def get_cve_database_path(self) -> Path:
        """Get path to CVE database."""
        return self.config.cve_path

    def get_exploitdb_path(self) -> Path:
        """Get path to ExploitDB."""
        return self.config.exploitdb_path
