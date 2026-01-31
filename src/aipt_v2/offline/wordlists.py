"""
AIPTX Wordlist Manager
======================

Manages wordlist downloads, organization, and access for offline operation.
Supports SecLists, Assetnote, FuzzDB, and custom wordlists.
"""

import asyncio
import logging
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


# Wordlist source definitions
WORDLIST_SOURCES = {
    "seclists": {
        "name": "SecLists",
        "url": "https://github.com/danielmiessler/SecLists/archive/master.zip",
        "description": "Comprehensive collection for security testing",
        "size_estimate": "800MB",
        "categories": ["Discovery", "Fuzzing", "Passwords", "Usernames", "Payloads"],
    },
    "assetnote": {
        "name": "Assetnote Wordlists",
        "base_url": "https://wordlists.assetnote.io/data/",
        "description": "Automated wordlists from HTTP Archive",
        "size_estimate": "500MB",
        "wordlists": {
            "httparchive_directories_1m": "automated/httparchive_directories_1m.txt",
            "httparchive_parameters_top_1m": "automated/httparchive_parameters_top_1m.txt",
            "httparchive_subdomains_1m": "automated/httparchive_subdomains_1m.txt",
        },
    },
    "fuzzdb": {
        "name": "FuzzDB",
        "url": "https://github.com/fuzzdb-project/fuzzdb/archive/master.zip",
        "description": "Attack patterns and discovery wordlists",
        "size_estimate": "50MB",
        "categories": ["attack", "discovery", "wordlists"],
    },
}

# Recommended wordlists for each category
RECOMMENDED_WORDLISTS = {
    "directories": [
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/big.txt",
    ],
    "files": [
        "Discovery/Web-Content/raft-medium-files.txt",
        "Discovery/Web-Content/web-extensions.txt",
    ],
    "passwords": [
        "Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
        "Passwords/Common-Credentials/10k-most-common.txt",
        "Passwords/Leaked-Databases/rockyou.txt",
    ],
    "usernames": [
        "Usernames/Names/names.txt",
        "Usernames/top-usernames-shortlist.txt",
    ],
    "subdomains": [
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/dns-Jhaddix.txt",
        "Discovery/DNS/bitquark-subdomains-top100000.txt",
    ],
    "parameters": [
        "Discovery/Web-Content/burp-parameter-names.txt",
        "Fuzzing/LFI/LFI-Jhaddix.txt",
    ],
    "sqli": [
        "Fuzzing/SQLi/Generic-SQLi.txt",
        "Fuzzing/SQLi/quick-SQLi.txt",
    ],
    "xss": [
        "Fuzzing/XSS/XSS-BruteLogic.txt",
        "Fuzzing/XSS/xss-payload-list.txt",
    ],
    "lfi": [
        "Fuzzing/LFI/LFI-Jhaddix.txt",
        "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    ],
}


@dataclass
class WordlistInfo:
    """Information about a wordlist."""

    name: str
    path: Path
    line_count: int
    size_bytes: int
    category: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "line_count": self.line_count,
            "size_mb": round(self.size_bytes / (1024 * 1024), 2),
            "category": self.category,
        }


class WordlistManager:
    """
    Manages wordlist downloads and access.

    Example:
        manager = WordlistManager(Path.home() / ".aiptx" / "data" / "wordlists")

        # Download SecLists
        await manager.download_source("seclists")

        # Get wordlist path
        path = manager.get_wordlist("directories", "common.txt")

        # List available wordlists
        wordlists = manager.list_wordlists("passwords")
    """

    def __init__(self, base_path: Path, download_timeout: int = 600):
        """
        Initialize wordlist manager.

        Args:
            base_path: Base directory for wordlists
            download_timeout: Timeout for downloads in seconds
        """
        self.base_path = Path(base_path)
        self.download_timeout = download_timeout
        self._cache: Dict[str, Path] = {}

    async def initialize(self) -> None:
        """Initialize the wordlist manager and create directories."""
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Create category directories
        categories = ["directories", "passwords", "usernames", "dns", "fuzzing", "custom"]
        for category in categories:
            (self.base_path / category).mkdir(exist_ok=True)

    async def download_source(
        self,
        source_name: str,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """
        Download wordlists from a source.

        Args:
            source_name: Name from WORDLIST_SOURCES
            progress_callback: Optional progress callback

        Returns:
            True if download successful
        """
        if source_name not in WORDLIST_SOURCES:
            raise ValueError(f"Unknown wordlist source: {source_name}")

        source = WORDLIST_SOURCES[source_name]

        if "url" in source:
            return await self._download_zip_source(source_name, source, progress_callback)
        elif "base_url" in source:
            return await self._download_individual_wordlists(source_name, source, progress_callback)
        else:
            logger.error(f"No download method for {source_name}")
            return False

    async def _download_zip_source(
        self,
        source_name: str,
        source: dict,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """Download and extract a zip-based wordlist source."""
        url = source["url"]
        zip_path = self.base_path / f"{source_name}.zip"
        extract_path = self.base_path / source_name

        try:
            if progress_callback:
                progress_callback(f"Downloading {source['name']}...", 0.0)

            # Download
            async with httpx.AsyncClient(timeout=self.download_timeout) as client:
                async with client.stream("GET", url, follow_redirects=True) as response:
                    response.raise_for_status()

                    total_size = int(response.headers.get("content-length", 0))
                    downloaded = 0

                    with open(zip_path, "wb") as f:
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)

                            if progress_callback and total_size > 0:
                                percent = (downloaded / total_size) * 50
                                progress_callback(f"Downloading...", percent)

            if progress_callback:
                progress_callback("Extracting...", 50.0)

            # Extract
            extract_path.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                total_files = len(zip_ref.namelist())
                for i, member in enumerate(zip_ref.namelist()):
                    zip_ref.extract(member, extract_path)
                    if progress_callback and i % 100 == 0:
                        percent = 50 + (i / total_files) * 50
                        progress_callback(f"Extracting...", percent)

            # Clean up
            zip_path.unlink()

            if progress_callback:
                progress_callback("Complete!", 100.0)

            logger.info(f"Downloaded {source['name']} to {extract_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to download {source_name}: {e}")
            if zip_path.exists():
                zip_path.unlink()
            return False

    async def _download_individual_wordlists(
        self,
        source_name: str,
        source: dict,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """Download individual wordlist files."""
        base_url = source["base_url"]
        wordlists = source.get("wordlists", {})
        target_dir = self.base_path / source_name

        target_dir.mkdir(parents=True, exist_ok=True)

        success_count = 0
        total = len(wordlists)

        async with httpx.AsyncClient(timeout=self.download_timeout) as client:
            for i, (name, path) in enumerate(wordlists.items()):
                url = f"{base_url}{path}"
                target_path = target_dir / f"{name}.txt"

                try:
                    if progress_callback:
                        percent = (i / total) * 100
                        progress_callback(f"Downloading {name}...", percent)

                    response = await client.get(url, follow_redirects=True)
                    response.raise_for_status()

                    with open(target_path, "wb") as f:
                        f.write(response.content)

                    success_count += 1

                except Exception as e:
                    logger.warning(f"Failed to download {name}: {e}")

        if progress_callback:
            progress_callback("Complete!", 100.0)

        logger.info(f"Downloaded {success_count}/{total} wordlists from {source_name}")
        return success_count > 0

    def get_wordlist(self, category: str, name: str) -> Optional[Path]:
        """
        Get path to a wordlist.

        Args:
            category: Category (directories, passwords, etc.)
            name: Wordlist filename or path

        Returns:
            Path to wordlist or None if not found
        """
        # Check cache first
        cache_key = f"{category}/{name}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if cached.exists():
                return cached

        # Try direct path
        direct = self.base_path / category / name
        if direct.exists():
            self._cache[cache_key] = direct
            return direct

        # Try in SecLists structure
        seclists_mappings = {
            "directories": ["SecLists-master/Discovery/Web-Content"],
            "passwords": ["SecLists-master/Passwords", "SecLists-master/Passwords/Common-Credentials"],
            "usernames": ["SecLists-master/Usernames", "SecLists-master/Usernames/Names"],
            "dns": ["SecLists-master/Discovery/DNS"],
            "fuzzing": ["SecLists-master/Fuzzing"],
            "sqli": ["SecLists-master/Fuzzing/SQLi"],
            "xss": ["SecLists-master/Fuzzing/XSS"],
            "lfi": ["SecLists-master/Fuzzing/LFI"],
        }

        for subpath in seclists_mappings.get(category, []):
            candidate = self.base_path / "seclists" / subpath / name
            if candidate.exists():
                self._cache[cache_key] = candidate
                return candidate

        # Try glob search
        matches = list(self.base_path.rglob(name))
        if matches:
            self._cache[cache_key] = matches[0]
            return matches[0]

        return None

    def get_recommended_wordlist(self, category: str, size: str = "medium") -> Optional[Path]:
        """
        Get recommended wordlist for a category.

        Args:
            category: Category name
            size: Size preference (small, medium, large)

        Returns:
            Path to recommended wordlist
        """
        recommendations = RECOMMENDED_WORDLISTS.get(category, [])
        if not recommendations:
            return None

        # Size mapping: first = small, middle = medium, last = large
        if size == "small" and len(recommendations) > 0:
            target = recommendations[0]
        elif size == "large" and len(recommendations) > 2:
            target = recommendations[-1]
        else:  # medium or default
            target = recommendations[len(recommendations) // 2]

        # Extract filename from path
        name = Path(target).name
        category_hint = Path(target).parent.name.lower()

        # Try to find it
        result = self.get_wordlist(category_hint, name)
        if result:
            return result

        # Try with full relative path in seclists
        full_path = self.base_path / "seclists" / "SecLists-master" / target
        if full_path.exists():
            return full_path

        return None

    def list_wordlists(self, category: Optional[str] = None) -> List[WordlistInfo]:
        """
        List available wordlists.

        Args:
            category: Optional category filter

        Returns:
            List of WordlistInfo objects
        """
        results = []

        if category:
            search_paths = [self.base_path / category]
            # Also search in seclists
            seclists_path = self.base_path / "seclists"
            if seclists_path.exists():
                search_paths.append(seclists_path)
        else:
            search_paths = [self.base_path]

        for search_path in search_paths:
            if not search_path.exists():
                continue

            for file_path in search_path.rglob("*.txt"):
                try:
                    size = file_path.stat().st_size
                    # Count lines (estimate for large files)
                    if size < 10_000_000:  # 10MB
                        with open(file_path, "rb") as f:
                            line_count = sum(1 for _ in f)
                    else:
                        line_count = size // 20  # Estimate ~20 bytes per line

                    # Determine category from path
                    cat = self._determine_category(file_path)

                    if category and cat != category:
                        continue

                    results.append(WordlistInfo(
                        name=file_path.name,
                        path=file_path,
                        line_count=line_count,
                        size_bytes=size,
                        category=cat,
                    ))
                except Exception as e:
                    logger.debug(f"Error processing {file_path}: {e}")

        return sorted(results, key=lambda x: x.name)

    def _determine_category(self, path: Path) -> str:
        """Determine wordlist category from path."""
        path_str = str(path).lower()

        if "password" in path_str:
            return "passwords"
        elif "username" in path_str or "user" in path_str:
            return "usernames"
        elif "dns" in path_str or "subdomain" in path_str:
            return "subdomains"
        elif "sqli" in path_str or "sql" in path_str:
            return "sqli"
        elif "xss" in path_str:
            return "xss"
        elif "lfi" in path_str or "rfi" in path_str:
            return "lfi"
        elif "directory" in path_str or "dir" in path_str or "web-content" in path_str:
            return "directories"
        elif "fuzz" in path_str:
            return "fuzzing"
        else:
            return "other"

    def add_custom_wordlist(self, name: str, content: List[str]) -> Path:
        """
        Add a custom wordlist.

        Args:
            name: Wordlist name
            content: List of lines

        Returns:
            Path to created wordlist
        """
        custom_dir = self.base_path / "custom"
        custom_dir.mkdir(exist_ok=True)

        if not name.endswith(".txt"):
            name = f"{name}.txt"

        path = custom_dir / name

        with open(path, "w") as f:
            for line in content:
                f.write(f"{line}\n")

        logger.info(f"Created custom wordlist: {path}")
        return path

    def get_total_size(self) -> int:
        """Get total size of all wordlists in bytes."""
        total = 0
        for path in self.base_path.rglob("*"):
            if path.is_file():
                total += path.stat().st_size
        return total

    def get_stats(self) -> Dict[str, Any]:
        """Get wordlist statistics."""
        total_files = 0
        total_size = 0
        categories = {}

        for path in self.base_path.rglob("*.txt"):
            if path.is_file():
                total_files += 1
                size = path.stat().st_size
                total_size += size

                cat = self._determine_category(path)
                if cat not in categories:
                    categories[cat] = {"count": 0, "size": 0}
                categories[cat]["count"] += 1
                categories[cat]["size"] += size

        return {
            "total_files": total_files,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "categories": categories,
            "sources_downloaded": [
                s for s in WORDLIST_SOURCES
                if (self.base_path / s).exists()
            ],
        }
