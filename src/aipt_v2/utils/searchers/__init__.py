"""
Searcher Utilities for AIPT v2
==============================

Provides utility functions for intelligence searchers:
- Domain filtering
- File extension filtering
- Repository filtering
- Directory cleanup

These are stub implementations for compatibility with
intelligence/searchers modules.
"""

import os
import re
from typing import List, Set
from pathlib import Path

from aipt_v2.utils.logging import logger


# Blocked domains for security/ethical reasons
BLOCKED_DOMAINS: Set[str] = {
    ".gov",
    ".mil",
    ".edu",
    ".bank",
    ".police",
}

# Allowed web page extensions
WEB_EXTENSIONS: Set[str] = {
    ".html",
    ".htm",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".do",
    "",  # No extension
}

# Blocked file patterns for GitHub
BLOCKED_GITHUB_PATTERNS: Set[str] = {
    "README",
    "LICENSE",
    "CHANGELOG",
    "CONTRIBUTING",
    ".md",
    ".txt",
    ".rst",
    ".lock",
}


class DomainFilter:
    """Filter domains based on security/ethical rules."""

    def __init__(self, blocked: Set[str] = None, allowed: Set[str] = None):
        self.blocked = blocked or BLOCKED_DOMAINS
        self.allowed = allowed or set()

    def __call__(self, domain: str) -> bool:
        return self.is_allowed(domain)

    def is_allowed(self, domain: str) -> bool:
        """
        Check if domain is allowed for scanning.

        Args:
            domain: Domain to check

        Returns:
            True if domain is allowed
        """
        domain_lower = domain.lower()

        # Check blocked list
        for blocked in self.blocked:
            if domain_lower.endswith(blocked):
                logger.debug("Domain blocked", domain=domain, reason=f"ends with {blocked}")
                return False

        # If allowed list exists, check it
        if self.allowed:
            for allowed in self.allowed:
                if domain_lower.endswith(allowed):
                    return True
            return False

        return True


class ExtensionFilter:
    """Filter files/URLs by extension."""

    def __init__(self, allowed: Set[str] = None, blocked: Set[str] = None):
        self.allowed = allowed or set()
        self.blocked = blocked or set()

    def __call__(self, filename: str) -> bool:
        return self.is_allowed(filename)

    def is_allowed(self, filename: str) -> bool:
        """Check if file extension is allowed."""
        ext = Path(filename).suffix.lower()

        if self.blocked and ext in self.blocked:
            return False

        if self.allowed:
            return ext in self.allowed

        return True


class RepositoryFilter:
    """Filter GitHub repositories."""

    def __init__(self, blocked_patterns: Set[str] = None):
        self.blocked = blocked_patterns or set()

    def __call__(self, repo: str) -> bool:
        return self.is_allowed(repo)

    def is_allowed(self, repo: str) -> bool:
        """Check if repository name is allowed."""
        repo_lower = repo.lower()

        for pattern in self.blocked:
            if pattern.lower() in repo_lower:
                return False

        return True


# Pre-configured filter instances
domain_filter = DomainFilter()
repository_filter = RepositoryFilter()


def for_google_webpage(extension: str) -> bool:
    """
    Check if extension is valid for web pages.

    Args:
        extension: File extension (with or without dot)

    Returns:
        True if valid web page extension
    """
    ext = extension.lower()
    if not ext.startswith("."):
        ext = f".{ext}" if ext else ""

    return ext in WEB_EXTENSIONS


def for_github_repo_file(filename: str) -> bool:
    """
    Check if file should be included from GitHub repo.

    Args:
        filename: File name to check

    Returns:
        True if file should be included
    """
    filename_upper = filename.upper()

    for pattern in BLOCKED_GITHUB_PATTERNS:
        if pattern.upper() in filename_upper or filename.endswith(pattern):
            return False

    return True


def remove_empty_directories(path: str) -> int:
    """
    Remove empty directories recursively.

    Args:
        path: Root path to clean

    Returns:
        Number of directories removed
    """
    removed = 0
    path_obj = Path(path)

    if not path_obj.exists():
        return 0

    for dirpath in sorted(path_obj.rglob("*"), reverse=True):
        if dirpath.is_dir():
            try:
                # Check if directory is empty
                if not any(dirpath.iterdir()):
                    dirpath.rmdir()
                    removed += 1
                    logger.debug("Removed empty directory", path=str(dirpath))
            except OSError as e:
                logger.warning("Failed to remove directory", path=str(dirpath), error=str(e))

    return removed


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem use.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    sanitized = re.sub(r'\s+', '_', sanitized)
    sanitized = sanitized.strip('._')

    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]

    return sanitized or "unnamed"


def validate_cve_id(cve_id: str) -> bool:
    """
    Validate CVE ID format.

    Args:
        cve_id: CVE identifier to validate

    Returns:
        True if valid CVE format
    """
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id.upper()))


def extract_cve_ids(text: str) -> List[str]:
    """
    Extract CVE IDs from text.

    Args:
        text: Text to search

    Returns:
        List of CVE IDs found
    """
    pattern = r'CVE-\d{4}-\d{4,}'
    matches = re.findall(pattern, text.upper())
    return list(set(matches))


# GitHub configuration compatibility
class GitHubConfig:
    """GitHub API configuration."""
    API_URL = "https://api.github.com"
    SEARCH_URL = f"{API_URL}/search"
    RATE_LIMIT = 30  # requests per minute for unauthenticated


# Alias for backwards compatibility
c = GitHubConfig
