"""
AIPTX Offline Mode Module
=========================

Provides fully offline operation capabilities including:
- Offline data management (wordlists, templates, CVE databases)
- Readiness checking for offline operation
- Database synchronization when online
"""

from .data_manager import OfflineDataConfig, OfflineDataManager
from .readiness import OfflineReadinessChecker, ReadinessResult
from .wordlists import RECOMMENDED_WORDLISTS, WORDLIST_SOURCES, WordlistManager

__all__ = [
    "OfflineDataManager",
    "OfflineDataConfig",
    "WordlistManager",
    "WORDLIST_SOURCES",
    "RECOMMENDED_WORDLISTS",
    "OfflineReadinessChecker",
    "ReadinessResult",
]
