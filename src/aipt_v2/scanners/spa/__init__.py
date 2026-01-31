"""
AIPTX SPA Scanner - Single-Page Application Security Testing

Provides comprehensive SPA security testing:
- Browser-based crawling with Playwright
- DOM-based XSS detection
- Client-side routing analysis
- State management inspection
- API request interception
- Source map analysis
"""

from aipt_v2.scanners.spa.scanner import (
    SPAScanner,
    SPAScanConfig,
    SPAScanResult,
    DOMXSSFinding,
)

__all__ = [
    "SPAScanner",
    "SPAScanConfig",
    "SPAScanResult",
    "DOMXSSFinding",
]
