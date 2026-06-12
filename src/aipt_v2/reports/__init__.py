"""
AIPT Report Generation

Generates professional pentest reports in multiple formats:
- HTML (standalone, styled)
- Markdown (for documentation)
- JSON (for integration)
- SARIF (for GitHub Security tab integration)
"""

from .generator import ReportConfig, ReportGenerator
from .html_report import generate_html_report, generate_html_report_v2
from .sarif import SARIFConfig, SARIFGenerator, generate_sarif

__all__ = [
    "ReportGenerator",
    "ReportConfig",
    "generate_html_report",
    "generate_html_report_v2",
    # SARIF for CI/CD integration
    "SARIFGenerator",
    "SARIFConfig",
    "generate_sarif",
]
