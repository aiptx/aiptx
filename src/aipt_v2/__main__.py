#!/usr/bin/env python3
"""
AIPTX - AI-Powered Penetration Testing Framework
================================================

This module allows running aiptx as a module:
    python -m aiptx scan example.com
    python -m aiptx --help

Or directly after pipx install:
    aiptx scan example.com
"""

import sys


def main():
    """Entry point for module execution."""
    from cli import main as cli_main
    sys.exit(cli_main())


if __name__ == "__main__":
    main()
