#!/usr/bin/env python3
"""
PyPI Version Yanking Helper Script

Since PyPI doesn't provide a programmatic API for yanking,
this script opens the browser to the yank page for each affected version.

Run: python3 scripts/yank_pypi_versions.py
"""

import time
import webbrowser

# All affected versions with hardcoded credentials
AFFECTED_VERSIONS = [
    # v2.x series
    "2.0.0",
    "2.0.1",
    "2.0.2",
    "2.0.3",
    "2.0.4",
    "2.0.5",
    "2.0.6",
    "2.0.7",
    "2.0.9",
    "2.0.10",
    # v3.x series
    "3.0.0",
    "3.0.1",
    "3.0.2",
    "3.0.3",
    "3.1.0",
    "3.1.1",
    "3.1.2",
    "3.2.0",
    "3.2.1",
    "3.3.0",
    "3.3.1",
    "3.4.0",
    "3.4.1",
    "3.4.2",
    "3.4.3",
    "3.4.4",
    "3.4.5",
    "3.5.1",
    "3.5.2",
    "3.6.0",
    # v4.x and v5.x
    "4.0.0",
    "4.0.1",
    "5.0.0",
]

PACKAGE_NAME = "aiptx"


def main():
    print("=" * 60)
    print("AIPTX PyPI Version Yanking Helper")
    print("=" * 60)
    print()
    print(f"This script will help you yank {len(AFFECTED_VERSIONS)} affected versions.")
    print()
    print("For each version, you need to:")
    print("  1. Click 'Options' dropdown")
    print("  2. Select 'Yank release'")
    print("  3. Enter reason: 'Security: hardcoded credentials exposed'")
    print("  4. Confirm yank")
    print()

    # Print all URLs first
    print("URLs to yank:")
    print("-" * 60)
    for version in AFFECTED_VERSIONS:
        url = f"https://pypi.org/project/{PACKAGE_NAME}/{version}/"
        print(f"  {version}: {url}")
    print()

    response = input("Open each URL in browser? (y/n): ").strip().lower()

    if response == "y":
        print()
        print("Opening browser tabs (one every 2 seconds to avoid rate limiting)...")
        print()

        for i, version in enumerate(AFFECTED_VERSIONS, 1):
            url = f"https://pypi.org/project/{PACKAGE_NAME}/{version}/"
            print(f"[{i}/{len(AFFECTED_VERSIONS)}] Opening {version}...")
            webbrowser.open(url)

            if i < len(AFFECTED_VERSIONS):
                time.sleep(2)  # Rate limit to avoid overwhelming browser

        print()
        print("=" * 60)
        print("All tabs opened! Now yank each version manually.")
        print("=" * 60)
    else:
        print()
        print("You can manually visit each URL above to yank the versions.")
        print()
        print("Alternative: Open PyPI manage page directly:")
        print(f"  https://pypi.org/manage/project/{PACKAGE_NAME}/releases/")


if __name__ == "__main__":
    main()
