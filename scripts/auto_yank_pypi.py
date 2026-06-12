#!/usr/bin/env python3
"""
Automated PyPI Version Yanking using Playwright

This script automates the process of yanking multiple PyPI versions
through browser automation since PyPI doesn't provide an API for yanking.

Requirements:
    pip install playwright
    playwright install chromium

Usage:
    python3 scripts/auto_yank_pypi.py
"""

import asyncio

from playwright.async_api import TimeoutError as PlaywrightTimeout
from playwright.async_api import async_playwright

PACKAGE_NAME = "aiptx"
YANK_REASON = "Security: hardcoded API credentials exposed"

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


async def wait_for_login(page, target_url: str, max_wait: int = 300):
    """Wait for user to login and reach the target page."""
    print(f"Waiting for login (max {max_wait}s)...")
    print("Please login in the browser window...")
    print()

    for i in range(max_wait):
        current_url = page.url
        if "manage/project" in current_url and "releases" in current_url:
            print("✓ Login successful, on releases page!")
            return True
        await asyncio.sleep(1)
        if i > 0 and i % 30 == 0:
            print(f"  Still waiting... ({i}s)")

    print("✗ Timeout waiting for login")
    return False


async def yank_version(page, version: str) -> str:
    """
    Yank a single version on the releases page.
    Returns: 'yanked', 'already_yanked', 'not_found', or 'error'
    """
    try:
        # Find the row for this version using various selectors
        # PyPI table structure: <tr> containing <a href="/project/aiptx/VERSION/">
        version_link = page.locator(f'a[href="/project/{PACKAGE_NAME}/{version}/"]')

        if await version_link.count() == 0:
            return "not_found"

        # Get the parent row
        version_row = page.locator(f'tr:has(a[href="/project/{PACKAGE_NAME}/{version}/"])')

        # Check if already yanked
        row_text = await version_row.inner_text()
        if "yanked" in row_text.lower():
            return "already_yanked"

        # Find the options menu button in this row
        # PyPI uses a dropdown with class "dropdown" or similar
        options_btn = version_row.locator(
            'details summary, button.dropdown-trigger, [data-dropdown-trigger], button:has-text("Options")'
        ).first

        if await options_btn.count() == 0:
            # Fallback: find any clickable element that might be options
            options_btn = version_row.locator("details, .dropdown").first

        if await options_btn.count() == 0:
            return "error"

        # Click to open dropdown
        await options_btn.click()
        await page.wait_for_timeout(300)

        # Find and click the Yank option
        # It might be in a dropdown menu or modal
        yank_link = page.locator('a:has-text("Yank"), button:has-text("Yank")').first

        if await yank_link.count() == 0:
            # Close dropdown and try again
            await page.keyboard.press("Escape")
            return "error"

        await yank_link.click()
        await page.wait_for_timeout(500)

        # Look for the yank confirmation modal/form
        # Fill in the reason
        reason_input = page.locator(
            '#yanked_reason, input[name="yanked_reason"], textarea[name="yanked_reason"]'
        ).first
        if await reason_input.count() > 0:
            await reason_input.fill(YANK_REASON)

        # Click confirm/submit
        submit_btn = page.locator(
            'button[type="submit"]:has-text("Yank"), input[type="submit"][value*="Yank"], button.primary:has-text("Yank"), form button[type="submit"]'
        ).first

        if await submit_btn.count() > 0:
            await submit_btn.click()
            await page.wait_for_timeout(1000)
            return "yanked"

        return "error"

    except PlaywrightTimeout:
        return "timeout"
    except Exception as e:
        print(f"    Error: {e}")
        return "error"


async def main():
    print("=" * 60)
    print("AIPTX Automated PyPI Yanking")
    print("=" * 60)
    print()
    print(f"Package: {PACKAGE_NAME}")
    print(f"Versions to yank: {len(AFFECTED_VERSIONS)}")
    print(f"Reason: {YANK_REASON}")
    print()

    async with async_playwright() as p:
        # Launch browser in headed mode so user can login
        print("Launching browser...")
        browser = await p.chromium.launch(headless=False, slow_mo=100)  # Slow down for visibility
        context = await browser.new_context(viewport={"width": 1280, "height": 900})
        page = await context.new_page()

        # Navigate to PyPI releases management page
        releases_url = f"https://pypi.org/manage/project/{PACKAGE_NAME}/releases/"
        print(f"Opening: {releases_url}")
        print()

        await page.goto(releases_url)
        await page.wait_for_load_state("domcontentloaded")

        # Check if we need to login (redirected to login page)
        if "login" in page.url.lower() or "account" in page.url.lower():
            print("=" * 60)
            print("LOGIN REQUIRED")
            print("Please login to PyPI in the browser window.")
            print("The script will continue automatically after login.")
            print("=" * 60)
            print()

            logged_in = await wait_for_login(page, releases_url)
            if not logged_in:
                print("Failed to detect login. Exiting.")
                await browser.close()
                return

        await page.wait_for_load_state("networkidle")
        await page.wait_for_timeout(1000)

        print()
        print("Starting yank process...")
        print("-" * 60)

        results = {
            "yanked": [],
            "already_yanked": [],
            "not_found": [],
            "error": [],
        }

        for i, version in enumerate(AFFECTED_VERSIONS, 1):
            print(f"[{i:2}/{len(AFFECTED_VERSIONS)}] Processing {version}...", end=" ")

            result = await yank_version(page, version)
            results.get(result, results["error"]).append(version)

            if result == "yanked":
                print("✓ Yanked")
            elif result == "already_yanked":
                print("○ Already yanked")
            elif result == "not_found":
                print("? Not found")
            else:
                print("✗ Error")

            # Refresh page periodically to get fresh state
            if i % 5 == 0 and i < len(AFFECTED_VERSIONS):
                print("    Refreshing page...")
                await page.goto(releases_url)
                await page.wait_for_load_state("networkidle")
                await page.wait_for_timeout(500)

        print()
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"  ✓ Yanked:         {len(results['yanked'])}")
        print(f"  ○ Already yanked: {len(results['already_yanked'])}")
        print(f"  ? Not found:      {len(results['not_found'])}")
        print(f"  ✗ Errors:         {len(results['error'])}")
        print(f"  Total processed:  {len(AFFECTED_VERSIONS)}")
        print()

        if results["yanked"]:
            print(f"Yanked versions: {', '.join(results['yanked'])}")
        if results["error"]:
            print(f"Failed versions (manual yank needed): {', '.join(results['error'])}")

        print()
        print("Browser will stay open for 30 seconds for review...")
        print("You can manually yank any failed versions.")
        await page.wait_for_timeout(30000)

        await browser.close()
        print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
