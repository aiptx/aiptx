"""
User-Agent Rotator

Provides realistic User-Agent strings for request rotation:
- Chrome, Firefox, Safari, Edge user agents
- Mobile user agents
- Bot/crawler user agents
- Custom user agent generation

Usage:
    from aipt_v2.evasion import UARotator, get_random_ua

    rotator = UARotator()
    ua = rotator.get_random()
"""

import random
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum


class UACategory(Enum):
    """User-Agent categories."""
    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"
    EDGE = "edge"
    MOBILE = "mobile"
    BOT = "bot"


@dataclass
class UserAgent:
    """User-Agent information."""
    string: str
    browser: str
    version: str
    os: str
    category: str


class UARotator:
    """
    User-Agent String Rotator.

    Provides realistic user agent strings for
    request rotation to avoid fingerprinting.
    """

    # Chrome User-Agents (Windows, Mac, Linux)
    CHROME_UA = [
        # Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ]

    # Firefox User-Agents
    FIREFOX_UA = [
        # Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
        # Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Linux
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ]

    # Safari User-Agents
    SAFARI_UA = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    ]

    # Edge User-Agents
    EDGE_UA = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]

    # Mobile User-Agents
    MOBILE_UA = [
        # iOS Safari
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        # Android Chrome
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    ]

    # Bot/Crawler User-Agents
    BOT_UA = [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)",
        "curl/8.4.0",
        "Wget/1.21",
        "Python-urllib/3.11",
        "python-requests/2.31.0",
    ]

    def __init__(self):
        """Initialize UA rotator."""
        self.all_uas = (
            self.CHROME_UA + self.FIREFOX_UA +
            self.SAFARI_UA + self.EDGE_UA + self.MOBILE_UA
        )
        self._current_index = 0

    def get_random(self, category: Optional[str] = None) -> UserAgent:
        """
        Get random user agent.

        Args:
            category: Optional category filter

        Returns:
            UserAgent
        """
        if category == "chrome":
            ua_list = self.CHROME_UA
        elif category == "firefox":
            ua_list = self.FIREFOX_UA
        elif category == "safari":
            ua_list = self.SAFARI_UA
        elif category == "edge":
            ua_list = self.EDGE_UA
        elif category == "mobile":
            ua_list = self.MOBILE_UA
        elif category == "bot":
            ua_list = self.BOT_UA
        else:
            ua_list = self.all_uas

        ua_string = random.choice(ua_list)
        return self._parse_ua(ua_string)

    def get_next(self) -> UserAgent:
        """
        Get next user agent (round-robin).

        Returns:
            UserAgent
        """
        ua_string = self.all_uas[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.all_uas)
        return self._parse_ua(ua_string)

    def get_all(self, category: Optional[str] = None) -> List[UserAgent]:
        """
        Get all user agents.

        Args:
            category: Optional category filter

        Returns:
            List of UserAgent
        """
        if category == "chrome":
            ua_list = self.CHROME_UA
        elif category == "firefox":
            ua_list = self.FIREFOX_UA
        elif category == "safari":
            ua_list = self.SAFARI_UA
        elif category == "edge":
            ua_list = self.EDGE_UA
        elif category == "mobile":
            ua_list = self.MOBILE_UA
        elif category == "bot":
            ua_list = self.BOT_UA
        else:
            ua_list = self.all_uas

        return [self._parse_ua(ua) for ua in ua_list]

    def _parse_ua(self, ua_string: str) -> UserAgent:
        """Parse user agent string into components."""
        browser = "Unknown"
        version = "Unknown"
        os = "Unknown"
        category = "desktop"

        # Detect browser
        if "Chrome/" in ua_string and "Edg/" not in ua_string:
            browser = "Chrome"
            version = ua_string.split("Chrome/")[1].split(" ")[0]
        elif "Firefox/" in ua_string:
            browser = "Firefox"
            version = ua_string.split("Firefox/")[1].split(" ")[0]
        elif "Safari/" in ua_string and "Chrome" not in ua_string:
            browser = "Safari"
            if "Version/" in ua_string:
                version = ua_string.split("Version/")[1].split(" ")[0]
        elif "Edg/" in ua_string:
            browser = "Edge"
            version = ua_string.split("Edg/")[1].split(" ")[0]
        elif "Googlebot" in ua_string:
            browser = "Googlebot"
            category = "bot"
        elif "bingbot" in ua_string:
            browser = "Bingbot"
            category = "bot"
        elif "curl" in ua_string:
            browser = "curl"
            category = "bot"

        # Detect OS
        if "Windows NT 10" in ua_string:
            os = "Windows 10"
        elif "Windows NT 11" in ua_string:
            os = "Windows 11"
        elif "Macintosh" in ua_string:
            os = "macOS"
        elif "Linux" in ua_string:
            os = "Linux"
        elif "iPhone" in ua_string:
            os = "iOS"
            category = "mobile"
        elif "iPad" in ua_string:
            os = "iPadOS"
            category = "mobile"
        elif "Android" in ua_string:
            os = "Android"
            category = "mobile"

        return UserAgent(
            string=ua_string,
            browser=browser,
            version=version,
            os=os,
            category=category
        )

    def generate_custom(
        self,
        browser: str = "Chrome",
        version: str = "120.0.0.0",
        os: str = "Windows"
    ) -> str:
        """
        Generate custom user agent string.

        Args:
            browser: Browser name
            version: Browser version
            os: Operating system

        Returns:
            Custom user agent string
        """
        os_strings = {
            "Windows": "Windows NT 10.0; Win64; x64",
            "Mac": "Macintosh; Intel Mac OS X 10_15_7",
            "Linux": "X11; Linux x86_64",
            "iOS": "iPhone; CPU iPhone OS 17_0 like Mac OS X",
            "Android": "Linux; Android 14; Pixel 8"
        }

        os_str = os_strings.get(os, os_strings["Windows"])

        if browser == "Chrome":
            return f"Mozilla/5.0 ({os_str}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"
        elif browser == "Firefox":
            return f"Mozilla/5.0 ({os_str}; rv:{version}) Gecko/20100101 Firefox/{version}"
        elif browser == "Safari":
            return f"Mozilla/5.0 ({os_str}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15"
        elif browser == "Edge":
            return f"Mozilla/5.0 ({os_str}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 Edg/{version}"

        return f"Mozilla/5.0 ({os_str})"


# Convenience function
def get_random_ua(category: Optional[str] = None) -> str:
    """
    Get random user agent string.

    Args:
        category: Optional category (chrome, firefox, safari, edge, mobile, bot)

    Returns:
        User agent string
    """
    rotator = UARotator()
    return rotator.get_random(category).string
