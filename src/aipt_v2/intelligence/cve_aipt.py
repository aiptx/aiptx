"""
AIPT CVE Intelligence - Vulnerability prioritization and exploit search
Prioritizes CVEs by actual exploitability, not just CVSS.

Inspired by: pentest-agent's CVE scoring formula
Score = 0.3*CVSS + 0.3*EPSS + 0.2*trending + 0.2*has_poc
"""

import os
import json
import time
import logging
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path

import requests

# Logger for CVE intelligence module
logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """Structured CVE information"""
    cve_id: str
    cvss: float = 0.0
    epss: float = 0.0
    description: str = ""
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploit_urls: list[str] = field(default_factory=list)
    is_trending: bool = False
    has_poc: bool = False
    priority_score: float = 0.0


class CVEIntelligence:
    """
    CVE intelligence and prioritization.

    Features:
    - Multi-source CVE data (CVEMap, NVD)
    - EPSS scoring for exploit probability
    - POC/exploit detection
    - Caching for performance
    """

    # Scoring weights (from pentest-agent)
    WEIGHT_CVSS = 0.3
    WEIGHT_EPSS = 0.3
    WEIGHT_TRENDING = 0.2
    WEIGHT_HAS_POC = 0.2

    # API endpoints
    CVEMAP_API = "https://cvedb.shodan.io/cve/{cve_id}"
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    EPSS_API = "https://api.first.org/data/v1/epss?cve={cve_id}"

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        cache_hours: int = 24,
    ):
        self.cache_dir = Path(cache_dir or os.path.expanduser("~/.aipt/cve_cache"))
        self.cache_hours = cache_hours
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def lookup(self, cve_id: str) -> CVEInfo:
        """
        Look up CVE information.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            CVEInfo with all available data
        """
        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        # Check cache
        cached = self._get_cached(cve_id)
        if cached:
            return cached

        # Fetch fresh data
        info = self._fetch_cve(cve_id)

        # Calculate priority score
        info.priority_score = self._calculate_priority(info)

        # Cache result
        self._cache(cve_id, info)

        return info

    def prioritize(self, cve_ids: list[str]) -> list[CVEInfo]:
        """
        Prioritize a list of CVEs by exploitability.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            List of CVEInfo sorted by priority score (highest first)
        """
        results = []

        for cve_id in cve_ids:
            try:
                info = self.lookup(cve_id)
                results.append(info)
            except Exception as e:
                # Create minimal info for failed lookups
                results.append(CVEInfo(
                    cve_id=cve_id,
                    description=f"Lookup failed: {e}",
                ))

        # Sort by priority score (descending)
        results.sort(key=lambda x: x.priority_score, reverse=True)

        return results

    def search_exploits(self, cve_id: str) -> list[str]:
        """
        Search for public exploits for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of exploit URLs
        """
        exploits = []

        # Search GitHub
        github_exploits = self._search_github_exploits(cve_id)
        exploits.extend(github_exploits)

        # Search ExploitDB
        edb_exploits = self._search_exploitdb(cve_id)
        exploits.extend(edb_exploits)

        return list(set(exploits))  # Deduplicate

    def _fetch_cve(self, cve_id: str) -> CVEInfo:
        """Fetch CVE data from multiple sources"""
        info = CVEInfo(cve_id=cve_id)

        # Try CVEMap (Shodan) first - faster
        try:
            resp = requests.get(
                self.CVEMAP_API.format(cve_id=cve_id),
                timeout=10,
            )
            if resp.ok:
                data = resp.json()
                info.cvss = float(data.get("cvss", 0) or 0)
                info.description = data.get("summary", "")
                info.references = data.get("references", [])
                info.is_trending = data.get("is_trending", False)

                # Check for POC
                refs_str = " ".join(info.references).lower()
                info.has_poc = any(kw in refs_str for kw in [
                    "exploit", "poc", "github.com", "exploit-db"
                ])
        except Exception as e:
            logger.debug("CVEMap lookup failed for %s: %s", cve_id, str(e))

        # Get EPSS score
        try:
            resp = requests.get(
                self.EPSS_API.format(cve_id=cve_id),
                timeout=10,
            )
            if resp.ok:
                data = resp.json()
                if data.get("data"):
                    info.epss = float(data["data"][0].get("epss", 0))
        except Exception as e:
            logger.debug("EPSS lookup failed for %s: %s", cve_id, str(e))

        # Fallback to NVD if no CVSS
        if info.cvss == 0:
            try:
                resp = requests.get(
                    self.NVD_API.format(cve_id=cve_id),
                    timeout=15,
                )
                if resp.ok:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        cve_data = vulns[0].get("cve", {})
                        metrics = cve_data.get("metrics", {})

                        # Try CVSS v3.1
                        if "cvssMetricV31" in metrics:
                            info.cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV30" in metrics:
                            info.cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV2" in metrics:
                            info.cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                        # Description
                        descriptions = cve_data.get("descriptions", [])
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                info.description = desc.get("value", "")
                                break
            except Exception as e:
                logger.debug("NVD lookup failed for %s: %s", cve_id, str(e))

        # Search for exploits
        info.exploit_urls = self.search_exploits(cve_id)
        if info.exploit_urls:
            info.has_poc = True

        return info

    def calculate_priority(
        self,
        cvss: float = 0.0,
        epss: float = 0.0,
        trending: bool = False,
        has_poc: bool = False,
    ) -> float:
        """
        Calculate priority score using pentest-agent formula.

        Score = 0.3*CVSS + 0.3*EPSS + 0.2*trending + 0.2*has_poc

        Args:
            cvss: CVSS score (0-10)
            epss: EPSS score (0-1)
            trending: Whether CVE is trending
            has_poc: Whether POC exists

        Returns:
            Priority score (0-1)
        """
        cvss_normalized = cvss / 10.0  # CVSS is 0-10
        epss_normalized = epss  # EPSS is already 0-1
        trending_score = 1.0 if trending else 0.0
        poc_score = 1.0 if has_poc else 0.0

        score = (
            self.WEIGHT_CVSS * cvss_normalized +
            self.WEIGHT_EPSS * epss_normalized +
            self.WEIGHT_TRENDING * trending_score +
            self.WEIGHT_HAS_POC * poc_score
        )

        return round(score, 4)

    def _calculate_priority(self, info: CVEInfo) -> float:
        """Internal method using CVEInfo object"""
        return self.calculate_priority(
            cvss=info.cvss,
            epss=info.epss,
            trending=info.is_trending,
            has_poc=info.has_poc,
        )

    def _search_github_exploits(self, cve_id: str) -> list[str]:
        """Search GitHub for exploits"""
        exploits = []
        try:
            # GitHub code search API (requires auth for higher rate limits)
            search_url = f"https://api.github.com/search/repositories?q={cve_id}+exploit&per_page=5"
            resp = requests.get(search_url, timeout=10)
            if resp.ok:
                data = resp.json()
                for item in data.get("items", [])[:5]:
                    exploits.append(item.get("html_url", ""))
        except Exception as e:
            logger.debug("GitHub exploit search failed for %s: %s", cve_id, str(e))
        return exploits

    def _search_exploitdb(self, cve_id: str) -> list[str]:
        """Search ExploitDB for exploits"""
        exploits = []
        try:
            # ExploitDB search
            search_url = f"https://www.exploit-db.com/search?cve={cve_id}"
            exploits.append(search_url)  # Return search URL as reference
        except Exception as e:
            logger.debug("ExploitDB search failed for %s: %s", cve_id, str(e))
        return exploits

    def _get_cached(self, cve_id: str) -> Optional[CVEInfo]:
        """Get cached CVE data if valid"""
        cache_file = self.cache_dir / f"{cve_id}.json"

        if not cache_file.exists():
            return None

        # Check age
        age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
        if age_hours > self.cache_hours:
            return None

        try:
            with open(cache_file, "r") as f:
                data = json.load(f)
                return CVEInfo(**data)
        except Exception:
            return None

    def _cache(self, cve_id: str, info: CVEInfo) -> None:
        """Cache CVE data"""
        cache_file = self.cache_dir / f"{cve_id}.json"

        try:
            with open(cache_file, "w") as f:
                json.dump({
                    "cve_id": info.cve_id,
                    "cvss": info.cvss,
                    "epss": info.epss,
                    "description": info.description,
                    "affected_products": info.affected_products,
                    "references": info.references,
                    "exploit_urls": info.exploit_urls,
                    "is_trending": info.is_trending,
                    "has_poc": info.has_poc,
                    "priority_score": info.priority_score,
                }, f)
        except Exception as e:
            logger.debug("Failed to cache CVE data for %s: %s", info.cve_id, str(e))
