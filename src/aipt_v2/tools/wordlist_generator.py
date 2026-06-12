"""
AIPTX Wordlist Generator - Targeted Password Lists.

Generate targeted wordlists for password attacks:
- Company-specific wordlists
- Target-based permutations (name, birthdate, hobbies)
- Pattern-based generation
- Common password mutations with leet speak

Integrated from Zen-AI-Pentest for AIPTX v5.2.

Example usage:
    from aipt_v2.tools import WordlistGenerator

    gen = WordlistGenerator()

    # Company-specific
    words = gen.generate_company_wordlist(
        "Acme Corp",
        industry="tech",
        locations=["NYC", "London"]
    )

    # Target-specific
    words = gen.generate_targeted_wordlist({
        "first_name": "John",
        "last_name": "Doe",
        "birthdate": "1990-05-15",
        "pet_names": ["max", "bella"],
    })

    # Password mutations
    mutations = gen.mutate_password("Password123")
"""

import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class WordlistConfig:
    """Configuration for wordlist generation."""

    min_length: int = 4
    max_length: int = 20
    include_numbers: bool = True
    include_special: bool = False
    include_years: bool = True
    years_range: List[int] = field(
        default_factory=lambda: [2020, 2021, 2022, 2023, 2024, 2025, 2026]
    )
    mutations: bool = True
    mutation_level: str = "medium"  # low, medium, high


class WordlistGenerator:
    """
    Generate targeted wordlists for password attacks.

    Features:
    - Target-specific word generation
    - Pattern-based permutations
    - Common password mutations
    - Leet speak transformations
    - Seasonal/year-based passwords
    """

    COMMON_SUFFIXES = [
        "1",
        "12",
        "123",
        "1234",
        "12345",
        "01",
        "02",
        "03",
        "04",
        "05",
        "06",
        "07",
        "08",
        "09",
        "10",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "17",
        "18",
        "19",
        "20",
        "00",
        "99",
        "88",
        "77",
        "66",
        "55",
        "44",
        "33",
        "22",
        "007",
        "666",
        "777",
        "888",
        "999",
        "000",
        "!",
        "!!",
        "@",
        "#",
        "$",
        "%",
        "&",
        "*",
        "2023",
        "2024",
        "2025",
        "2026",
        "23",
        "24",
        "25",
        "26",
    ]

    COMMON_PREFIXES = ["", "The", "My", "Mr", "Ms", "Dr", "Admin", "User", "Test"]

    SPECIAL_CHARS = ["!", "@", "#", "$", "%", "&", "*", "?", "_", "-"]

    SEASONS = ["Spring", "Summer", "Fall", "Autumn", "Winter"]

    MONTHS = [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]

    LEET_SPEAK = {
        "a": ["4", "@"],
        "e": ["3"],
        "i": ["1", "!"],
        "o": ["0"],
        "s": ["5", "$"],
        "t": ["7"],
        "l": ["1"],
        "g": ["9"],
        "b": ["8"],
    }

    COMMON_BASES = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "monkey",
        "letmein",
        "dragon",
        "111111",
        "baseball",
        "iloveyou",
        "trustno1",
        "sunshine",
        "princess",
        "admin",
        "welcome",
        "shadow",
        "ashley",
        "football",
        "jesus",
        "michael",
        "ninja",
        "mustang",
        "password1",
        "123456789",
        "adobe123",
        "admin123",
        "root",
        "toor",
        "guest",
        "default",
        "changeme",
        "p@ssw0rd",
        "Passw0rd",
        "Password1",
        "P@ssword",
        "Qwerty123",
        "Welcome1",
        "Summer2024",
        "Winter2024",
    ]

    def __init__(self, config: Optional[WordlistConfig] = None):
        """
        Initialize the wordlist generator.

        Args:
            config: Optional configuration
        """
        self.config = config or WordlistConfig()
        self._generated: Set[str] = set()

    def generate_company_wordlist(
        self,
        company_name: str,
        industry: Optional[str] = None,
        locations: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Generate wordlist based on company information.

        Args:
            company_name: Company name
            industry: Industry type (tech, finance, healthcare, etc.)
            locations: Office locations
            keywords: Additional keywords

        Returns:
            List of generated passwords
        """
        words: Set[str] = set()

        # Base words from company name
        base_words = self._extract_base_words(company_name)
        words.update(base_words)

        # Add industry terms
        if industry:
            industry_words = self._get_industry_words(industry)
            words.update(industry_words)

        # Add locations
        if locations:
            for loc in locations:
                words.update(self._extract_base_words(loc))

        # Add keywords
        if keywords:
            for kw in keywords:
                words.update(self._extract_base_words(kw))

        # Generate permutations
        all_words: Set[str] = set(words)
        for word in words:
            all_words.update(self._generate_permutations(word))
            all_words.update(self._add_numbers(word))

            if self.config.include_special:
                all_words.update(self._add_special(word))

            if self.config.mutations:
                all_words.update(self._mutate_word(word))

        # Add years to base words
        if self.config.include_years:
            for word in list(words)[:30]:  # Limit to prevent explosion
                for year in self.config.years_range:
                    all_words.add(f"{word}{year}")
                    all_words.add(f"{year}{word}")
                    all_words.add(f"{word}{str(year)[2:]}")

        # Filter by length
        filtered = {
            w for w in all_words if self.config.min_length <= len(w) <= self.config.max_length
        }

        return sorted(list(filtered))

    def generate_targeted_wordlist(self, target_info: Dict[str, Any]) -> List[str]:
        """
        Generate wordlist from target information.

        Args:
            target_info: Dictionary containing:
                - first_name: First name
                - last_name: Last name
                - birthdate: Birth date (YYYY-MM-DD)
                - pet_names: List of pet names
                - hobbies: List of hobbies
                - favorite_things: List of favorite items
                - phone: Phone number
                - username: Known username

        Returns:
            List of generated passwords
        """
        keywords: List[str] = []

        # Names
        if "first_name" in target_info:
            fn = target_info["first_name"]
            keywords.extend([fn, fn.lower(), fn.capitalize()])

        if "last_name" in target_info:
            ln = target_info["last_name"]
            keywords.extend([ln, ln.lower(), ln.capitalize()])

        # Birth date variations
        if "birthdate" in target_info:
            bd = target_info["birthdate"]
            parts = bd.split("-")
            if len(parts) == 3:
                year, month, day = parts
                keywords.extend(
                    [
                        bd.replace("-", ""),  # 19900515
                        bd.replace("-", "")[2:],  # 900515
                        bd.replace("-", "/"),  # 1990/05/15
                        f"{month}{day}{year}",  # 05151990
                        f"{month}{day}{year[2:]}",  # 051590
                        f"{day}{month}{year}",  # 15051990
                        f"{day}{month}",  # 1505
                        f"{month}{day}",  # 0515
                        year,  # 1990
                        year[2:],  # 90
                    ]
                )

        # Pet names
        if "pet_names" in target_info:
            for pet in target_info["pet_names"]:
                keywords.extend([pet, pet.lower(), pet.capitalize()])

        # Hobbies
        if "hobbies" in target_info:
            keywords.extend(target_info["hobbies"])

        # Favorites
        if "favorite_things" in target_info:
            keywords.extend(target_info["favorite_things"])

        # Phone number
        if "phone" in target_info:
            phone = re.sub(r"\D", "", target_info["phone"])  # Remove non-digits
            keywords.extend([phone, phone[-4:], phone[-6:]])

        # Username
        if "username" in target_info:
            keywords.append(target_info["username"])

        # Generate name combinations
        base_words: Set[str] = set(keywords)

        if "first_name" in target_info and "last_name" in target_info:
            first = target_info["first_name"]
            last = target_info["last_name"]
            combinations = [
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                f"{last}{first}",
                f"{first[0]}.{last}",
                f"{first.lower()}{last.lower()}",
                f"{first.capitalize()}{last.capitalize()}",
                f"{last.lower()}{first[0].lower()}",
            ]
            base_words.update(combinations)

        # Generate permutations
        all_words: Set[str] = set(base_words)
        for word in base_words:
            all_words.update(self._generate_permutations(word))
            all_words.update(self._add_numbers(word))

            if self.config.mutations:
                all_words.update(self._mutate_word(word))

        # Filter by length
        filtered = {
            w for w in all_words if self.config.min_length <= len(w) <= self.config.max_length
        }

        return sorted(list(filtered))

    def generate_pattern_wordlist(self, pattern: str, values: Dict[str, List[str]]) -> List[str]:
        """
        Generate wordlist from pattern.

        Args:
            pattern: Pattern with placeholders (e.g., "{word}{number}{special}")
            values: Dictionary of placeholder values

        Returns:
            List of generated passwords

        Example:
            pattern = "{word}{number}{special}"
            values = {
                "word": ["Pass", "Secret"],
                "number": ["1", "123"],
                "special": ["!", "@"]
            }
        """
        # Find all placeholders
        placeholders = re.findall(r"\{(\w+)\}", pattern)

        # Get value lists for each placeholder
        value_lists = []
        for ph in placeholders:
            if ph in values:
                value_lists.append(values[ph])
            else:
                value_lists.append([f"{{{ph}}}"])

        # Generate all combinations
        words: Set[str] = set()
        for combo in itertools.product(*value_lists):
            word = pattern
            for ph, val in zip(placeholders, combo):
                word = word.replace(f"{{{ph}}}", val, 1)
            words.add(word)

        return sorted(list(words))

    def mutate_password(self, base_password: str) -> List[str]:
        """
        Generate common password mutations.

        Args:
            base_password: Base password to mutate

        Returns:
            List of mutated passwords

        Mutations include:
        - Case variations
        - Leet speak transformations
        - Number/special char appending
        - Common substitutions
        """
        mutations: Set[str] = set()
        mutations.add(base_password)

        # Case variations
        mutations.add(base_password.lower())
        mutations.add(base_password.upper())
        mutations.add(base_password.capitalize())
        mutations.add(base_password.swapcase())
        mutations.add(base_password.title())

        # Leet speak
        leet_versions = self._apply_leet_speak(base_password)
        mutations.update(leet_versions)

        # Add numbers
        mutations.update(self._add_numbers(base_password))

        # Add special chars
        if self.config.include_special:
            mutations.update(self._add_special(base_password))

        # Reverse
        mutations.add(base_password[::-1])

        # Duplicate
        mutations.add(base_password * 2)

        # Common substitutions
        substitutions = [
            ("a", "@"),
            ("a", "4"),
            ("e", "3"),
            ("i", "1"),
            ("i", "!"),
            ("o", "0"),
            ("s", "$"),
            ("s", "5"),
            ("t", "7"),
        ]

        for old, new in substitutions:
            mutated = base_password.replace(old, new).replace(old.upper(), new)
            mutations.add(mutated)
            mutations.add(mutated.capitalize())

        return sorted(list(mutations))

    def generate_common_passwords(self, count: int = 10000) -> List[str]:
        """
        Generate list of common passwords with variations.

        Args:
            count: Maximum number of passwords to return

        Returns:
            List of common passwords with mutations
        """
        passwords: Set[str] = set(self.COMMON_BASES)

        # Add mutations for top passwords
        for base in self.COMMON_BASES[:40]:
            passwords.update(self.mutate_password(base))

        # Add years
        for base in self.COMMON_BASES[:20]:
            for year in self.config.years_range:
                passwords.add(f"{base}{year}")
                passwords.add(f"{base}{str(year)[2:]}")

        return sorted(list(passwords))[:count]

    def save_wordlist(self, words: List[str], filepath: str) -> Path:
        """
        Save wordlist to file.

        Args:
            words: List of words to save
            filepath: Output file path

        Returns:
            Path to saved file
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            for word in words:
                f.write(f"{word}\n")

        return path.absolute()

    def _extract_base_words(self, text: str) -> Set[str]:
        """Extract base words from text."""
        words: Set[str] = set()

        # Original variations
        words.add(text)
        words.add(text.lower())
        words.add(text.upper())
        words.add(text.capitalize())

        # Remove spaces
        words.add(text.replace(" ", ""))
        words.add(text.replace(" ", "").lower())

        # Remove special chars
        clean = "".join(c for c in text if c.isalnum())
        words.add(clean)
        words.add(clean.lower())

        # Acronyms
        if " " in text:
            parts = text.split()
            if len(parts) >= 2:
                acronym = "".join(word[0] for word in parts if word)
                words.add(acronym)
                words.add(acronym.upper())
                words.add(acronym.lower())

        return words

    def _get_industry_words(self, industry: str) -> Set[str]:
        """Get common words for an industry."""
        industry_terms = {
            "tech": ["tech", "software", "digital", "data", "cloud", "cyber", "it", "dev", "code"],
            "finance": ["finance", "bank", "money", "capital", "invest", "trade", "stock", "fund"],
            "healthcare": ["health", "medical", "care", "clinic", "patient", "doctor", "nurse"],
            "education": ["edu", "school", "learn", "student", "academy", "college", "university"],
            "retail": ["shop", "store", "retail", "sale", "market", "buy", "ecommerce"],
            "manufacturing": ["mfg", "factory", "production", "supply", "logistics"],
            "legal": ["law", "legal", "attorney", "court", "justice"],
            "media": ["media", "news", "press", "publish", "content", "creative"],
        }

        return set(industry_terms.get(industry.lower(), []))

    def _generate_permutations(self, word: str) -> Set[str]:
        """Generate case and format permutations."""
        perms: Set[str] = {
            word,
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase(),
        }

        # CamelCase
        if " " in word:
            camel = "".join(w.capitalize() for w in word.split())
            perms.add(camel)
            perms.add(camel.lower())

        return perms

    def _add_numbers(self, word: str) -> Set[str]:
        """Add number suffixes/prefixes."""
        results: Set[str] = set()

        for suffix in self.COMMON_SUFFIXES:
            results.add(f"{word}{suffix}")
            results.add(f"{suffix}{word}")

        return results

    def _add_special(self, word: str) -> Set[str]:
        """Add special characters."""
        results: Set[str] = set()

        for char in self.SPECIAL_CHARS:
            results.add(f"{word}{char}")
            results.add(f"{char}{word}")
            results.add(f"{word}{char}{char}")

        return results

    def _mutate_word(self, word: str) -> Set[str]:
        """Apply word mutations."""
        mutations: Set[str] = set()

        # Add years
        for year in self.config.years_range:
            mutations.add(f"{word}{year}")
            mutations.add(f"{word}{str(year)[2:]}")

        # Add seasons
        for season in self.SEASONS:
            mutations.add(f"{word}{season}")
            mutations.add(f"{season}{word}")

        # Add months
        for month in self.MONTHS[:12]:  # Short names only
            mutations.add(f"{word}{month}")
            mutations.add(f"{month}{word}")

        return mutations

    def _apply_leet_speak(self, text: str) -> Set[str]:
        """Apply leet speak transformations."""
        results: Set[str] = set()

        for char, replacements in self.LEET_SPEAK.items():
            for replacement in replacements:
                leet = text.replace(char, replacement).replace(char.upper(), replacement)
                results.add(leet)

        return results


# Convenience functions
def generate_company_wordlist(
    company: str,
    industry: Optional[str] = None,
    locations: Optional[List[str]] = None,
    keywords: Optional[List[str]] = None,
) -> List[str]:
    """
    Convenience function for company wordlist generation.

    Args:
        company: Company name
        industry: Industry type
        locations: Office locations
        keywords: Additional keywords

    Returns:
        List of generated passwords
    """
    gen = WordlistGenerator()
    return gen.generate_company_wordlist(company, industry, locations, keywords)


def generate_targeted_wordlist(target_info: Dict[str, Any]) -> List[str]:
    """
    Convenience function for targeted wordlist generation.

    Args:
        target_info: Target information dictionary

    Returns:
        List of generated passwords
    """
    gen = WordlistGenerator()
    return gen.generate_targeted_wordlist(target_info)


def mutate_password(password: str) -> List[str]:
    """
    Convenience function for password mutation.

    Args:
        password: Base password

    Returns:
        List of mutated passwords
    """
    gen = WordlistGenerator()
    return gen.mutate_password(password)
