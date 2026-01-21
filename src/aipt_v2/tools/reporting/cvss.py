"""
CVSS 3.1 Calculator
===================

Calculates CVSS 3.1 base scores and severity ratings.
Provides both programmatic and string-based vector parsing.

Integrated from Strix's reporting system.

Reference: https://www.first.org/cvss/v3.1/specification-document

Example:
    # From individual components
    score, severity, vector = calculate_cvss_score(
        attack_vector="N",      # Network
        attack_complexity="L",  # Low
        privileges_required="N", # None
        user_interaction="N",   # None
        scope="U",              # Unchanged
        confidentiality="H",    # High
        integrity="H",          # High
        availability="H",       # High
    )
    # Result: (9.8, "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    # From vector string
    score, severity = CVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").calculate()
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Literal


logger = logging.getLogger(__name__)

# Valid CVSS 3.1 parameter values
CVSS_VALID_VALUES = {
    "attack_vector": ["N", "A", "L", "P"],  # Network, Adjacent, Local, Physical
    "attack_complexity": ["L", "H"],  # Low, High
    "privileges_required": ["N", "L", "H"],  # None, Low, High
    "user_interaction": ["N", "R"],  # None, Required
    "scope": ["U", "C"],  # Unchanged, Changed
    "confidentiality": ["N", "L", "H"],  # None, Low, High
    "integrity": ["N", "L", "H"],  # None, Low, High
    "availability": ["N", "L", "H"],  # None, Low, High
}

# CVSS 3.1 metric weights
CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},  # Scope Changed
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0, "L": 0.22, "H": 0.56},
    "I": {"N": 0, "L": 0.22, "H": 0.56},
    "A": {"N": 0, "L": 0.22, "H": 0.56},
}


def validate_cvss_parameters(**kwargs: str) -> list[str]:
    """
    Validate CVSS parameter values.

    Args:
        **kwargs: CVSS parameters to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors: list[str] = []

    for param_name, valid_values in CVSS_VALID_VALUES.items():
        value = kwargs.get(param_name)
        if value is not None and value not in valid_values:
            errors.append(f"Invalid {param_name}: {value}. Must be one of: {valid_values}")

    return errors


@dataclass
class CVSSVector:
    """
    CVSS 3.1 Vector representation and calculator.

    Supports both parsing from vector string and building from components.
    """

    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"

    def __init__(self, vector_string: str | None = None, **kwargs: str):
        """
        Initialize CVSS vector.

        Args:
            vector_string: Optional CVSS vector string to parse.
            **kwargs: Individual CVSS components.
        """
        if vector_string:
            self._parse_vector(vector_string)
        else:
            self.attack_vector = kwargs.get("attack_vector", "N")
            self.attack_complexity = kwargs.get("attack_complexity", "L")
            self.privileges_required = kwargs.get("privileges_required", "N")
            self.user_interaction = kwargs.get("user_interaction", "N")
            self.scope = kwargs.get("scope", "U")
            self.confidentiality = kwargs.get("confidentiality", "N")
            self.integrity = kwargs.get("integrity", "N")
            self.availability = kwargs.get("availability", "N")

    def _parse_vector(self, vector_string: str) -> None:
        """Parse a CVSS vector string into components."""
        # Handle both "CVSS:3.1/..." and "AV:N/..." formats
        vector = vector_string.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")

        # Map short names to attributes
        mapping = {
            "AV": "attack_vector",
            "AC": "attack_complexity",
            "PR": "privileges_required",
            "UI": "user_interaction",
            "S": "scope",
            "C": "confidentiality",
            "I": "integrity",
            "A": "availability",
        }

        for part in vector.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                if key in mapping:
                    setattr(self, mapping[key], value)

    def to_string(self) -> str:
        """Convert to CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/"
            f"C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )

    def calculate(self) -> tuple[float, str]:
        """
        Calculate CVSS base score and severity.

        Returns:
            Tuple of (score, severity).
        """
        # Get weights
        av = CVSS_WEIGHTS["AV"][self.attack_vector]
        ac = CVSS_WEIGHTS["AC"][self.attack_complexity]
        pr = CVSS_WEIGHTS["PR"][self.scope][self.privileges_required]
        ui = CVSS_WEIGHTS["UI"][self.user_interaction]

        c = CVSS_WEIGHTS["C"][self.confidentiality]
        i = CVSS_WEIGHTS["I"][self.integrity]
        a = CVSS_WEIGHTS["A"][self.availability]

        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if self.scope == "U":
            impact = 6.42 * iss
        else:  # Changed scope
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif self.scope == "U":
            base_score = min(impact + exploitability, 10)
        else:  # Changed scope
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal place
        base_score = round(base_score * 10) / 10

        # Determine severity
        severity = self._score_to_severity(base_score)

        return base_score, severity

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert CVSS score to severity rating."""
        if score == 0:
            return "none"
        elif score < 4.0:
            return "low"
        elif score < 7.0:
            return "medium"
        elif score < 9.0:
            return "high"
        else:
            return "critical"


def calculate_cvss_score(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> tuple[float, str, str]:
    """
    Calculate CVSS 3.1 base score, severity, and vector string.

    Args:
        attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
        attack_complexity: L (Low), H (High)
        privileges_required: N (None), L (Low), H (High)
        user_interaction: N (None), R (Required)
        scope: U (Unchanged), C (Changed)
        confidentiality: N (None), L (Low), H (High)
        integrity: N (None), L (Low), H (High)
        availability: N (None), L (Low), H (High)

    Returns:
        Tuple of (score, severity, vector_string).
        Example: (9.8, "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    Raises:
        ValueError: If any parameter is invalid.
    """
    # Validate parameters
    errors = validate_cvss_parameters(
        attack_vector=attack_vector,
        attack_complexity=attack_complexity,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        scope=scope,
        confidentiality=confidentiality,
        integrity=integrity,
        availability=availability,
    )

    if errors:
        raise ValueError(f"Invalid CVSS parameters: {'; '.join(errors)}")

    # Try to use the cvss library if available
    try:
        from cvss import CVSS3

        vector_string = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/"
            f"PR:{privileges_required}/UI:{user_interaction}/S:{scope}/"
            f"C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        c = CVSS3(vector_string)
        scores = c.scores()
        severities = c.severities()

        base_score = scores[0]
        base_severity = severities[0].lower()

        return base_score, base_severity, vector_string

    except ImportError:
        # Fall back to our implementation
        logger.debug("cvss library not available, using built-in calculator")

        vector = CVSSVector(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )

        score, severity = vector.calculate()
        return score, severity, vector.to_string()

    except Exception as e:
        logger.exception(f"CVSS calculation failed: {e}")
        # Return a safe default
        return 7.5, "high", ""


def calculate_cvss_from_string(vector_string: str) -> tuple[float, str]:
    """
    Calculate CVSS score from a vector string.

    Args:
        vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")

    Returns:
        Tuple of (score, severity).
    """
    try:
        from cvss import CVSS3

        c = CVSS3(vector_string)
        scores = c.scores()
        severities = c.severities()
        return scores[0], severities[0].lower()

    except ImportError:
        vector = CVSSVector(vector_string)
        return vector.calculate()

    except Exception as e:
        logger.exception(f"CVSS calculation failed: {e}")
        return 7.5, "high"
