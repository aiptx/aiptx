"""
AIPTX Beast Mode - Obfuscation Module
=====================================

Command and payload obfuscation techniques.
"""

from __future__ import annotations

from aipt_v2.stealth.obfuscation.bash_obfusc import BashObfuscator
from aipt_v2.stealth.obfuscation.powershell_obfusc import PowerShellObfuscator

__all__ = [
    "PowerShellObfuscator",
    "BashObfuscator",
]
