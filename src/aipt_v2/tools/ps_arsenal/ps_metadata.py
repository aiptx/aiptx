"""
PowerShell Arsenal Script Metadata Registry

Complete metadata for all 87 PowerShell scripts.
Maps scripts to their capabilities, parameters, MITRE ATT&CK techniques,
and execution requirements.

Usage:
    from aipt_v2.tools.ps_arsenal.ps_metadata import (
        SCRIPT_METADATA,
        get_script_metadata,
        get_scripts_by_category
    )

    metadata = get_script_metadata("Invoke-Mimikatz")
    gather_scripts = get_scripts_by_category(ScriptCategory.GATHER)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

# Import RequiredPrivilege from ps_config to avoid duplicate enum definitions
from aipt_v2.tools.ps_arsenal.ps_config import RequiredPrivilege


class ScriptCategory(Enum):
    """PowerShell script categories."""

    GATHER = "Gather"
    SHELLS = "Shells"
    UTILITY = "Utility"
    BACKDOORS = "Backdoors"
    CLIENT = "Client"
    ESCALATION = "Escalation"
    EXECUTION = "Execution"
    SCAN = "Scan"
    PIVOT = "Pivot"
    MITM = "MITM"
    ACTIVE_DIRECTORY = "ActiveDirectory"
    BYPASS = "Bypass"
    MISC = "Misc"
    PRASADHAK = "Prasadhak"


class OutputType(Enum):
    """Script output type."""

    TEXT = "text"
    CREDENTIALS = "credentials"
    SHELL = "shell"
    FILE = "file"
    STREAM = "stream"


@dataclass
class ScriptMetadata:
    """Metadata for a single PowerShell script."""

    name: str
    category: ScriptCategory
    function_name: str
    description: str
    required_privilege: RequiredPrivilege
    parameters: Dict[str, str] = field(default_factory=dict)
    required_params: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    output_type: OutputType = OutputType.TEXT
    is_destructive: bool = False
    requires_interaction: bool = False
    remote_capable: bool = True
    supports_exfil: bool = False


# =============================================================================
# COMPLETE SCRIPT METADATA REGISTRY (87 scripts)
# =============================================================================

SCRIPT_METADATA: Dict[str, ScriptMetadata] = {
    # =========================================================================
    # GATHER CATEGORY (18 scripts)
    # =========================================================================
    "Invoke-Mimikatz": ScriptMetadata(
        name="Invoke-Mimikatz",
        category=ScriptCategory.GATHER,
        function_name="Invoke-Mimikatz",
        description="In-memory Mimikatz execution for credential extraction from LSASS",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "DumpCreds": "Dump credentials from LSASS memory",
            "DumpCerts": "Export private certificates",
            "Command": "Custom Mimikatz command to execute",
            "ComputerName": "Remote computer(s) to target",
        },
        required_params=[],
        mitre_techniques=["T1003.001", "T1552.004"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Invoke-MimikatzWDigestDowngrade": ScriptMetadata(
        name="Invoke-MimikatzWDigestDowngrade",
        category=ScriptCategory.GATHER,
        function_name="Invoke-MimikatzWDigestDowngrade",
        description="Force WDigest to cache plaintext passwords and extract them",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "DumpCreds": "Dump credentials after enabling WDigest",
        },
        mitre_techniques=["T1003.001", "T1112"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Get-PassHashes": ScriptMetadata(
        name="Get-PassHashes",
        category=ScriptCategory.GATHER,
        function_name="Get-PassHashes",
        description="Dump password hashes from SAM database using modified powerdump",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "PSObjectFormat": "Return results as PSObject for piping",
        },
        mitre_techniques=["T1003.002"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Get-LSASecret": ScriptMetadata(
        name="Get-LSASecret",
        category=ScriptCategory.GATHER,
        function_name="Get-LSASecret",
        description="Extract LSA secrets from registry (service account passwords)",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={},
        mitre_techniques=["T1003.004"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Get-WLAN-Keys": ScriptMetadata(
        name="Get-WLAN-Keys",
        category=ScriptCategory.GATHER,
        function_name="Get-WLAN-Keys",
        description="Extract saved WiFi passwords from Windows",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1552.001"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Get-WebCredentials": ScriptMetadata(
        name="Get-WebCredentials",
        category=ScriptCategory.GATHER,
        function_name="Get-WebCredentials",
        description="Extract web credentials from Windows Vault",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1555.003"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Get-Information": ScriptMetadata(
        name="Get-Information",
        category=ScriptCategory.GATHER,
        function_name="Get-Information",
        description="Gather comprehensive system information via registry and commands",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1082", "T1016", "T1033"],
        output_type=OutputType.TEXT,
    ),
    "Get-PassHints": ScriptMetadata(
        name="Get-PassHints",
        category=ScriptCategory.GATHER,
        function_name="Get-PassHints",
        description="Extract password hints from local user registry",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1552.001"],
        output_type=OutputType.TEXT,
    ),
    "Check-VM": ScriptMetadata(
        name="Check-VM",
        category=ScriptCategory.GATHER,
        function_name="Check-VM",
        description="Detect if running in a virtual machine environment",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1497.001"],
        output_type=OutputType.TEXT,
    ),
    "Copy-VSS": ScriptMetadata(
        name="Copy-VSS",
        category=ScriptCategory.GATHER,
        function_name="Copy-VSS",
        description="Copy SAM file using Volume Shadow Copy Service",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "DestinationDir": "Directory to save copied files",
        },
        mitre_techniques=["T1003.002", "T1490"],
        output_type=OutputType.FILE,
    ),
    "Keylogger": ScriptMetadata(
        name="Keylogger",
        category=ScriptCategory.GATHER,
        function_name="Keylogger",
        description="PowerShell keylogger with exfiltration support",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "ExfilOption": "Exfiltration method (pastebin, gmail, webserver, dns)",
            "MagicString": "Trigger string for exfiltration",
            "CheckURL": "URL for remote instructions",
            "dev_key": "Pastebin API key",
            "username": "Gmail username for exfil",
            "password": "Gmail password for exfil",
        },
        mitre_techniques=["T1056.001"],
        output_type=OutputType.TEXT,
        requires_interaction=True,
        supports_exfil=True,
    ),
    "Invoke-CredentialsPhish": ScriptMetadata(
        name="Invoke-CredentialsPhish",
        category=ScriptCategory.GATHER,
        function_name="Invoke-CredentialsPhish",
        description="Display fake Windows credential prompt to phish user",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1056.002"],
        output_type=OutputType.CREDENTIALS,
        requires_interaction=True,
    ),
    "Invoke-Mimikittenz": ScriptMetadata(
        name="Invoke-Mimikittenz",
        category=ScriptCategory.GATHER,
        function_name="Invoke-Mimikittenz",
        description="Extract credentials from process memory using regex patterns",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={},
        mitre_techniques=["T1552.004"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Invoke-SessionGopher": ScriptMetadata(
        name="Invoke-SessionGopher",
        category=ScriptCategory.GATHER,
        function_name="Invoke-SessionGopher",
        description="Find saved session info for PuTTY, WinSCP, RDP, etc.",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "Thorough": "Search all drives",
            "o": "Output file path",
            "iL": "File containing target list",
        },
        mitre_techniques=["T1552.001", "T1555"],
        output_type=OutputType.CREDENTIALS,
    ),
    "Invoke-SSIDExfil": ScriptMetadata(
        name="Invoke-SSIDExfil",
        category=ScriptCategory.GATHER,
        function_name="Invoke-SSIDExfil",
        description="Exfiltrate data via WLAN SSID names (covert channel)",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "ExfilData": "Data to exfiltrate",
        },
        mitre_techniques=["T1011", "T1567"],
        output_type=OutputType.TEXT,
    ),
    "Show-TargetScreen": ScriptMetadata(
        name="Show-TargetScreen",
        category=ScriptCategory.GATHER,
        function_name="Show-TargetScreen",
        description="Stream target screen via MJPEG to attacker",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Attacker IP to stream to",
            "Port": "Port for streaming",
        },
        required_params=["IPAddress", "Port"],
        mitre_techniques=["T1113"],
        output_type=OutputType.STREAM,
    ),
    "FireBuster": ScriptMetadata(
        name="FireBuster",
        category=ScriptCategory.GATHER,
        function_name="FireBuster",
        description="Test firewall egress rules (paired with FireListener)",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "FireListenerIP": "IP of FireListener",
            "StartPort": "Start of port range",
            "EndPort": "End of port range",
        },
        required_params=["FireListenerIP"],
        mitre_techniques=["T1046"],
        output_type=OutputType.TEXT,
    ),
    "FireListener": ScriptMetadata(
        name="FireListener",
        category=ScriptCategory.GATHER,
        function_name="FireListener",
        description="Receive FireBuster connections for egress testing",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "BindPort": "Port to listen on",
        },
        required_params=["BindPort"],
        mitre_techniques=["T1046"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # SHELLS CATEGORY (15 scripts)
    # =========================================================================
    "Invoke-PowerShellTcp": ScriptMetadata(
        name="Invoke-PowerShellTcp",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PowerShellTcp",
        description="TCP reverse/bind interactive PowerShell shell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Target IP for reverse shell",
            "Port": "Connection port",
            "Reverse": "Use reverse shell mode",
            "Bind": "Use bind shell mode",
        },
        required_params=["Port"],
        mitre_techniques=["T1059.001", "T1071.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PowerShellTcpOneLine": ScriptMetadata(
        name="Invoke-PowerShellTcpOneLine",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PowerShellTcpOneLine",
        description="Minimal one-line TCP reverse shell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Target IP",
            "Port": "Connection port",
        },
        required_params=["IPAddress", "Port"],
        mitre_techniques=["T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PowerShellTcpOneLineBind": ScriptMetadata(
        name="Invoke-PowerShellTcpOneLineBind",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PowerShellTcpOneLineBind",
        description="Minimal one-line TCP bind shell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "Port": "Bind port",
        },
        required_params=["Port"],
        mitre_techniques=["T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PowerShellUdp": ScriptMetadata(
        name="Invoke-PowerShellUdp",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PowerShellUdp",
        description="UDP reverse/bind interactive PowerShell shell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Target IP",
            "Port": "Connection port",
            "Reverse": "Use reverse shell",
            "Bind": "Use bind shell",
        },
        required_params=["Port"],
        mitre_techniques=["T1059.001", "T1095"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PowerShellUdpOneLine": ScriptMetadata(
        name="Invoke-PowerShellUdpOneLine",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PowerShellUdpOneLine",
        description="Minimal one-line UDP reverse shell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Target IP",
            "Port": "Connection port",
        },
        required_params=["IPAddress", "Port"],
        mitre_techniques=["T1059.001", "T1095"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PowerShellIcmp": ScriptMetadata(
        name="Invoke-PowerShellIcmp",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PowerShellIcmp",
        description="ICMP-based shell using ping packets",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "IPAddress": "Target IP",
            "Delay": "Delay between packets",
            "BufferSize": "ICMP buffer size",
        },
        required_params=["IPAddress"],
        mitre_techniques=["T1095", "T1572"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PowerShellWmi": ScriptMetadata(
        name="Invoke-PowerShellWmi",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PowerShellWmi",
        description="WMI-based interactive shell",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "IPAddress": "Target IP",
            "Username": "WMI username",
            "Password": "WMI password",
        },
        required_params=["IPAddress", "Username"],
        mitre_techniques=["T1047", "T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PoshRatHttp": ScriptMetadata(
        name="Invoke-PoshRatHttp",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PoshRatHttp",
        description="HTTP-based reverse interactive PowerShell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Listener IP",
            "Port": "Listener port",
        },
        required_params=["IPAddress", "Port"],
        mitre_techniques=["T1071.001", "T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PoshRatHttps": ScriptMetadata(
        name="Invoke-PoshRatHttps",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PoshRatHttps",
        description="HTTPS-based reverse interactive PowerShell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Listener IP",
            "Port": "Listener port",
        },
        required_params=["IPAddress", "Port"],
        mitre_techniques=["T1071.001", "T1059.001", "T1573.002"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-ConPtyShell": ScriptMetadata(
        name="Invoke-ConPtyShell",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-ConPtyShell",
        description="ConPTY-based fully interactive shell (Windows 10 1803+)",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "RemoteIp": "Listener IP",
            "RemotePort": "Listener port",
            "Rows": "Terminal rows",
            "Cols": "Terminal columns",
        },
        required_params=["RemoteIp", "RemotePort"],
        mitre_techniques=["T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-JSRatRegsvr": ScriptMetadata(
        name="Invoke-JSRatRegsvr",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-JSRatRegsvr",
        description="HTTP reverse shell via regsvr32.exe",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Listener IP",
            "Port": "Listener port",
        },
        required_params=["IPAddress", "Port"],
        mitre_techniques=["T1218.010", "T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-JSRatRundll": ScriptMetadata(
        name="Invoke-JSRatRundll",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-JSRatRundll",
        description="HTTP reverse shell via rundll32.exe",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "IPAddress": "Listener IP",
            "Port": "Listener port",
        },
        required_params=["IPAddress", "Port"],
        mitre_techniques=["T1218.011", "T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PsGcat": ScriptMetadata(
        name="Invoke-PsGcat",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PsGcat",
        description="Gmail-based command delivery shell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "Username": "Gmail username",
            "Password": "Gmail password",
        },
        required_params=["Username", "Password"],
        mitre_techniques=["T1102", "T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-PsGcatAgent": ScriptMetadata(
        name="Invoke-PsGcatAgent",
        category=ScriptCategory.SHELLS,
        function_name="Invoke-PsGcatAgent",
        description="Gmail-based command execution agent",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "Username": "Gmail username",
            "Password": "Gmail password",
        },
        required_params=["Username", "Password"],
        mitre_techniques=["T1102", "T1059.001"],
        output_type=OutputType.SHELL,
    ),
    "Remove-PoshRat": ScriptMetadata(
        name="Remove-PoshRat",
        category=ScriptCategory.SHELLS,
        function_name="Remove-PoshRat",
        description="Cleanup after PoshRat shell usage",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1070"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # UTILITY CATEGORY (15 scripts)
    # =========================================================================
    "Add-Persistence": ScriptMetadata(
        name="Add-Persistence",
        category=ScriptCategory.UTILITY,
        function_name="Add-Persistence",
        description="Add WMI-based persistence mechanism",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "PayloadURL": "URL of payload to execute",
            "PayloadScript": "Local script path",
            "Arguments": "Script arguments",
        },
        mitre_techniques=["T1546.003"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Add-Exfiltration": ScriptMetadata(
        name="Add-Exfiltration",
        category=ScriptCategory.UTILITY,
        function_name="Add-Exfiltration",
        description="Add exfiltration capability to scripts",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "ExfilOption": "Exfiltration method (pastebin, gmail, webserver, dns)",
            "DomainName": "DNS exfil domain",
            "dev_key": "Pastebin API key",
        },
        required_params=["ExfilOption"],
        mitre_techniques=["T1041", "T1567"],
        output_type=OutputType.TEXT,
        supports_exfil=True,
    ),
    "Do-Exfiltration": ScriptMetadata(
        name="Do-Exfiltration",
        category=ScriptCategory.UTILITY,
        function_name="Do-Exfiltration",
        description="Pipe-based data exfiltration",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "ExfilOption": "Exfiltration method",
            "dev_key": "Pastebin API key",
        },
        required_params=["ExfilOption"],
        mitre_techniques=["T1041"],
        output_type=OutputType.TEXT,
    ),
    "Invoke-Encode": ScriptMetadata(
        name="Invoke-Encode",
        category=ScriptCategory.UTILITY,
        function_name="Invoke-Encode",
        description="Encode scripts for obfuscation",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "DataToEncode": "Data to encode",
            "OutCommand": "Output as PowerShell command",
        },
        required_params=["DataToEncode"],
        mitre_techniques=["T1027", "T1140"],
        output_type=OutputType.TEXT,
    ),
    "Invoke-Decode": ScriptMetadata(
        name="Invoke-Decode",
        category=ScriptCategory.UTILITY,
        function_name="Invoke-Decode",
        description="Decode and decompress encoded data",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "EncodedData": "Data to decode",
        },
        required_params=["EncodedData"],
        mitre_techniques=["T1140"],
        output_type=OutputType.TEXT,
    ),
    "Download": ScriptMetadata(
        name="Download",
        category=ScriptCategory.UTILITY,
        function_name="Download",
        description="Download file from URL",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "URL": "URL to download from",
            "FileName": "Output filename",
        },
        required_params=["URL", "FileName"],
        mitre_techniques=["T1105"],
        output_type=OutputType.FILE,
    ),
    "Base64ToString": ScriptMetadata(
        name="Base64ToString",
        category=ScriptCategory.UTILITY,
        function_name="Base64ToString",
        description="Decode Base64 to string",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Base64Str": "Base64 string to decode",
        },
        required_params=["Base64Str"],
        mitre_techniques=["T1140"],
        output_type=OutputType.TEXT,
    ),
    "StringToBase64": ScriptMetadata(
        name="StringToBase64",
        category=ScriptCategory.UTILITY,
        function_name="StringToBase64",
        description="Encode string to Base64",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Str": "String to encode",
        },
        required_params=["Str"],
        mitre_techniques=["T1027"],
        output_type=OutputType.TEXT,
    ),
    "ConvertTo-ROT13": ScriptMetadata(
        name="ConvertTo-ROT13",
        category=ScriptCategory.UTILITY,
        function_name="ConvertTo-ROT13",
        description="ROT13 encoding/decoding",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "String": "String to encode/decode",
        },
        required_params=["String"],
        mitre_techniques=["T1027"],
        output_type=OutputType.TEXT,
    ),
    "ExetoText": ScriptMetadata(
        name="ExetoText",
        category=ScriptCategory.UTILITY,
        function_name="ExetoText",
        description="Convert binary executable to text",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "EXE": "Path to executable",
        },
        required_params=["EXE"],
        mitre_techniques=["T1027"],
        output_type=OutputType.TEXT,
    ),
    "TexttoExe": ScriptMetadata(
        name="TexttoExe",
        category=ScriptCategory.UTILITY,
        function_name="TexttoExe",
        description="Convert text back to binary executable",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "EXE": "Output path",
            "Text": "Text to convert",
        },
        required_params=["EXE", "Text"],
        mitre_techniques=["T1140"],
        output_type=OutputType.FILE,
    ),
    "Out-DnsTxt": ScriptMetadata(
        name="Out-DnsTxt",
        category=ScriptCategory.UTILITY,
        function_name="Out-DnsTxt",
        description="Generate DNS TXT records for data exfiltration",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "DataToEncode": "Data to encode",
        },
        required_params=["DataToEncode"],
        mitre_techniques=["T1071.004"],
        output_type=OutputType.TEXT,
    ),
    "Parse_Keys": ScriptMetadata(
        name="Parse_Keys",
        category=ScriptCategory.UTILITY,
        function_name="Parse_Keys",
        description="Parse keylogger output into readable format",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "KeylogFile": "Path to keylogger output",
        },
        required_params=["KeylogFile"],
        mitre_techniques=["T1056.001"],
        output_type=OutputType.TEXT,
    ),
    "Remove-Persistence": ScriptMetadata(
        name="Remove-Persistence",
        category=ScriptCategory.UTILITY,
        function_name="Remove-Persistence",
        description="Remove persistence created by Add-Persistence",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={},
        mitre_techniques=["T1070"],
        output_type=OutputType.TEXT,
    ),
    "Start-CaptureServer": ScriptMetadata(
        name="Start-CaptureServer",
        category=ScriptCategory.UTILITY,
        function_name="Start-CaptureServer",
        description="Web server to capture Basic auth and SMB hashes",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "ListenPort": "Port to listen on",
        },
        required_params=["ListenPort"],
        mitre_techniques=["T1557", "T1040"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # BACKDOORS CATEGORY (10 scripts)
    # =========================================================================
    "HTTP-Backdoor": ScriptMetadata(
        name="HTTP-Backdoor",
        category=ScriptCategory.BACKDOORS,
        function_name="HTTP-Backdoor",
        description="HTTP-based backdoor with command polling",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "CheckURL": "URL to poll for commands",
            "PayloadURL": "Payload download URL",
            "MagicString": "Trigger string to execute",
            "StopString": "String to stop backdoor",
        },
        required_params=["CheckURL", "PayloadURL", "MagicString", "StopString"],
        mitre_techniques=["T1071.001", "T1105"],
        output_type=OutputType.SHELL,
    ),
    "DNS_TXT_Pwnage": ScriptMetadata(
        name="DNS_TXT_Pwnage",
        category=ScriptCategory.BACKDOORS,
        function_name="DNS_TXT_Pwnage",
        description="DNS TXT record-based command execution",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "startdomain": "Initial domain to query",
            "cmdstring": "Command trigger string",
            "stopstring": "Stop trigger string",
            "AuthNS": "Authoritative nameserver",
        },
        required_params=["startdomain"],
        mitre_techniques=["T1071.004", "T1568.002"],
        output_type=OutputType.SHELL,
    ),
    "Add-RegBackdoor": ScriptMetadata(
        name="Add-RegBackdoor",
        category=ScriptCategory.BACKDOORS,
        function_name="Add-RegBackdoor",
        description="Registry-based backdoor (Sticky Keys/Utilman debugger)",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={},
        mitre_techniques=["T1546.008"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Add-ScrnSaveBackdoor": ScriptMetadata(
        name="Add-ScrnSaveBackdoor",
        category=ScriptCategory.BACKDOORS,
        function_name="Add-ScrnSaveBackdoor",
        description="Screen saver-based persistence backdoor",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "Payload": "Command to execute",
            "PayloadURL": "URL of payload script",
        },
        mitre_techniques=["T1546"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Execute-OnTime": ScriptMetadata(
        name="Execute-OnTime",
        category=ScriptCategory.BACKDOORS,
        function_name="Execute-OnTime",
        description="Scheduled time-based script execution",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "PayloadURL": "URL of payload",
            "Arguments": "Script arguments",
            "time": "Execution time",
            "CheckURL": "URL to check for trigger",
            "StopString": "Stop trigger",
        },
        required_params=["PayloadURL", "time"],
        mitre_techniques=["T1053.005"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Gupt-Backdoor": ScriptMetadata(
        name="Gupt-Backdoor",
        category=ScriptCategory.BACKDOORS,
        function_name="Gupt-Backdoor",
        description="SSID-based command execution (no network needed)",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "MagicString": "SSID trigger pattern",
            "Arguments": "Script arguments",
        },
        required_params=["MagicString"],
        mitre_techniques=["T1205.001"],
        output_type=OutputType.SHELL,
    ),
    "Invoke-ADSBackdoor": ScriptMetadata(
        name="Invoke-ADSBackdoor",
        category=ScriptCategory.BACKDOORS,
        function_name="Invoke-ADSBackdoor",
        description="Alternate Data Streams + Registry persistence",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "PayloadURL": "URL of payload",
        },
        required_params=["PayloadURL"],
        mitre_techniques=["T1564.004", "T1547.001"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Set-RemotePSRemoting": ScriptMetadata(
        name="Set-RemotePSRemoting",
        category=ScriptCategory.BACKDOORS,
        function_name="Set-RemotePSRemoting",
        description="Enable PowerShell remoting for non-admin users",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "UserName": "Username to enable",
            "ComputerName": "Target computer",
        },
        required_params=["UserName"],
        mitre_techniques=["T1021.006"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Set-RemoteWMI": ScriptMetadata(
        name="Set-RemoteWMI",
        category=ScriptCategory.BACKDOORS,
        function_name="Set-RemoteWMI",
        description="Enable WMI access for non-admin users",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "UserName": "Username to enable",
            "ComputerName": "Target computer",
            "Namespace": "WMI namespace",
        },
        required_params=["UserName"],
        mitre_techniques=["T1047"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    # =========================================================================
    # ESCALATION CATEGORY (3 scripts)
    # =========================================================================
    "Invoke-PsUACme": ScriptMetadata(
        name="Invoke-PsUACme",
        category=ScriptCategory.ESCALATION,
        function_name="Invoke-PsUACme",
        description="UAC bypass using known methods (sysprep, oobe, etc.)",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "Payload": "Command to run elevated",
            "method": "Bypass method (sysprep, oobe, ActionQueue, migwiz)",
        },
        mitre_techniques=["T1548.002"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Enable-DuplicateToken": ScriptMetadata(
        name="Enable-DuplicateToken",
        category=ScriptCategory.ESCALATION,
        function_name="Enable-DuplicateToken",
        description="SYSTEM privilege escalation via token duplication",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={},
        mitre_techniques=["T1134.001"],
        output_type=OutputType.TEXT,
    ),
    "Remove-Update": ScriptMetadata(
        name="Remove-Update",
        category=ScriptCategory.ESCALATION,
        function_name="Remove-Update",
        description="Remove Windows security patches to reintroduce vulns",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "HotfixID": "KB number to remove",
        },
        mitre_techniques=["T1562.001"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    # =========================================================================
    # CLIENT CATEGORY (10 scripts)
    # =========================================================================
    "Out-Word": ScriptMetadata(
        name="Out-Word",
        category=ScriptCategory.CLIENT,
        function_name="Out-Word",
        description="Create Word document with macro/DDE payload",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "PayloadURL": "URL of payload script",
            "OutputFile": "Output document path",
            "DDE": "Use DDE instead of macro",
        },
        mitre_techniques=["T1204.002", "T1559.002"],
        output_type=OutputType.FILE,
    ),
    "Out-Excel": ScriptMetadata(
        name="Out-Excel",
        category=ScriptCategory.CLIENT,
        function_name="Out-Excel",
        description="Create Excel document with macro payload",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "PayloadURL": "URL of payload script",
            "OutputFile": "Output document path",
        },
        mitre_techniques=["T1204.002"],
        output_type=OutputType.FILE,
    ),
    "Out-CHM": ScriptMetadata(
        name="Out-CHM",
        category=ScriptCategory.CLIENT,
        function_name="Out-CHM",
        description="Create malicious CHM (Compiled HTML Help) file",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "PayloadURL": "URL of payload script",
            "HHCPath": "Path to hhc.exe compiler",
        },
        mitre_techniques=["T1218.001"],
        output_type=OutputType.FILE,
    ),
    "Out-HTA": ScriptMetadata(
        name="Out-HTA",
        category=ScriptCategory.CLIENT,
        function_name="Out-HTA",
        description="Create HTA (HTML Application) with PowerShell payload",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "PayloadURL": "URL of payload script",
            "OutputFile": "Output HTA path",
        },
        mitre_techniques=["T1218.005"],
        output_type=OutputType.FILE,
    ),
    "Out-JS": ScriptMetadata(
        name="Out-JS",
        category=ScriptCategory.CLIENT,
        function_name="Out-JS",
        description="Create JavaScript file executing PowerShell",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "OutputFile": "Output JS path",
        },
        mitre_techniques=["T1059.007"],
        output_type=OutputType.FILE,
    ),
    "Out-SCF": ScriptMetadata(
        name="Out-SCF",
        category=ScriptCategory.CLIENT,
        function_name="Out-SCF",
        description="Create SCF file for UNC path capture (NTLM relay)",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "IPAddress": "Attacker IP for UNC path",
            "OutputFile": "Output SCF path",
        },
        required_params=["IPAddress", "OutputFile"],
        mitre_techniques=["T1187"],
        output_type=OutputType.FILE,
    ),
    "Out-SCT": ScriptMetadata(
        name="Out-SCT",
        category=ScriptCategory.CLIENT,
        function_name="Out-SCT",
        description="Create Script Component file for regsvr32 execution",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "OutputFile": "Output SCT path",
        },
        mitre_techniques=["T1218.010"],
        output_type=OutputType.FILE,
    ),
    "Out-Shortcut": ScriptMetadata(
        name="Out-Shortcut",
        category=ScriptCategory.CLIENT,
        function_name="Out-Shortcut",
        description="Create LNK shortcut with PowerShell execution",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "PayloadURL": "URL of payload script",
            "OutputFile": "Output LNK path",
            "Arguments": "Shortcut arguments",
        },
        mitre_techniques=["T1547.009"],
        output_type=OutputType.FILE,
    ),
    "Out-WebQuery": ScriptMetadata(
        name="Out-WebQuery",
        category=ScriptCategory.CLIENT,
        function_name="Out-WebQuery",
        description="Create IQY file for credential phishing",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "URL": "Malicious URL",
            "OutputFile": "Output IQY path",
        },
        required_params=["URL", "OutputFile"],
        mitre_techniques=["T1566.001"],
        output_type=OutputType.FILE,
    ),
    "Out-Java": ScriptMetadata(
        name="Out-Java",
        category=ScriptCategory.CLIENT,
        function_name="Out-Java",
        description="Create signed JAR file with applet payload",
        required_privilege=RequiredPrivilege.NONE,
        parameters={
            "Payload": "PowerShell payload",
            "PayloadURL": "URL of payload script",
        },
        mitre_techniques=["T1189"],
        output_type=OutputType.FILE,
    ),
    # =========================================================================
    # EXECUTION CATEGORY (5 scripts)
    # =========================================================================
    "Download-Execute-PS": ScriptMetadata(
        name="Download-Execute-PS",
        category=ScriptCategory.EXECUTION,
        function_name="Download-Execute-PS",
        description="Download and execute PowerShell script from URL",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "ScriptURL": "URL of script to download",
            "Arguments": "Script arguments",
            "Nodownload": "Execute in memory without file write",
        },
        required_params=["ScriptURL"],
        mitre_techniques=["T1059.001", "T1105"],
        output_type=OutputType.TEXT,
    ),
    "Download_Execute": ScriptMetadata(
        name="Download_Execute",
        category=ScriptCategory.EXECUTION,
        function_name="Download_Execute",
        description="Download executable, convert from text, execute",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "URL": "URL of text-encoded executable",
        },
        required_params=["URL"],
        mitre_techniques=["T1105", "T1204.002"],
        output_type=OutputType.TEXT,
    ),
    "Execute-Command-MSSQL": ScriptMetadata(
        name="Execute-Command-MSSQL",
        category=ScriptCategory.EXECUTION,
        function_name="Execute-Command-MSSQL",
        description="Execute commands via SQL Server xp_cmdshell",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "ComputerName": "SQL Server hostname",
            "UserName": "SQL username",
            "Password": "SQL password",
            "payload": "Command to execute",
        },
        required_params=["ComputerName", "UserName", "Password"],
        mitre_techniques=["T1505.001"],
        output_type=OutputType.TEXT,
    ),
    "Execute-DNSTXT-Code": ScriptMetadata(
        name="Execute-DNSTXT-Code",
        category=ScriptCategory.EXECUTION,
        function_name="Execute-DNSTXT-Code",
        description="Execute shellcode retrieved via DNS TXT queries",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "DomainName": "Domain with TXT records",
            "AuthNS": "Authoritative nameserver",
        },
        required_params=["DomainName"],
        mitre_techniques=["T1071.004", "T1055"],
        output_type=OutputType.TEXT,
    ),
    "Out-RundllCommand": ScriptMetadata(
        name="Out-RundllCommand",
        category=ScriptCategory.EXECUTION,
        function_name="Out-RundllCommand",
        description="Execute commands via rundll32.exe",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "PayloadURL": "URL of payload",
        },
        mitre_techniques=["T1218.011"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # SCAN CATEGORY (2 scripts)
    # =========================================================================
    "Invoke-BruteForce": ScriptMetadata(
        name="Invoke-BruteForce",
        category=ScriptCategory.SCAN,
        function_name="Invoke-BruteForce",
        description="Multi-service brute forcing (FTP, AD, MSSQL, etc.)",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "ComputerName": "Target hostname",
            "UserList": "Username list file",
            "PasswordList": "Password list file",
            "Service": "Service to brute force (FTP, ActiveDirectory, MSSQL)",
        },
        required_params=["ComputerName", "Service"],
        mitre_techniques=["T1110.001"],
        output_type=OutputType.TEXT,
    ),
    "Invoke-PortScan": ScriptMetadata(
        name="Invoke-PortScan",
        category=ScriptCategory.SCAN,
        function_name="Invoke-PortScan",
        description="Network/host/port discovery and scanning",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "StartAddress": "Start IP address",
            "EndAddress": "End IP address",
            "ResolveHost": "Resolve hostnames",
            "ScanPort": "Scan ports",
            "Ports": "Ports to scan",
            "TimeOut": "Connection timeout",
        },
        mitre_techniques=["T1046"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # PIVOT CATEGORY (3 scripts)
    # =========================================================================
    "Create-MultipleSessions": ScriptMetadata(
        name="Create-MultipleSessions",
        category=ScriptCategory.PIVOT,
        function_name="Create-MultipleSessions",
        description="Validate credentials and create PSSessions on multiple hosts",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "filename": "File with target server list",
            "Creds": "Prompt for credentials",
            "CreateSessions": "Create PSSessions",
        },
        required_params=["filename"],
        mitre_techniques=["T1021.006"],
        output_type=OutputType.TEXT,
    ),
    "Invoke-NetworkRelay": ScriptMetadata(
        name="Invoke-NetworkRelay",
        category=ScriptCategory.PIVOT,
        function_name="Invoke-NetworkRelay",
        description="Create network relay/tunnel between computers",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "L2RRelayIP": "Local to remote relay IP",
            "R2LRelayIP": "Remote to local relay IP",
            "L2RRelayPort": "Local to remote port",
            "R2LRelayPort": "Remote to local port",
        },
        mitre_techniques=["T1572"],
        output_type=OutputType.TEXT,
    ),
    "Run-EXEonRemote": ScriptMetadata(
        name="Run-EXEonRemote",
        category=ScriptCategory.PIVOT,
        function_name="Run-EXEonRemote",
        description="Copy and execute binaries on remote machines",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "ComputerName": "Target computer",
            "EXEPath": "Path to executable",
            "Creds": "Credentials",
        },
        required_params=["ComputerName", "EXEPath"],
        mitre_techniques=["T1021.002", "T1570"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # MITM CATEGORY (1 script)
    # =========================================================================
    "Invoke-Interceptor": ScriptMetadata(
        name="Invoke-Interceptor",
        category=ScriptCategory.MITM,
        function_name="Invoke-Interceptor",
        description="Local HTTPS proxy for MITM interception",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "ProxyPort": "Proxy listen port",
        },
        mitre_techniques=["T1557", "T1557.002"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # ACTIVE DIRECTORY CATEGORY (2 scripts)
    # =========================================================================
    "Add-ConstrainedDelegationBackdoor": ScriptMetadata(
        name="Add-ConstrainedDelegationBackdoor",
        category=ScriptCategory.ACTIVE_DIRECTORY,
        function_name="Add-ConstrainedDelegationBackdoor",
        description="Create service account with constrained delegation",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "SamAccountName": "Service account name",
            "Password": "Account password",
            "Domain": "Target domain",
            "ServicePrincipalName": "SPN to assign",
            "AllowedToDelegateTo": "SPNs allowed for delegation",
        },
        required_params=["SamAccountName", "Password"],
        mitre_techniques=["T1134.001", "T1558.003"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    "Set-DCShadowPermissions": ScriptMetadata(
        name="Set-DCShadowPermissions",
        category=ScriptCategory.ACTIVE_DIRECTORY,
        function_name="Set-DCShadowPermissions",
        description="Configure AD permissions for DCShadow attack",
        required_privilege=RequiredPrivilege.ADMIN,
        parameters={
            "FakeDC": "Fake DC computer name",
            "SamAccountName": "Account to grant permissions",
        },
        mitre_techniques=["T1207"],
        output_type=OutputType.TEXT,
        is_destructive=True,
    ),
    # =========================================================================
    # BYPASS CATEGORY (1 script)
    # =========================================================================
    "Invoke-AmsiBypass": ScriptMetadata(
        name="Invoke-AmsiBypass",
        category=ScriptCategory.BYPASS,
        function_name="Invoke-AmsiBypass",
        description="AMSI (Antimalware Scan Interface) bypass techniques",
        required_privilege=RequiredPrivilege.USER,
        parameters={},
        mitre_techniques=["T1562.001"],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # MISC CATEGORY (1 script)
    # =========================================================================
    "Speak": ScriptMetadata(
        name="Speak",
        category=ScriptCategory.MISC,
        function_name="Speak",
        description="Text-to-speech utility",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "Sentence": "Text to speak",
        },
        required_params=["Sentence"],
        mitre_techniques=[],
        output_type=OutputType.TEXT,
    ),
    # =========================================================================
    # PRASADHAK CATEGORY (1 script)
    # =========================================================================
    "Invoke-Prasadhak": ScriptMetadata(
        name="Invoke-Prasadhak",
        category=ScriptCategory.PRASADHAK,
        function_name="Invoke-Prasadhak",
        description="Validate process hashes against VirusTotal database",
        required_privilege=RequiredPrivilege.USER,
        parameters={
            "ApiKey": "VirusTotal API key",
        },
        mitre_techniques=["T1518.001"],
        output_type=OutputType.TEXT,
    ),
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def get_script_metadata(name: str) -> Optional[ScriptMetadata]:
    """Get metadata for a script by name."""
    return SCRIPT_METADATA.get(name)


def get_scripts_by_category(category: ScriptCategory) -> List[ScriptMetadata]:
    """Get all scripts in a category."""
    return [s for s in SCRIPT_METADATA.values() if s.category == category]


def get_credential_scripts() -> List[ScriptMetadata]:
    """Get all scripts that extract credentials."""
    return [s for s in SCRIPT_METADATA.values() if s.output_type == OutputType.CREDENTIALS]


def get_shell_scripts() -> List[ScriptMetadata]:
    """Get all shell scripts."""
    return [s for s in SCRIPT_METADATA.values() if s.output_type == OutputType.SHELL]


def get_admin_scripts() -> List[ScriptMetadata]:
    """Get scripts requiring admin privileges."""
    return [
        s
        for s in SCRIPT_METADATA.values()
        if s.required_privilege in [RequiredPrivilege.ADMIN, RequiredPrivilege.SYSTEM]
    ]


def get_destructive_scripts() -> List[ScriptMetadata]:
    """Get scripts that modify system state."""
    return [s for s in SCRIPT_METADATA.values() if s.is_destructive]


def get_scripts_by_mitre(technique_id: str) -> List[ScriptMetadata]:
    """Get scripts that map to a MITRE ATT&CK technique."""
    return [s for s in SCRIPT_METADATA.values() if technique_id in s.mitre_techniques]


def get_all_script_names() -> List[str]:
    """Get list of all script names."""
    return list(SCRIPT_METADATA.keys())


def get_category_counts() -> Dict[str, int]:
    """Get count of scripts per category."""
    counts = {}
    for category in ScriptCategory:
        scripts = get_scripts_by_category(category)
        if scripts:
            counts[category.value] = len(scripts)
    return counts


__all__ = [
    "ScriptMetadata",
    "ScriptCategory",
    "RequiredPrivilege",
    "OutputType",
    "SCRIPT_METADATA",
    "get_script_metadata",
    "get_scripts_by_category",
    "get_credential_scripts",
    "get_shell_scripts",
    "get_admin_scripts",
    "get_destructive_scripts",
    "get_scripts_by_mitre",
    "get_all_script_names",
    "get_category_counts",
]
