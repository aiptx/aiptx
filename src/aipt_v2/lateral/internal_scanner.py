"""
AIPTX Beast Mode - Internal Scanner
====================================

Port scanning and service detection through pivot points.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Information about a detected service."""
    port: int
    protocol: str
    service: str
    version: str | None = None
    banner: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    """Result of a scan operation."""
    host: str
    alive: bool
    services: list[ServiceInfo] = field(default_factory=list)
    os_guess: str | None = None
    hostname: str | None = None
    scan_time: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "host": self.host,
            "alive": self.alive,
            "services": [s.to_dict() for s in self.services],
            "os_guess": self.os_guess,
            "hostname": self.hostname,
            "scan_time": self.scan_time,
            "error": self.error,
        }


# Common ports for quick scanning
COMMON_PORTS = {
    "top_20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "top_100": [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157,
    ],
    "web": [80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9443],
    "database": [1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984],
    "remote_access": [22, 23, 3389, 5900, 5901, 5985, 5986],
    "windows": [135, 139, 445, 3389, 5985, 5986, 47001],
    "linux": [22, 111, 2049, 6000],
}

# Service signatures for banner matching
SERVICE_SIGNATURES = {
    "SSH": [b"SSH-", b"OpenSSH", b"Dropbear"],
    "HTTP": [b"HTTP/", b"<!DOCTYPE", b"<html"],
    "FTP": [b"220 ", b"FTP", b"vsftpd", b"ProFTPD"],
    "SMTP": [b"220 ", b"SMTP", b"ESMTP", b"Postfix"],
    "MySQL": [b"\x00\x00\x00\x0a", b"mysql_native"],
    "PostgreSQL": [b"PostgreSQL"],
    "Redis": [b"+PONG", b"-NOAUTH", b"$"],
    "MongoDB": [b"MongoDB"],
    "RDP": [b"\x03\x00\x00"],
    "SMB": [b"\x00\x00\x00\x85", b"SMB"],
}


class InternalScanner:
    """
    Scan internal networks through pivot points.

    Provides port scanning, service detection, and host discovery
    capabilities designed to work through SOCKS proxies.
    """

    def __init__(self, proxy: str | None = None):
        """
        Initialize internal scanner.

        Args:
            proxy: SOCKS proxy URL (e.g., socks5://127.0.0.1:9050)
        """
        self.proxy = proxy
        self._results: list[ScanResult] = []

    def get_nmap_scan_commands(
        self,
        target: str,
        scan_type: str = "quick",
        ports: str | None = None,
    ) -> dict[str, str]:
        """
        Get nmap scan commands for various scenarios.

        Args:
            target: Target IP or network
            scan_type: Type of scan (quick, full, stealth, service)
            ports: Custom port specification

        Returns:
            Nmap command configuration
        """
        base_opts = "-Pn"  # Assume host is up (common through proxies)

        if self.proxy:
            base_opts += f" --proxy {self.proxy}"

        scans = {
            "quick": {
                "command": f"nmap {base_opts} -sT -T4 --top-ports 20 {target}",
                "description": "Quick TCP scan of top 20 ports",
            },
            "full": {
                "command": f"nmap {base_opts} -sT -p- -T4 {target}",
                "description": "Full TCP port scan (all 65535 ports)",
            },
            "stealth": {
                "command": f"nmap {base_opts} -sS -T2 --top-ports 100 {target}",
                "description": "Stealth SYN scan (requires root)",
            },
            "service": {
                "command": f"nmap {base_opts} -sT -sV -T4 --top-ports 100 {target}",
                "description": "Service version detection",
            },
            "vuln": {
                "command": f"nmap {base_opts} -sT -sV --script vuln -T4 {target}",
                "description": "Vulnerability scan with NSE scripts",
            },
            "smb": {
                "command": f"nmap {base_opts} -sT -p445,139 --script smb-enum* {target}",
                "description": "SMB enumeration",
            },
            "discovery": {
                "command": f"nmap -sn -T4 {target}",
                "description": "Host discovery (ping scan)",
            },
        }

        if ports:
            for key in scans:
                scans[key]["command"] = scans[key]["command"].replace("--top-ports 20", f"-p{ports}")
                scans[key]["command"] = scans[key]["command"].replace("--top-ports 100", f"-p{ports}")

        return scans.get(scan_type, scans["quick"])

    def get_proxychains_scan_commands(
        self,
        target: str,
        ports: list[int] | None = None,
    ) -> dict[str, str]:
        """
        Get proxychains-based scan commands.

        Args:
            target: Target IP
            ports: Ports to scan

        Returns:
            Proxychains scan commands
        """
        if ports is None:
            ports = COMMON_PORTS["top_20"]

        port_str = ",".join(map(str, ports))

        return {
            "nmap_scan": f"proxychains nmap -sT -Pn -p{port_str} {target}",
            "nc_scan": f"proxychains nc -zv {target} {ports[0]}-{ports[-1]}",
            "curl_check": f"proxychains curl -sI http://{target} --connect-timeout 5",
            "ssh_banner": f"proxychains nc -w3 {target} 22",
            "description": f"Scan {target} through proxychains",
        }

    def get_native_scan_commands(
        self,
        target: str,
        ports: list[int] | None = None,
    ) -> list[dict[str, str]]:
        """
        Get commands for native scanning (without nmap).

        Useful when nmap isn't available on pivot host.

        Args:
            target: Target IP
            ports: Ports to scan

        Returns:
            List of native scan commands
        """
        if ports is None:
            ports = COMMON_PORTS["top_20"]

        commands = []

        # Bash TCP scan
        bash_ports = " ".join(map(str, ports))
        commands.append({
            "name": "bash_tcp_scan",
            "command": f"for port in {bash_ports}; do (echo >/dev/tcp/{target}/$port) 2>/dev/null && echo \"$port open\"; done",
            "description": "Bash /dev/tcp port scan",
            "shell": "bash",
        })

        # Netcat scan
        commands.append({
            "name": "nc_scan",
            "command": f"nc -zv {target} {ports[0]}-{ports[-1]} 2>&1 | grep -v refused",
            "description": "Netcat port scan",
        })

        # Python scan
        python_script = f"""
import socket
target = "{target}"
ports = {ports}
for port in ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((target, port)) == 0:
            print(f"{{port}} open")
        s.close()
    except: pass
"""
        commands.append({
            "name": "python_scan",
            "command": f"python3 -c '{python_script.strip()}'",
            "description": "Python socket scan",
        })

        # Perl scan
        commands.append({
            "name": "perl_scan",
            "command": f'perl -e \'use IO::Socket; for $p ({",".join(map(str,ports))}){{$s=IO::Socket::INET->new(PeerAddr=>"{target}",PeerPort=>$p,Proto=>"tcp",Timeout=>1) and print "$p open\\n"}}\'',
            "description": "Perl socket scan",
        })

        return commands

    def get_smb_enum_commands(self, target: str) -> list[dict[str, str]]:
        """
        Get SMB enumeration commands.

        Args:
            target: Target IP

        Returns:
            SMB enumeration commands
        """
        return [
            {
                "name": "smbclient_list",
                "command": f"smbclient -L //{target} -N",
                "description": "List SMB shares (anonymous)",
            },
            {
                "name": "enum4linux",
                "command": f"enum4linux -a {target}",
                "description": "Full SMB enumeration",
            },
            {
                "name": "crackmapexec_smb",
                "command": f"crackmapexec smb {target}",
                "description": "CME SMB scan",
            },
            {
                "name": "smbmap",
                "command": f"smbmap -H {target}",
                "description": "SMB share mapper",
            },
            {
                "name": "rpcclient",
                "command": f"rpcclient -U '' -N {target}",
                "description": "RPC client (null session)",
            },
            {
                "name": "nmap_smb",
                "command": f"nmap -p445 --script=smb-enum-shares,smb-enum-users {target}",
                "description": "Nmap SMB scripts",
            },
        ]

    def get_ldap_enum_commands(self, target: str, domain: str | None = None) -> list[dict[str, str]]:
        """
        Get LDAP enumeration commands.

        Args:
            target: Target DC IP
            domain: Domain name

        Returns:
            LDAP enumeration commands
        """
        commands = [
            {
                "name": "ldapsearch_anon",
                "command": f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts",
                "description": "LDAP anonymous base query",
            },
            {
                "name": "nmap_ldap",
                "command": f"nmap -p389,636 --script=ldap-search {target}",
                "description": "Nmap LDAP scripts",
            },
        ]

        if domain:
            base_dn = ",".join(f"DC={part}" for part in domain.split("."))
            commands.extend([
                {
                    "name": "ldap_users",
                    "command": f"ldapsearch -x -H ldap://{target} -b '{base_dn}' '(objectClass=user)' sAMAccountName",
                    "description": "Enumerate domain users",
                },
                {
                    "name": "ldap_computers",
                    "command": f"ldapsearch -x -H ldap://{target} -b '{base_dn}' '(objectClass=computer)' dNSHostName",
                    "description": "Enumerate domain computers",
                },
            ])

        return commands

    def get_web_discovery_commands(self, target: str, ports: list[int] | None = None) -> list[dict[str, str]]:
        """
        Get web service discovery commands.

        Args:
            target: Target IP
            ports: Web ports to check

        Returns:
            Web discovery commands
        """
        if ports is None:
            ports = COMMON_PORTS["web"]

        commands = []

        for port in ports:
            proto = "https" if port in (443, 8443, 9443) else "http"
            commands.append({
                "name": f"curl_{port}",
                "command": f"curl -sIk {proto}://{target}:{port} --connect-timeout 5 | head -20",
                "description": f"Check {proto}://{target}:{port}",
            })

        # Directory busting
        commands.append({
            "name": "gobuster",
            "command": f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 20",
            "description": "Directory bruteforce",
        })

        # Tech detection
        commands.append({
            "name": "whatweb",
            "command": f"whatweb -a 3 http://{target}",
            "description": "Web technology fingerprinting",
        })

        return commands

    def parse_nmap_output(self, output: str) -> list[ScanResult]:
        """
        Parse nmap output into ScanResult objects.

        Args:
            output: Raw nmap output

        Returns:
            List of ScanResult objects
        """
        import re
        results = []
        current_host = None
        current_services = []

        for line in output.split("\n"):
            # Match host
            host_match = re.search(r"Nmap scan report for (\S+)", line)
            if host_match:
                # Save previous host
                if current_host:
                    results.append(ScanResult(
                        host=current_host,
                        alive=True,
                        services=current_services,
                    ))
                current_host = host_match.group(1)
                current_services = []
                continue

            # Match port
            port_match = re.search(r"(\d+)/(tcp|udp)\s+(\w+)\s+(.+)?", line)
            if port_match and current_host:
                port, proto, state, service = port_match.groups()
                if state == "open":
                    current_services.append(ServiceInfo(
                        port=int(port),
                        protocol=proto,
                        service=service.strip() if service else "unknown",
                    ))

        # Save last host
        if current_host:
            results.append(ScanResult(
                host=current_host,
                alive=True,
                services=current_services,
            ))

        self._results.extend(results)
        return results

    def get_scan_results(self) -> list[ScanResult]:
        """Get all scan results."""
        return self._results.copy()

    def get_common_ports(self, category: str = "top_20") -> list[int]:
        """Get common ports by category."""
        return COMMON_PORTS.get(category, COMMON_PORTS["top_20"])


def scan_internal_network(
    target: str,
    scan_type: str = "quick",
    proxy: str | None = None,
) -> dict[str, str]:
    """Convenience function for internal scanning."""
    scanner = InternalScanner(proxy=proxy)
    return scanner.get_nmap_scan_commands(target, scan_type)


__all__ = [
    "ServiceInfo",
    "ScanResult",
    "InternalScanner",
    "scan_internal_network",
    "COMMON_PORTS",
]
