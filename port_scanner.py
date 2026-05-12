#!/usr/bin/env python3
"""
port_scanner.py - A fast, nmap-style TCP port scanner
Author: Isaac
GitHub: github.com/IHandysides
"""

import socket
import argparse
import threading
import ipaddress
from queue import Queue
from datetime import datetime
import sys
import struct

# Common ports and service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    587: "SMTP", 631: "IPP", 636: "LDAPS", 873: "rsync",
    902: "VMware", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanelSSL",
    2222: "SSH-alt", 2375: "Docker", 2376: "DockerSSL", 3000: "Dev",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4444: "Metasploit",
    4848: "GlassFish", 5000: "Flask/UPnP", 5432: "PostgreSQL",
    5900: "VNC", 5901: "VNC", 6379: "Redis", 6667: "IRC",
    7070: "RealAudio", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8443: "HTTPS-alt", 8888: "Jupyter", 9000: "PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch",
    27017: "MongoDB", 27018: "MongoDB", 50000: "SAP",
}

def grab_banner(ip, port, timeout=2):
    """Attempt to grab service banner from open port."""
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        # Send a generic HTTP request for web ports
        if port in (80, 8080, 8000, 8888):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        # Return first line only
        return banner.split("\n")[0][:60] if banner else ""
    except Exception:
        return ""

def scan_port(ip, port, timeout, results, banner_grab=False):
    """Scan a single port and store result."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            banner = grab_banner(ip, port) if banner_grab else ""
            results[port] = {"state": "open", "service": service, "banner": banner}
        s.close()
    except Exception:
        pass

def worker(ip, timeout, results, banner_grab, queue):
    """Thread worker that pulls ports from queue."""
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port, timeout, results, banner_grab)
        queue.task_done()

def run_scan(ip, ports, timeout=1, threads=200, banner_grab=False):
    """Run threaded port scan and return results."""
    results = {}
    queue = Queue()

    for port in ports:
        queue.put(port)

    thread_list = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(
            target=worker,
            args=(ip, timeout, results, banner_grab, queue),
            daemon=True
        )
        thread_list.append(t)
        t.start()

    queue.join()
    return results

def parse_ports(port_arg):
    """Parse port argument like nmap: 80, 1-1024, 22,80,443"""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def print_results(ip, results, start_time):
    """Print nmap-style results."""
    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()

    open_ports = {p: v for p, v in sorted(results.items()) if v["state"] == "open"}

    print(f"\n{'─'*60}")
    print(f"Scan report for {ip}")
    print(f"Scanned at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*60}")

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"{'PORT':<10} {'STATE':<8} {'SERVICE':<15} {'BANNER'}")
        print(f"{'─'*10} {'─'*8} {'─'*15} {'─'*25}")
        for port, info in open_ports.items():
            banner = info["banner"][:40] if info["banner"] else ""
            print(f"{str(port)+'/tcp':<10} {'open':<8} {info['service']:<15} {banner}")

    print(f"{'─'*60}")
    print(f"Found {len(open_ports)} open port(s) in {elapsed:.2f}s")
    print(f"{'─'*60}\n")

def resolve_target(target):
    """Resolve hostname to IP."""
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"[*] Resolved {target} → {ip}")
        return ip
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Fast nmap-style TCP port scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py 192.168.0.1
  python3 port_scanner.py 192.168.0.1 -p 1-1024
  python3 port_scanner.py 192.168.0.1 -p 22,80,443,3306
  python3 port_scanner.py scanme.nmap.org --top-ports -b
  python3 port_scanner.py 192.168.0.1 -p 1-65535 -t 500

Disclaimer:
  Only scan systems you own or have explicit permission to test.
        """
    )

    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "-p", "--ports",
        default=None,
        help="Port range (e.g. 1-1024, 22,80,443). Default: top 1000 common ports"
    )
    parser.add_argument(
        "--top-ports",
        action="store_true",
        help="Scan top common ports only (faster)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int, default=200,
        help="Number of threads (default: 200)"
    )
    parser.add_argument(
        "--timeout",
        type=float, default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-b", "--banner",
        action="store_true",
        help="Attempt banner grabbing on open ports"
    )

    args = parser.parse_args()

    # Resolve target
    ip = resolve_target(args.target)

    # Determine ports to scan
    if args.top_ports:
        ports = sorted(COMMON_PORTS.keys())
        port_desc = f"top {len(ports)} common ports"
    elif args.ports:
        ports = parse_ports(args.ports)
        port_desc = args.ports
    else:
        # Default: 1-1024 + common high ports
        ports = list(range(1, 1025)) + [p for p in COMMON_PORTS if p > 1024]
        ports = sorted(set(ports))
        port_desc = f"1-1024 + common high ports ({len(ports)} total)"

    print(f"\n[*] Starting scan on {ip}")
    print(f"[*] Ports: {port_desc}")
    print(f"[*] Threads: {args.threads} | Timeout: {args.timeout}s | Banner: {args.banner}")

    start_time = datetime.now()
    results = run_scan(ip, ports, args.timeout, args.threads, args.banner)
    print_results(ip, results, start_time)

if __name__ == "__main__":
    main()
