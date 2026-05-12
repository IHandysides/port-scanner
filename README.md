# Python Port Scanner

A fast, multithreaded TCP port scanner written from scratch in Python. Built as a learning project to understand how network scanning tools like Nmap work under the hood. No external dependencies — uses only the Python standard library.

---

## Features

- Multithreaded scanning with configurable thread count
- Custom port ranges, comma separated ports, or top common ports mode
- Banner grabbing to fingerprint services on open ports
- Hostname resolution
- nmap-style terminal output
- Adjustable socket timeout
- 71 common ports mapped to service names built in

---

## Installation

No dependencies required. Just clone and run.

```bash
git clone https://github.com/IHandysides/port-scanner.git
cd port-scanner
python3 port_scanner.py --help
```

---

## Usage

```
usage: port_scanner.py [-h] [-p PORTS] [--top-ports] [-t THREADS] [--timeout TIMEOUT] [-b] target

positional arguments:
  target                Target IP address or hostname

optional arguments:
  -p, --ports           Port range or list (e.g. 1-1024 or 22,80,443)
  --top-ports           Scan top 71 common ports only
  -t, --threads         Number of threads (default: 200)
  --timeout             Socket timeout in seconds (default: 1.0)
  -b, --banner          Attempt banner grabbing on open ports
```

---

## Examples

**Default scan — ports 1-1024 plus common high ports:**
```bash
python3 port_scanner.py 192.168.0.1
```

**Scan specific ports:**
```bash
python3 port_scanner.py 192.168.0.1 -p 22,80,443,3306,8080
```

**Scan a port range:**
```bash
python3 port_scanner.py 192.168.0.1 -p 1-1024
```

**Full scan across all 65535 ports with more threads:**
```bash
python3 port_scanner.py 192.168.0.1 -p 1-65535 -t 500
```

**Top common ports with banner grabbing:**
```bash
python3 port_scanner.py 192.168.0.1 --top-ports -b
```

**Scan by hostname:**
```bash
python3 port_scanner.py scanme.nmap.org --top-ports -b
```

---

## Example Output

```
[*] Starting scan on 192.168.0.1
[*] Ports: top 71 common ports
[*] Threads: 200 | Timeout: 1.0s | Banner: True

────────────────────────────────────────────────────────────
Scan report for 192.168.0.1
Scanned at 2026-05-12 14:05:47
────────────────────────────────────────────────────────────
PORT       STATE    SERVICE         BANNER
────────── ──────── ─────────────── ─────────────────────────
22/tcp     open     SSH             SSH-2.0-OpenSSH_9.6p1 Ubuntu
53/tcp     open     DNS
80/tcp     open     HTTP            HTTP/1.1 200 OK
443/tcp    open     HTTPS
3306/tcp   open     MySQL
8080/tcp   open     HTTP-proxy      HTTP/1.1 302 Found
────────────────────────────────────────────────────────────
Found 6 open port(s) in 1.24s
────────────────────────────────────────────────────────────
```

---

## How It Works

1. Parses the target and resolves hostnames to IP addresses
2. Builds a queue of ports to scan
3. Spawns a configurable number of threads that each pull from the queue
4. Each thread attempts a TCP connect to the port with a set timeout
5. Open ports are recorded along with their service name
6. If banner grabbing is enabled, a follow-up connection reads the service response
7. Results are printed in a formatted table once all threads complete

---

## Tested Against

- Personal home lab infrastructure (authorized)
- `scanme.nmap.org` — Nmap's public test server
- VulnHub CTF machines

---

## Roadmap

- [ ] UDP scanning
- [ ] Ping sweep / host discovery mode
- [ ] Output to file (txt, json)
- [ ] OS detection
- [ ] CVE lookup against detected service versions

---

## Disclaimer

This tool is intended for use on systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

---

## Author

Isaac Handysides
[github.com/IHandysides](https://github.com/IHandysides) · [tryhackme.com/p/Handysides](https://tryhackme.com/p/Handysides)
