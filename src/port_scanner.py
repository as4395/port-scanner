import socket
import argparse
import os
import random
import json
import csv
import subprocess
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Top 100 commonly used ports
# Top 100 commonly used TCP/UDP ports (services, exploits, scanning targets)
TOP_PORTS = [
    20,    # FTP (Data Transfer)
    21,    # FTP (Command)
    22,    # SSH (Secure Shell)
    23,    # Telnet (Unencrypted Remote Login)
    24,    # Priv-Mail (any private mail system)
    25,    # SMTP (Mail Transfer)
    26,    # Alternate SMTP (Mail)
    53,    # DNS (Domain Name System)
    69,    # TFTP (Trivial File Transfer Protocol)
    80,    # HTTP (Web)
    81,    # HTTP Alternate / Management UI
    88,    # Kerberos (Authentication)
    110,   # POP3 (Mail Retrieval)
    111,   # RPCBind / Portmapper (SunRPC)
    135,   # MS RPC (DCOM Service Control)
    137,   # NetBIOS Name Service
    139,   # NetBIOS Session Service
    143,   # IMAP (Mail Retrieval)
    161,   # SNMP (Monitoring)
    162,   # SNMP Trap (Asynchronous Alerts)
    389,   # LDAP (Directory Services)
    443,   # HTTPS (Secure Web)
    445,   # SMB over IP (Windows File Sharing)
    465,   # SMTPS (Secure Mail Transfer)
    500,   # IKE (VPN IPsec Key Exchange)
    636,   # LDAPS (Secure LDAP)
    993,   # IMAPS (Secure IMAP)
    995,   # POP3S (Secure POP3)
    1025,  # Windows RPC (High)
    1026,  # Windows Service Port
    1027,  # Windows Service Port
    1028,  # Windows Service Port
    1029,  # Windows Service Port
    1030,  # Windows Service Port
    1080,  # SOCKS Proxy
    1433,  # Microsoft SQL Server
    1521,  # Oracle Database
    1720,  # H.323 (VoIP/Video)
    1723,  # PPTP (VPN Tunneling)
    1900,  # SSDP (UPnP Discovery)
    3128,  # Squid HTTP Proxy
    3306,  # MySQL Database
    3389,  # RDP (Remote Desktop)
    5000,  # UPnP / Flask / IoT APIs
    5432,  # PostgreSQL
    5800,  # VNC Web Interface
    5900,  # VNC (Remote GUI)
    5901,  # VNC Alternate Instance
    6000,  # X11 (Graphical Remote)
    7000,  # AFS (File System) / Other Services
    8000,  # HTTP Dev Server / IoT
    8080,  # HTTP Proxy / Alternate Web
    8081,  # HTTP Alt / Web UI
    8443,  # HTTPS Alternate (Tomcat, Admin UIs)
    8888,  # Web UI / Alt HTTP
    10000, # Webmin / Backup Exec / Misc Admin Panels
    32768, # RPC (Linux legacy ephemeral port)

    # Microsoft Windows Ephemeral Port Range (RFC 6056)
    49152  # Start of dynamic/private (ephemeral) ports per IANA (RFC 6335); used by Windows, Linux, macOS, and other operating systems.
    49153,
    49154,
    49155,
    49156,
    49157,
    49158,
    49159,
    49160,
    49161,
    49162,
    49163,
    49164,
    49165,
    49166,
    49167,
    49168,
    49169,
    49170,
    49171,
    49172,
    49173,
    49174,
    49175,
    49176,
    49177,
    49178,
    49179,
    49180,
    49181,
    49182,
    49183,
    49184,
    49185,
    49186,
    49187,
    49188,
    49189,
    49190,
    49191,
    49192,
    49193,
    49194  # End of the default ephemeral port range in computer networking
]

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

def is_host_alive(ip, fallback_ports=[80, 443]):
    try:
        # Try ICMP ping first
        ping_result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
        if ping_result.returncode == 0:
            return True
    except:
        pass

    # Fall back to TCP connection attempt on common ports
    for port in fallback_ports:
        try:
            with socket.create_connection((ip, port), timeout=1):
                return True
        except:
            continue
    return False

def scan_tcp(target, port, timeout):
    category_lookup = {
        'http': 'Web', 'https': 'Web', 'ftp': 'File Sharing', 'ssh': 'Remote Access', 'telnet': 'Remote Access',
        'smtp': 'Email', 'pop3': 'Email', 'imap': 'Email', 'mysql': 'Database', 'postgresql': 'Database',
        'rdp': 'Remote Access', 'vnc': 'Remote Access', 'smb': 'File Sharing'
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                banner = ""
                try:
                    if port in [80, 8080, 8000, 8888]:
                        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    elif port == 21:
                        s.sendall(b"USER anonymous\r\n")
                    elif port == 25:
                        s.sendall(b"EHLO scanner\r\n")
                    elif port == 3306:
                        s.sendall(b"\x00")
                    else:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except:
                    pass
                service = get_service_name(port)
                category = category_lookup.get(service.lower(), "Other")
                return {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "protocol": "TCP",
                    "category": category,
                    "timestamp": datetime.now().isoformat()
                }
    except:
        pass
    return None

def scan_udp(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (target, port))
            s.recvfrom(1024)
            service = get_service_name(port)
            return {"port": port, "service": service, "banner": "", "protocol": "UDP", "category": "Other", "timestamp": datetime.now().isoformat()}
    except:
        return None

def detect_weak_credentials(target):
    default_ftp_creds = [("anonymous", "anonymous@domain.com"), ("admin", "admin"), ("root", "toor")]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, 21))
            s.recv(1024)
            for user, pwd in default_ftp_creds:
                s.sendall(f"USER {user}\r\n".encode())
                s.recv(1024)
                s.sendall(f"PASS {pwd}\r\n".encode())
                response = s.recv(1024).decode(errors="ignore")
                if "230" in response:
                    return (user, pwd)
    except:
        pass
    return None

def save_results(results, output, fmt):
    try:
        with open(output, "w", newline="") as f:
            if fmt == "json":
                json.dump(results, f, indent=2)
            elif fmt == "csv":
                writer = csv.DictWriter(f, fieldnames=["port", "service", "banner", "protocol", "category", "timestamp"])
                writer.writeheader()
                for row in results:
                    writer.writerow({key: row.get(key, '') for key in writer.fieldnames})
    except Exception as e:
        print(Fore.RED + f"[!] Failed to write output: {e}")

def scan_target(target, ports, args):
    results = []
    print(f"\n[~] Scanning {target} ({len(ports)} ports) | Timeout: {args.timeout}s\n")
    start_time = datetime.now()

    if args.shuffle:
        random.shuffle(ports)

    for i, port in enumerate(ports, 1):
        print(f"\rScanning port {port} ({i}/{len(ports)})...", end="", flush=True)
        result = scan_tcp(target, port, args.timeout)

        if args.udp:
            udp_result = scan_udp(target, port, args.timeout)
            if udp_result:
                results.append(udp_result)

        if result:
            if args.filter_banner and not result["banner"]:
                continue
            if args.filter_service and result["service"].lower() not in args.filter_service:
                continue
            results.append(result)
            print(Fore.GREEN + f"\n[+] Port {result['port']} ({result['service'].upper()}) {result['protocol']} open" +
                  (f" | Banner: {result['banner'].splitlines()[0]}" if result['banner'] else ""))

    if args.detect_creds:
        creds = detect_weak_credentials(target)
        if creds:
            print(Fore.YELLOW + f"[!] Weak FTP credentials found: {creds[0]}:{creds[1]}")

    duration = datetime.now() - start_time
    print(f"\n[✓] Scan complete in {duration}")
    print(f"[✓] Open ports: {len(results)}\n")

    if args.output and args.format:
        save_results(results, args.output, args.format)
        print(Fore.MAGENTA + f"[+] Results saved to {args.output} ({args.format.upper()})")

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with TCP/UDP, JSON/CSV, Filters, and Credential Detection")
    parser.add_argument("--detect-creds", action="store_true", help="Attempt to detect default/weak credentials (FTP only)")
    parser.add_argument("target", nargs="?", help="Target IP or domain")
    parser.add_argument("-r", "--range", help="Custom port range (e.g. 1-1024)")
    parser.add_argument("-f", "--file", help="File with list of targets (one per line)")
    parser.add_argument("-o", "--output", help="File to save results")
    parser.add_argument("--format", choices=["json", "csv"], help="Output format")
    parser.add_argument("--timeout", type=float, default=0.2, help="Timeout in seconds")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--shuffle", action="store_true", help="Randomize port order")
    parser.add_argument("--filter-banner", action="store_true", help="Only show ports with banners")
    parser.add_argument("--filter-service", type=lambda s: s.lower().split(","), help="Only show services (e.g. http,ssh)")
    args = parser.parse_args()

    ports = list(range(*map(int, args.range.split("-")))) if args.range else TOP_PORTS

    targets = []
    if args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]
    else:
        user_input = input("Enter a target IP or domain to scan: ").strip()
        if user_input:
            try:
                resolved_ip = socket.gethostbyname(user_input)
                targets = [resolved_ip]
            except socket.gaierror:
                print(Fore.RED + f"[!] Could not resolve {user_input}. Exiting.")
                return
        else:
            print("[!] No target specified. Exiting.")
            return

    for target in targets:
        try:
            ip = socket.gethostbyname(target)
            if is_host_alive(ip):
                try:
                    reverse_dns = socket.gethostbyaddr(ip)[0]
                    print(f"[~] Scanning {target} ({ip}) | Reverse DNS: {reverse_dns}")
                except socket.herror:
                    print(f"[~] Scanning {target} ({ip}) | Reverse DNS: Not found")
                print(Fore.CYAN + f"[+] Host {ip} is alive. Proceeding to scan.")
                scan_target(ip, ports, args)
            else:
                print(Fore.RED + f"[!] Host {ip} appears to be down or unresponsive.")
        except socket.gaierror:
            print(Fore.RED + f"[!] Could not resolve {target}")

if __name__ == "__main__":
    main()
