import socket
import argparse
import os
import random
import json
import csv
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Top 100 commonly used ports
TOP_PORTS = [
    20, 21, 22, 23, 24, 25, 26, 53, 69, 80, 81, 88, 110, 111, 135, 137, 139, 143,
    161, 162, 389, 443, 445, 465, 500, 636, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1030, 1080, 1433, 1521, 1720, 1723, 1900, 3128, 3306, 3389, 5000, 5432, 5800,
    5900, 5901, 6000, 7000, 8000, 8080, 8081, 8443, 8888, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49162,
    49163, 49164, 49165, 49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173,
    49174, 49175, 49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184,
    49185, 49186, 49187, 49188, 49189, 49190, 49191, 49192, 49193, 49194
]

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

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
                        s.sendall(b"\x00") # Basic MySQL handshake
                    else:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except:
                    pass
                service = get_service_name(port)
                service_lower = service.lower()
                category = category_lookup.get(service_lower, "Other")
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
            result_udp = scan_udp(target, port, args.timeout)
            if result_udp:
                result = result_udp
        if result:
            if args.filter_banner and not result["banner"]:
                continue
            if args.filter_service and result["service"].lower() not in args.filter_service:
                continue
            results.append(result)
            print(Fore.GREEN + f"\n[+] Port {result['port']} ({result['service'].upper()}) {result['protocol']} open" +
                  (f" | Banner: {result['banner'].splitlines()[0]}" if result['banner'] else ""))

    duration = datetime.now() - start_time
    print(f"\n[✓] Scan complete in {duration}")
    print(f"[✓] Open ports: {len(results)}\n")

    if args.output and args.format:
        save_results(results, args.output, args.format)
        print(Fore.MAGENTA + f"[+] Results saved to {args.output} ({args.format.upper()})")

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with TCP/UDP, JSON/CSV, and Filters")
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
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
                print(f"[~] Scanning {target} ({ip}) | Reverse DNS: {reverse_dns}")
            except socket.herror:
                print(f"[~] Scanning {target} ({ip}) | Reverse DNS: Not found")
            scan_target(ip, ports, args)
        except socket.gaierror:
            print(Fore.RED + f"[!] Could not resolve {target}")

if __name__ == "__main__":
    main()
