import socket
from datetime import datetime

def scan_ports(target, start_port, end_port):
    print(f"\nScanning host: {target}")
    print(f"Scanning ports: {start_port} to {end_port}")
    print(f"Scan started at: {datetime.now()}\n")

    try:
        for port in range(start_port, end_port + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)  # Timeout for response
                result = s.connect_ex((target, port)) 
                if result == 0:
                    print(f"[+] Port {port} is open")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except socket.gaierror:
        print("[!] Hostname could not be resolved.")
    except socket.error:
        print("[!] Could not connect to the host.")
    
    print(f"\nScan completed at: {datetime.now()}")


def main():
    target = input("Enter target host (e.g., example.com or 192.168.1.1): ").strip()
    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            raise ValueError
        ip = socket.gethostbyname(target)  # Resolve hostname to IP
        scan_ports(ip, start_port, end_port)
    except ValueError:
        print("[!] Invalid port range.")

if __name__ == "__main__":
    main()
