import socket
target_host = "scanme.nmap.org"
port_range = range(20, 1025)
timeout = 1

print(f"Scanning {target_host}...")

open_ports = []

for port in port_range s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    result = s.connect_ex((target_host, port))  # Returns 0 if success, else error code
    if result == 0:
        print(f"Port {port} is OPEN")
        open_ports.append(port)
    else:
        pass  # Port is closed or unreachable
    
    s.close()

print("Scan complete.")
