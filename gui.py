import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import socket
import random
import json
import csv
from datetime import datetime

def scan_tcp(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = ""
                return {"port": port, "protocol": "TCP", "service": service, "banner": banner}
    except:
        pass
    return None

def scan_udp(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"", (ip, port))
            sock.recvfrom(1024)
            try:
                service = socket.getservbyport(port, "udp")
            except:
                service = "unknown"
            return {"port": port, "protocol": "UDP", "service": service, "banner": ""}
    except:
        return None

def start_scan():
    target = entry_target.get().strip()
    ports_input = entry_ports.get().strip()
    shuffle = shuffle_var.get()
    do_udp = udp_var.get()

    if not target:
        messagebox.showerror("Input Error", "Please enter a target.")
        return

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        messagebox.showerror("Error", f"Cannot resolve {target}.")
        return

    if ports_input:
        try:
            start, end = map(int, ports_input.split('-'))
            ports = list(range(start, end + 1))
        except:
            messagebox.showerror("Input Error", "Port range must be start-end.")
            return
    else:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 8080]

    if shuffle:
        random.shuffle(ports)

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"Scanning {ip} on {len(ports)} ports...\n\n")
    start_time = datetime.now()

    results = []
