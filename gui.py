
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
