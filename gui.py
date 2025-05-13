import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import random
from datetime import datetime

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

def scan_tcp(target, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                service = get_service_name(port)
                return f"Port {port}/TCP OPEN ({service})"
    except:
        pass
    return None

def start_scan():
    target = entry_target.get().strip()
    port_range = entry_ports.get().strip()
    shuffle = var_shuffle.get()

    if not target:
        messagebox.showerror("Error", "Please enter a target IP or hostname.")
        return

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        messagebox.showerror("Error", f"Could not resolve {target}.")
        return

    if port_range:
        try:
            start, end = map(int, port_range.split("-"))
            ports = list(range(start, end + 1))
        except:
            messagebox.showerror("Error", "Port range must be in format start-end (e.g. 20-80).")
            return
    else:
        ports = TOP_PORTS.copy()

    if shuffle:
        random.shuffle(ports)

    results_box.delete(1.0, tk.END)
    results_box.insert(tk.END, f"Scanning {ip} ({len(ports)} ports)...\n\n")
    start_time = datetime.now()

    for i, port in enumerate(ports, 1):
        result = scan_tcp(ip, port)
        if result:
            results_box.insert(tk.END, result + "\n")
        root.update_idletasks()  # Allow GUI to stay responsive

    duration = datetime.now() - start_time
    results_box.insert(tk.END, f"\nScan completed in {duration}.\n")

root = tk.Tk()
root.title("Python GUI Port Scanner")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

tk.Label(frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky="e")
entry_target = tk.Entry(frame, width=30)
entry_target.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame, text="Port Range (e.g. 20-80):").grid(row=1, column=0, sticky="e")
entry_ports = tk.Entry(frame, width=30)
entry_ports.grid(row=1, column=1, padx=5, pady=5)

var_shuffle = tk.BooleanVar()
chk_shuffle = tk.Checkbutton(frame, text="Shuffle Ports", variable=var_shuffle)
chk_shuffle.grid(row=2, column=1, sticky="w", pady=5)

btn_scan = tk.Button(frame, text="Start Scan", command=start_scan, bg="#4CAF50", fg="white")
btn_scan.grid(row=3, column=0, columnspan=2, pady=10)

results_box = scrolledtext.ScrolledText(root, width=80, height=20)
results_box.pack(padx=10, pady=10)

root.mainloop()
