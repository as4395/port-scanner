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


    for port in ports:
        result = scan_tcp(ip, port)
        if result:
            results.append(result)
            output_box.insert(tk.END, f"{result['protocol']} {result['port']} OPEN ({result['service']})\n")

        if do_udp:
            result_udp = scan_udp(ip, port)
            if result_udp:
                results.append(result_udp)
                output_box.insert(tk.END, f"{result_udp['protocol']} {result_udp['port']} OPEN ({result_udp['service']})\n")

        root.update()

    duration = datetime.now() - start_time
    output_box.insert(tk.END, f"\nScan completed in {duration}.\n")

    export_button.config(state="normal")
    root.results_data = results

def export_results():
    results = getattr(root, 'results_data', None)
    if not results:
        messagebox.showinfo("No Results", "No results to export.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")])
    if not file_path:
        return

    if file_path.endswith(".json"):
        with open(file_path, "w") as f:
            json.dump(results, f, indent=4)
    elif file_path.endswith(".csv"):
        with open(file_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "protocol", "service", "banner"])
            writer.writeheader()
            writer.writerows(results)


root = tk.Tk()
root.title("Advanced GUI Port Scanner")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

tk.Label(frame, text="Target:").grid(row=0, column=0, sticky="e")
entry_target = tk.Entry(frame, width=30)
entry_target.grid(row=0, column=1, pady=5)

tk.Label(frame, text="Port Range (start-end):").grid(row=1, column=0, sticky="e")
entry_ports = tk.Entry(frame, width=30)
entry_ports.grid(row=1, column=1, pady=5)

shuffle_var = tk.BooleanVar()
tk.Checkbutton(frame, text="Shuffle Ports", variable=shuffle_var).grid(row=2, column=1, sticky="w")

udp_var = tk.BooleanVar()
tk.Checkbutton(frame, text="Enable UDP Scan", variable=udp_var).grid(row=3, column=1, sticky="w")

scan_button = tk.Button(frame, text="Start Scan", command=start_scan, bg="green", fg="white")
scan_button.grid(row=4, column=0, columnspan=2, pady=10)

export_button = tk.Button(frame, text="Export Results", command=export_results, state="disabled")
export_button.grid(row=5, column=0, columnspan=2)

output_box = scrolledtext.ScrolledText(root, width=80, height=20)
output_box.pack(padx=10, pady=10)

root.mainloop()
