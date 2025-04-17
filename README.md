# 🔍 Port Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)

This Python script allows you to scan TCP and UDP ports on one or more targets with support for banner grabbing, filtering, output to JSON/CSV, port shuffling, default credential detection, and reverse DNS resolution.

---

## 🛠 Requirements

This script uses Python’s built-in libraries plus one external module:

- `socket`
- `argparse`
- `os`
- `random`
- `json`
- `csv`
- `datetime`
- `subprocess`
- `colorama` *(install with `pip install colorama`)*

---

## 🧰 Features

- Scan **TCP and/or UDP** ports
- **ICMP ping + TCP fallback** to verify live hosts
- Supports **custom port ranges**
- Scan **multiple targets** from a file
- **Banner grabbing** on known ports (e.g., HTTP, FTP, SSH)
- **Detect default/weak FTP credentials**
- Save results in **JSON or CSV**
- **Color-coded output** in the terminal
- **Reverse DNS lookup** for targets
- **Shuffle port order** to avoid detection patterns
- Filter:
  - Only ports that return **banners**
  - Only **specific services** (e.g., HTTP, SSH)
- Service **categorization** (Web, Remote Access, Email, etc.)

---

## 🚀 How to Use

### 1. Clone the Repository

To download the project files, open a terminal and run:

```bash
git clone https://github.com/as4395/port_sec.git
cd port_sec
```

### 2. Install Dependencies

This project only requires one external library:

```bash
pip install colorama
```

### 3. Run the Script

Ensure you have Python 3 installed:

```bash
python3 --version
```
Run the scanner using:
```bash
python3 scanner.py [target] [options]
```
If no target is provided, the script will prompt you to enter one interactively.

---

## ⚙️ Available Options

| Option               | Description                                             |
|----------------------|---------------------------------------------------------|
| `target`             | Target IP or domain (positional argument)               |
| `-r`, `--range`      | Port range to scan (e.g. `1-1024`)                       |
| `-f`, `--file`       | File containing targets (one per line)                  |
| `-o`, `--output`     | File to save results                                    |
| `--format`           | Output format: `json` or `csv`                          |
| `--timeout`          | Timeout per port in seconds (default: `0.2`)            |
| `--udp`              | Enable UDP scanning                                     |
| `--shuffle`          | Randomize port order                                    |
| `--filter-banner`    | Only show ports that return banners                     |
| `--filter-service`   | Only show specific services (e.g. `http,ssh`)           |
| `--detect-creds`     | Attempt default/weak FTP credentials                    |

---

# 💡 Example Commands

Scan top 100 TCP ports:

```bash
python3 scanner.py scanme.nmap.org
```
Scan ports 1–1024 and save output as JSON:
```bash
python3 scanner.py scanme.nmap.org -r 1-1024 -o results.json --format json
```
Scan multiple targets from a file:
```bash
python3 scanner.py -f targets.txt
```
Enable UDP scan and only show HTTP/SSH:
```bash
python3 scanner.py scanme.nmap.org --udp --filter-service http,ssh
```
Shuffle ports and filter for banners:
```bash
python3 scanner.py scanme.nmap.org --shuffle --filter-banner
```
Scan and check for default FTP credentials:
```bash
python3 scanner.py scanme.nmap.org --detect-creds
```

## 📤 Output Formats

### JSON

```json
[
  {
    "port": 22,
    "service": "ssh",
    "banner": "SSH-2.0-OpenSSH_7.6p1 Ubuntu",
    "protocol": "TCP",
    "category": "Remote Access",
    "timestamp": "2024-07-10T15:32:48.679123"
  }
]
```
### CSV

```csv
| port | service | banner                       | protocol | category      | timestamp                     |
|------|---------|------------------------------|----------|---------------|-------------------------------|
| 22   | ssh     | SSH-2.0-OpenSSH_7.6p1 Ubuntu | TCP      | Remote Access | 2024-07-10T15:32:48.679123    |
```

## 🧠 Tips

- Combine filters to narrow down meaningful results.
- Use `--shuffle` to avoid triggering intrusion detection systems.
- Banners may help identify vulnerable services—use them responsibly.
- Try both TCP and UDP scans for a more complete picture.

## ⚠️ Disclaimer

This tool is intended for educational and authorized security testing only. Do not use it against systems without explicit permission.
