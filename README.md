# 🔍 Port Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)

This Python script allows you to scan TCP and UDP ports on one or more targets with support for banner grabbing, filtering, output to JSON/CSV, port shuffling, and reverse DNS resolution. It's a flexible and extensible tool for network reconnaissance and service discovery.

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
- `colorama` *(install with `pip install colorama`)*

---

## 🧰 Features

- Scan **TCP and/or UDP** ports
- Supports **custom port ranges**
- Scan **multiple targets** from a file
- **Banner grabbing** on known ports (e.g., HTTP, FTP, SSH)
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
