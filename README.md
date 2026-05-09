# 🛡️ NetSentinel — Network Security Scanner & Firewall Visualizer
**Information Security Assignment A3**

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Backend-black?logo=flask)
![Nmap](https://img.shields.io/badge/Nmap-Scanner-brightgreen?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)

A web-based tool to scan a local network or specific IP address for open ports,
services, and vulnerabilities — with a built-in firewall rule simulator and
visual traffic flow diagram.

---

## ✨ Features

| Feature | Details |
|---------|---------|
| Port Scanner | TCP Full Connect, TCP SYN, UDP, Comprehensive+Version |
| Risk Assessment | HIGH / MEDIUM / LOW per port based on service |
| Firewall Simulator | Allow/Deny rules with priority-based chaining |
| Traffic Flow Diagram | Canvas-drawn visual showing blocked vs allowed traffic |
| Clean UI | Cyberpunk-themed single-page web app |

---

## 🚀 Quick Start

### Prerequisites
1. Install **Python 3.x**
2. Install **Nmap** → https://nmap.org/download.html (Windows: also install **Npcap**)
3. Add Nmap to your system PATH

### Setup
```bash
git clone https://github.com/YOUR_USERNAME/network-security-scanner
cd network-security-scanner
pip install -r requirements.txt
```

### Run
```bash
# For TCP SYN / UDP scans — run as Administrator:
python scanner_app.py

# Then open scanner.html in your browser
```

> ⚠️ **Windows users:** TCP SYN (`-sS`) and UDP (`-sU`) scans require:
> - Running the terminal **as Administrator**
> - **Npcap** installed (https://npcap.com)
>
> TCP Full Connect (`-sT`) works **without** admin rights.

---

## 🗂️ Project Structure

```
network-security-scanner/
├── scanner_app.py       # Flask backend — scanning & firewall logic
├── scanner.html         # Frontend — single-page UI
├── requirements.txt     # Python dependencies
└── README.md
```

---

## 🔍 Scanning Engine

Uses **python-nmap** (a Python wrapper for Nmap) to perform:

| Scan Type | Flag | Requires Admin |
|-----------|------|----------------|
| TCP Full Connect | `-sT` | No |
| TCP SYN Stealth | `-sS` | Yes (+ Npcap) |
| UDP Scan | `-sU` | Yes (+ Npcap) |
| Comprehensive | `-sT -sV` | No |

Results include: IP, Port, Protocol, Service/Version, Status, Risk Level.

---

## 🔥 Firewall Simulation Logic

Rules are evaluated in **priority order** (lowest number = first evaluated).
First matching rule wins. Default verdict if no rule matches: **ALLOW**.

**Rule fields:**
- **Action** — Allow or Deny
- **IP** — exact IP or `*` for wildcard
- **Port** — specific port or `Any`
- **Protocol** — TCP, UDP, or ANY
- **Priority** — integer, lower = higher priority

**Example rule chain:**
```
Priority 1 → DENY  192.168.1.50  Port:Any    TCP
Priority 2 → ALLOW *             Port:80     TCP
Priority 3 → DENY  *             Port:Any    ANY
```

---

## 🛠️ Tech Stack
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, Canvas API
- **Backend:** Python 3, Flask, Flask-CORS
- **Scanning:** python-nmap (Nmap wrapper)
- **Visualization:** HTML Canvas (traffic flow diagram)
