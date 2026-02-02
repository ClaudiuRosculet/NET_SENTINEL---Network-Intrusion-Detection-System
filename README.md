# 🛡️ NET_SENTINEL - Network Intrusion Detection System

**NET_SENTINEL** is a lightweight Network Forensics and real-time monitoring tool developed in Python. It analyzes network traffic to identify suspicious activities and common cyber attacks.

## ✨ Key Features

* **🕵️ Cleartext Credential Detection:** Identifies unencrypted login attempts (passwords and usernames) sent via HTTP (POST), FTP, and Telnet.
* **🚫 DoS (Denial of Service) Alerts:** Monitors packet volume and alerts when a single IP exceeds the threshold of 500 packets per second.
* **☠️ ARP Spoofing Protection:** Detects Man-in-the-Middle (MITM) attempts by monitoring ARP table mappings and identifying IP/MAC mismatches.
* **📊 Visual Terminal Interface:** Color-coded logs for immediate threat identification (Red for DoS, Yellow for Credentials, Magenta for MITM).

---

## 🚀 Installation & Setup

### 1. Environment Preparation (Pop!_OS / Ubuntu)
To keep your system clean, it is highly recommended to use a virtual environment:

```bash
# Install venv support
sudo apt update && sudo apt install python3-venv

# Create and activate the environment
python3 -m venv .venv
source .venv/bin/activate

# Install required libraries
pip install scapy colorama