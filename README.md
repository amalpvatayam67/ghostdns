# 👻 GhostDNS - Subdomain Takeover Scanner

**GhostDNS** is a lightweight Python tool to detect potential subdomain takeover vulnerabilities.  
It also includes a passive DNS sniffer mode using Scapy to capture real-time DNS queries and analyze them for potential issues.

---

## ✨ Features

- CNAME & A record subdomain resolution
- 100+ known takeover signature detection
- HTTP content checking for validation
- JSON reporting
- Passive DNS sniffing (Scapy)
- Spinner-based UI for user feedback

---

## 🚀 Requirements

- Python 3.7+
- Install required modules using:

```bash
pip install -r requirements.txt
```

---

## 📦 Installation & Usage

1. Clone the repository:
```bash
git clone https://github.com/yourname/GhostDNS.git
cd GhostDNS
```

2. Run the setup:
```bash
chmod +x setup.sh
./setup.sh
```

3. Scan for subdomain takeovers:
```bash
python ghostdns.py -d example.com -w wordlist.txt -o results.json
```

4. OR use passive DNS sniffer mode:
```bash
sudo python ghostdns.py -d example.com --sniff --timeout 60
```

> ⚠️ **Sniffer mode requires root privileges.**

---

## 🔧 Arguments

| Argument        | Description                          |
|----------------|--------------------------------------|
| `-d`, `--domain`| Root domain to scan (required)       |
| `-w`, `--wordlist`| Subdomain wordlist path            |
| `-o`, `--output`| JSON output file (optional)         |
| `--sniff`       | Enable DNS sniffer mode             |
| `--timeout`     | Timeout for sniffer mode (seconds)  |

---

## 🧪 Example

```bash
python ghostdns.py -d example.com -w subdomains.txt -o report.json
```

```bash
sudo python ghostdns.py -d example.com --sniff --timeout 90
```

---

## 🛠 setup.sh (Auto install)

```bash
#!/bin/bash

echo "[i] Setting up GhostDNS Environment..."

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "[i] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[i] Installing required Python packages..."
pip install -r requirements.txt

echo "[✓] Setup complete. To run GhostDNS:"
echo "--------------------------------------"
echo "source venv/bin/activate"
echo "python ghostdns.py -d example.com -w subdomains.txt -o result.json"
```

Save this as `setup.sh` in your project root.

---

## 📝 License

This tool is for educational and ethical testing purposes only.  
Author: amalp[amalpvatayam67]

---

## 🤝 Contributions

PRs are welcome to add more signatures or enhance features!
