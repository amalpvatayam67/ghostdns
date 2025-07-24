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
