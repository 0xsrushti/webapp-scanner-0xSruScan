#!/bin/bash
# startup helper for local Kali use

if [ ! -d ".venv" ]; then
  echo "[+] Creating virtual environment..."
  python3 -m venv .venv
fi
source .venv/bin/activate

if [ ! -f ".venv/.installed" ]; then
  echo "[+] Installing dependencies..."
  pip install -r requirements.txt
  python -m playwright install chromium
  touch .venv/.installed
fi

echo "[+] Starting Flask webapp scanner..."
python app.py
