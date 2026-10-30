#!/usr/bin/env bash
set -euo pipefail

# Clean Mininet leftovers and old generated evidence.
echo "[*] Cleaning Mininet leftovers..."
mn -c >/dev/null 2>&1 || true

echo "[*] Removing old logs and captures..."
rm -rf logs captures
mkdir -p logs/anonymized captures

echo "[OK] Cleanup complete."
