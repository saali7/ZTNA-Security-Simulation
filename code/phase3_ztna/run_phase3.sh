#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Please run with sudo: sudo ./run_phase3.sh"
  exit 1
fi

python3 dependency_check.py
./cleanup.sh
python3 traffic_tests.py

echo ""
echo "[DONE] Phase 3 completed."
echo "Results: logs/"
echo "Anonymized logs: logs/anonymized/"
echo "Packet captures: captures/"
echo "Summary: logs/phase3_summary.csv"
