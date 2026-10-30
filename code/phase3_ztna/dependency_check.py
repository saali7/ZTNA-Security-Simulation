# dependency_check.py
"""Check required tools before running the ZTNA simulation."""

import os
import shutil
import sys

from config import OPTIONAL_COMMANDS, REQUIRED_COMMANDS


def main():
    missing = [cmd for cmd in REQUIRED_COMMANDS if shutil.which(cmd) is None]
    optional_missing = [cmd for cmd in OPTIONAL_COMMANDS if shutil.which(cmd) is None]

    if os.geteuid() != 0:
        print("[ERROR] Run this project with sudo because Mininet, tcpdump, and iptables need root.")
        print("        Example: sudo ./run_phase3.sh")
        return 1

    if missing:
        print("[ERROR] Missing required commands:")
        for cmd in missing:
            print(f"  - {cmd}")
        print("Install missing packages, then run again.")
        return 1

    if optional_missing:
        print("[WARNING] Optional command missing:")
        for cmd in optional_missing:
            print(f"  - {cmd} (SYN flood test will use a weaker nc approximation)")

    print("[OK] Required dependencies are available.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
