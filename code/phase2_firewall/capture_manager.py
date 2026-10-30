import os
import time


def start_capture(host, filename):
    """
    Start tcpdump on the selected host.
    """

    print(f"[*] Starting capture: {filename}")

    os.makedirs("../../logs", exist_ok=True)

    # Remove old capture file if it exists
    host.cmd(f"rm -f ../../logs/{filename}")

    # Stop any old tcpdump process on this host
    host.cmd("pkill -f tcpdump")

    # Start tcpdump and save its process ID
    host.cmd(
        f"tcpdump -i {host.name}-eth0 -nn -U -w ../../logs/{filename} "
        f"> ../../logs/{filename}.tcpdump.log 2>&1 & echo $! > /tmp/{filename}.pid"
    )

    # Give tcpdump time to start before traffic begins
    time.sleep(2)


def stop_capture(host, filename=None):
    """
    Stop tcpdump safely on the selected host.
    """

    print("[*] Stopping capture...")

    # Stop tcpdump safely using SIGINT so it writes the pcap correctly
    if filename:
        host.cmd(f"kill -2 $(cat /tmp/{filename}.pid) 2>/dev/null")
        host.cmd(f"rm -f /tmp/{filename}.pid")
    else:
        host.cmd("pkill -2 tcpdump")

    # Give tcpdump time to write the file
    time.sleep(2)
