# capture_manager.py

import logging
import os
import signal
import subprocess
import time

logger = logging.getLogger(__name__)

# Capture only Mininet project traffic.
# This prevents VirtualBox/NAT traffic such as 10.0.2.15 from appearing in PCAP files.
MININET_CAPTURE_FILTER = "net 10.0.0.0/24"


def start_capture(pcap_file):
    """
    Start tcpdump and save captured Mininet packets into a PCAP file.

    This capture is restricted to the project Mininet subnet:
    10.0.0.0/24

    This avoids capturing unrelated VM/NAT traffic.
    Raises RuntimeError if tcpdump fails to start.
    """
    os.makedirs(os.path.dirname(pcap_file), exist_ok=True)

    tcpdump_log = f"{pcap_file}.tcpdump.log"

    # Remove old files so every test has fresh evidence.
    for path in [pcap_file, tcpdump_log]:
        if os.path.exists(path):
            os.remove(path)

    with open(tcpdump_log, "w") as log_file:
        process = subprocess.Popen(
            [
                "tcpdump",
                "-i", "any",
                "-nn",
                "-U",
                "-w", pcap_file,
                MININET_CAPTURE_FILTER,
            ],
            stdout=log_file,
            stderr=log_file,
        )

    # Give tcpdump time to initialise and begin writing.
    time.sleep(2)

    # Verify the process is still alive after startup.
    if process.poll() is not None:
        raise RuntimeError(
            "tcpdump failed to start. "
            "Check that it is installed (sudo apt install tcpdump), "
            "that you have sufficient permissions, "
            f"and check tcpdump log: {tcpdump_log}"
        )

    logger.info("Capture started -> %s", pcap_file)
    logger.info("tcpdump log -> %s", tcpdump_log)

    return process


def stop_capture(process):
    """
    Stop tcpdump safely using SIGINT so it flushes and closes the PCAP file.
    Falls back to SIGKILL if it does not exit within 5 seconds.
    """
    if process.poll() is not None:
        logger.warning("stop_capture: process already exited before stop was called")
        return

    process.send_signal(signal.SIGINT)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        logger.warning("stop_capture: tcpdump did not exit cleanly — killing")
        process.kill()
        process.wait()

    # Brief pause to ensure the file is fully flushed to disk.
    time.sleep(1)

    logger.info("Capture stopped")


def validate_pcap(pcap_file):
    """
    Validate that the PCAP exists and contains packet data.
    Returns True if the PCAP looks usable, otherwise False.
    """
    if not os.path.exists(pcap_file):
        logger.warning("PCAP validation failed: file does not exist -> %s", pcap_file)
        return False

    size = os.path.getsize(pcap_file)

    # A very tiny PCAP may contain only headers and no useful packets.
    if size <= 24:
        logger.warning("PCAP validation failed: file is empty or header-only -> %s", pcap_file)
        return False

    logger.info("PCAP validation passed -> %s (%s bytes)", pcap_file, size)
    return True


def convert_pcap_to_txt(pcap_file, txt_file):
    """
    Convert a PCAP file into human-readable text using tcpdump.

    Raises FileNotFoundError if the PCAP does not exist.
    Raises RuntimeError if tcpdump reports an error during reading.
    """
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_file}. "
            "The capture may have failed silently — check start_capture()."
        )

    os.makedirs(os.path.dirname(txt_file), exist_ok=True)

    with open(txt_file, "w") as output:
        result = subprocess.run(
            ["tcpdump", "-nn", "-r", pcap_file],
            stdout=output,
            stderr=subprocess.PIPE,
        )

    if result.returncode != 0:
        error_msg = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(
            f"tcpdump failed to read PCAP '{pcap_file}': {error_msg}"
        )

    # Add a warning to the converted text if the PCAP has no useful packets.
    if not validate_pcap(pcap_file):
        with open(txt_file, "a") as output:
            output.write(
                "\n[WARNING] PCAP file exists but appears empty or header-only.\n"
                "This may mean no Mininet 10.0.0.0/24 packets were observed during the test.\n"
            )

    logger.info("Capture converted -> %s", txt_file)
