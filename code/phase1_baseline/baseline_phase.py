import os
PHASE1_GENERATED_FILES = [
    "baseline_normal_http.txt",
    "baseline_attacker_http.txt",
    "baseline_lateral_ping.txt",
    "baseline_subnet_scan.txt",
    "baseline_port_scan.txt",
    "baseline_syn_dos.txt",

    "baseline_normal_http.pcap",
    "baseline_attacker_http.pcap",
    "baseline_lateral_ping.pcap",
    "baseline_subnet_scan.pcap",
    "baseline_port_scan.pcap",
    "baseline_syn_dos.pcap",

    "baseline_normal_http.pcap.tcpdump.log",
    "baseline_attacker_http.pcap.tcpdump.log",
    "baseline_lateral_ping.pcap.tcpdump.log",
    "baseline_subnet_scan.pcap.tcpdump.log",
    "baseline_port_scan.pcap.tcpdump.log",
    "baseline_syn_dos.pcap.tcpdump.log",
]


def cleanup_phase1_logs():
    """
    Remove only Phase 1 generated files before rerunning Phase 1.
    This avoids mixing old and new baseline evidence.
    """
    log_dir = "../../logs"

    for filename in PHASE1_GENERATED_FILES:
        path = os.path.join(log_dir, filename)
        if os.path.exists(path):
            os.remove(path)
            print(f"[*] Removed old Phase 1 log: {filename}")

from ztna_topology import create_network, stop_network
from traffic_tests import (
    start_http_server,
    normal_http,
    attacker_http,
    lateral_ping,
    subnet_scan,
    port_scan,
    syn_dos,
)
from capture_manager import start_capture, stop_capture


def save_result(filename, content):
    """
    Save text output into the main project logs directory.
    """
    os.makedirs("../../logs", exist_ok=True)
    with open(f"../../logs/{filename}", "w") as file:
        file.write(content)


def run_test(test_name, test_function, net, capture_host):
    """
    Run one baseline test, capture packets, and save the text result.
    """
    print(f"\n========== Running baseline test: {test_name} ==========")
    print(f"[*] Capture host: {capture_host.name}")

    pcap_file = f"baseline_{test_name}.pcap"
    txt_file = f"baseline_{test_name}.txt"

    start_capture(capture_host, pcap_file)
    result = test_function(net)
    stop_capture(capture_host)

    save_result(txt_file, result)

    print(f"[*] Saved packet capture to ../../logs/{pcap_file}")
    print(f"[*] Saved command output to ../../logs/{txt_file}")


def main():
    cleanup_phase1_logs()
    ...
    net = None

    try:
        print("[*] Starting Phase 1: Baseline testing...")
        net = create_network()

        # Get hosts
        h1 = net.get("h1")   # server
        h2 = net.get("h2")   # legitimate user
        h3 = net.get("h3")   # attacker

        # Start HTTP service on h1
        start_http_server(net)

        # Run baseline tests (no firewall rules applied)
        run_test("normal_http", normal_http, net, h1)      # server sees user HTTP
        run_test("attacker_http", attacker_http, net, h1)  # server sees attacker HTTP
        run_test("lateral_ping", lateral_ping, net, h2)    # h2 sees incoming ICMP
        run_test("subnet_scan", subnet_scan, net, h3)      # h3 generates scan traffic
        run_test("port_scan", port_scan, net, h1)          # server sees probe traffic
        run_test("syn_dos", syn_dos, net, h1)              # server sees SYN flood

        print("\n[*] Phase 1 baseline testing completed successfully.")

    finally:
        if net is not None:
            stop_network(net)
            print("[*] Network stopped cleanly.")


if __name__ == "__main__":
    main()
