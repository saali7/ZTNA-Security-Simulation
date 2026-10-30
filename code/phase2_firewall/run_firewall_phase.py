import os
PHASE2_GENERATED_FILES = [
    "firewall_normal_http.txt",
    "firewall_attacker_http.txt",
    "firewall_lateral_ping.txt",
    "firewall_subnet_scan.txt",
    "firewall_port_scan.txt",
    "firewall_syn_dos.txt",
    "firewall_rules.txt",

    "firewall_normal_http.pcap",
    "firewall_attacker_http.pcap",
    "firewall_lateral_ping.pcap",
    "firewall_subnet_scan.pcap",
    "firewall_port_scan.pcap",
    "firewall_syn_dos.pcap",

    "firewall_normal_http.pcap.tcpdump.log",
    "firewall_attacker_http.pcap.tcpdump.log",
    "firewall_lateral_ping.pcap.tcpdump.log",
    "firewall_subnet_scan.pcap.tcpdump.log",
    "firewall_port_scan.pcap.tcpdump.log",
    "firewall_syn_dos.pcap.tcpdump.log",

    # Old Phase 2 names from before adding firewall_ prefix.
    # These are deleted once to avoid confusion in the dashboard.
    "normal_http.txt",
    "attacker_http.txt",
    "lateral_ping.txt",
    "subnet_scan.txt",
    "port_scan.txt",
    "syn_dos.txt",

    "normal_http.pcap",
    "attacker_http.pcap",
    "lateral_ping.pcap",
    "subnet_scan.pcap",
    "port_scan.pcap",
    "syn_dos.pcap",

    "normal_http.pcap.tcpdump.log",
    "attacker_http.pcap.tcpdump.log",
    "lateral_ping.pcap.tcpdump.log",
    "subnet_scan.pcap.tcpdump.log",
    "port_scan.pcap.tcpdump.log",
    "syn_dos.pcap.tcpdump.log",
]


def cleanup_phase2_logs():
    """
    Remove only Phase 2 generated files before rerunning Phase 2.
    This avoids mixing old firewall logs with new firewall-prefixed logs.
    """
    log_dir = "../../logs"

    for filename in PHASE2_GENERATED_FILES:
        path = os.path.join(log_dir, filename)
        if os.path.exists(path):
            os.remove(path)
            print(f"[*] Removed old Phase 2 log: {filename}")

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
from firewall_phase import apply_firewall_rules, show_firewall_rules


def save_result(filename, content):
    os.makedirs("../../logs", exist_ok=True)
    with open(f"../../logs/{filename}", "w") as file:
        file.write(content)


def run_test(test_name, test_function, net, capture_host):
    """
    Run one test, capture packets on the chosen host,
    and save the command output.
    """
    print(f"\n========== Running test: {test_name} ==========")
    print(f"[*] Capture host: {capture_host.name}")

    pcap_file = f"{test_name}.pcap"
    txt_file = f"{test_name}.txt"

    start_capture(capture_host, pcap_file)
    result = test_function(net)
    stop_capture(capture_host, pcap_file)

    save_result(txt_file, result)

    print(f"[*] Saved packet capture to ../../logs/{pcap_file}")
    print(f"[*] Saved command output to ../../logs/{txt_file}")


def main():
    cleanup_phase2_logs()
    net = None

    try:
        print("[*] Starting Phase 2: Firewall testing...")
        net = create_network()


        h1 = net.get("h1")
        h2 = net.get("h2")
        h3 = net.get("h3")


        start_http_server(net)


        apply_firewall_rules(h1)


        rules_output = show_firewall_rules(h1)
        save_result("firewall_rules.txt", rules_output)


        run_test("firewall_normal_http", normal_http, net, h1)
        run_test("firewall_attacker_http", attacker_http, net, h1)
        run_test("firewall_lateral_ping", lateral_ping, net, h2)
        run_test("firewall_subnet_scan", subnet_scan, net, h3)
        run_test("firewall_port_scan", port_scan, net, h1)
        run_test("firewall_syn_dos", syn_dos, net, h1)

        print("\n[*] Phase 2 firewall testing completed successfully.")

    finally:
        if net is not None:
            stop_network(net)
            print("[*] Network stopped cleanly.")


if __name__ == "__main__":
    main()
