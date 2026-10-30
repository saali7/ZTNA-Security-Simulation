"""Central configuration for the Phase 3 ZTNA simulation."""

HOSTS = {
    "APP_SERVER": {"name": "h1", "ip": "10.0.0.1", "http_port": 80},
    "USER": {"name": "h2", "ip": "10.0.0.2"},
    "UNKNOWN": {"name": "h3", "ip": "10.0.0.3"},
    "DATABASE": {"name": "h4", "ip": "10.0.0.4", "db_port": 3306},
}

IP_TO_ROLE = {data["ip"]: role for role, data in HOSTS.items()}

LOG_DIR = "../../logs"
CAPTURE_DIR = "../../logs/captures"
ANONYMIZED_LOG_DIR = "../../logs/anonymized"
SUMMARY_FILE = "../../logs/phase3_summary.csv"

PORT_SCAN_PORTS = [21, 22, 23, 25, 80, 443]
SUBNET_SCAN_TARGETS = ["10.0.0.1", "10.0.0.4", "10.0.0.2"]

SYN_FLOOD_THRESHOLD = 30
SUBNET_SCAN_THRESHOLD = 3
PORT_SCAN_THRESHOLD = 5

REQUIRED_COMMANDS = ["python3", "sudo", "mn", "ovs-vsctl", "tcpdump", "iptables", "curl", "nc"]
OPTIONAL_COMMANDS = ["hping3"]

# If False, raw per-test logs are deleted after anonymized copies are created.
# phase3_summary.csv and PCAP files are kept for dashboard and evidence.
KEEP_RAW_LOGS = False
