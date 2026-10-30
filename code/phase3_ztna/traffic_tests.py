# traffic_tests.py
"""Main test runner for Phase 3 ZTNA simulation."""

import csv
import logging
import os
import time

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch

from anonymizer import anonymize_log_file
from behavior_detector import reset_state
from capture_manager import convert_pcap_to_txt, start_capture, stop_capture
from config import (
    ANONYMIZED_LOG_DIR,
    CAPTURE_DIR,
    HOSTS,
    KEEP_RAW_LOGS,
    LOG_DIR,
    PORT_SCAN_PORTS,
    SUBNET_SCAN_TARGETS,
    SUMMARY_FILE,
)
from controller import process_traffic
from enforcement import cleanup_all_ztna_rules
from phase3_topology import Phase3Topology
from risk_engine import reset_scores

logger = logging.getLogger(__name__)
SUMMARY_ROWS = []


def terminal_msg(tag, message):
    """
    Print clean terminal messages for the Phase 3 demo.
    This is only for user-friendly runtime visibility.
    """
    print(f"[{tag}] {message}", flush=True)


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(ANONYMIZED_LOG_DIR, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(LOG_DIR, "ztna.log")),
            logging.StreamHandler(),
        ],
    )


def flush_logging_handlers():
    """
    Flush logging handlers before anonymizing/deleting raw ztna.log.
    """
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:
            pass


def get_host(net, name):
    host = net.get(name)
    if host is None:
        raise ValueError(f"Host {name!r} not found in topology")
    return host


def write_log(log_handle, text):
    log_handle.write(text + "\n")
    log_handle.flush()


def pcap_probe(src_host, dst_ip, dst_port=None, protocol="tcp"):
    """
    Generate a small real packet during packet capture before ZTNA enforcement.

    This improves PCAP evidence only.
    It does not change the Zero Trust decision logic.
    """
    if protocol == "icmp" or dst_port is None:
        src_host.cmd(f"ping -c 1 -W 1 {dst_ip} >/dev/null 2>&1")
    else:
        src_host.cmd(f"nc -z -w 1 {dst_ip} {dst_port} >/dev/null 2>&1")


def record_summary(
    test_name,
    scenario,
    expected_decision,
    actual_decision,
    evidence,
    passed,
    event="",
    risk_score="",
    risk_level="",
    attempts_before_decision="",
    detection_time_seconds="",
):
    SUMMARY_ROWS.append({
        "test_name": test_name,
        "scenario": scenario,
        "expected_decision": expected_decision,
        "actual_decision": actual_decision,
        "event": event,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "attempts_before_decision": attempts_before_decision,
        "detection_time_seconds": detection_time_seconds,
        "evidence": evidence,
        "status": "PASS" if passed else "FAIL",
    })


def write_summary_file():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(SUMMARY_FILE, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "test_name",
                "scenario",
                "expected_decision",
                "actual_decision",
                "event",
                "risk_score",
                "risk_level",
                "attempts_before_decision",
                "detection_time_seconds",
                "evidence",
                "status",
            ],
        )
        writer.writeheader()
        writer.writerows(SUMMARY_ROWS)

    anon_summary = os.path.join(ANONYMIZED_LOG_DIR, "phase3_summary_anonymized.csv")
    anonymize_log_file(SUMMARY_FILE, anon_summary)


def anonymize_outputs_for_test(test_name):
    for suffix in ["_result.txt", "_capture.txt"]:
        input_path = os.path.join(LOG_DIR, f"{test_name}{suffix}")
        if os.path.exists(input_path):
            output_path = os.path.join(
                ANONYMIZED_LOG_DIR,
                f"{test_name}{suffix.replace('.txt', '_anonymized.txt')}",
            )
            anonymize_log_file(input_path, output_path)


def delete_raw_outputs_for_test(test_name):
    """
    Delete raw per-test log files after anonymization.

    This keeps:
    - phase3_summary.csv for the dashboard
    - anonymized logs for privacy-aware reporting
    - PCAP files as packet evidence
    """
    if KEEP_RAW_LOGS:
        return

    raw_files = [
        os.path.join(LOG_DIR, f"{test_name}_result.txt"),
        os.path.join(LOG_DIR, f"{test_name}_capture.txt"),
    ]

    for raw_file in raw_files:
        try:
            if os.path.exists(raw_file):
                os.remove(raw_file)
                logger.info("Deleted raw log file after anonymization: %s", raw_file)
        except Exception:
            logger.exception("Could not delete raw log file: %s", raw_file)


def delete_raw_ztna_log():
    """
    Delete raw ztna.log after creating the anonymized copy.
    """
    if KEEP_RAW_LOGS:
        return

    raw_ztna_log = os.path.join(LOG_DIR, "ztna.log")

    try:
        if os.path.exists(raw_ztna_log):
            os.remove(raw_ztna_log)
            terminal_msg("LOGS", "Raw ztna.log deleted after anonymization")
    except Exception:
        logger.exception("Could not delete raw ztna.log")


def kill_all_servers(net):
    for host in net.hosts:
        host.cmd("pkill -f 'http.server' 2>/dev/null")
        host.cmd("pkill -f 'nc -lk' 2>/dev/null")
        host.cmd("pkill -f 'hping3' 2>/dev/null")
    time.sleep(0.5)


def run_test(test_name, net, test_function):
    logger.info("=== Starting test: %s ===", test_name)
    terminal_msg("ZTNA", f"Running test: {test_name}")

    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(ANONYMIZED_LOG_DIR, exist_ok=True)

    pcap_file = os.path.join(CAPTURE_DIR, f"{test_name}.pcap")
    capture_txt_file = os.path.join(LOG_DIR, f"{test_name}_capture.txt")
    result_file = os.path.join(LOG_DIR, f"{test_name}_result.txt")

    kill_all_servers(net)
    cleanup_all_ztna_rules(net)
    reset_state()
    reset_scores()

    capture = None
    capture_error = None

    try:
        capture = start_capture(pcap_file)
    except Exception as exc:
        capture_error = str(exc)
        logger.exception("Packet capture could not start for test %s", test_name)

    try:
        with open(result_file, "w") as log_handle:
            if capture_error:
                write_log(log_handle, f"[WARNING] Packet capture disabled: {capture_error}")
            test_function(test_name, net, log_handle)
    except Exception:
        logger.exception("Test %s failed with an exception", test_name)
        record_summary(
            test_name,
            "runtime_exception",
            "NO_EXCEPTION",
            "EXCEPTION",
            "See ztna.log",
            False,
        )
    finally:
        if capture is not None:
            stop_capture(capture)
        kill_all_servers(net)
        cleanup_all_ztna_rules(net)

    if capture is not None:
        try:
            convert_pcap_to_txt(pcap_file, capture_txt_file)
        except Exception as exc:
            logger.exception("Could not convert PCAP for test %s", test_name)
            with open(capture_txt_file, "w") as f:
                f.write(f"PCAP conversion failed: {exc}\n")
    else:
        with open(capture_txt_file, "w") as f:
            f.write(f"Packet capture was not available for this test: {capture_error}\n")

    anonymize_outputs_for_test(test_name)
    delete_raw_outputs_for_test(test_name)

    terminal_msg("LOGS", f"Saved anonymized logs and evidence for {test_name}")
    terminal_msg("ZTNA", f"Completed test: {test_name}")
    print("-" * 70, flush=True)
    logger.info("[OK] %s completed", test_name)


def normal_policy_test(test_name, net, log_handle):
    h1 = get_host(net, HOSTS["APP_SERVER"]["name"])
    h2 = get_host(net, HOSTS["USER"]["name"])
    h4 = get_host(net, HOSTS["DATABASE"]["name"])

    h1.cmd("python3 -m http.server 80 --bind 10.0.0.1 >/tmp/h1_http.log 2>&1 &")
    h4.cmd("nc -lk -p 3306 >/tmp/h4_db.log 2>&1 &")
    time.sleep(1)

    terminal_msg("ZTNA", "Testing normal user access and database restriction")
    start_time = time.time()

    write_log(log_handle, "[TEST] USER -> APP_SERVER HTTP")
    record = process_traffic("10.0.0.2", "10.0.0.1", 80, net=net)
    result = h2.cmd(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://10.0.0.1:80"
    ).strip()

    detection_time = time.time() - start_time

    write_log(
        log_handle,
        f"Decision: {record['decision']} | Event: {record['event']} | "
        f"Risk: {record['risk_level']} | HTTP: {result}",
    )

    record_summary(
        test_name,
        "USER to APP_SERVER",
        "ALLOW",
        record["decision"],
        f"HTTP={result}",
        record["decision"] == "ALLOW" and result == "200",
        event=record["event"],
        risk_score=record["risk_score"],
        risk_level=record["risk_level"],
        attempts_before_decision=1,
        detection_time_seconds=f"{detection_time:.3f}",
    )

    start_time = time.time()

    write_log(log_handle, "\n[TEST] USER -> DATABASE direct access")
    pcap_probe(h2, "10.0.0.4", 3306)
    record = process_traffic("10.0.0.2", "10.0.0.4", 3306, net=net)
    result = h2.cmd("nc -zv -w 2 10.0.0.4 3306 2>&1").strip()

    detection_time = time.time() - start_time

    write_log(
        log_handle,
        f"Decision: {record['decision']} | Event: {record['event']} | "
        f"Risk: {record['risk_level']} | nc: {result}",
    )

    record_summary(
        test_name,
        "USER to DATABASE",
        "DENY",
        record["decision"],
        result[:120],
        record["decision"] == "DENY",
        event=record["event"],
        risk_score=record["risk_score"],
        risk_level=record["risk_level"],
        attempts_before_decision=1,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def app_to_database_test(test_name, net, log_handle):
    h1 = get_host(net, HOSTS["APP_SERVER"]["name"])
    h4 = get_host(net, HOSTS["DATABASE"]["name"])

    h4.cmd("nc -lk -p 3306 >/tmp/h4_db.log 2>&1 &")
    time.sleep(1)

    terminal_msg("ZTNA", "Testing APP_SERVER to DATABASE allowed access")
    start_time = time.time()

    write_log(log_handle, "[TEST] APP_SERVER -> DATABASE access")
    pcap_probe(h1, "10.0.0.4", 3306)
    record = process_traffic("10.0.0.1", "10.0.0.4", 3306, net=net)
    result = h1.cmd("nc -zv -w 2 10.0.0.4 3306 2>&1").strip()

    detection_time = time.time() - start_time

    write_log(
        log_handle,
        f"Decision: {record['decision']} | Event: {record['event']} | "
        f"Risk: {record['risk_level']} | nc: {result}",
    )

    record_summary(
        test_name,
        "APP_SERVER to DATABASE",
        "ALLOW",
        record["decision"],
        result[:120],
        record["decision"] == "ALLOW",
        event=record["event"],
        risk_score=record["risk_score"],
        risk_level=record["risk_level"],
        attempts_before_decision=1,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def unknown_http_access_test(test_name, net, log_handle):
    h1 = get_host(net, HOSTS["APP_SERVER"]["name"])
    h3 = get_host(net, HOSTS["UNKNOWN"]["name"])

    h1.cmd("python3 -m http.server 80 --bind 10.0.0.1 >/tmp/h1_http.log 2>&1 &")
    time.sleep(1)

    terminal_msg("ATTACK", "Unauthorized HTTP access attempt from UNKNOWN device")
    start_time = time.time()

    write_log(log_handle, "[TEST] UNKNOWN -> APP_SERVER HTTP access")
    pcap_probe(h3, "10.0.0.1", 80)
    record = process_traffic("10.0.0.3", "10.0.0.1", 80, net=net)
    result = h3.cmd(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://10.0.0.1:80"
    ).strip()

    detection_time = time.time() - start_time

    write_log(
        log_handle,
        f"Decision: {record['decision']} | Event: {record['event']} | "
        f"Risk: {record['risk_level']} | HTTP: {result}",
    )

    record_summary(
        test_name,
        "UNKNOWN to APP_SERVER HTTP",
        "DENY",
        record["decision"],
        f"HTTP={result}",
        record["decision"] == "DENY" and result != "200",
        event=record["event"],
        risk_score=record["risk_score"],
        risk_level=record["risk_level"],
        attempts_before_decision=1,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def unknown_to_database_test(test_name, net, log_handle):
    h3 = get_host(net, HOSTS["UNKNOWN"]["name"])
    h4 = get_host(net, HOSTS["DATABASE"]["name"])

    h4.cmd("nc -lk -p 3306 >/tmp/h4_db.log 2>&1 &")
    time.sleep(1)

    terminal_msg("ATTACK", "UNKNOWN device attempting direct DATABASE access")
    start_time = time.time()

    write_log(log_handle, "[TEST] UNKNOWN -> DATABASE direct access")
    pcap_probe(h3, "10.0.0.4", 3306)
    record = process_traffic("10.0.0.3", "10.0.0.4", 3306, net=net)
    result = h3.cmd("nc -zv -w 2 10.0.0.4 3306 2>&1").strip()

    detection_time = time.time() - start_time

    write_log(
        log_handle,
        f"Decision: {record['decision']} | Event: {record['event']} | "
        f"Risk: {record['risk_level']} | nc: {result}",
    )

    record_summary(
        test_name,
        "UNKNOWN to DATABASE",
        "DENY",
        record["decision"],
        result[:120],
        record["decision"] == "DENY",
        event=record["event"],
        risk_score=record["risk_score"],
        risk_level=record["risk_level"],
        attempts_before_decision=1,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def app_server_to_user_test(test_name, net, log_handle):
    h1 = get_host(net, HOSTS["APP_SERVER"]["name"])
    h2 = get_host(net, HOSTS["USER"]["name"])

    h2.cmd("python3 -m http.server 80 --bind 10.0.0.2 >/tmp/h2_http.log 2>&1 &")
    time.sleep(1)

    terminal_msg("POLICY", "Testing APP_SERVER to USER access restriction")
    start_time = time.time()

    write_log(log_handle, "[TEST] APP_SERVER -> USER access")
    pcap_probe(h1, "10.0.0.2", 80)
    record = process_traffic("10.0.0.1", "10.0.0.2", 80, net=net)
    result = h1.cmd(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://10.0.0.2:80"
    ).strip()

    detection_time = time.time() - start_time

    write_log(
        log_handle,
        f"Decision: {record['decision']} | Event: {record['event']} | "
        f"Risk: {record['risk_level']} | HTTP: {result}",
    )

    record_summary(
        test_name,
        "APP_SERVER to USER",
        "DENY",
        record["decision"],
        f"HTTP={result}",
        record["decision"] == "DENY" and result != "200",
        event=record["event"],
        risk_score=record["risk_score"],
        risk_level=record["risk_level"],
        attempts_before_decision=1,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def port_scan_test(test_name, net, log_handle):
    h1 = get_host(net, HOSTS["APP_SERVER"]["name"])
    h3 = get_host(net, HOSTS["UNKNOWN"]["name"])

    h1.cmd("python3 -m http.server 80 --bind 10.0.0.1 >/tmp/h1_http.log 2>&1 &")
    time.sleep(1)

    terminal_msg("ATTACK", "Port scan attempt: UNKNOWN host scanning APP_SERVER ports")
    start_time = time.time()
    final_record = None
    attempts = 0

    for port in PORT_SCAN_PORTS:
        attempts += 1

        pcap_probe(h3, "10.0.0.1", port)
        final_record = process_traffic("10.0.0.3", "10.0.0.1", port, net=net, verbose=False)
        result = h3.cmd(f"nc -zv -w 1 10.0.0.1 {port} 2>&1").strip()

        write_log(
            log_handle,
            f"Port {port}: decision={final_record['decision']} "
            f"event={final_record['event']} risk={final_record['risk_level']} "
            f"result={result}",
        )

    detection_time = time.time() - start_time

    if final_record:
        terminal_msg(
            "BEHAVIOR",
            f"Event={final_record['event']} | Risk={final_record['risk_level']}/{final_record['risk_score']}",
        )
        terminal_msg("DECISION", final_record["decision"])
        if final_record["decision"] == "QUARANTINE":
            terminal_msg("ENFORCEMENT", "Threat contained successfully")

    record_summary(
        test_name,
        "UNKNOWN scans multiple ports",
        "QUARANTINE",
        final_record["decision"] if final_record else "NONE",
        f"last_event={final_record['event'] if final_record else 'NONE'}",
        bool(final_record and final_record["decision"] == "QUARANTINE"),
        event=final_record["event"] if final_record else "",
        risk_score=final_record["risk_score"] if final_record else "",
        risk_level=final_record["risk_level"] if final_record else "",
        attempts_before_decision=attempts,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def trusted_user_port_scan_test(test_name, net, log_handle):
    h1 = get_host(net, HOSTS["APP_SERVER"]["name"])
    h2 = get_host(net, HOSTS["USER"]["name"])

    h1.cmd("python3 -m http.server 80 --bind 10.0.0.1 >/tmp/h1_http.log 2>&1 &")
    time.sleep(1)

    terminal_msg("ATTACK", "Trusted USER is performing suspicious port scanning")
    start_time = time.time()
    final_record = None
    attempts = 0

    write_log(log_handle, "[TEST] Trusted USER performs port scan against APP_SERVER")

    for port in PORT_SCAN_PORTS:
        attempts += 1

        pcap_probe(h2, "10.0.0.1", port)
        final_record = process_traffic("10.0.0.2", "10.0.0.1", port, net=net, verbose=False)
        result = h2.cmd(f"nc -zv -w 1 10.0.0.1 {port} 2>&1").strip()

        write_log(
            log_handle,
            f"Port {port}: decision={final_record['decision']} "
            f"event={final_record['event']} risk={final_record['risk_level']} "
            f"result={result}",
        )

    detection_time = time.time() - start_time

    if final_record:
        terminal_msg(
            "BEHAVIOR",
            f"Event={final_record['event']} | Risk={final_record['risk_level']}/{final_record['risk_score']}",
        )
        terminal_msg("DECISION", final_record["decision"])
        if final_record["decision"] == "QUARANTINE":
            terminal_msg("ENFORCEMENT", "Threat contained successfully")

    record_summary(
        test_name,
        "Trusted USER scans multiple ports",
        "QUARANTINE",
        final_record["decision"] if final_record else "NONE",
        f"last_event={final_record['event'] if final_record else 'NONE'}",
        bool(final_record and final_record["decision"] == "QUARANTINE"),
        event=final_record["event"] if final_record else "",
        risk_score=final_record["risk_score"] if final_record else "",
        risk_level=final_record["risk_level"] if final_record else "",
        attempts_before_decision=attempts,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def subnet_scan_test(test_name, net, log_handle):
    h3 = get_host(net, HOSTS["UNKNOWN"]["name"])

    terminal_msg("ATTACK", "Subnet scan attempt: UNKNOWN host scanning internal destinations")
    start_time = time.time()
    final_record = None
    attempts = 0

    for target in SUBNET_SCAN_TARGETS:
        attempts += 1

        pcap_probe(h3, target, 80)
        final_record = process_traffic("10.0.0.3", target, 80, net=net, verbose=False)
        result = h3.cmd(f"nc -zv -w 1 {target} 80 2>&1").strip()

        write_log(
            log_handle,
            f"Target {target}: decision={final_record['decision']} "
            f"event={final_record['event']} risk={final_record['risk_level']} "
            f"result={result}",
        )

    detection_time = time.time() - start_time

    if final_record:
        terminal_msg(
            "BEHAVIOR",
            f"Event={final_record['event']} | Risk={final_record['risk_level']}/{final_record['risk_score']}",
        )
        terminal_msg("DECISION", final_record["decision"])
        if final_record["decision"] == "QUARANTINE":
            terminal_msg("ENFORCEMENT", "Threat contained successfully")

    record_summary(
        test_name,
        "UNKNOWN scans several hosts",
        "QUARANTINE",
        final_record["decision"] if final_record else "NONE",
        f"last_event={final_record['event'] if final_record else 'NONE'}",
        bool(final_record and final_record["decision"] == "QUARANTINE"),
        event=final_record["event"] if final_record else "",
        risk_score=final_record["risk_score"] if final_record else "",
        risk_level=final_record["risk_level"] if final_record else "",
        attempts_before_decision=attempts,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def syn_flood_test(test_name, net, log_handle):
    h1 = get_host(net, HOSTS["APP_SERVER"]["name"])
    h3 = get_host(net, HOSTS["UNKNOWN"]["name"])

    h1.cmd("python3 -m http.server 80 --bind 10.0.0.1 >/tmp/h1_http.log 2>&1 &")
    time.sleep(1)

    hping_available = bool(h3.cmd("which hping3").strip())

    terminal_msg("ATTACK", "SYN flood attempt against APP_SERVER")

    if hping_available:
        write_log(
            log_handle,
            "[TEST] UNKNOWN SYN flood against APP_SERVER using hping3 background flood",
        )
        h3.cmd(
            "timeout 2 hping3 -S --flood -p 80 10.0.0.1 "
            ">/tmp/h3_syn_flood.log 2>&1 &"
        )
        time.sleep(0.2)
    else:
        write_log(
            log_handle,
            "[NOTE] hping3 missing; using event-driven SYN approximation. "
            "Install hping3 for stronger SYN-flood PCAP evidence.",
        )

    start_time = time.time()
    final_record = None
    iterations = 0

    for i in range(35):
        iterations = i + 1

        final_record = process_traffic(
            "10.0.0.3",
            "10.0.0.1",
            80,
            packet_type="SYN",
            net=None,
            verbose=False,
        )

        write_log(
            log_handle,
            f"Iteration {iterations}: decision={final_record['decision']} "
            f"event={final_record['event']} risk={final_record['risk_level']}",
        )

        if final_record["decision"] == "QUARANTINE":
            break

    if final_record and final_record["decision"] == "QUARANTINE":
        final_record = process_traffic(
            "10.0.0.3",
            "10.0.0.1",
            80,
            packet_type="SYN",
            net=net,
        )

    h3.cmd("pkill -f 'hping3' 2>/dev/null")

    detection_time = time.time() - start_time

    record_summary(
        test_name,
        "UNKNOWN SYN flood against APP_SERVER",
        "QUARANTINE",
        final_record["decision"] if final_record else "NONE",
        f"iterations={iterations}; hping3={hping_available}",
        bool(final_record and final_record["decision"] == "QUARANTINE"),
        event=final_record["event"] if final_record else "",
        risk_score=final_record["risk_score"] if final_record else "",
        risk_level=final_record["risk_level"] if final_record else "",
        attempts_before_decision=iterations,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def lateral_movement_test(test_name, net, log_handle):
    h2 = get_host(net, HOSTS["USER"]["name"])
    h3 = get_host(net, HOSTS["UNKNOWN"]["name"])

    h2.cmd("python3 -m http.server 80 --bind 10.0.0.2 >/tmp/h2_http.log 2>&1 &")
    time.sleep(1)

    terminal_msg("ATTACK", "Lateral movement attempt: UNKNOWN host targeting USER")
    start_time = time.time()

    pcap_probe(h3, "10.0.0.2", 80)
    record = process_traffic("10.0.0.3", "10.0.0.2", 80, net=net)
    result = h3.cmd(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://10.0.0.2:80"
    ).strip()

    detection_time = time.time() - start_time

    write_log(
        log_handle,
        f"Decision: {record['decision']} | Event: {record['event']} | "
        f"Risk: {record['risk_level']} | HTTP: {result}",
    )

    record_summary(
        test_name,
        "UNKNOWN to USER",
        "DENY",
        record["decision"],
        f"HTTP={result}",
        record["decision"] == "DENY",
        event=record["event"],
        risk_score=record["risk_score"],
        risk_level=record["risk_level"],
        attempts_before_decision=1,
        detection_time_seconds=f"{detection_time:.3f}",
    )


def main():
    setup_logging()
    setLogLevel("warning")

    terminal_msg("ZTNA", "Phase 3 Simulation Started")

    net = Mininet(
        topo=Phase3Topology(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
    )

    net.start()

    terminal_msg("ZTNA", "Network topology initialized")
    terminal_msg("ZTNA", "Zero Trust policy evaluation is active")
    print("-" * 70, flush=True)

    for switch in net.switches:
        switch.cmd(f"ovs-vsctl set-fail-mode {switch.name} standalone")

    try:
        run_test("normal_policy", net, normal_policy_test)
        run_test("app_to_database", net, app_to_database_test)
        run_test("unknown_http_access", net, unknown_http_access_test)
        run_test("unknown_to_database", net, unknown_to_database_test)
        run_test("app_server_to_user", net, app_server_to_user_test)
        run_test("port_scan", net, port_scan_test)
        run_test("trusted_user_port_scan", net, trusted_user_port_scan_test)
        run_test("subnet_scan", net, subnet_scan_test)
        run_test("syn_flood", net, syn_flood_test)
        run_test("lateral_movement", net, lateral_movement_test)

        write_summary_file()
        terminal_msg("LOGS", "Phase 3 summary CSV saved")

        logger.info("=== ALL PHASE 3 TESTS COMPLETED ===")
        flush_logging_handlers()

        raw_ztna_log = os.path.join(LOG_DIR, "ztna.log")
        anon_ztna_log = os.path.join(ANONYMIZED_LOG_DIR, "ztna_anonymized.log")

        if os.path.exists(raw_ztna_log):
            anonymize_log_file(raw_ztna_log, anon_ztna_log)
            terminal_msg("LOGS", "Anonymized ztna.log saved")
            delete_raw_ztna_log()

        terminal_msg("LOGS", "Anonymized logs saved")
        terminal_msg("ZTNA", "All Phase 3 tests completed successfully")

    finally:
        cleanup_all_ztna_rules(net)
        net.stop()


if __name__ == "__main__":
    main()
