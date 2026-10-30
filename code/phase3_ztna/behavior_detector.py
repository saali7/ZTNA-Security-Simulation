# behavior_detector.py
"""Behavior detection module for Phase 3 ZTNA simulation."""

import time
from collections import defaultdict

from config import (
    PORT_SCAN_THRESHOLD,
    SUBNET_SCAN_THRESHOLD,
    SYN_FLOOD_THRESHOLD,
)

destinations_contacted = defaultdict(set)
ports_contacted = defaultdict(lambda: defaultdict(set))
syn_timestamps = defaultdict(list)


def reset_state():
    """
    Reset stored behavior state before each independent test.
    """
    destinations_contacted.clear()
    ports_contacted.clear()
    syn_timestamps.clear()


def detect_behavior(
    src_ip,
    dst_ip,
    source_role,
    destination_role,
    dst_port=None,
    packet_type="NORMAL",
):
    """
    Detect suspicious behavior based on source, destination, port,
    packet type, and accumulated activity.

    Returns one of:
    NORMAL
    PORT_SCAN
    SUBNET_SCAN
    SYN_FLOOD
    LATERAL_MOVEMENT
    """
    current_time = time.time()

    # Track destination contact history
    if src_ip and dst_ip:
        destinations_contacted[src_ip].add(dst_ip)

    # Track destination port contact history
    if src_ip and dst_ip and dst_port is not None:
        ports_contacted[src_ip][dst_ip].add(dst_port)

    # SYN flood detection must apply to ANY source role,
    # including trusted users. Zero Trust continuously monitors behavior.
    if packet_type == "SYN":
        syn_timestamps[src_ip].append(current_time)

        recent_syns = [
            t for t in syn_timestamps[src_ip]
            if current_time - t <= 5
        ]

        syn_timestamps[src_ip] = recent_syns

        if len(recent_syns) > SYN_FLOOD_THRESHOLD:
            return "SYN_FLOOD"

    # Port scan detection
    if (
        src_ip
        and dst_ip
        and dst_port is not None
        and len(ports_contacted[src_ip][dst_ip]) > PORT_SCAN_THRESHOLD
    ):
        return "PORT_SCAN"

    # Subnet scan detection
    if (
        source_role == "UNKNOWN"
        and src_ip
        and len(destinations_contacted[src_ip]) >= SUBNET_SCAN_THRESHOLD
    ):
        return "SUBNET_SCAN"

    # Lateral movement / unauthorized internal access detection
    if destination_role == "DATABASE" and source_role != "APP_SERVER":
        return "LATERAL_MOVEMENT"

    if destination_role == "USER" and source_role == "UNKNOWN":
        return "LATERAL_MOVEMENT"

    return "NORMAL"
