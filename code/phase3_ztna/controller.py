"""ZTNA decision pipeline: identity, behavior, risk, policy, enforcement."""

import logging

from behavior_detector import detect_behavior
from enforcement import enforce_decision
from identity import get_role
from policy_engine import check_policy
from risk_engine import get_risk_level, get_risk_score, update_risk

logger = logging.getLogger(__name__)


def terminal_msg(tag, message):
    """
    Print clean terminal messages for the Phase 3 demo.
    This does not change the decision logic.
    """
    print(f"[{tag}] {message}", flush=True)


def process_traffic(
    src_ip,
    dst_ip,
    dst_port=None,
    packet_type="NORMAL",
    net=None,
    verbose=True,
):
    """Process one traffic event and return a dictionary containing the decision context."""
    source_role = get_role(src_ip)
    destination_role = get_role(dst_ip)

    if verbose:
        terminal_msg(
            "IDENTITY",
            f"Source={source_role} ({src_ip}) | Destination={destination_role} ({dst_ip})",
        )

    event = detect_behavior(
        src_ip,
        dst_ip,
        source_role,
        destination_role,
        dst_port,
        packet_type,
    )
    risk_score = update_risk(src_ip, event)
    risk_level = get_risk_level(src_ip)

    if verbose:
        terminal_msg(
            "BEHAVIOR",
            f"Event={event} | Risk={risk_level}/{risk_score}",
        )
        terminal_msg("POLICY", "Checking access rules...")

    decision = check_policy(source_role, destination_role, risk_level)

    if verbose:
        terminal_msg("DECISION", decision)

    record = {
        "src_ip": src_ip,
        "src_role": source_role,
        "dst_ip": dst_ip,
        "dst_role": destination_role,
        "dst_port": dst_port,
        "packet_type": packet_type,
        "event": event,
        "risk_score": get_risk_score(src_ip),
        "risk_level": risk_level,
        "decision": decision,
    }

    logger.info(
        "ZTNA | src=%s(%s) dst=%s(%s) port=%s event=%s score=%s risk=%s decision=%s",
        src_ip, source_role, dst_ip, destination_role, dst_port, event, risk_score, risk_level, decision,
    )

    if net is not None:
        enforce_decision(src_ip, dst_ip, decision, net, dst_port)

        if verbose:
            if decision == "ALLOW":
                terminal_msg("ENFORCEMENT", "Access allowed")
            elif decision == "DENY":
                terminal_msg("ENFORCEMENT", "Access blocked")
            elif decision == "QUARANTINE":
                terminal_msg("ENFORCEMENT", "Threat contained successfully")
            else:
                terminal_msg("ENFORCEMENT", "Unknown decision handled with default deny")

    return record

