# risk_engine.py
"""Risk scoring for ZTNA decisions."""

import logging

logger = logging.getLogger(__name__)

risk_scores = {}
KNOWN_EVENTS = {"NORMAL", "SUBNET_SCAN", "PORT_SCAN", "LATERAL_MOVEMENT", "SYN_FLOOD"}

# Scan and flood events are serious enough to trigger HIGH risk immediately.
# This makes the Phase 3 tests correctly escalate scanning behavior to quarantine.
EVENT_WEIGHTS = {
    "NORMAL": 0,
    "SUBNET_SCAN": 10,
    "PORT_SCAN": 10,
    "LATERAL_MOVEMENT": 5,
    "SYN_FLOOD": 10,
}


def reset_scores():
    """Clear all stored risk scores."""
    risk_scores.clear()


def update_risk(ip, event):
    """Update and return numeric risk score for an IP."""
    if ip not in risk_scores:
        risk_scores[ip] = 0

    if event not in KNOWN_EVENTS:
        logger.warning("Unknown risk event %r for %s; score unchanged", event, ip)
        return risk_scores[ip]

    risk_scores[ip] = max(0, risk_scores[ip] + EVENT_WEIGHTS[event])
    return risk_scores[ip]


def get_risk_level(ip):
    """Convert numeric score into LOW, MEDIUM, or HIGH."""
    score = risk_scores.get(ip, 0)
    if score < 5:
        return "LOW"
    if score < 10:
        return "MEDIUM"
    return "HIGH"


def get_risk_score(ip):
    """Return raw numeric risk score."""
    return risk_scores.get(ip, 0)
