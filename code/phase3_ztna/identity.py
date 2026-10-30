# identity.py
"""Identity and role lookup for the ZTNA policy engine."""

from config import IP_TO_ROLE


def get_role(ip):
    """Return the role of an IP address, or UNKNOWN if it is not registered."""
    if ip is None:
        return "UNKNOWN"
    return IP_TO_ROLE.get(str(ip), "UNKNOWN")
