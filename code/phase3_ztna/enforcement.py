# enforcement.py
"""iptables enforcement for the Mininet ZTNA simulation."""

import logging

logger = logging.getLogger(__name__)

ZTNA_OUT_CHAIN = "ZTNA_OUT"
ZTNA_IN_CHAIN = "ZTNA_IN"


def find_host_by_ip(net, ip):
    for host in net.hosts:
        if host.IP() == ip:
            return host
    return None


def ensure_ztna_chains(host):
    """Create project-owned chains and attach them to INPUT/OUTPUT."""
    host.cmd(f"iptables -N {ZTNA_OUT_CHAIN} 2>/dev/null")
    host.cmd(f"iptables -N {ZTNA_IN_CHAIN} 2>/dev/null")

    if host.cmd(f"iptables -C OUTPUT -j {ZTNA_OUT_CHAIN} 2>/dev/null; echo $?").strip() != "0":
        host.cmd(f"iptables -I OUTPUT 1 -j {ZTNA_OUT_CHAIN}")

    if host.cmd(f"iptables -C INPUT -j {ZTNA_IN_CHAIN} 2>/dev/null; echo $?").strip() != "0":
        host.cmd(f"iptables -I INPUT 1 -j {ZTNA_IN_CHAIN}")


def clear_host_rules(src_ip, net):
    host = find_host_by_ip(net, src_ip)
    if host is None:
        logger.error("Host with IP %s not found", src_ip)
        return
    ensure_ztna_chains(host)
    host.cmd(f"iptables -F {ZTNA_OUT_CHAIN}")
    host.cmd(f"iptables -F {ZTNA_IN_CHAIN}")


def allow_traffic(src_ip, dst_ip, net, dst_port=None):
    """
    Add explicit ACCEPT rule for allowed traffic, followed by a default DROP.

    This makes the rule behave like a stricter Zero Trust allow-list for the
    source host during the current decision window.
    """
    host = find_host_by_ip(net, src_ip)
    if host is None:
        logger.error("allow_traffic: host with IP %s not found", src_ip)
        return
    ensure_ztna_chains(host)
    if dst_port is None:
        host.cmd(f"iptables -A {ZTNA_OUT_CHAIN} -d {dst_ip} -j ACCEPT")
        logger.info("ALLOW rule applied: %s -> %s all protocols", src_ip, dst_ip)
    else:
        host.cmd(f"iptables -A {ZTNA_OUT_CHAIN} -p tcp -d {dst_ip} --dport {dst_port} -j ACCEPT")
        logger.info("ALLOW rule applied: %s -> %s:%s TCP", src_ip, dst_ip, dst_port)

    # Default deny after the explicit allow, so non-approved traffic is blocked.
    host.cmd(f"iptables -A {ZTNA_OUT_CHAIN} -j DROP")


def deny_traffic(src_ip, dst_ip, net, dst_port=None):
    """Block traffic from source to destination."""
    host = find_host_by_ip(net, src_ip)
    if host is None:
        logger.error("deny_traffic: host with IP %s not found", src_ip)
        return
    ensure_ztna_chains(host)

    if dst_port is None:
        host.cmd(f"iptables -A {ZTNA_OUT_CHAIN} -d {dst_ip} -j DROP")
        logger.info("DENY rule applied: %s -> %s all protocols", src_ip, dst_ip)
    else:
        # Block the specific TCP service and also block non-TCP traffic to the
        # same destination to avoid ping/ICMP bypass in evidence screenshots.
        host.cmd(f"iptables -A {ZTNA_OUT_CHAIN} -p tcp -d {dst_ip} --dport {dst_port} -j DROP")
        host.cmd(f"iptables -A {ZTNA_OUT_CHAIN} ! -p tcp -d {dst_ip} -j DROP")
        logger.info("DENY rule applied: %s -> %s:%s TCP and non-TCP to destination", src_ip, dst_ip, dst_port)


def quarantine_host(src_ip, net):
    """Isolate a source host in both directions."""
    host = find_host_by_ip(net, src_ip)
    if host is None:
        logger.error("quarantine_host: host with IP %s not found", src_ip)
        return
    ensure_ztna_chains(host)
    host.cmd(f"iptables -A {ZTNA_OUT_CHAIN} -j DROP")
    host.cmd(f"iptables -A {ZTNA_IN_CHAIN} -j DROP")
    logger.info("QUARANTINE applied to %s", src_ip)


def enforce_decision(src_ip, dst_ip, decision, net, dst_port=None):
    """Apply ALLOW, DENY, or QUARANTINE using project-owned iptables chains."""
    clear_host_rules(src_ip, net)

    if decision == "ALLOW":
        allow_traffic(src_ip, dst_ip, net, dst_port)
    elif decision == "DENY":
        deny_traffic(src_ip, dst_ip, net, dst_port)
    elif decision == "QUARANTINE":
        quarantine_host(src_ip, net)
    else:
        logger.warning("Unknown decision %r; deny by default", decision)
        deny_traffic(src_ip, dst_ip, net, dst_port)


def cleanup_all_ztna_rules(net):
    """Remove project-owned rules/chains from all Mininet hosts."""
    for host in net.hosts:
        host.cmd(f"iptables -D OUTPUT -j {ZTNA_OUT_CHAIN} 2>/dev/null")
        host.cmd(f"iptables -D INPUT -j {ZTNA_IN_CHAIN} 2>/dev/null")
        host.cmd(f"iptables -F {ZTNA_OUT_CHAIN} 2>/dev/null")
        host.cmd(f"iptables -F {ZTNA_IN_CHAIN} 2>/dev/null")
        host.cmd(f"iptables -X {ZTNA_OUT_CHAIN} 2>/dev/null")
        host.cmd(f"iptables -X {ZTNA_IN_CHAIN} 2>/dev/null")
