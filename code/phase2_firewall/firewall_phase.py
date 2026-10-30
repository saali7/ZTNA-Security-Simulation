def apply_firewall_rules(server):
    """
    Set up the firewall rules on h1 using iptables.
    """

    print("[*] Applying firewall rules on h1...")

    server.cmd("iptables -F")
    server.cmd("iptables -X")
    server.cmd("iptables -Z")

    # Set default behavior: block incoming and forwarded traffic, allow outgoing
    server.cmd("iptables -P INPUT DROP")
    server.cmd("iptables -P FORWARD DROP")
    server.cmd("iptables -P OUTPUT ACCEPT")

    # Allow internal loopback communication (system processes)
    server.cmd("iptables -A INPUT -i lo -j ACCEPT")

    # Allow packets that are part of an already established connection
    server.cmd("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # Drop packets that are invalid or malformed
    server.cmd("iptables -A INPUT -m conntrack --ctstate INVALID -j DROP")

    # Allow HTTP traffic (port 80) for new connections
    server.cmd("iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT")

    # Limit ping requests to avoid abuse (basic rate control)
    server.cmd("iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/second -j ACCEPT")

    # Limit incoming SYN packets to reduce impact of SYN flood attacks
    server.cmd("iptables -A INPUT -p tcp --syn -m limit --limit 10/second --limit-burst 20 -j ACCEPT")

    # Log any packets that get dropped (useful for debugging/analysis)
    server.cmd('iptables -A INPUT -j LOG --log-prefix "IPTABLES_DROP: " --log-level 4')

    # Drop everything else that doesn't match the rules above
    server.cmd("iptables -A INPUT -j DROP")


def show_firewall_rules(server):
    """
    Print the current iptables rules on h1.
    """

    print("[*] Current firewall rules:")
    rules = server.cmd("iptables -L -n -v")
    print(rules)
    return rules
