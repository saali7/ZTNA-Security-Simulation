from mininet.net import Mininet
import time


def start_http_server(net: Mininet) -> None:

    print("[*] Starting HTTP server on h1...")
    h1 = net.get("h1")


    h1.cmd("pkill -f 'python3 -m http.server'")


    h1.cmd("python3 -m http.server 80 > /tmp/http_server.log 2>&1 &")


    time.sleep(2)


def normal_http(net: Mininet) -> str:
    print("[*] Testing normal HTTP access: h2 -> h1")
    h2 = net.get("h2")
    return h2.cmd("curl -I --max-time 5 http://10.0.0.1")


def attacker_http(net: Mininet) -> str:
    print("[*] Testing attacker HTTP access: h3 -> h1")
    h3 = net.get("h3")
    return h3.cmd("curl -I --max-time 5 http://10.0.0.1")


def lateral_ping(net: Mininet) -> str:
    print("[*] Testing lateral ping: h3 -> h2")
    h3 = net.get("h3")
    return h3.cmd("ping -c 4 10.0.0.2")


def subnet_scan(net: Mininet) -> str:
    print("[*] Testing subnet scan from h3")
    h3 = net.get("h3")
    return h3.cmd("nmap -sn 10.0.0.0/24")


def port_scan(net: Mininet) -> str:
    print("[*] Testing port scan: h3 -> h1")
    h3 = net.get("h3")
    return h3.cmd("nmap -Pn 10.0.0.1")


def syn_dos(net: Mininet) -> str:
    print("[*] Testing SYN flood: h3 -> h1")
    h3 = net.get("h3")
    return h3.cmd("timeout 5 hping3 -S -p 80 --flood 10.0.0.1")
