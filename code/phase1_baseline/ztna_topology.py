from mininet.net import Mininet
from mininet.node import OVSKernelSwitch


def create_network():

    net = Mininet(switch=OVSKernelSwitch, controller=None)

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    s1 = net.addSwitch("s1", failMode="standalone")

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.start()
    return net


def stop_network(net):
    """
    Stop the Mininet network cleanly.
    """
    if net is not None:
        net.stop()
