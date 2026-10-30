# phase3_topology.py

from mininet.topo import Topo


class Phase3Topology(Topo):
    def build(self):

        # Create hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Application Server
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Legitimate User
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Unknown Device
        h4 = self.addHost('h4', ip='10.0.0.4/24')  # Database Server

        # Create one switch and connect all hosts to it
        s1 = self.addSwitch('s1')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


topos = {
    'phase3topology': Phase3Topology
}
