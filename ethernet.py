from conduits import *
from muxlib.scapy import *

import protocols

class EthernetProtocol(Protocol):
    promisc = False

    def setup(self):
        addr = ARP().hwsrc
        self.hwaddrs = set()
        self.hwaddrs.add(addr)

    def packetReceived(self, packet, fullPacket):
        if self.promisc or packet.dst in self.hwaddrs:
            self.dispatch(packet, fullPacket)

    def buildPacket(self, remoteIP, *args, **kwargs):
        iff,a,gw = conf.route.route(remoteIP)

        if gw != "0.0.0.0":
            ipaddr = gw
        else:
            ipaddr = remoteIP

        if iff == "lo":
            mac = "ff:ff:ff:ff:ff:ff"
        else:
            mac = protocols["arp"].whohas(ipaddr)
        
        if not mac:
            print "Couldn't find mac addr for", ipaddr
            mac = "ff:ff:ff:ff:ff:ff"

        kwargs["dst"] = mac
        return Ether(*args, **kwargs)
