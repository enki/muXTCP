from conduits import *
from muxlib.scapy import *

import muxconf

class ARPProtocol(Protocol):
    def setup(self):
        self.arp_cache = muxconf.arp_cache

    def whohas(self, ipaddr):
        packet = Ether(dst=ETHER_BROADCAST)/ARP(op="who-has", pdst=ipaddr)
        self.sendPacket(packet)
#        print "whohas?", ipaddr
        return self.arp_cache.get(ipaddr, None)

    def packetReceived(self, packet, fullPacket):
        arp = fullPacket[ARP]
        if arp.op == arp.is_at:
            self.arp_cache[arp.psrc] = arp.hwsrc

#        print "arp cache:", self.arp_cache
