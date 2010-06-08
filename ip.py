from conduits import *
from muxlib.scapy import *
import muxconf

class IPProtocol(Protocol): 
    promisc = False

    def setup(self):
        self.ips = muxconf.myIPs

    def packetReceived(self, packet, fullPacket):
        if self.promisc or packet.dst in self.ips:
            self.dispatch(packet, fullPacket)
        else:
            print "Not for me, ip", self.ips, packet.dst

    def buildPacket(self, *args, **kwargs):
        return IP(*args, **kwargs)


