from conduits import *
from muxlib.scapy import *
import muxconf

class EthernetDriver(Conduit):
    def packetReceived(self, packet):
        target = self.handlers.get(packet.name, self.handlers["default"])
        target.packetReceived(packet, packet)

    def setup(self):
        from scapyLink import ScapyLink
#        link = ScapyLink("eth0")
        link = ScapyLink(muxconf.interface)
        link.registerProtocol(self)

    def setTransport(self, transport):
        self.setDownlink(transport)

    def sendPacket(self, packet):
#        print repr(packet), packet.summary()
#        print arp_cache
        print repr(packet)
        self.downlink.send(packet)
