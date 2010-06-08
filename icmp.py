from conduits import *

class ICMPProtocol(Protocol):
    def packetReceived(self, packet, fullPacket):
        print "Received ICMP", repr(packet)


