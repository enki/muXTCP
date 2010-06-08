import protocols

class Conduit:
    downlink = None

    def __init__(self):
        self.handlers = {}
        self.setup()

    def setup(self):
        pass

    def setDownlink(self, downlink):
        self.downlink = downlink

    def packetReceived(self, packet, fullPacket):
        self.dispatch(packet, fullPacket)
    
    def dispatch(self, packet, fullPacket):
        target = self.handlers.get(packet.payload.name, self.handlers["default"])
        target.packetReceived(packet.payload, fullPacket)

    def sendPacket(self, packet):
        print "sendPacket", repr(packet)
        self.downlink.sendPacket(packet)

    def registerHandler(self, name, protocol):
        self.handlers[name] = protocol

class Protocol(Conduit):
    def sendPacket(self, packet):
        protocols["driver"].sendPacket(packet)

class Scream(Protocol):
    def __init__(self, name):
        self.name = name
    def packetReceived(self, packet, fullPacket):
        print "scream", self.name, repr(fullPacket)


