from muxlib.scapy import *
from conduits import *
from random import *
from tools import *

import muxconf
import protocols

class TCPProtocol(Protocol):
    def packetReceived(self, packet, fullPacket):
        self.dispatch(packet, fullPacket)

    def dispatch(self, packet, fullPacket):
        tcp = fullPacket[TCP]
        ip = fullPacket[IP]
        
        remotePort = tcp.sport
        remoteIP = ip.src
        localIP = ip.dst
        localPort = tcp.dport

        if localPort in muxconf.listenPorts:
            connID = (localIP, localPort, remoteIP, remotePort)
            handler = self.handlers.get(connID, self.handlers["default"])
            handler.packetReceived(packet, fullPacket)

    def createConnection(self, conn, localIP, localPort, remoteIP, remotePort):
        self.registerHandler((localIP, localPort, remoteIP, remotePort), conn)

    def buildPacket(self, *args, **kwargs):
        return TCP(*args, **kwargs)

    def replyRST(self, packet):
        ether = protocols["ether"].buildPacket(packet[IP].src)
        ackNo = packet.seq
        if "S" in getTCPFlags(packet):
            ackNo += 1

        data = extractData(packet)
        if data:
            ackNo += len(data)

        ip = IP(src=packet[IP].dst, dst=packet[IP].src)
        tcp = TCP(sport=packet[TCP].dport,
                  dport=packet[TCP].sport, flags="RA",
                  ack=ackNo, seq=packet[TCP].ack)
        rstPacket = ether/ip/tcp
#        print "RSTing with", repr(rstPacket)
        self.sendPacket( rstPacket )

class TCPDefaultHandlerDROP:
    def packetReceived(self, packet, fullPacket):
        print "Dropping TCP:", repr(fullPacket)

class TCPDefaultHandlerRST:
    def packetReceived(self, packet, fullPacket):
        print "RSTing TCP:", repr(fullPacket)
        protocols["tcp"].replyRST(fullPacket)

class TCPDefaultHandlerAccept:
    def __init__(self, prototype):
        self.prototype = prototype
        
    def packetReceived(self, packet, fullPacket):
        localIP = fullPacket.dst
        localPort = fullPacket.dport
        remoteIP = fullPacket.src
        remotePort = fullPacket.sport

        protocol = self.prototype()

        protocols["tcp"].createConnection(protocol, localIP, localPort, remoteIP, remotePort)

        protocol.packetReceived(packet, fullPacket)

class State:
    def __init__(self, connection):
        self.connection = connection

    def cleanup(self):
        print "cleanup not implemented yet"

class TCPState_FIN_WAIT_1(State):
     def packetReceived(self, packet, fullPacket):
        print "FIN_WAIT_1", repr(fullPacket)

class TCPState_CLOSED(State):
    def packetReceived(self, packet, fullPacket):
        print "CLOSED", repr(fullPacket)

    def connect(self, dst, dport):
        print "Connect", dst, dport
        ips = protocols["ip"].ips.copy()
        localIP = ips.pop()
        localPort = randrange(1200,65000)

        remoteIP = socket.gethostbyname(dst)
        remotePort = dport

        seqNo = randrange(0, (2**32) - 1)
        ackNo = 0

        self.connection.registerConnection(localIP, localPort, remoteIP, remotePort, seqNo, ackNo)

        self.connection.sendSYN()

class TCPState_LISTEN(State):
    def packetReceived(self, packet, fullPacket):
#        print "LISTEN: Packet received", repr(fullPacket)
        
        ip = fullPacket[IP]
        tcp = fullPacket[TCP]
        if getTCPFlags(fullPacket) == "S" and ip.dport == self.connection.localPort:

            seqNo = random.randrange(0, (2**32) - 1)
            ackNo = tcp.seq + 1 # SYN Consumes one ACK
            
            localIP = ip.dst
            localPort = tcp.dport
            remoteIP = ip.src
            remotePort = tcp.sport

            self.connection.registerConnection(localIP, localPort, remoteIP, remotePort, seqNo, ackNo)

            self.connection.sendSYNACK()
            self.connection.enterState( TCPState_SYN_RCVD(self.connection) )
        else:
            protocols["tcp"].replyRST(fullPacket)

class TCPState_SYN_RCVD(State):
     def packetReceived(self, packet, fullPacket):
#        print "SYN_RCVD", repr(fullPacket)
        if getTCPFlags(fullPacket) == "A":
            self.connection.enterState( TCPState_ESTABLISHED(self.connection) )
            print "Connection Established", repr(fullPacket)
            self.connection.connectionEstablished()
            self.connection.state.packetReceived(packet, fullPacket)
        else:
            protocols["tcp"].replyRST(fullPacket)

class TCPState_ESTABLISHED(State):
    def packetReceived(self, packet, fullPacket):
        if getTCPFlags(fullPacket) in ("A", "AP"):
            self.connection.ack(fullPacket)
#            print "ACKed", repr(packet)
            data = extractData(fullPacket)
            if data:
                self.connection.dataReceived(data)
        else:
            print "huh?", repr(fullPacket)
            protocols["tcp"].replyRST(fullPacket)
            # XXX: FIN
            # XXX: RST. fix replyRST stuff so that the connection knows what happened.

class TCPConnectionProtocol(Protocol):
    def packetReceived(self, packet, fullPacket):
        self.state.packetReceived(packet, fullPacket)

    def buildPacketForDatagram(self, flags=""):
        ether = protocols["ether"].buildPacket(self.remoteIP)
        ip = protocols["ip"].buildPacket(dst=self.remoteIP, src=self.localIP)
        tcp = protocols["tcp"].buildPacket(sport=self.localPort, \
                dport=self.remotePort, seq=self.seqNo, ack=self.ackNo, \
                flags=flags)

        self.seqNo += 1 # SYN consumes one Seq

        packet = ether/ip/tcp

        return packet

    def sendSYN(self):
        ether = protocols["ether"].buildPacket(self.remoteIP)
        ip = protocols["ip"].buildPacket(dst=self.remoteIP, src=self.localIP)
        tcp = protocols["tcp"].buildPacket(sport=self.localPort, \
                dport=self.remotePort, seq=self.seqNo, ack=self.ackNo, \
                flags="S")

        self.seqNo += 1 # SYN consumes one Seq

        packet = ether/ip/tcp
        self.sendPacket(packet)

    def sendFINACK(self):
        packet = self.buildPacketForDatagram("FA")
        self.sendPacket(packet)

    def sendSYNACK(self):
        ether = protocols["ether"].buildPacket(self.remoteIP)
        ip = protocols["ip"].buildPacket(dst=self.remoteIP, src=self.localIP)
        tcp = protocols["tcp"].buildPacket(sport=self.localPort, \
                dport=self.remotePort, seq=self.seqNo, ack=self.ackNo, \
                flags="SA")

        self.seqNo += 1 # SYN consumes one Seq

        packet = ether/ip/tcp
        self.sendPacket(packet)

    def sendACK(self, data=None):
        ether = protocols["ether"].buildPacket(self.remoteIP)
        ip = protocols["ip"].buildPacket(dst=self.remoteIP, src=self.localIP)
        tcp = protocols["tcp"].buildPacket(sport=self.localPort, \
                dport=self.remotePort, seq=self.seqNo, ack=self.ackNo, \
                flags="A")

        packet = ether/ip/tcp
        if data:
            packet[TCP].flags = "AP"
            packet /= data
            self.seqNo += len(data)

        self.sendPacket(packet)

    def sendData(self, data):
        self.sendACK(data)

    def ack(self, packet):
        data = extractData(packet)
        if data:
            self.ackNo += len(data)
            self.sendACK()

    def enterState(self, state):
        print "STATE", self.state, "->", state
        self.state = state

    def registerConnection(self, localIP, localPort, remoteIP, remotePort, seqNo, ackNo):
        print "Register Connection:", localIP, localPort, remoteIP, remotePort, seqNo, ackNo
        self.localIP = localIP
        self.localPort = localPort
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.seqNo = seqNo
        self.ackNo = ackNo
        protocols["tcp"].createConnection(self, self.localIP, self.localPort, \
                                          self.remoteIP, self.remotePort)



class TCPServerProtocol(TCPConnectionProtocol):
    disconnecting = False

    def setup(self):
        self.state = TCPState_LISTEN(self)
        self.localPort = 8000

    def connectionEstablished(self):
        self.sshServer()

    def webServer(self):
        from twisted.web.server import Site
        from twisted.web import demo, static

        self.app = Site(demo.Test()).buildProtocol("lala")
        self.app = Site(static.File(os.path.abspath("."))).buildProtocol("lala")
        self.app.transport = self

    def sshServer(self):

        from twisted.conch import checkers, unix
        from twisted.conch.openssh_compat import factory
        from twisted.cred import portal
        from twisted.python import usage
        from twisted.application import strports

        t = factory.OpenSSHFactory()
        t.portal = portal.Portal(unix.UnixSSHRealm())
        t.portal.registerChecker(checkers.UNIXPasswordDatabase())
        t.portal.registerChecker(checkers.SSHPublicKeyDatabase())
        if checkers.pamauth:
            t.portal.registerChecker(checkers.PluggableAuthenticationModulesChecker())
        t.dataRoot = '/etc/ssh'
        t.moduliRoot = '/etc/ssh'

        t.startFactory()
        self.app = t.buildProtocol("lala")
        self.app.transport = self

        self.app.connectionMade()
        
    def dataReceived(self, data):
        try:
            self.app.dataReceived(data)
        except Exception, e:
            print "some noise", e
#        self.sendData(data)

    def write(self, data):
        while len(data) > 0:
            x = data[0:1000]
            data = data[1000:]
            self.sendData(x)

    def getPeer(self):
        class X:
            host = "lala"
            port = "fup"
        return X()

    def getHost(self):
        return self.getPeer()

    def writeSequence(self, iovec):
        print "Sequence:", iovec
        self.write("".join(iovec))

    def logPrefix(self):
        return "muXTCPServer"

    def loseConnection(self):
        self.sendFINACK()
        self.enterState( TCPState_FIN_WAIT_1() )

    def setTcpNoDelay(self, tog):
        pass
    
class TCPClientProtocol(TCPConnectionProtocol):
    def setup(self):
        self.state = TCPState_CLOSED(self)


