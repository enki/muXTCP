#!/usr/bin/python
# TCP UDP ICMP
#  |   |   |
# Layer3(Mux)
#   |
#  IP   ARP
#   |    |
# Layer2(Mux)
#     |
# Ethernet(Protocol)
#     |
# Layer1(Mux)
#     |
# EthernetDriver(Adapter)

# =[('MSS', 1460), ('SAckOK', ''), ('Timestamp', (1225447751L, 910591087L)), ('NOP', None), ('WScale', 0)] 

protocols = {}
import sys
sys.modules["protocols"] = protocols

import sys
from udp import * 
from twisted.internet import reactor
from scapyLink import ScapyLink
import io
from random import *
from tools import * 

from conduits import *
from driver import *
from ethernet import *
from arp import *
from ip import *
from udp import *
from icmp import *
from tcp import *

class EchoClientProtocol(TCPClientProtocol):
    def startProtocol(self):
        print "Protocol starting..."
        self.state.connect("kybernet.org", 8000)

class EchoServerProtocol(TCPServerProtocol):
    # XXX: What happens when the connection has been established?
    pass

def main():
#    io.linkInputToProtocol(protocol)
  
    global protocols
  
    # Layer 1 - Data Link Layer
    driver = EthernetDriver()
    protocols["driver"] = driver

    ether = EthernetProtocol()
    driver.registerHandler("default", ether)
    protocols["ether"] = ether

    # Layer 2 - Network Layer

    ip = IPProtocol()
    ether.registerHandler("IP", ip)
    protocols["ip"] = ip

    arp = ARPProtocol()
    ether.registerHandler("ARP", arp)
    protocols["arp"] = arp
    
    ether.registerHandler("default", Scream("Ether"))

    # Layer 3 - Transport Layer

    udp = UDPProtocol()
    ip.registerHandler("UDP", udp)
    protocols["udp"] = udp
    
    tcp = TCPProtocol()
    ip.registerHandler("TCP", tcp)
    protocols["tcp"] = tcp

    icmp = ICMPProtocol()
    ip.registerHandler("ICMP", icmp)
    protocols["icmp"] = icmp

    # Layer 4 - Application Layer
    ip.registerHandler("default", Scream("IP"))

    tcp.registerHandler("default", TCPDefaultHandlerAccept( EchoServerProtocol ) )

    echo = EchoClientProtocol()
#    echo.startProtocol()

    reactor.run()

if __name__ == '__main__':
    main()
