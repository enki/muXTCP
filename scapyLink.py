#!/usr/bin/python

from muxlib.scapy import *
import sys
from twisted.internet import base, fdesc, reactor, protocol
import socket

import iptables

class ScapyLink(base.BasePort):
    def __init__(self, interface=None, plusIPs=[]):
        base.BasePort.__init__(self, reactor)
        self.protocols = []
        self.interface = interface

        if interface:
            self.listenIPs = [get_if_addr(interface)] 
        self.listenIPs += plusIPs

        self.listenOnWire()

    def getHandle(self):
        return self.socket

    def listenOnWire(self):
#        self.socket = scapy.L3RawSocket(iface=self.interface, promisc=True, filter='')
        self.socket = L2Socket(iface=self.interface)
        reactor.addReader(self)

    def fileno(self):
        return self.socket.ins.fileno()

    def doRead(self):
        packet = self.socket.recv(MTU)
        for protocol in self.protocols:
            protocol.packetReceived(packet)

    def registerProtocol(self, protocol):
        if protocol not in self.protocols:
            self.protocols.append(protocol)
#            protocol.startProtocol()
        else:
            raise "Registered Protocol", protocol, "twice"
        protocol.setTransport(self)

    def unRegisterProtocol(self, protocol):
        if protocol in self.protocols:
            protocol.setTransport(None)
            self.protocols.remove(protocol)
        else:
            raise "Removed Protocol", protocol, "that isn't registered"

    def send(self, packet):
        self.socket.send(packet)
