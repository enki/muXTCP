#!/usr/bin/python

import atexit
from os import system

filteredPorts = set()

def _filterPort(port, protocol):
    global filteredPorts
    if (port, protocol) in filteredPorts:
        return
    filteredPorts.add( (port, protocol) )
    system("iptables -A INPUT -p %s --dport %d -j DROP" % (protocol, port))

def _unfilterPort(port, protocol):
    global filteredPorts
    if (port, protocol) not in filteredPorts:
        return
    filteredPorts.remove( (port, protocol) )
    system("iptables -D INPUT -p %s --dport %d -j DROP" % (protocol, port))

def filterPort(port, protocol):
    _unfilterPort(port, protocol)
    atexit.register(_unfilterPort, port, protocol)
    _filterPort(port, protocol)

if __name__ == "__main__":
    filterPort(7999)
    while True:
        pass
