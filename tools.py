from muxlib.scapy import *

def extractData(packet):
    raw = packet[Raw]

    if not raw:
        return None

    return raw.load

def getTCPFlags(packet):
    return TCPflags2str(packet[TCP].flags)
