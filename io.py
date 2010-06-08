from twisted.internet import protocol
from twisted.internet.stdio import StandardIO
import atexit
from termios import TCSAFLUSH, tcgetattr, tcsetattr
import tty, sys

def setcooked(fd, when=TCSAFLUSH):
    """Put terminal into cooked mode."""
    from tty import LFLAG, ECHO, ICANON, CC, VMIN, VTIME
    mode = tcgetattr(fd)
    mode[LFLAG] = mode[LFLAG] | (ECHO | ICANON)
    mode[CC][VMIN] = 1
    mode[CC][VTIME] = 0
    tcsetattr(fd, when, mode)



class InputProtocol(protocol.Protocol):
    def __init__(self, target):
        self.target = target

    def dataReceived(self, data):
        self.target.userInputReceived(data)

#x = scapy.L3PacketSocket(iface="lo")
#y = x.recv(1024)
#print type(y),repr(y)

def linkInputToProtocol(target):
#    atexit.register(setcooked, sys.stdin.fileno())
#    tty.setcbreak(sys.stdin.fileno())
    inputprotocol = InputProtocol(target)
    StandardIO(inputprotocol)
