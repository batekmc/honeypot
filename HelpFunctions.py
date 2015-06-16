import socket
import struct
import fcntl

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def ethernetAddr ( addr) :
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ( ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]), ord(addr[4]), ord(addr[5]) )
    return mac

#returns hw address of given interface
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])