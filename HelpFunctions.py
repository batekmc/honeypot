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

def getIPaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def ipTableScriptGenerator(ipList):
    '''generates a file with rules for Linux netfilter/IPtables
    rules necessary for running honeypot. It is because the kernet 
    drops packets with destination address other than host PC.'''
    ret=[]
    start="iptables -A INPUT -d "
    end=" -j ACCEPT"
    last="iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
    
    for addr in ipList:
        ret.append(start + addr + end)
    ret.append(last)
    
    return ret