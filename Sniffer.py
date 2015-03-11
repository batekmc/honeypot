import pcapy
from impacket.ImpactDecoder import EthDecoder
import sys
import struct as struct
import socket 

class Sniffer: 
    
    def __init__(self):
        
        devList = pcapy.findalldevs() # list of all avalible devices
        if len(sys.argv) < 2:
            print "Please select device to listen on"
            print "Here is the list of acceptable devices: ", devList
            return
        dev = sys.argv[1]
        if dev not in devList:
            print "Selected device: " + dev + " is not acceptable." 
            print "Here Is list of acceptable devices: ", devList
            return
            
        max_bytes = 65536   # maximum number of bytes to be captured by pcap
        promiscuous = True # set Promiscous mode on 
        read_timeout = 10  # in milliseconds, for more info see: http://www.tcpdump.org/pcap.htm
        self.packet_limit = -1  # infinite - sniff "forever"
        
        self.pc = pcapy.open_live(dev, max_bytes, promiscuous, read_timeout)        
        if self.pc.datalink() is not pcapy.DLT_EN10MB:
            print "Not appropriate ethernet header. See: http://www.tcpdump.org/linktypes.html"
        #TODO
#         str = "(host 192.168.1.1 or localhost)"
#         bpf = pcapy.compile(pcapy.DLT_EN10MB, max_bytes, str, 1, 1'''maska''')
#         self.pc.setfilter(bpf)
        
        # Actual sniffing
        self.sniff()

    
    
    # callback for received packets
    # is called, when self.pc.loop recives packet and it process the packet
    def recivedPackets(self, hdr, data):
#         try:
#             packet = EthDecoder().decode(data) -- resources consuming...
#             print packet
#         except Exception:
#             print "Fail--------------\n"
             
        #parse ethernet header
        eth_length = 14
         
        eth_header = data[:eth_length]
        eth = struct.unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print 'Destination MAC : ' + self.ethernetAddr(data[0:6]) + ' Source MAC : ' + self.ethernetAddr(data[6:12]) + ' Protocol : ' + str(eth_protocol)
        
    # capture packets
    def sniff(self):
        self.pc.loop(self.packet_limit, self.recivedPackets)
        
        
    #Convert a string of 6 characters of ethernet address into a dash separated hex string
    def ethernetAddr (self, addr) :
        mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ( ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]), ord(addr[4]) , ord(addr[5]) )
        return mac
            
    
c = Sniffer()
        

