import pcapy
import sys
import struct as struct
import socket 
import dpkt
import threading
import atexit
import Queue
import dnet

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def ethernetAddr ( addr) :
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ( ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]), ord(addr[4]), ord(addr[5]) )
    return mac

class Sniffer(threading.Thread):
    '''This is the class representing - as you can guess from its name - a sniffer, which 
    based on destination hw addr moves packets to queues of threads representing honeypots''' 
    
    def __init__(self, queue):
        print "inserterd" 
        
        #run in a new thread
        threading.Thread.__init__(self)
        
        self.queue = queue
        
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
        
        atexit.register(self.onExit)
        
        self.pc = pcapy.open_live(dev, max_bytes, promiscuous, read_timeout)        
        if self.pc.datalink() is not pcapy.DLT_EN10MB:
            print "Not appropriate ethernet header. See: http://www.tcpdump.org/linktypes.html"
            return
        #TODO
#         str = "(host 192.168.1.1 or localhost)"
#         bpf = pcapy.compile(pcapy.DLT_EN10MB, max_bytes, str, 1, 1'''maska''')
#         self.pc.setfilter(bpf)   
    
    
    def onExit(self):
        self.pc = None
        
    # callback for received packets
    # is called, when self.pc.loop recives packet and it process the packet
    def recivedPackets(self, hdr, data): 
        self.queue.put(data)          

    # capture packets
    def sniff(self):
        self.pc.loop(self.packet_limit, self.recivedPackets)
        
    
    def run(self):
        # Actual sniffing
        self.sniff()
        
        
        
class Honeypot(threading.Thread):
    def __init__(self, queue):
        
        threading.Thread.__init__(self)
        
        self.mac = ""
        self.ip=""
        #honeypots incoming packets
        self.packetQueue = queue
        self.start()
    
    def run(self):
        #TODO ------ testing only-------------------------------
        f = FileReader("conf.txt")
        ip, mac = f.getIpMac()    
        
        arp = Arp(ip, mac)
        snd = dnet.eth(sys.argv[1])
        snd.send( str(arp.buildAnnouncment(ip, mac)) ) 
        
        # ------------------------------------------------------
           
        while True:
            #if queue is empty, then it is blocked
            packet = self.packetQueue.get()
            self.parsePacket(packet)
            self.packetQueue.task_done()
    
    def parsePacket(self, data):
        #parse ethernet header
        eth_length = 14
          
        eth_header = data[:eth_length]
        eth = struct.unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print 'Destination MAC : ' + ethernetAddr(data[0:6]) + ' Source MAC : ' + ethernetAddr(data[6:12]) + ' Protocol : ' + str(eth_protocol)
        if eth_protocol == 8:
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
            tcp = ip.data
        

            
class FileReader:
    '''TODO file format...'''
    def __init__(self, ff):
        self.f = ff
        self.ip = ''
        self.mac = ''
        self.readF(self.f)
        
        
    def readF(self, ff):
        f = open(ff, 'r')
        for line in f:
            if line[0] == "#":
                continue
            spl = line.split()
            self.ip = spl[0]
            self.mac = spl[1]
    
    
    def getIpMac(self):
        return self.ip, self.mac
    
class Arp:
    
    #TODO - REQUEST, REPLY
    def __init__(self, ip , mac):
        pass
    
    
    def buildAnnouncment(self, ip, mac):
        '''Gratuitous ARP'''
        
        arp = dpkt.arp.ARP()
        #The source hardware address
        arp.sha = dnet.eth_aton(mac)
        #The source protocol address
        arp.spa = dnet.ip_aton(ip)
        #The target hardware address
        arp.tha = '0'
        #The target protocol address
        arp.tpa = dnet.ip_aton(ip)
        arp.op = dpkt.arp.ARP_OP_REQUEST
        
        packet = dpkt.ethernet.Ethernet()
        packet.src = dnet.eth_aton(mac)
        packet.dst = dnet.eth_aton("FF:FF:FF:FF:FF:FF")
        packet.data = arp
        packet.type = dpkt.ethernet.ETH_TYPE_ARP
            
        return packet
    
        
class Main:
    def __init__(self):
        #TODO - multiple threads, each will have its own queue, sniffer will
        #divide traffice based on the MAC addr
        queue = Queue.Queue()
        hpot = Honeypot(queue)
        self.sniff = Sniffer(queue)
        self.sniff.start()
        
Main()