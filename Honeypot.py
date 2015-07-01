import threading
import dpkt
import Sender 
import dumbnet
import DataSingelton as ds
from time import sleep
import Arp
import Log
import DNS


class Honeypot(threading.Thread):
    def __init__(self, queue, data):
        
        threading.Thread.__init__(self)
        
        self.daemon = True
        
        self.mac = ""
        self.ip=""
        self.icmp = False
        #0 is block, 1 is close, 2 is open
        self.tcp=0         
        self.tcpOpenPorts=[]
        
        self.initData(data)
        
        #honeypots incoming packets
        self.packetQueue = queue
        
        self.counter = 1
        
        #outgoing queue
        self.snd = Sender.send.getSQueue()
        #Log
        self.log = Log.log.getWQueue()
    
    def initData(self, data):
        self.mac = data.mac
        self.ip = data.ip
        if data.icmp == "on":
            self.icmp = True
        #if blocked, then will do nothing
        if data.tcp[0] != "block":
            self.tcp = 1
        # are there some open ports?    
        if data.tcp[0] == "open":
            self.tcpOpenPorts = data.tcp[1:]
            #code 2 is for open ports
            self.tcp = 2
            print self.tcpOpenPorts
             
        
    def run(self):
           
        while True:
            #if queue is empty, then it is blocked
            packet = self.packetQueue.get(block=True,timeout=None)
            self.parsePacket(packet)
    
    def parsePacket(self, eth):
        '''receives dpkt.ethernet Object!'''
        ip = eth.data
        ipPacket = dpkt.ip.IP(str(ip))
        #ip.p is protocol number -
        #http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        destIP = dumbnet.ip_ntoa(ipPacket.src)
        #ICMP
        if ipPacket.p == dpkt.ip.IP_PROTO_ICMP and self.icmp:
            ipPacket.icmp.type = dpkt.icmp.ICMP_ECHOREPLY
            ipPacket.icmp.sum = 0
            self.sendEthFrame(eth, ipPacket, destIP)
            self.log.put("ICMP-ECHOREPLY#" +"dstIP:" + destIP + ";srcIP:" + self.ip )
            
        #TCP - if self.tcp is 0 - "filtered" in conf file
        elif ipPacket.p == dpkt.ip.IP_PROTO_TCP and self.tcp:
            if not self.TCPdefault(ipPacket):
                return
            self.sendEthFrame(eth, ipPacket, destIP)
            self.log.put("TCP-RST#" +"dstIP:" + destIP + ";srcIP:" 
                         + self.ip + ";sPort:" + str(ipPacket.tcp.dport) 
                         + ";dPort:" + str(ipPacket.tcp.sport) )
        #UDP
        elif ipPacket.p == dpkt.ip.IP_PROTO_UDP:
            if ipPacket.udp.dport == 53:
                dns = dpkt.dns.DNS(ipPacket.udp.data)
                if DNS.dnsResponse(ipPacket):
                    self.sendEthFrame(eth, ipPacket, destIP)
                   
                
            
    
    def sendEthFrame(self, eth, ipPacket, destIP):
        '''
        sends ethernet frame
        @eth - incoming eth frame
        @prtoData - data of ethernet frame
        @destIP - ip destination address
        '''
        ipPacket.len = len(ipPacket)
        ipPacket.src, ipPacket.dst = ipPacket.dst, ipPacket.src
        ipPacket.ttl -= 1
        #MUST be set to zero, to find out that should calculate new
        ipPacket.sum = 0
        eth.dst = self.getMACfromARPtable(destIP)
        eth.src = eth.dst
        eth.data = ipPacket
        self.snd.put(eth)
    
    def getMACfromARPtable(self, ip):
        '''
        return MAC of given IP.
        If there is no match, then is send ARP reques for given IP,
        and system waits for answer
        @ip - IP address in x.x.x.x format
        '''
        
        arpTable = ds.globalData.arpTable
        c = 0
        #6 seconds max - if ip-mac record not found, wait 2 s and send ARP request.
        #Max 3 requests are sent.
        while c < 59:
            if ip in arpTable:
                return dumbnet.eth_aton(arpTable[ip])
            if c%20 == 0:
                self.snd.put(Arp.ArpRequest(dumbnet.ip_aton(ip), self.ip, self.mac))
                print "ARP request sent!"
            #if there is no ARP entry for given IP, then wait for it and try again
            sleep(0.1)
        raise ValueError("ARP FAIL!")
    
    
    def TCPdefault(self, ipPacket):
        '''
        Respond to incomnig tcp connections.
        Responds are based on conf file.
        @ipPacket - dpkt.ip object of the tcp type
        '''
        #0x014 - RST-ACK
        if ipPacket.tcp.flags == dpkt.tcp.TH_RST or ipPacket.tcp.flags == 0x014:
            return False
        #RST Packet - closed
        elif self.tcp == 1:
            ipPacket.tcp.sport, ipPacket.tcp.dport = ipPacket.tcp.dport, ipPacket.tcp.sport
            ipPacket.tcp.flags = dpkt.tcp.TH_RST
            ipPacket.tcp.sum = 0
        #ACK Packet - open for SYN scanner
        elif self.tcp == 2:
            if str(ipPacket.tcp.dport) not in self.tcpOpenPorts:
                return False
            ipPacket.tcp.sport, ipPacket.tcp.dport = ipPacket.tcp.dport, ipPacket.tcp.sport
            #0x012 SYN-ACK flag
            ipPacket.tcp.flags = 0x012
            ipPacket.tcp.seq = 0
            ipPacket.tcp.ack = ipPacket.tcp.seq + 1
            ipPacket.tcp.sum = 0
        else:
            return False
        
        return True
    
            
            
            
                
                
                
                
                
                
                
                
                
                