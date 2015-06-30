import threading
import dpkt
import Sender 
import dumbnet
import DataSingelton as ds
from time import sleep
import Arp
import Log


class Honeypot(threading.Thread):
    def __init__(self, queue, data):
        
        threading.Thread.__init__(self)
        
        self.daemon = True
        
        self.mac = ""
        self.ip=""
        self.icmp = False
        #0 is block, 1 is close
        self.tcp=0        
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
        if data.tcp == "close":
            self.tcp = 1 
        
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
        
        #HPOT answer to ping, based on conf file
        if ipPacket.p == dpkt.ip.IP_PROTO_ICMP and self.icmp:
            ipPacket.icmp.type = dpkt.icmp.ICMP_ECHOREPLY
            ipPacket.icmp.sum = 0
            tmp = ipPacket.src
            ipPacket.src = ipPacket.dst
            ipPacket.dst = tmp
            ipPacket.ttl -= 1
            #MUST be set to zero, to find out that should calculate new
            ipPacket.sum = 0
            destIP = dumbnet.ip_ntoa(ipPacket.dst)
            self.sendEthPacket(eth, ipPacket, destIP)
            self.log.put("ICMP-ECHOREPLY#" +"dstIP:" + destIP + ";srcIP:" + self.ip )
            
        
        if ipPacket.p == dpkt.ip.IP_PROTO_TCP and self.tcp:
            pass
    
    def sendEthPacket(self, eth, protoData, ip):
        '''
        sends eth packet
        @eth - incoming eth frame
        @prtoData - data of ethernet frame
        @ip - IP in printable format x.x.x.x
        '''
        eth.dst = self.getMACfromARPtable(ip)
        eth.src = eth.dst
        eth.data = protoData
        self.snd.put(eth)
    
    def getMACfromARPtable(self, ip):
        '''
        return MAC of given IP.
        If there is no match, then is send ARP reques for given IP
        @ip - IP address in x.x.x.x format
        '''
        
        arpTable = ds.globalData.arpTable
        c = 1
        while True:
            if ip in arpTable:
                return dumbnet.eth_aton(arpTable[ip])
            if c:
                c = 0
                self.snd.put(Arp.ArpRequest(dumbnet.ip_aton(ip), self.ip, self.mac))
                print "ARP request sent!"
            #if there is no ARP entry for given IP, then wait for it and try again
            sleep(0.1)
            
            
            
            
                
                
                
                
                
                
                
                
                
                