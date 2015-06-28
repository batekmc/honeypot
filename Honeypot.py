import threading
import dpkt
import Sender 


class Honeypot(threading.Thread):
    def __init__(self, queue):
        
        threading.Thread.__init__(self)
        
        self.daemon = True
        
        self.mac = ""
        self.ip=""
        #honeypots incoming packets
        self.packetQueue = queue
        
        self.counter = 1
        
        #outgoing queue
        self.snd = Sender.send.getSQueue()
    
    def run(self):
           
        while True:
            #if queue is empty, then it is blocked
            packet = self.packetQueue.get(block=True,timeout=None)
            self.parsePacket(packet)
    
    def parsePacket(self, eth):
        '''receives dpkt.ethernet Object!'''
        ip = eth.data
        tcp = ip.data
        ipPacket = dpkt.ip.IP(str(ip))
        #ip.p is protocol number -
        #http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        
        #EVERY HPOT answers to ping, might add switch to conf file
        if ipPacket.p == dpkt.ip.IP_PROTO_ICMP:
            ipPacket.icmp.type = dpkt.icmp.ICMP_ECHOREPLY
            ipPacket.icmp.sum = 0
            tmp = ipPacket.src
            ipPacket.src = ipPacket.dst
            ipPacket.dst = tmp
            ipPacket.ttl -= 1
            #MUST be set to zero, to find out that should calculate new
            ipPacket.sum = 0
            tmp = eth.dst
            eth.dst = eth.src
            eth.src = tmp
            eth.data = ipPacket
            self.snd.put(eth)
            
                
                
                
                
                
                
                
                
                
                