import threading
import Queue
import dpkt
import socket
import struct
import HelpFunctions as hf

class Dispatcher(threading.Thread):
    
    def __init__(self, hpotsQ, arpQ, ipList, macList):
        ''' @hpotsQ - queues from honeypots
            @arpQ - queue for arp requests
            @ipList - list of IP addresses in order as hpotsQ
            @macList - same as above, but L2 addresses
            
            This class acts as router or switch in computer networks. It divides traffic
            based on L2 addresses for single virtual systems, and separates arp traffic,
            which is processed in separate thread ( in file ARP.py).
        '''
        
        threading.Thread.__init__(self)
        self.daemon = True
        
        self.arpQ = arpQ
        self.hpotsQ = hpotsQ
        self.ipList = ipList
        self.macList = macList
        
        self.fifo = Queue.Queue()
    
    def dispatch(self):
        
        while True:
            packet = self.fifo.get(block=True, timeout=None)
            
            ethLen = 14
            ethHeader = packet[:ethLen]
            eth = struct.unpack('!6s6sH' , ethHeader)
            protocol = socket.ntohs(eth[2])
            
            #1544 stands for ARP - should be 0x0806...
            #something is wrong:)
            if protocol == 1544:
                self.arpQ.put(packet)
            #ipv4 protocol, also should be 0x0800...
            elif protocol == 8:
                #split traffic based on MAC
                mac = hf.ethernetAddr(packet[0:6])
                try:
                    index = self.macList.index(mac)
                    ethernetObject = dpkt.ethernet.Ethernet(packet)
                    #each honeypot will process traffic on its own
                    self.hpotsQ[index].put(ethernetObject)
                except ValueError:
                    print "fail! MAC: " + str(mac)
            #might add ipv6 support, or some other protocols using ethernet,
            #Just by using protocol number and then put it to the queue + modify sniffer filter.
                 
    
    #return pointer to own queue - for sniffer
    def getQueue(self):
        return self.fifo
    
    def run(self):
        self.dispatch()
        
        
        
        
        
        