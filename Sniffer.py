import pcapy
import sys
import threading
import atexit

class Sniffer(threading.Thread):
    '''This is the class representing a sniffer, which 
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
            

