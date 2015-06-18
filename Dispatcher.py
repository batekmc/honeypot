import threading
import Queue
import dpkt

class Dispatcher(threading.Thread):
    
    def __init__(self, hpotsQ, arpQ, ipList, macList):
        ''' @hpotsQ - queues from honeypots
            @arpQ - queue for arp requests
            @ipList - list of IP addresses in order as hpotsQ
            @macList - same as above, but L2 addresses
            
            This class acts as router or switch in computer networks. It divides traffic
            based on L3 addresses for single virtual systems, and separates arp traffic,
            which is processed in separate thread ( in file ARP.py).
        '''
        
        threading.Thread.__init__(self)
        self.fifo = Queue.Queue()
        