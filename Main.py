import Queue
import Honeypot
import Sniffer


class Main:
    def __init__(self):
        #TODO - multiple threads, each will have its own queue, sniffer will
        #divide traffice based on the MAC addr
        queue = Queue.Queue()
        hpot = Honeypot(queue)
        self.sniff = Sniffer(queue)
        self.sniff.start()
        
Main()