import dumbnet
import DataSingelton as ds
import Queue
import threading


class Sender(threading.Thread):
    
    def __init__(self):
        
        threading.Thread.__init__(self)
        self.daemon = True
        
        #FIFO memory for sending
        self.sQueue = Queue.Queue()
        
    
    def sendingLoop(self):
        
        while True:
            packet = self.sQueue.get(block=True, timeout=None)
            bytesSended = self.snd.send(str(packet))
            print "Sended bytes: " + str(bytesSended)
    
    def getSQueue(self):
        return self.sQueue
    
    def run(self):
        dev = ds.globalData.dev
        #open L2 interface for sending
        self.snd = dumbnet.eth(dev)
        self.sendingLoop()
        
#Singleton
send = Sender()
        
        