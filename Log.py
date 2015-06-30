import threading
import Queue
from datetime import datetime


class Log(threading.Thread):
    
    def __init__(self, fileName=None):
        
        threading.Thread.__init__(self)
        self.daemon = True
        
        self.fileName=""
        if fileName is None:
            self.fileName="honeypotLog"
        else:
            self.fileName=fileName
        
        self.file = open(self.fileName, 'w')
        
        
        self.queue = Queue.Queue()
        
        #Log starts itself, because it is singleton class
    
    def writingLoop(self):
        
        while True:
            line= self.queue.get(block=True, timeout=None)
            self.file.write("[" + str(datetime.now()) + "]" + line + "\n")
            self.file.flush()
    
    def getWQueue(self):
        return self.queue
    
    def run(self):
        self.writingLoop()
        
#singleton
log = Log()   
log.start()
        
        