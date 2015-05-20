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
            if line[0] == "#" or not line:
                continue
            spl = line.split()
            self.ip = spl[0]
            self.mac = spl[1]
    
    
    def getIpMac(self):
        return self.ip, self.mac