import HpotData

class FileParser:
    '''TODO file format...'''
    def __init__(self, ff):
        self.f = ff      
        
    def readF(self):
        f = open(self.f, 'r')
        retArr = []
        for line in f:
            if line[0] == "#" or not line:
                continue
            spl = line.split()
            retArr.append(HpotData.HpotData(spl[0], spl[1]))

        return retArr
    
    
    def getIpMac(self):
        return self.ip, self.mac