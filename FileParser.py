import HpotData as hpd

class FileParser:
    '''
    A new system always starts with world honeypot.
    On next lines are pairs - attribute and its value separate by spaces fxp 
    ip x.x.x.x.
    An empty lines and lines starting with # are ignored.
    Example config file is something like:
    
    honeypot
    ip 1.1.1.1
    mac FF:FF:FF:FF:FF:FF
    icmp on
    #comment - tcp has more args
    tcp default block
    
    honeypot
    #second system
    ...
    
    '''
    def __init__(self, ff):
        self.f = ff      
        
    def readF(self):
        f = open(self.f, 'r')
        retArr = []
        #index of honeypot
        hpot = -1
        for line in f:
            #test for comment or empty line
            if line[0] == "#" or line.strip() == '':
                continue
            spl = line.split()
            if spl[0] == "honeypot":
                hpot += 1                
                retArr.append(hpd.HpotData())
            else:
                if spl[0] == 'ip':
                    retArr[hpot].ip = spl[1]
                elif spl[0] == 'mac':
                    retArr[hpot].mac = spl[1]
                elif spl[0] == 'icmp':
                    retArr[hpot].icmp = spl[1]
                elif spl[0] == 'tcp':
                    if spl[1] == "default":
                        retArr[hpot].tcp = spl[2]
                    
                

        return retArr
    
    