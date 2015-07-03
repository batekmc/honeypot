
class DataSingelton:
    '''
    Global date initialized in Main an accessed by all honeypots
    '''
    def __init__(self, dev="",confFile="",hostMac="", ip="", gw=""):
        self.dev = dev  #device to listen on
        self.confFile = confFile    #configuration file
        self.mac = hostMac  #host mac
        self.ip=ip  #host ip
        self.arpTable = {}  #arp table for all honeypots
        self.gw=gw  #gaetway in x.x.x.x/x format
        
#act as singleton class        
globalData = DataSingelton()