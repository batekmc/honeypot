
class DataSingelton:
    def __init__(self, dev="",confFile="",hostMac="", ip=""):
        self.dev = dev#device to listen on
        self.confFile = confFile #configuration file
        self.mac = hostMac#host mac
        self.ip=ip#host ip
        self.arpTable = {}#arp table for all honeypots
        
#act as singleton class        
globalData = DataSingelton()