
class DataSingelton:
    def __init__(self, dev="",confFile="",hostMac="" ):
        self.dev = dev
        self.confFile = confFile
        self.mac = hostMac
#act as singleton class        
globalData = DataSingelton()