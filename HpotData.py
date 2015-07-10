
class  HpotData:
    
    def __init__(self, ip = None, mac=None, icmp=None, tcp=None, 
                 tcpServices = None, udpServices = None):
        self.ip = ip
        self.mac = mac
        self.icmp = icmp#dafault behavior
        self.tcp = tcp#dafault behavior
        self.tcpServices = tcpServices#open ports for services
        self.udpServices = udpServices#open ports for services
    
