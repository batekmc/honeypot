import dumbnet
import dpkt


class Arp:
    
    #TODO - REQUEST, REPLY
    def __init__(self, ip , mac):
        self.ip = ip
        self.mac = mac
        pass
    
    
    def buildAnnouncment(self):
        '''Gratuitous ARP
        A host sends an ARP request for
        its own    IP address'''
        
        arp = dpkt.arp.ARP()
        #The source hardware address
        arp.sha = dumbnet.eth_aton(self.mac)
        #The source protocol address
        arp.spa = dumbnet.ip_aton(self.ip)
        #The target hardware address
        arp.tha = '0'
        #The target protocol address
        arp.tpa = dumbnet.ip_aton(self.ip)
        arp.op = dpkt.arp.ARP_OP_REQUEST
        
        packet = dpkt.ethernet.Ethernet()
        packet.src = dumbnet.eth_aton(self.mac)
        packet.dst = dumbnet.eth_aton("FF:FF:FF:FF:FF:FF")
        packet.data = arp
        packet.type = dpkt.ethernet.ETH_TYPE_ARP
            
        return packet
    

    def builReply(self, destMac, destIp):
        '''arp reply packet
        reply to Arp request'''
        
        arp = dpkt.arp.ARP()
        #The source hardware address
        arp.sha = dumbnet.eth_aton(self.mac)
        #The source protocol address
        arp.spa = dumbnet.ip_aton(self.ip)
        #The target hardware address
        arp.tha = dumbnet.eth_aton(destMac)
        #The target protocol address
        arp.tpa = dumbnet.ip_aton(destIp)
        arp.op = dpkt.arp.ARP_OP_REPLY
        
        packet = dpkt.ethernet.Ethernet()
        packet.src = dumbnet.eth_aton(self.mac)
        packet.dst = dumbnet.eth_aton(destMac)
        packet.data = arp
        packet.type = dpkt.ethernet.ETH_TYPE_ARP
            
        return packet

    def refreshArpCache(self):
        pass        