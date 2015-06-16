import dumbnet
import dpkt
import os
import DataSingelton as ds


class Arp:
    
    #TODO - REQUEST, REPLY
    def __init__(self, ip=0 , mac=0):
        self.ip = ip
        self.mac = mac
        pass   

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
    
    def updateArpCache(self, listOfAddresses):
        ''' lisOfAddresses is a list with addresses,
         which will be used for virtual hosts'''
        
        command = "sudo arp -s "
        mac = ds.globalData.mac
        
        #arp -s ip mac
        for addr in listOfAddresses:
            ret = os.popen(command + addr + " " + mac)
            print ret
            

        