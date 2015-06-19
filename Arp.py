import dumbnet
import dpkt
import os
import DataSingelton as ds
import threading
import HelpFunctions as hf


class Arp(threading.Thread):
    
    #TODO - REQUEST, REPLY
    def __init__(self, ipList, macList, arpQ):
        
        threading.Thread.__init__(self)
        self.daemon = True
        self.queue = arpQ     
        
        if ipList is None or macList is None or len(ipList) != len(macList):
            raise Exception("missing ip or mac address")
        
        self.ipList = ipList
        self.macList = macList
        
        self.updateArpCache()
    
    def run(self):
        self.arpLoop()
        
    def arpLoop(self):
        while True:
            packet = self.queue.get(block=True,timeout=None)
            self.proccessPacket(packet)
    
    
    def proccessPacket(self, packet):
        print "ARP!"
        arp = dpkt.arp.ARP(packet)
        print hf.ethernetAddr(arp.sha)

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
    
    def updateArpCache(self):
        ''' lisOfAddresses is a list with addresses,
         which will be used for virtual hosts'''
        
        command = "sudo arp -s "
        mac = ds.globalData.mac
        
        com2 = "sudo arping -U -I " + ds.globalData.dev + " "#not working on some hosts...
        
        #arp -s ip mac
        for addr in self.ipList:
            ret = os.popen(com2 + addr)
            print ret
            ret = os.popen(command + addr + " " + mac)
            print ret
            
            

        