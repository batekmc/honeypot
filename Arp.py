import dumbnet
import dpkt
import os
import DataSingelton as ds
import threading
import Sender 
import Log

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
        
        self.snd = Sender.send.getSQueue()
        
        self.log = Log.log.getWQueue()  
        
        self.updateArpCache()
        
        #IMPORTANT - ARP has to start sender, because it needs to know about user input -
        #device to open, so it starts sending packets at this point.
        Sender.send.start()

    
    def run(self):
        self.arpLoop()
        
    def arpLoop(self):
        while True:
            packet = self.queue.get(block=True,timeout=None)
            self.proccessPacket(packet)
    
    
    def proccessPacket(self, packet):
        print "ARP!"
        
        #parse ethernet
        eth = dpkt.ethernet.Ethernet(packet)
        arp = eth.arp
        sIp =  dumbnet.ip_ntoa(str(arp.tpa))
        
        try:
            i = self.ipList.index(sIp)
            mac = self.macList[i]
            arpReply = self.builReply(arp.sha, arp.spa, sIp, mac)
            self.snd.put(arpReply)
                        
        except ValueError:
            return
        
        

    def builReply(self, destMac, destIp, ip, mac):
        '''
        @destMac - MAC of requesting machine in binary format
        @destIp - ip of requesting machine in binary format
        @ip - hpot ip in x.x.x.x format
        @mac - hpot mac in X:X:X:X:X:X format
        
        arp reply packet to request
        '''
        
        arp = dpkt.arp.ARP()
        #The source hardware address
        arp.sha = dumbnet.eth_aton(mac)
        #The source protocol address
        arp.spa = dumbnet.ip_aton(ip)
        #The target hardware address
        arp.tha = destMac
        #The target protocol address
        arp.tpa = destIp
        arp.op = dpkt.arp.ARP_OP_REPLY
        
        packet = dpkt.ethernet.Ethernet()
        #Routers sometimes ignores replies from different hosts,
        #but on the non csma/ca network it should work
        packet.src = dumbnet.eth_aton(ds.globalData.mac)
        packet.dst = destMac
        packet.data = arp
        packet.type = dpkt.ethernet.ETH_TYPE_ARP
        
        self.log.put("ARP-REPLY#" + "dstMAC:" + dumbnet.eth_ntoa(destMac) + ";dstIP:" +
                     dumbnet.ip_ntoa(destIp) + ";sourceIP:" + ip + ";sourceMAC:" + mac +"\n")
        return packet
    
    def updateArpCache(self):
        ''' lisOfAddresses is a list with addresses,
         which will be used for virtual hosts'''
        
        #blbost...................................
        
        command = "sudo arp -s "
        mac = ds.globalData.mac
        
        com2 = "sudo arping -U -I " 
        
        #arp -s ip mac
        for i in range(len(self.ipList)):
            ret = os.popen(com2 + self.ipList[i] + " " + self.macList[i])
            ret = os.popen(command + self.ipList[i] + " " + self.macList[i])
            
            

        