import Queue
import Honeypot as hp
import Sniffer  as sn
import FileParser as fp
import Arp
import DataSingelton as ds
import pcapy
import sys
import HelpFunctions as hf
import os
from time import sleep



class Main:
    def __init__(self):
        #TODO - multiple threads, each will have its own queue, sniffer will
        #divide traffic based on the MAC addr
        
        #test, if given interface and 
        if not self.loadAndVerify():
            return
        
        #read conf file
        f = fp.FileParser("conf.txt")
        #get list of HpotData objects
        data = f.readF()
        #get list of ip addresses only
        ipList, macList = self.getIPandMACLists(data)
        arp = Arp.Arp()
        #update system arp cache //TODO refresh interval
        arp.updateArpCache(ipList)
        #update system firewall 
        ipTab=hf.ipTableScriptGenerator(ipList)
        self.updateIPTables(ipTab)
                        
        #queue for virtual system //TODO multiple systems
        queue = Queue.Queue()
        hpot = hp.Honeypot(queue)
        hpot.start()
        #create packtet filter
        filter = self.generateFilter(ipList)
        #start giving packets to queue
        self.sniff = sn.Sniffer(queue, filter)
        self.sniff.start()
        
        #stupid workaround to kill all threads...
        while True:
            try:
                sleep(1000)
            except KeyboardInterrupt:
                raise Exception("kill all threads")
    
    def getIPandMACLists(self, hpDat):
        IPlist = []
        MACList = []
        for hp in hpDat:
            IPlist.append(hp.ip)
            MACList.append(hp.mac)
        return IPlist, MACList
    
    def loadAndVerify(self):
        a = ds.globalData
        devList = pcapy.findalldevs() # list of all avalible devices
        if len(sys.argv) < 2:
            print "Please select device to listen on"
            print "Here is the list of acceptable devices: ", devList
            return False
        dev = sys.argv[1]
        if dev not in devList:
            print "Selected device: " + dev + " is not acceptable." 
            print "Here Is list of acceptable devices: ", devList
            return False
        else:
            a.dev = sys.argv[1]
        
        a.mac = hf.getHwAddr(sys.argv[1])
        return True       
    
    def updateIPTables(self, rules):
        for rule in rules:
            ret = os.popen(rule)
            print ret
            
    def generateFilter(self, ipList):
        '''"host 192.168.1.222 or 192.168.1.1"'''
        nebo=" or "
        N=len(ipList)
        if N == 0:
            return None
        filterP="ether host FF:FF:FF:FF:FF:FF or host "
        
        for i in range(N):
            if i == N-1:
                break
            filterP+= ipList[i] + nebo
        filterP+=ipList[N-1]
        return filterP
    
    #TODO
    def stopThreads(self):
        self.sniff.onExit()


if __name__ == '__main__':
    m = None
    try:
        m = Main()
    except :
        #TODO - better cleaning
        os.popen("sudo killall python")
        os.popen("sudo iptables -F INPUT")
        raise      
