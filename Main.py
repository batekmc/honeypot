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

#process pid
pid = 0
#this is only for deleting rules before program stops
globIPtab =""

class Main:
    def __init__(self):
        #TODO - multiple threads, each will have its own queue, sniffer will
        #divide traffic based on the MAC addr
        
        #test input
        if not self.loadAndVerify():
            return
      
        #read conf file
        f = fp.FileParser("conf.txt")
        #get list of HpotData objects
        hpotData = f.readF()
        #get list of ip addresses only
        ipList, macList = self.getIPandMACLists(hpotData)
        #for CLEANING
        global globIPtab 
        globIPtab = hf.ipTableScriptGeneratorDelete(ipList)
                
        #run arp daemon
        arpQ = Queue.Queue()
        arp = Arp.Arp(ipList, macList, arpQ)
        arp.start()
                
        #update system firewall 
        ipTab=hf.ipTableScriptGenerator(ipList)
        updateIPTables(ipTab)
                        
        #queue for virtual system
        queueR = []
        #honeypot objects
        hpot = []
        for i in range(len(hpotData)):
            queueR.append(Queue.Queue())
            hpot.append(hp.Honeypot(queueR[i], hpotData[i]))
        
        for h in hpot:
            h.start()
        #create packtet filter
        filter = self.generateFilter(ipList)
        #start giving packets to queue
        self.sniff = sn.Sniffer(queueR, arpQ, ipList, macList, filter)
        self.sniff.start()
        
        #get process pid to kill program if future
        pid = os.getpid()
        
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
        a.ip = hf.getIPaddr(sys.argv[1])
        #create ARP record for hosting machine
        a.arpTable[a.ip] = a.mac
        return True       
    
            
    def generateFilter(self, ipList):
        '''"dst 192.168.1.222 or dst 192.168.1.1"'''
        nebo=" or dst "
        N=len(ipList)
        if N == 0:
            return None
        filterP="ether dst FF:FF:FF:FF:FF:FF or dst "
        
        for i in range(N):
            if i == N-1:
                break
            filterP+= ipList[i] + nebo
        filterP+=ipList[N-1]
        return filterP
    
    #TODO
    def stopThreads(self):
        self.sniff.onExit()
        
def updateIPTables(rules):
    for rule in rules:
        ret = os.popen(rule)
        print ret


if __name__ == '__main__':
    m = None
    try:
        m = Main()
    except :
        updateIPTables(globIPtab)
        os.popen("sudo kill -9 " + str(pid))
        raise      
