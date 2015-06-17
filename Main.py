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
        ipList = self.getIPList(data)
        arp = Arp.Arp()
        #update system arp cache //TODO refresh interval
        arp.updateArpCache(ipList)
        #update system firewall 
        ipTab=hf.ipTableScriptGenerator(ipList)
        self.updateIPTables(ipTab)
                        
        #queue for virtual system //TODO multiple systems
        queue = Queue.Queue()
        hpot = hp.Honeypot(queue)
        #create packtet filter
        filter = self.generateFilter(ipList)
        print filter
        return
        #start giving packets to queue
        self.sniff = sn.Sniffer(queue, filter)
        self.sniff.start()
    
    def getIPList(self, hpDat):
        list = []
        for hp in hpDat:
            list.append(hp.ip)
        return list
    
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
        nebo=" or "
        ipA="ip.addr ==  "
        N=len(ipList)
        if N == 0:
            return None
        filterP=""
        
        for i in range(N):
            if i == N-1:
                break
            filterP+= ipA + ipList[i] + nebo
        filterP+=ipA + ipList[N-1]
        return filterP
        
      
Main()