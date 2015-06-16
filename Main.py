import Queue
import Honeypot as hp
import Sniffer  as sn
import FileParser as fp
import Arp
import DataSingelton as ds
import pcapy
import sys
import HelpFunctions as hf



class Main:
    def __init__(self):
        #TODO - multiple threads, each will have its own queue, sniffer will
        #divide traffic based on the MAC addr
        
        #test, if given interface and 
        if not self.loadAndVerify():
            return
        
        f = fp.FileParser("conf.txt")
        data = f.readF()
        ipList = self.getIPList(data)
        arp = Arp.Arp()
        arp.updateArpCache(ipList)     
                        
        queue = Queue.Queue()
        hpot = hp.Honeypot(queue)
        self.sniff = sn.Sniffer(queue)
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
        
        
        
Main()