import threading
import struct
import socket
import dpkt
import Arp 
import dumbnet
import sys
import HelpFunctions as hp


class Honeypot(threading.Thread):
    def __init__(self, queue):
        
        threading.Thread.__init__(self)
        
        self.mac = ""
        self.ip=""
        #honeypots incoming packets
        self.packetQueue = queue
        self.start()
    
    def run(self):
           
        while True:
            #if queue is empty, then it is blocked
            packet = self.packetQueue.get()
            self.parsePacket(packet)
            self.packetQueue.task_done()
    
    def parsePacket(self, data):
        #parse ethernet header
        eth_length = 14
          
        eth_header = data[:eth_length]
        eth = struct.unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print 'Destination MAC : ' + hp.ethernetAddr(data[0:6]) + ' Source MAC : ' + hp.ethernetAddr(data[6:12]) + ' Protocol : ' + str(eth_protocol)
        if eth_protocol == 8:
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
            tcp = ip.data