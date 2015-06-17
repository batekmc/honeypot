import threading
import struct
import socket
import dpkt
import HelpFunctions as hp

import dumbnet
import DataSingelton as ds


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
        print "OK"
        #parse ethernet header
        eth_length = 14
          
        eth_header = data[:eth_length]
        eth = struct.unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print 'Destination MAC : ' + hp.ethernetAddr(data[0:6]) + ' Source MAC : ' + hp.ethernetAddr(data[6:12]) + ' Protocol : ' + str(eth_protocol)
        
        if eth_protocol == dpkt.ethernet.ETH_TYPE_IP:
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
            tcp = ip.data
            ipPacket = dpkt.ip.IP(str(ip))
            #ip.p is protocol number -
            #http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
            if ipPacket.p == dpkt.ip.IP_PROTO_ICMP:
                print "OK"
                icmp = dpkt.icmp.ICMP(tcp)
                icmp.code = dpkt.icmp.ICMP_ECHOREPLY
                ipPacket.data = icmp
                tmp = ipPacket.src
                ipPacket.src = ipPacket.dst
                ipPacket.dst = tmp
                tmp = eth.dst
                eth.dst = eth.src
                eth.src = tmp
                snd = dumbnet.eth(ds.globalData.dev)
                snd.send(str(eth))
                
                
                
                
                
                
                
                