import dpkt
import dumbnet

records = {"www.aaa.cz":"1.2.3.4", "www.bbb.cz":"4.3.2.1"}


def dnsResponse(ipPacket):
    '''
    modify ipPacket with appropriate DNS data.
    Warrning - don not dereference ipPacket object
    @ipPacket - dpkt.ip object of UDP type
    
    @return True if dns data in IP are set, False otherwise
    '''
    dns = dpkt.dns.DNS(ipPacket.udp.data)
    if dns.qr != dpkt.dns.DNS_Q:
        return False
    if dns.opcode != dpkt.dns.DNS_QUERY:
        return False
    if len(dns.qd) != 1:
        return False
    if len(dns.an) != 0:
        return False
    if len(dns.ns) != 0:
        return False
    if dns.qd[0].cls != dpkt.dns.DNS_IN:
        return False
    if dns.qd[0].type != dpkt.dns.DNS_A:
        return False
    # transform DNS query into response
    dns.op = dpkt.dns.DNS_RA
    dns.rcode = dpkt.dns.DNS_RCODE_NOERR
    dns.qr = dpkt.dns.DNS_R 
    
    # construct answer RR
    arr = dpkt.dns.DNS.RR()
    arr.cls = dpkt.dns.DNS_IN
    arr.type = dpkt.dns.DNS_A
    arr.name = dns.qd[0].name
    if arr.name in records:
        arr.ip = dumbnet.ip_aton(records[arr.name])
    else:
        arr.ip = dumbnet.ip_aton('5.5.5.5')
    
    dns.an.append(arr)
    #calc new
    ipPacket.udp.sum = 0
    ipPacket.udp.sport, ipPacket.udp.dport = ipPacket.udp.dport, ipPacket.udp.sport
    ipPacket.udp.data = dns
    #data has changed, so must be set new because of checksum
    ipPacket.udp.ulen = len(ipPacket.udp)
    
    return True