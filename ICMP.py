import dpkt


def buildechoReply(ipPacket):
    '''
    Creates echo reply from echo request.
    @ipPacket - dpkt.ip.IP objcet of ICMP type
    '''
    ipPacket.icmp.type = dpkt.icmp.ICMP_ECHOREPLY
    #MUST be set to zero, to find out that should calculate new
    ipPacket.icmp.sum = 0
    tmp = ipPacket.src
    ipPacket.src = ipPacket.dst
    ipPacket.dst = tmp
    ipPacket.ttl -= 1
    #MUST be set to zero, to find out that should calculate new
    ipPacket.sum = 0
    return ipPacket
