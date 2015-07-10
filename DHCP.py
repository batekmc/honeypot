from dpkt import dhcp
from dpkt import udp
from dpkt import ip
from dpkt import ethernet
import dumbnet

def budildRequest(sMac):
    '''
    Not working! Do not know why?! Illuminates!!:)
    '''
    # build a dhcp discover packet to request an ip
    d = dhcp.DHCP(
            chaddr = dumbnet.eth_aton(sMac),
            xid = 1337,
            op = dhcp.DHCPDISCOVER,
#             opts = (
#                 (dhcp.DHCP_OP_REQUEST, ''),
#                 (dhcp.DHCP_OPT_REQ_IP, ''),
#                 (dhcp.DHCP_OPT_ROUTER, ''),
#                 (dhcp.DHCP_OPT_NETMASK, ''),
#                 (dhcp.DHCP_OPT_DNS_SVRS, '')            
#                 )
            )
    
    # build udp packet
    u = udp.UDP(
            dport = 67,
            sport = 68,
            data = d,
            sum = 0
        )
    u.ulen = len(u)
    
    # build ip packet
    i = ip.IP(
            dst = dumbnet.ip_aton('255.255.255.255'),
            src = dumbnet.ip_aton('0.0.0.0'),
            data = u,
            p = ip.IP_PROTO_UDP,
            sum=0,
            ttl=16
        )
    i.len = len(i)
    
    # build ethernet frame
    e = ethernet.Ethernet(
            dst = dumbnet.ETH_ADDR_BROADCAST,
            src = dumbnet.eth_aton(sMac),
            data = i,
        )
    return e
