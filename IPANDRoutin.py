import DataSingelton as ds
import netaddr

def isInSubnet(ip):
    '''
    Test, if given @dstIP is on the same subnet as @myIP,
    based on gw subnet mask given in conf file 
    '''
    gw = ds.globalData.gw
    if netaddr.IPAddress(ip) in netaddr.IPNetwork(gw):
        return True
    return False


def isIPValid(ip):
    
    try:
        i = netaddr.IPAddress(ip)
        return True
    except ValueError:
        return False
