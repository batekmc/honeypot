#Convert a string of 6 characters of ethernet address into a dash separated hex string
def ethernetAddr ( addr) :
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ( ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]), ord(addr[4]), ord(addr[5]) )
    return mac