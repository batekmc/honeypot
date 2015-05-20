import dpkt


#TODO
class ICMP:

    def __init__(self):
        pass

    def buildechoReply(self, request):
        request.code = ICMP.icmp.ICMP_ECHOREPLY
        return request

    def buildechoRequest(self):
        pass