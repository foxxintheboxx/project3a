from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
class Packet(object):
    def __init__(self):
        #IP HEADER
        self.total_length = None
        self.frag_offset = None
        self.ip_flags = None
        self.src_ip = None
        self.dest_ip = None
        self.ip_id = None


        #TRANSPORT
        self.src_port = None
        self.dst_port = None
        self.seq_num = None #TCP
        self.trans_length = None 
        self.window = 1 #TCP
        self.syn = False

        self.icmp_type = None 
        self.dns_query = None
        self.is_DNS = False
        self.protocol = "unknown"

        self.dir = None

        self.http_contents = None
        self.http_host = None



    def set_protocol(self,decimal_value):
        if decimal_value == 17:
            self.protocol = "udp"
        elif decimal_value == 1:
            self.protocol = "icmp"
        elif decimal_value == 6:
            self.protocol = "tcp"

    def set_src_port(self, decimal_value):
        self.src_port = decimal_value

    def set_dst_port(self, decimal_value):
        self.dst_port = decimal_value
