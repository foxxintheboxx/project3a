
class Packet(object):
    def __init__(self):
        self.src_ip = None
        self.dest_ip = None
        self.src_port = None
        self.dst_port = None
        self.dir = None
        self.is_DNS = False
        self.protocol = "unknown"
        self.icmp_type = None
        self.dns_query = None

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
