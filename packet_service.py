import packet
import struct
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
class Packet_Service(object):

    def __init__(self):
        self.protocol_to_int = {"tcp": 6, "udp": 17}


    def packet_to_data(self, packet):
        total_pkt = ""
        total_pkt = self.craft_ip(packet)
        proto = packet.protocol
        if str.lower(proto) == "tcp":
            print len(total_pkt)
            total_pkt = self.craft_ip(packet)
            total_pkt += self.craft_tcp(packet)
            print len(total_pkt)
            print repr(total_pkt)
        elif proto == "udp":
            if packet.is_DNS == False:
                print "BAD RECONTSTRUCT"
                return None
            total_pkt = self.craft_ip(packet)
            total_pkt +=  self.craft_udp(packet)
            total_pkt += self.craft_dns(packet)
        return total_pkt

    def data_to_packet(self, pkt, pkt_dir):
        packet0 = packet.Packet()
        header_len = self.ip_header_length(pkt)
        packet0.dir = pkt_dir
        if header_len < 5:
            return None
        packet0.total_length = self.total_length(pkt)
        packet0.ip_id = self.get_ip_id(pkt)
        proto_dec = self.get_protocol(pkt)
        packet0.set_protocol(proto_dec)
        src = dst = None

        try:
            src = self.get_src(pkt)
            dst = self.get_dst(pkt)
        except:
            return
        if src == None or dst == None:
            return None
        packet0.src_ip = src
        packet0.dest_ip = dst
        start_trans_header = header_len * 4
        if packet0.protocol == "tcp":
            try:
                flags = self.get_tcp_flags(pkt, start_trans_header)
                packet0.syn = ((flags & 0x02) >> 1) == 1
                packet0.src_port = int(self.get_src_port_std(pkt, start_trans_header))
                packet0.dst_port = int(self.get_dst_port_std(pkt, start_trans_header))
                packet0.seq_num = self.seq_number(pkt)


                if (pkt_dir == PKT_DIR_OUTGOING and packet0.dst_port == 80) or (pkt_dir == PKT_DIR_INCOMING and packet0.src_port == 80):
                    http_offset = 4*int(self.get_end_tcp(pkt,start_trans_header))
                    
                    if pkt_dir == PKT_DIR_OUTGOING:
                        print "outgoing"
                    else:
                        print "incoming"
                    print "srcport: ", packet0.src_port
                    print "dstport: ", packet0.dst_port
                    print start_trans_header, "trans header <<__"
                    print http_offset, "http offsettttt << --"
                    packet0.http_contents = self.get_http_contents(pkt, start_trans_header + http_offset)
                    packet0.http_host = self.get_http_host(packet0)

            except Exception as e:
                print e
                return None
        elif packet0.protocol == "udp":
            try:
                packet0.src_port = int(self.get_src_port_std(pkt, start_trans_header))
                packet0.dst_port = int(self.get_dst_port_std(pkt, start_trans_header))
            except:
                return None
            if pkt_dir == PKT_DIR_OUTGOING and packet0.dst_port == 53:
                try:
                    result = self.parse_dns(pkt, start_trans_header + 8)
                    if result != None:
                        packet0.dns_query = result
                        packet0.is_DNS = True
                except:
                    return None
        elif packet0.protocol == "icmp":
            try:
                packet0.icmp_type = self.get_icmp_type(pkt, start_trans_header)
            except:
                return
        else:
            return None
        return packet0

    def get_http_host(self, pkt):
        pass 

#MARK PARSING
    #returns a big endian version of pkt
    def ip_header_length(self, pkt):
        byte0 = pkt[0]
        unpacked_byte = struct.unpack("!B", byte0)[0]
        header_len = unpacked_byte & 0x0F
        return header_len

    def ttl(self, pkt):
        ttl_byte = pkt[8]
        unpacked_byte = struct.unpack("!B", ttl_byte)[0]
        return unpacked_byte

    def ack_number(self, pkt):
        ack_byte = pkt[8:12]
        unpacked_byte = struct.unpack("!L", ack_byte)[0]
        return unpacked_byte

    def seq_number(self, pkt):
        seq_byte = pkt[4:8]
        unpacked_byte = struct.unpack("!L", seq_byte)[0]
        return unpacked_byte

    def total_length(self, pkt):
        total_byte = pkt[2:4]
        unpacked_byte = struct.unpack("!H", total_byte)[0]
        return unpacked_byte

    def udp_length(self, pkt, offset):
        length_byte = pkt[(offset + 4): (offset + 6)]
        unpacked_byte = struct.unpack("!H", length_byte)[0]
        return unpacked_byte

    def get_src_port_std(self, pkt, offset):
        dst_bytes = pkt[offset: offset + 2]
        unpacked_byte = struct.unpack("!H", dst_bytes)[0]
        return unpacked_byte

    def get_dst_port_std(self, pkt, offset):
        dst_bytes = pkt[offset + 2: offset + 4]
        unpacked_byte = struct.unpack("!H", dst_bytes)[0]
        return unpacked_byte

    def get_end_tcp(self, pkt, offset):
        offset_byte = pkt[offset+12: offset+13]
        unpacked_byte = struct.unpack("!B", offset_byte)[0]
        offset_nybble = unpacked_byte & 0xF0
        return (offset_nybble>>4)

    #get icmp type -- firsty byte of icmp header
    def get_icmp_type(self, pkt, offset):
        type_byte = pkt[offset]
        unpacked_byte = struct.unpack("!B", type_byte)[0]
        icmp_type = unpacked_byte
        return icmp_type

    #return the decimal protocol from pkt
    def get_protocol(self, pkt):
        proto_byte = pkt[9]
        unpacked_byte = struct.unpack("!B", proto_byte)[0]
        return unpacked_byte

    def get_src(self, pkt):
        address_byte = pkt[12:16]
        unpacked_byte = struct.unpack("!I", address_byte)[0]
        return unpacked_byte

    def get_dst(self, pkt):
        address_byte = pkt[16:20]
        unpacked_byte = struct.unpack("!I", address_byte)[0]
        return unpacked_byte

    def get_ip_id(self, pkt):
        id_bytes = pkt[4:6]
        unpacked = struct.unpack("!H",id_bytes)[0]
        return unpacked

    def get_tcp_flags(self, pkt, offset):
        flag_bytes = pkt[offset + 13]
        unpacked_byte = struct.unpack("!B", flag_bytes)[0]
        return unpacked_byte

    def get_http_contents(self, pkt, offset):
        content = pkt[offset:]
        print "HTTTTTTP CONTENT: "
        print content
        return content


    def parse_dns(self, pkt, offset):
        dns_header = pkt[offset:offset+12]
        qd_count_byte = dns_header[4:6]
        qd_count = struct.unpack("!H", qd_count_byte)[0]
        if qd_count != 1:
            return None
        offset = offset + 12

        question = pkt[offset:]
        qname_end = 0
        byte_val = struct.unpack("!B", question[qname_end])[0]
        q_name = []
        while byte_val != 0x00:
            length = byte_val
            string = ""
            qname_end += 1
            while length > 0:
                char_byte = struct.unpack("!B", question[qname_end])[0]
                string += chr(char_byte)
                length -= 1
                qname_end += 1

            q_name.append(string)
            byte_val = struct.unpack("!B", question[qname_end])[0]

        q_type_byte = question[qname_end + 1 : qname_end + 3]
        q_class_byte = question[qname_end + 3: qname_end + 5]

        q_type = struct.unpack("!H", q_type_byte)[0]
        q_class = struct.unpack("!H", q_class_byte)[0]

        if q_type != 28 and q_type != 1:
            return None

        if q_class != 1:
            return None

        return q_name

#MARK CONSTRUCTING
    def craft_tcp(self, packet):
        source = packet.dst_port
        dest = packet.src_port
        seq = 0
        ack = packet.seq_num + 1
        res_off = 5 << 4
        flag = 20
        window = 1
        urgent_pointer = 0
        check_sum = 0
        tcp_header = struct.pack("!HHLLBBHHH", source, dest, seq, ack, res_off, flag, window, check_sum, urgent_pointer)
        check_sum = self.checksum_calc(tcp_header, 20)
        tcp_header = struct.pack("!HHLLBBHHH", source, dest, seq, ack, res_off, flag, window, check_sum, urgent_pointer)
        return tcp_header

    def craft_udp(self, packet):
        source = packet.dst_port
        dest = packet.src_port
        length = 8
        checksum = 0
        udp_header = struct.pack("!HHHH", source, dest, length, checksum)
        checksum = self.checksum_calc(udp_header, 8)
        udp_header = struct.pack("!HHHH", source, dest, length, checksum)
        return udp_header

    def craft_dns(self, packet):
        return None

    def checksum_calc(self, packet_string, num_bytes):
        index = 0;
        sum = 0;
        for i in range(0,num_bytes/2):
            index = i*2
            header_bytes = struct.unpack("!H", packet_string[index:index+2])[0]
            sum = self.short_carry_add(sum,header_bytes)
        return ~sum & 0xffff

    def short_carry_add(self, a,b):
        sum = a + b
        return (sum & 0xffff) + (sum >> 16)

    def craft_ip(self, packet):
        version = 4 << 4
        header_len = 5
        first_byte = version | header_len
        tos = 0
        total_length = 40
        identification = packet.ip_id
        fragment_offset = 0
        ttl = 64
        protocol = self.protocol_to_int[packet.protocol]
        header_checksum = 0
        source_address = packet.dest_ip
        destination_address = packet.src_ip

        ip_header = struct.pack("!BBHHHBBHLL", first_byte, tos, total_length, identification, fragment_offset, ttl, protocol, header_checksum, source_address, destination_address)

        header_checksum = self.checksum_calc(ip_header, 20)

        ip_header = struct.pack("!BBHHHBBHLL", first_byte, tos, total_length, identification, fragment_offset, ttl, protocol, header_checksum, source_address, destination_address)
        return ip_header

