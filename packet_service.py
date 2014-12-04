import packet
import struct
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
class Packet_Service(object):

    def __init__(self):
        self.protocol_to_int = {"tcp": 6, "udp": 17}


    def packet_to_data(self, packet):
        total_pkt = ""
        proto = packet.protocol
        if str.lower(proto) == "tcp":
            total_pkt = self.craft_ip(packet, 20)
            total_pkt += self.craft_tcp(packet)
        elif proto == "udp":
            if packet.is_DNS == False:
                print "BAD RECONTSTRUCT"
                return None
            total_pkt = self.craft_dns(packet)
            total_pkt =  self.craft_udp(packet, len(total_pkt)) + total_pkt
            total_pkt = self.craft_ip(packet, len(total_pkt)) + total_pkt
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
                packet0.ack = (flags & 0x10) > 1
                packet0.fin = (flags & 0x01) == 1
                packet0.src_port = int(self.get_src_port_std(pkt, start_trans_header))
                packet0.dst_port = int(self.get_dst_port_std(pkt, start_trans_header))
                packet0.seq_num = self.seq_number(pkt, start_trans_header)


                if (pkt_dir == PKT_DIR_OUTGOING and packet0.dst_port == 80) or (pkt_dir == PKT_DIR_INCOMING and packet0.src_port == 80):
                    http_offset = 4*int(self.get_end_tcp(pkt,start_trans_header))
                    

                    packet0.ip_header_length = start_trans_header
                    packet0.tcp_header_length = http_offset
                    packet0.http_contents_string = self.get_http_contents(pkt, start_trans_header + http_offset)

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
                    if result != None and result != -1:
                        packet0.dns_id = result[0]
                        packet0.dns_opcode_plus = result[1]
                        packet0.dns_query = result[2]
                        packet0.dns_question_bytes = result[3]
                        packet0.qname_bytes = result[4]
                        packet0.is_DNS = True
                    if result == 12:
                        packet0.is_AAAA = True
                        
                        
                        
                except Exception, e:
                    print e
                    print "failed dns parse"
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

    def seq_number(self, pkt, offset):
        seq_byte = pkt[offset + 4: offset + 8]
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

        return content


    def parse_dns(self, pkt, offset):
        response = ["ID", "OPCODE", "QUERY", "QUESTION", "QNAME_BYTE"]
        dns_header = pkt[offset:offset+12]
        response[0] = self.dns_id(dns_header)
        response[1] = self.dns_opcode_plus(dns_header)
        qd_count_byte = dns_header[4:6]
        qd_count = struct.unpack("!H", qd_count_byte)[0]
        if qd_count != 1:
            return None
        offset = offset + 12

        question = pkt[offset:]
        response[3] = question
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
        qname_byte = question[0: qname_end + 1]
        q_type_byte = question[qname_end + 1 : qname_end + 3]
        q_class_byte = question[qname_end + 3: qname_end + 5]

        q_type = struct.unpack("!H", q_type_byte)[0]
        q_class = struct.unpack("!H", q_class_byte)[0]
        ##I eliminated QTYPE == 28 (AAAA) 
        if q_type == 28:
            # some flag to indicate to drop because otherwise it would think it is just udp
            return 12 

        if q_class != 1:
            #not dns
            return None
        response[2] = q_name
        response[4] = qname_byte
        return response

    def dns_id(self, dns_header):
        id_byte = dns_header[0:2]
        _id = struct.unpack("!H", id_byte)[0]
        return _id

    def dns_opcode_plus(self, dns_header):
        op_bytes = dns_header[2:3]
        _bytes = struct.unpack("!B", op_bytes)[0]
        return _bytes


#MARK CONSTRUCTING
    def craft_tcp(self, packet):
        source = packet.dst_port
        dest = packet.src_port
        seq = packet.seq_num
        ack = 1 + packet.seq_num
        res_off = 5 << 4
        flag = 20
        window = 1
        urgent_pointer = 0
        check_sum = 0
        tcp_header = struct.pack("!HHLLBBHHH", source, dest, seq, ack, res_off, flag, window, check_sum, urgent_pointer)
        
        psuedo_header = struct.pack("!LLBBH", packet.dest_ip, packet.src_ip, 0, 6, 20)
        check_header = psuedo_header + tcp_header
        check_sum = self.checksum_calc(check_header, 32)
        tcp_header = struct.pack("!HHLLBBHHH", source, dest, seq, ack, res_off, flag, window, check_sum, urgent_pointer)
        return tcp_header

    def craft_udp(self, packet, leng):
        source = packet.dst_port
        dest = packet.src_port
        length = leng + 8
        checksum = 0
        udp_header = struct.pack("!HHHH", source, dest, length, checksum)
        #checksum = self.checksum_calc(udp_header, 8)
        #udp_header = struct.pack("!HHHH", source, dest, length, checksum)
        return udp_header

    def craft_dns(self, packet):
        dns_header = self.craft_dns_header(packet)
        question = packet.dns_question_bytes
        ## add answer fields
        _type = _class = _ttl = 1
        _rdlength = 4
        cat_ip = 917364886
        dns_answer = packet.qname_bytes + struct.pack("!HHLHL", _type, _class, _ttl, 4, cat_ip)
        dns_pkt = dns_header + packet.qname_bytes + struct.pack("!HH", 1,1) + dns_answer
        return dns_pkt

    def craft_dns_header(self, packet):
        _id = packet.dns_id
        opcode_plus = 1
        rcode_plus = 0
        qd_count = 1
        ancount = 1
        nscount = 0
        arcount = 0
        dns_header = struct.pack("!HHHHHH", _id, (1 << 15) | (1 << 8), qd_count, ancount, nscount, arcount)

        return dns_header

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

    def craft_ip(self, packet, leng):
        version = 4 << 4
        header_len = 5
        first_byte = version | header_len
        tos = 0
        total_length = leng + 20
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

