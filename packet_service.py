import packet
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
class Packet_Service(object):


	def packet_to_data(self, packet):
		total_pkt = ""
		total_pkt = self.craft_ip(packet)
		proto = packet.protocol
		if proto == "TCP":
			total_pkt += self.craft_tcp(packet)
		elif proto == "UDP":
			total_pkt +=  self.craft_udp(packet)
			if packet.is_DNS == False:
				print "BAD RECONTSTRUCT"
			total_pkt += self.craft_dns(packet)
		return total_pkt

	def data_to_packet(self, pkt, pkt_dir):
		packet = Packet()
        header_len = self.ip_header_length(pkt)
        if header_len < 5:
            return None
        proto_dec = self.get_protocol(pkt)
        packet.set_protocol(proto_dec)
        src = dst = None
        try:
            src = self.get_src(pkt)
            dst = self.get_dst(pkt)
        except:
            return
        if src == None or dst == None:
            return None
        packet.src_ip = src
        packet.dest_ip = dst

        start_trans_header = header_len * 4
        
        if packet.protocol == "tcp":
            try:
                packet.src_port = int(self.get_src_port_std(pkt, start_trans_header))
                packet.dst_port = int(self.get_dst_port_std(pkt, start_trans_header))
            except:
                return None

        elif packet.protocol == "udp":
            try:
                packet.src_port = int(self.get_src_port_std(pkt, start_trans_header))
                packet.dst_port = int(self.get_dst_port_std(pkt, start_trans_header))
            except:
                return None
            if pkt_dir == PKT_DIR_OUTGOING and packet.dst_port == 53:
                try:
                    result = self.parse_dns(pkt, start_trans_header + 8)
                    if result != None:
                        packet.dns_query = result
                        packet.is_DNS = True
                except:
                    return None
        elif packet.protocol == "icmp":
            try:
                packet.icmp_type = self.get_icmp_type(pkt, start_trans_header)
            except:
                return
        else:
            return None

        return packet


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

    # def frag_offset(self, pkt):
    # 	byte = pkt[6:8]
    # 	unpacked_byte = struct.unpack("!H", fr)

    def version(self, pkt):
        byte0 = pkt[0]
        unpacked_byte = struct.unpack("!B", byte0)[0]
        version = unpacked_byte & 0xF0
        return version

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


