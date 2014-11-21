#!/usr/bin/env python        
import socket, struct, firewall_rules, packet, packet_service
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        with open(config['rule']) as file:
            rule_content = file.read()
        fw_rules = FireWall_Rules(rule_content)

        self.fw_rules = fw_rules

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        packet = Packet()
        header_len = self.ip_header_length(pkt)
        if header_len < 5:
            return
        proto_dec = self.get_protocol(pkt)
        packet.set_protocol(proto_dec)
        src = dst = None
        try:
            src = self.get_src(pkt)
            dst = self.get_dst(pkt)
        except:
            return
        if src == None or dst == None:
            return
        packet.src_ip = src
        packet.dest_ip = dst

        start_trans_header = header_len * 4
        
        if packet.protocol == "tcp":
            try:
                packet.src_port = int(self.get_src_port_std(pkt, start_trans_header))
                packet.dst_port = int(self.get_dst_port_std(pkt, start_trans_header))
            except:
                return

        elif packet.protocol == "udp":
            try:
                packet.src_port = int(self.get_src_port_std(pkt, start_trans_header))
                packet.dst_port = int(self.get_dst_port_std(pkt, start_trans_header))
            ## UDP and the destination port is going to be 53
            except:
                return
            if pkt_dir == PKT_DIR_OUTGOING and packet.dst_port == 53:
                try:
                    result = self.parse_dns(pkt, start_trans_header + 8)
                    if result != None:
                        packet.dns_query = result
                        packet.is_DNS = True
                except Exception, e:
                    return
        elif packet.protocol == "icmp":
            try:
                packet.icmp_type = self.get_icmp_type(pkt, start_trans_header)
            except:
                return
        else:
            self.send_pkt(pkt_dir, pkt)
            return
        verdict = self.fw_rules.check_rules(packet, pkt_dir)
        if verdict == "pass":
            self.send_pkt(pkt_dir, pkt)


        return

    #sends packet to respected location
    def send_pkt(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    #returns a big endian version of pkt
    def ip_header_length(self, pkt):
        byte0 = pkt[0]
        unpacked_byte = struct.unpack("!B", byte0)[0]
        header_len = unpacked_byte & 0x0F
        return header_len

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


        

