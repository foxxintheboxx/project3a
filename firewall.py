#!/usr/bin/env python
        
import socket, struct
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
#QD count == 1, QClass == 1, QTYPE == 1 (IPV4) QTYPE == 28 (IPV6) ,
#test dns throught

#1.1.1.1/0 is any
#ns -u send as udp
#empty rule --
# qnames  any where the asterick by itself 
# ipdb with just one entry and empty
# specific country
# 
# Ask about dropping dns malformed packets

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.geo_array = []
        self.rule_dict = dict()

        # TODO: Load the firewall rules (from rule_filename) here.
        # print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
        #         config['rule']


        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.

        with open("geoipdb.txt") as file:
            content = file.read()
            for line in content.split("\n"):
                elements = line.split(" ")
                if (len(elements) == 3):
                    g_node = GeoIPNode(elements[2], self.ip2int(elements[0]), self.ip2int(elements[1]))
                    self.geo_array.append(g_node)




        with open(config['rule']) as file:
            content = file.read()
            rule_dict = self.ingest_rules(content)



        # TODO: Also do some initialization if needed.
    #function to initialize the rules dictionary
    #input: the whole str contents of rules.conf
    #output, dictionary of proper form
        # i.e. {dns: [[verdict, domain],
        #             [vertict, domain]],
        #         tcp: [[verdict, ip1, ip2]]
        #         }
    def ingest_rules(self,rules_str):
        ret_dict = dict()

        for line in rules_str.split("\n"):
            if line == '':
                continue
            contents = []
            elements = line.split(" ")
            verdict = elements[0]
            protocol = elements[1]
            contents = []

            if protocol == "dns":
                #do dns things
                contents =[verdict, elements[2]]
            else:
                external_ip = elements[2]
                external_port = elements[3]

            if protocol not in ret_dict:
                ret_dict[protocol] = []

            ret_dict[protocol].append(contents)

        return ret_dict




    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        packet = Packet()
        try:
            print("handling")
            header_len = self.ip_header_length(pkt)
            if header_len < 5:
                return
            proto_dec = self.get_protocol(pkt)
            packet.set_protocol(proto_dec)
            src = self.get_src(pkt)
            dst = self.get_dst(pkt)

            packet.src_ip = src
            packet.dest_ip = dst

            start_trans_header = header_len * 4

            if packet.protocol == "TCP":
                packet.src_port = self.get_src_port_std(pkt, start_trans_header)
                packet.dst_port = self.get_dst_port_std(pkt, start_trans_header)

            elif packet.protocol == "UDP":
                packet.src_port = self.get_src_port_std(pkt, start_trans_header)
                packet.dst_port = self.get_dst_port_std(pkt, start_trans_header)
                ## UDP and the destination port is going to be 53

                if pkt_dir == PKT_DIR_OUTGOING and packet.dst_port == 53:
                    try:
                        result = self.parse_dns(pkt, start_trans_header + 8)
                        if result != None:
                            packet.dns_query = result
                            packet.is_DNS = True
                    except Exception, e:
                        print e
            elif packet.protocol == "ICMP":
                packet.icmp_type = self.get_icmp_type(pkt, start_trans_header)
            else:
                self.send_pkt(pkt_dir, pkt)

        except Exception, e:
            print e , " 1"
            return 
        print "Source IP: " + packet.src_ip + ", ",
        print "Source port: " + packet.src_port + ", ", 
        print "Destination IP: " + packet.dst_ip + ", ",
        print "Destination Port: " + packet.dst_port + ", ",
        print "Length: " + --length-- ", ",
        print "Protocol: " + packet.protocol + ", "
        if packet.is_DNS:
            print "DNS Address: " + packet.dns_query + ", "
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
        unpacked_byte = struct.unpack("!HH", address_byte)[0]
        return unpacked_byte


    def get_dst(self, pkt):
        address_byte = pkt[16:20]
        unpacked_byte = struct.unpack("!HH", address_byte)[0]
        return unpacked_byte

    #@packet is the data structure for a packet with our necessary contents
    #@return either true or false for whether the packet passed our rule check
    #packet.protocol should be either udp,tcp,icmp
    # packet.Port should be against "any", a single port(int), or a range tuple([2000-3000])
    # packetIp should be checking against "any", a single IP(1.1.1.1), a 2 string country("AU"), an IP prefix tuple(["1.1.1.0",18])
    def rule_check(self, packet):
        protocol = packet.protocol
        port = packet.port
        ip = packet.dst_port
        dns_query = packet.dns_query
        verdict = None

        country = self.get_country(packet.dst_port)

        #do run through of dictionary based rules
            #for each rule
                #do comparisons against the IP and Port of the rule
                #find out which type of IP rule to use based on what rule[1]
                    #check to see if there is a match
                #find out which type of 
        #if dns, then additionally do DNS rule checks second

        if  packet.is_DNS:
            #do dns things
            pass
        else:
            country = self.get_country(ip)
            condition1 = False
            condition2 = False
            #need to go through the dictionary and check to see what the most recent match is
            for rule in self.rule_dict[protocol]:
                rule_ip = rule[1]
                if rule_ip == 'any':
                    condition1 = True
                elif type(rule_ip) is str:
                    if rule_ip == ip:
                        condition1 = True
                else:
                    condition1 = False
                rule_port = rule[2]
                if rule_port == 'any':
                    condition2 = True
                # elif :
                else:
                    condition2 = False
                if condition1 and condition2:
                    verdict = rule_ip[0]

        if verdict == "pass":
            return True
        else:
            return False

    #return int
    def ip2int(self, ip):
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!I", packedIP)[0]

    def bst_geo_array(self, int_ip, min_index, max_index):

        if min_index == (max_index - 1):
            return self.geo_array[min_index]
        total = min_index + max_index
        mid = 0
        if total % 2 != 0:
            mid = total / 2 + 1
        else:
            mid = total / 2

        g_node = self.geo_array[mid]
        if g_node.min_ip > int_ip:
            # go down
            return self.bst_geo_array(int_ip, min_index, mid)
        else:
            return self.bst_geo_array(int_ip, mid, max_index)
            #go up

    def parse_dns(self, pkt, offset):
        dns_header = pkt[offset:offset+12]
        qd_count_byte = dns_header[4:6]
        qd_count = struct.unpack("!H", qd_count_byte)[0]
        if qd_count != 1:
            return None
        offset = offset + 12

        question = pkt[offset: offset + 6]
        q_name_byte = question[0 : 2]
        q_type_byte = question[2 : 4]
        q_class_byte = question[4 : 6]

        q_name = struct.unpack("!H", q_name_byte)[0]
        q_type = struct.unpack("!H", q_type_byte)[0]
        q_class = struct.unpack("!H", q_class_byte)[0]

        if q_type != 28 or q_type != 1:
            return None

        if q_class != 1:
            return None

        return q_name


        






'''
A GeoIPNode is an object holding the a two character string @param country.
@param min -- an int corresponding to the smaller ip
@param max -- an int corresponding to the larger ip
'''
class GeoIPNode(object):
    def __init__(self, country, min, max):
        self.min_ip = min
        self.max_ip = max
        self.country = country

    def in_range(self, ip_int):
        if ip_int < self.min_ip or ip_int > self.max_ip:
            return False
        return True


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
            self.protocol = "UDP"
        elif decimal_value == 1:
            self.protocol = "ICMP"
        elif decimal_value == 6:
            self.protocol = "TCP"

    def set_src_port(self, decimal_value):
        self.src_port = decimal_value

    def set_dst_port(self, decimal_value):
        self.dst_port = decimal_value



