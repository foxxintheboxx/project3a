#!/usr/bin/env python
        
import socket, struct
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config = None, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.geo_array = []
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






        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        print pkt 
        pass

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




