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
        self.packet_service = packet_service.Packet_Service() #parse and constructing

        with open(config['rule']) as file:
            rule_content = file.read()
        fw_rules = firewall_rules.FireWall_Rules(rule_content)

        self.fw_rules = fw_rules

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        packet = self.packet_service.data_to_packet(pkt, pkt_dir)
        verdict = self.fw_rules.check_rules(packet, pkt_dir)
        if verdict == "pass":
            self.send_pkt(pkt_dir, pkt)
        elif verdict == "deny":
            rst_pkt = self.packet_service.packet_to_data(packet)
            packet = self.packet_service.data_to_packet(pkt, pkt_dir)

            self.iface_ext.send_ip_packet(rst_pkt)
        return


    #sends packet to respected location
    def send_pkt(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)



        

