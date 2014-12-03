#!/usr/bin/env python        
import socket, struct, firewall_rules, packet, packet_service, log_handler
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import random

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
        self.log_handler = log_handler.Log_Handler()

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        print "\n\n\n\n"
        packet = self.packet_service.data_to_packet(pkt, pkt_dir)
        # number = random.randint(1,6)
        # if number == 3:
        #     return
        if packet.is_DNS and packet.dns_qtype == 28:
            return
        verdict = self.fw_rules.check_rules(packet, pkt_dir)
        #print packet.http_contents == ""

        if verdict == "pass":
            print "packet sending"
            #if its not the right seq number, drop it
            #if it is an unmatching response, drop it
            #else, send it
            #log i
            if pkt_dir == PKT_DIR_INCOMING:
                ext_port = packet.src_port
            else:
                ext_port = packet.dst_port

            if (packet.protocol == "tcp") and (ext_port == 80):

                if pkt_dir == PKT_DIR_OUTGOING:
                    int_port = packet.src_port
                    ext_ip = packet.dest_ip
                else:
                    int_port = packet.dst_port
                    ext_ip = packet.src_ip
                key = (ext_ip,int_port)

                if packet.syn:
                    #create a dictionary entry
                    if packet.ack:
                        self.log_handler.log_dict[key].current_response_index = packet.seq_num + 1
                    else:
                        print "got the syn!"
                        print "syn number: ", packet.seq_num
                        self.log_handler.create_entry(key, packet)
                else:
                    
                    #if its empty and not a fin
                    if packet.http_contents_string == "" and not packet.fin:
                        pass
                    else:
                        #check the sequence number
                        if pkt_dir == PKT_DIR_OUTGOING:
                            print "request packet"
                            expected_sequence = self.log_handler.get_expected_request_index(key)
                        else:
                            print "response packet"
                            if key not in self.log_handler.log_dict:
                                self.send_pkt(pkt_dir, pkt)
                                return
                            else:
                                expected_sequence = self.log_handler.get_expected_response_index(key)
                                
                        print "packet sequence number: ", packet.seq_num
                        print "expected sequence number: ", expected_sequence

                        if expected_sequence != packet.seq_num:
                            return
                        elif packet.fin and packet.ack:
                            print "got a fin ack!"
                            self.log_handler.remove_entry(key)
                        else:
                            #got a data packet of some sort
                            log_contents = self.log_handler.handle_log(packet,pkt_dir)
                            if log_contents != None:
                                self.fw_rules.check_http(packet, ext_ip)
            self.send_pkt(pkt_dir, pkt)

        elif verdict == "deny":
            ## ADD rule about syn
            rst_pkt = self.packet_service.packet_to_data(packet)
            self.send_pkt(PKT_DIR_INCOMING, rst_pkt)
        else:
            self.send_pkt(pkt_dir, pkt)
        return


    #sends packet to respected location
    def send_pkt(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)



        

