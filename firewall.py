#!/usr/bin/env python        
import socket, struct, firewall_rules, packet, packet_service, log_handler
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
        self.log_handler = log_handler.Log_Handler()

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        packet = self.packet_service.data_to_packet(pkt, pkt_dir)
        if pkt_dir == PKT_DIR_OUTGOING and packet.is_AAAA == True:
            return
        verdict = self.fw_rules.check_rules(packet, pkt_dir)
        #print packet.http_contents == ""
        if verdict == "pass":
            #print "sending here!!"
            #if its not the right seq number, drop it
            #if it is an unmatching response, drop it
            #else, send it
            #log i
            if pkt_dir == PKT_DIR_INCOMING:
                ext_port = packet.src_port
                ext_ip = packet.src_ip
            else:
                ext_port = packet.dst_port
                ext_ip = packet.dest_ip

            log_contents = None
            sub_verdict = "pass"
            if (packet.protocol == "tcp") and (ext_port == 80):
                if packet.http_contents_string ==  "":
                    jack_shit = 1 # this does jack shit
                else:
                    try:
                    	tup = self.log_handler.handle_log(packet, pkt_dir)
                        log_contents = tup[0]
                        sub_verdict = tup[1]
                    except Exception, e:
                        print e
                        return


            if log_contents != None:
                try:
                   self.fw_rules.check_http(packet, ext_ip)
                except:
                   return
            if sub_verdict == "pass":
                self.send_pkt(pkt_dir, pkt)
            
        elif verdict == "deny" or verdict == "drop":
            ## ADD rule about syn
            rst_pkt = self.packet_service.packet_to_data(packet)
            if pkt_dir == PKT_DIR_OUTGOING:
            	self.send_pkt(PKT_DIR_INCOMING, rst_pkt)
            return
        else:
            self.send_pkt(pkt_dir, pkt)
        return


    #sends packet to respected location
    def send_pkt(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)



        

