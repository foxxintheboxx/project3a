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



class Packet(object):
    def __init__(self):
        #IP HEADER
        self.total_length = None
        self.frag_offset = None
        self.ip_flags = None
        self.src_ip = None
        self.dest_ip = None
        self.ip_id = None
        self.ip_header_length = None


        #TRANSPORT
        self.src_port = None
        self.dst_port = None
        self.seq_num = None #TCP
        self.trans_length = None 
        self.window = 1 #TCP
        self.syn = False
        self.ack = False
        self.fin = False
        self.tcp_header_length = None

        self.icmp_type = None 
        self.protocol = "unknown"

        self.dir = None

        self.http_contents_string = ""
        self.http_contents = None

        #DNS FIELDS
        self.dns_query = None
        self.is_DNS = False
        self.dns_question_bytes = None
        self.qname_bytes = None
        self.dns_id = None
        self.is_AAAA = False
        self.dns_opcode_plus = None



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

class FireWall_Rules(object):

    def __init__(self, rules_str):
        self.rule_dictionary = self.ingest_rules(rules_str)
        for key, rules in self.rule_dictionary.iteritems():
            for rule in rules:
                rule.parent = self

    #@pkt Packet class object
    #@dir either PKT_DIR_INCOMING, PKT_DIR_OUTGOING
    #@return True or False
    def check_rules(self, pkt, dir):
        #depending on packet type
        # #
        # if pkt.syn == False:
        #     return "pass"
        ext_port = None
        ext_ip = None
        verdict = "pass"
        if dir == PKT_DIR_OUTGOING:
            ext_port = pkt.dst_port
            ext_ip = pkt.dest_ip
        else: 
            ext_port = pkt.src_port
            ext_ip = pkt.src_ip

        if pkt.protocol not in self.rule_dictionary:
            return "pass"
        rule_list = self.rule_dictionary[pkt.protocol]

        for rule in rule_list:
            condition1 = False
            condition2 = False
            if rule.protocol != "dns":
                if rule.check_port(ext_port):
                    condition1 = True
                
                
                if rule.check_ip(ext_ip):
                    condition2 = True
                if condition1 and condition2:
                    verdict = rule.verdict
            else: #rule is a DNS_rule
                if pkt.is_DNS and rule.check_dns_query(pkt.dns_query):
                    
                    verdict = rule.verdict
        return verdict


    def check_http(self, packet_class, ext_ip):
        packet_http = packet_class.http_contents
        #pull out the http contents class
        if packet_hostname == None:
            packet_hostname = int2ip(ext_ip)
        else:
            packet_hostname = packet_http.hostname
        #pull out the httpcontents.hostname
        #check the hostname against the rules we have
        if "http" not in self.rule_dictionary:
            return
        for rule in self.rule_dictionary["http"]:
            if rule.check_http_rule(packet_hostname):

                packet_http.writeback()
                break
        #if it passes, call the http_contents.writeback method

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
            if line == '' or line[0] == "%":
                continue
            elements = line.split(" ")
            protocol = elements[1].lower()
            rule = None
            if protocol == "dns":
                protocol = "udp"
                #do dns things
                rule = self.DNS_Rule()
                rule.verdict = elements[0].lower()
                rule.dns_query = elements[2].split(".")
            elif protocol == "http":
                rule = self.HTTP_Rule(elements[2].lower())

            else:
                rule = self.Rule(protocol)
                rule.set_verdict(elements[0].lower())
                rule.set_ip_rule(elements[2])
                rule.set_port_rule(elements[3])
            if protocol not in ret_dict:
                ret_dict[protocol] = []
          
            ret_dict[protocol].append(rule)

        return ret_dict

    class HTTP_Rule(object):
        def __init__(self, hostname):
            self.hostname = hostname
            
        def check_http_rule(self, pkt_hostname):
            rev_hostname = pkt_hostname[::-1]
            self_hostname = self.hostname[::-1]
            index = 0
            for el in rev_hostname:
                if index < len(self_hostname) and el == self_hostname[index]:
                    index += 1
                    continue
                elif index < len(self_hostname) and self_hostname[index] == "*":
                    break
                else:
                    return False
            return True if len(self_hostname) == len(rev_hostname) else False

    class DNS_Rule(object):
        def __init__(self):
            self.verdict = None
            self.dns_query = None
            self.protocol = "dns"
            #self.dns_query = ["*", "google", "com"] -> ["com", "google", "www"]
            #pkt_dns = ["www", "google", "com"] -> ["com", "google"]
        def check_dns_query(self, pkt_dns):
            rev_pkt_dns = pkt_dns[::-1]
            dns_query = self.dns_query[::-1]
            index = 0

            for el in rev_pkt_dns:
                if index < len(dns_query) and el == dns_query[index]:
                    index += 1
                    continue
                elif index < len(dns_query) and dns_query[index] == "*":
                    return True
                else:
                    return False
            if len(rev_pkt_dns) != len(dns_query):
              return False
            return True

    class Rule(object):
        def __init__(self, protocol):
            self.parent = None
            self.verdict = None
            self.protocol = protocol
            self.ext_port_case = None
            self.ext_ip_case = None
            self.port_rule = None
            self.ip_rule = None
            
        def set_verdict(self, verd):
            self.verdict = verd

        def set_port_rule(self,ext_port_str):
            if ext_port_str.lower() == "any":
                    self.ext_port_case = 0
            elif "-" in ext_port_str:
                self.port_rule = [int(i) for i in ext_port_str.split("-")]
                self.ext_port_case = 2
            else:
                self.port_rule = int(ext_port_str)
                self.ext_port_case = 1

        def set_ip_rule(self,ext_ip_str):
            if ext_ip_str.lower() == "any":
                self.ext_ip_case = 0
            elif "/" in ext_ip_str:
                self.ext_ip_case = 3
                elements = ext_ip_str.split("/")
                #turns "1.1.1.0/28" into [16843008,28]
                self.ip_rule = [ip2int(elements[0]),int(elements[1])]
            elif "." in ext_ip_str:
                self.ext_ip_case = 2
                self.ip_rule = ip2int(ext_ip_str)
            else:
                self.ip_rule = ext_ip_str
                self.ext_ip_case = 1


        def check_port(self, pkt_port):
            #could be any
            
            if self.ext_port_case == 0:
                return True
            elif self.ext_port_case == 1:
                
                return (pkt_port == self.port_rule)
            else:
                return ((pkt_port >= self.port_rule[0]) and (pkt_port <= self.port_rule[1]))

        #@should be receiving pkt_ip as integer
        def check_ip(self, pkt_ip):
           
            if self.ext_ip_case == 0:
                return True
            elif self.ext_ip_case == 1:
                
                response = self.parent.get_country(pkt_ip)
                if response == None:
                   return False
                return self.ip_rule.lower() == response.lower()
            elif self.ext_ip_case == 2:
                
                return self.ip_rule == pkt_ip
            else:
                ## figure out difference between 32 and second
                difference = 32 - self.ip_rule[1]
                ## bit shift both right that many
                return ((pkt_ip >> difference) == (self.ip_rule[0] >> difference))

def ip2int(ip):
    try:
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!I", packedIP)[0]
    except Exception, e:
        return None

def int2ip(addr):                                                               
    return socket.inet_ntoa(struct.pack("!I", addr))



class Log_Handler(object):

    #will take in a list of lines for the rules
    def __init__(self):
        self.log_dict = {}
    class Log_Buffer():
        def __init__(self):
            self.key = None

            #array of lines of current request
            #will be complete header when *_complete is true
            self.current_request = []
            self.current_response = []

            self.current_request_index = None
            self.current_response_index = None

            #store the partial lines, before get the entirety of it
            self.request_buffer = ""
            self.response_buffer = ""

            self.request_complete = False
            self.response_complete = False

        #purpose is because you do not want to buffer the whole response body if you already have all the header fields you need
        #so you should continue to get the buffer, until you reach a new line
        #once you reach a new line, then the header is complete
        #so you change that field, you will continue to buffer partial headers until you reach the end of the body
        def handle_response(self, partial_response_string):
            if self.response_complete:
                return False

            temp_buff = self.response_buffer + partial_response_string
            response_lines = partial_response_string.lower().split("\r\n")

            if "\r\n\r\n" in temp_buff:
                for response_line in response_lines:
                    if self.response_complete:
                        break
                    else:
                        if response_line == "":
                            self.response_complete = True
                        else:
                            self.current_response.append(response_line)
                return True
            else:
                return False

        def handle_request(self, partial_request_string):
            if self.request_complete:
                return

            temp_buff = self.request_buffer + partial_request_string
            request_lines = temp_buff.split("\r\n")

            if "\r\n\r\n" in temp_buff:

                for request_line in request_lines:
                    if self.request_complete:
                        break
                    else:
                        if request_line == "":
                            self.request_complete = True
                        else:
                            self.current_request.append(request_line)
            else:
                self.request_buffer = temp_buff


    #should only handle actual tcp packets, if direction is incoming it must be a response vise versa
    #responses should only be passed through if we have a request for it
    #sequence number should be checked before handle_log is called
    def handle_log(self, pkt, direction):

        #if outgoing --> request
        retval = [None, "pass"]
        if direction == PKT_DIR_OUTGOING:
            key = (pkt.dest_ip, pkt.src_port)

            #if its a new request
            if key not in self.log_dict:
                buff = self.create_entry(key, pkt)
                    buff.current_request_index = pkt.seq_num
            else:   
                buff = self.log_dict[key]
                                
                 
                    exp = buff.current_request_index
                    if exp != pkt.seq_num:
                       if exp < pkt.seq_num:
                          retval[1] = "drop"
                          return
                    #on track so increment
                    buff.current_request_index = pkt.seq_num + pkt.total_length - pkt.ip_header_length - pkt.tcp_header_length % (0xffffffff - 1)
            buff.handle_request(pkt.http_contents_string)

            #next index = seqno + contentlength - ip header - tcp header
            
        else:

            key = (pkt.src_ip, pkt.dst_port)

            if key not in self.log_dict:
                return [None, "pass"]
            buff = self.log_dict[key]
                        if buff.current_response_index == None:
                            buff.current_response_index = pkt.seq_num

                        if buff.current_response_index != pkt.seq_num:
                if buff.current_response_index < pkt.seq_num:
                   retval[1] = "drop"
                                return retval
            http_complete = buff.handle_response(pkt.http_contents_string)
            buff.current_response_index = pkt.seq_num + pkt.total_length - pkt.ip_header_length - pkt.tcp_header_length % (0xffffffff - 1)
            if http_complete:
                packet = self.complete_http(key, pkt)
                retval[0] = packet
                                return retval

        return retval

    def create_entry(self, key, packet):
            buff = self.Log_Buffer()
            buff.key = key
            self.log_dict[key] = buff
            return buff


    #to be called outside log handler to tell whether a response should be passed through or dropped
    #!! dont think should be used
    def have_request(self, src_ip, src_port):
        key = (source_ip, source_port)
        return key in self.current_requests

    #promote a complete request
    def promote_request(self, key):
        request_string = self.partial_requests.pop(key)
        partial_http_contents = self.parse_request(request_string)
        self.current_requests[key] = partial_http_contents

        self.partial_request_indexes.pop(key)

    #to write things back to the log once everthing is done
    #return the same packet with changed contents
    #called by
    def complete_http(self, key, pkt):
        log_buff = self.log_dict.pop(key)
        partial_http_contents = self.parse_request(log_buff.current_request)
        http_contents = self.parse_response(log_buff.current_response, partial_http_contents)
        pkt.http_contents = http_contents

        return pkt

    #to be called outside log handler to figure whether the packet should be passed or dropped
    def get_expected_request_index(self, dest_ip, source_port):
        key = (dest_ip, source_port)
                if key in self.log_dict:
           return self.log_dict[key].current_request_index

    def get_expected_response_index(self, src_ip, destination_port):
        key = (src_ip, destination_port)
                 
        return self.log_dict[key].current_response_index


    def parse_request(self, current_request):
        lines = current_request
        contents = self.Http_Contents()

        request_line = lines.pop(0).split(" ")
        contents.method = request_line[0]
        contents.path = request_line[1]
        contents.version = request_line[2]

        for line in lines:
            request_line = line.split(" ")
            if request_line == "":
                break
            elif str.lower(request_line[0]) == "host:":
                contents.hostname = request_line[1]

        return contents 

    def parse_response(self, current_response, http_contents):
        lines = current_response

        for line in lines:
            response_line = line.split(" ")
            #print "!!!!!!", response_line
            if response_line == " ":
                break
            elif str.lower(response_line[0]) == str.lower(http_contents.version):
                http_contents.statuscode = response_line[1]
            elif str.lower(response_line[0]) == "content-length:":
                http_contents.object_size = response_line[1]

        return http_contents



    class Http_Contents(object):
        def __init__(self):
            self.hostname = None
            self.method = None
            self.path = None
            self.version = None
            self.statuscode = None
            self.object_size = "-1" 


        def to_string(self):
            print "hostname: ", self.hostname
            print "method: ", self.method
            print "path: ", self.path
            print "version: ", self.version
            print "statuscode: ", self.statuscode
            print "object_size: ", self.object_size

        def writeback(self):
            with open("http.log", "a") as f:
                f.write(self.hostname)
                f.flush()
                f.write(" ")
                f.flush()
                f.write(self.method)
                f.flush()
                f.write(" ") 
                f.flush()
                f.write(self.path)
                f.flush()
                f.write(" ")
                f.flush()
                f.write(self.version)
                f.flush()
                f.write(" ")
                f.flush()
                f.write(self.statuscode)
                f.flush()
                f.write(" ")
                f.flush()
                f.write(self.object_size)
                f.flush()
                f.write("\n")
                f.flush()


