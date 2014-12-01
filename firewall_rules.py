from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
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
        verdict = "drop"
        if pkt == PKT_DIR_OUTGOING:
            ext_port = pkt.dest_port
            ext_ip = pkt.dst_ip
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


    def check_http(self, packet_class):
        packet_http = packet_class.http_contents
        print "checking http"
        #pull out the http contents class
        packet_hostname = packet_http.hostname
        #pull out the httpcontents.hostname
        #check the hostname against the rules we have
        for rule in self.rule_dictionary["http"]:
            if rule.check_http_rule(packet_hostname):
                print "host passed: ", packet_hostname
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
            return True

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
                    break
                else:
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
