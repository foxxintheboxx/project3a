import packet
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING


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

		if direction == PKT_DIR_OUTGOING:
			key = (pkt.dest_ip, pkt.src_port)

			#if its a new request
			if key not in self.log_dict:
				buff = self.create_entry(key, pkt)
                                
			else:	
				buff = self.log_dict[key]
                                exp = buff.current_request_index
                                buff.current_request_index = pkt.seq_num + pkt.total_length - pkt.ip_header_length - pkt.tcp_header_length
                        exp = buff.current_request_index

                        #if exp != pkt.seq_num:
                        #   return None
                        #on track so increment
                        buff.current_request_index = pkt.seq_num + pkt.total_length - pkt.ip_header_length - pkt.tcp_header_length
			buff.handle_request(pkt.http_contents_string)

			#next index = seqno + contentlength - ip header - tcp header
			

		else:

                        
			key = (pkt.src_ip, pkt.dst_port)

			if key not in self.log_dict:

				return None 
			buff = self.log_dict[key]
                        if buff.current_response_index == None:
                        	buff.current_response_index = pkt.seq_num

			http_complete = buff.handle_response(pkt.http_contents_string)
			buff.current_response_index = pkt.seq_num + pkt.total_length - pkt.ip_header_length - pkt.tcp_header_length
			if http_complete:
				packet = self.complete_http(key, pkt)
				return packet

		return None

	def create_entry(self, key, packet):
			buff = self.Log_Buffer()
			buff.key = key
			self.log_dict[key] = buff
			buff.current_request_index = packet.seq_num
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



	#@param http_string should be the request string and response string concantenated together
	#@return an HTTP Contents instance
	# def http_parser(self, http_string):
	# 	lines = http_string.lower().split("\n")
	# 	line_num = 0
	# 	contents = self.Http_Contents()
	# 	for line in lines:
	# 		request_line_contents = line.split(" ")
	# 		if len(request_line_contents) == 0:
	# 			break

	# 		#if payload, continue

	# 		if request_line_contents[0] in ["post","get", "put","drop"]:
	# 			contents.method = request_line_contents[0]
	# 			contents.path = request_line_contents[1]
	# 			contents.version = request_line_contents[2]

	# 		elif request_line_contents[0] == "host:":
	# 			contents.hostname = request_line_contents[1]

	# 		elif request_line_contents[0] == "content-length:":
	# 			contents.object_size = request_line_contents[1]

	# 		elif "http" in request_line_contents[0]:
	# 			contents.statuscode = request_line_contents[1]
	# 	return contents



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
				f.write(" ")
				f.write(self.method)
				f.write(" ") 
				f.write(self.path)
				f.write(" ")
				f.write(self.version)
				f.write(" ")
				f.write(self.statuscode)
				f.write(" ")
				f.write(self.object_size)
				f.write("\n")

log_handler = Log_Handler()
request = "GET / HTTP/1.1\nHost: google.com\nUser-Agent: Web-sniffer/1.0.46 (+http://web-sniffer.net/\nAccept-Encoding: gzip\nAccept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7\nCache-Control: no-cache\nAccept-Language: de,en;q=0.7,en-us;q=0.3 \n \n"
response = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.google.com/\nContent-Type: text/html; charset=UTF-8\nDate: Mon, 18 Nov 2013 23:58:12 GMT\nExpires: Wed, 18 Dec 2013 23:58:12 GMT\nCache-Control: public, max-age=2 592000\nServer: gws\nContent-Length: 219\nX-XSS-Protection: 1; mode=block\nX-Frame-Options: SAMEORIGIN\nAlternate-Protocol: 80:quic"

