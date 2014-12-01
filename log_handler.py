import packet
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING


class Log_Handler(object):

	#will take in a list of lines for the rules
	def __init__(self):
		self.log_dict = {}

	class Log_Buffer():
		def __init__():
			self.key = None

			self.current_request = []
			self.current_response = []

			self.current_request_index = None
			self.current_response_index = None

			self.request_buffer = ""
			self.response_buffer = ""

			self.request_complete = False
			self.response_complete = False

		#purpose is because you do not want to buffer the whole response body if you already have all the header fields you need
		#so you should continue to get the buffer, until you reach a new line
		#once you reach a new line, then the header is complete
		#so you change that field, you will continue to buffer partial headers until you reach the end of the body
		def handle_response(self, partial_response_string):
			index = 0
			response_lines = partial_response_string.lower().split("\n")
			return_value = False
			for response_line in response_lines:
				if self.response_complete:
					pass
				else:
					if response_line = "":
						self.response_complete = True
						return_value = True
					else:
						self.current_response.append(response_line)

			return return_value

		def handle_request(self, partial_request_string):
			request_lines = partial_request_string.lower().split("\n")
			for request_line in request_lines:
				if self.request_complete:
					pass
				else:
					if resquest_line = "":
						self.request_complete = True
					else:
						self.current_request.append(request_line)




	#should only handle actual tcp packets, if direction is incoming it must be a response vise versa
	#responses should only be passed through if we have a request for it
	#sequence number should be checked before handle_log is called
	def handle_log(self, pkt, direction):

		#if outgoing --> request

		if direction == PKT_DIR_OUTGOING:
			key = (pkt.destination_ip, pkt.src_port)

			if key not in self.log_dict:
				buff = self.Log_Buffer()
				buff.key = key
			else:	
				buff = self.log_dict[key]

			buff.handle_request(pkt.http_contents_string)

			buff.current_request_index = pkt.seq_num

		else:
			key = (source_ip, dest_port)

			if key not in self.log_dict:
				print "i think something went awry"
				continue
			else:
				buff = self.log_dict[key]

			http_complete = buff.handle_response(plt.http_contents_string)
			buff.current_response_index = pkt.seq_num
			if http_compete:
				packet = self.writeback(key, pkt)
				print "Completed HTTP Piece!"
				return packet

		return None



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
	def write_back(self, key, pkt):
		log_buff = log_dict.pop(key)
		partial_http_contents = self.parse_request(log_buff.current_request)
		http_contents = self.parse_response(log_buff.current_response, partial_http_contents)
		pkt.http_contents = http_contents

		return pkt

	#to be called outside log handler to figure whether the packet should be passed or dropped
	def get_expected_request_index(self, dest_ip, source_port):
		key = (dest_ip, source_port)
		return self.log_dict[key].current_request_index + 1

	def get_expected_response_index(self, src_ip, destination_port):
		key = (src_ip, destination_port)
		return self.log_dict[key].current_response_index + 1


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
			elif request_line[0] == "host:":
				contents.hostname = request_line[1]

		return contents 

	def parse_response(self, current_response, http_contents):
		lines = current_response

		for line in lines:
			response_line = lines.split(" ")
			if response_line == " ":
				break
			elif response_line[0] == http_contents.version:
				http_contents.statuscode = response_line[1]
			elif response_line[0] == "content-length":
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




	def if_complete(self, http_string):
		#check to see if you reached the null string
		pass



	class Http_Contents(object):
		def __init__(self):
			self.hostname = None
			self.method = None
			self.path = None
			self.version = None
			self.statuscode = None
			self.object_size = -1 


		def to_string(self):
			print "hostname: ", self.hostname
			print "method: ", self.method
			print "path: ", self.path
			print "version: ", self.version
			print "statuscode: ", self.statuscode
			print "object_size: ", self.object_size

		def writeback(self):
			f = open("http.log","w")
			f.write(self.hostname + " " + self.method + " " + self.path + " " + self.version + " " + self.statuscode + " " + self.object_size)

log_handler = Log_Handler()
request = "GET / HTTP/1.1\nHost: google.com\nUser-Agent: Web-sniffer/1.0.46 (+http://web-sniffer.net/\nAccept-Encoding: gzip\nAccept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7\nCache-Control: no-cache\nAccept-Language: de,en;q=0.7,en-us;q=0.3 \n \n"
response = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.google.com/\nContent-Type: text/html; charset=UTF-8\nDate: Mon, 18 Nov 2013 23:58:12 GMT\nExpires: Wed, 18 Dec 2013 23:58:12 GMT\nCache-Control: public, max-age=2 592000\nServer: gws\nContent-Length: 219\nX-XSS-Protection: 1; mode=block\nX-Frame-Options: SAMEORIGIN\nAlternate-Protocol: 80:quic"

