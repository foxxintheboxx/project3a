import packet
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING


class Log_Handler(object):

	def __init__(self):
		self.partial_requests = {}
		self.partial_request_indexes = {}
		self.current_requests = {}
		self.partial_responses = {}
		self.partial_responses_indexes = {}


	def 
	#should only handle actual tcp packets, if direction is incoming it must be a response vise versa
	#responses should only be passed through if we have a request for it
	def handle_log(self, pkt, direction):

		#if outgoing --> request
		if direction == PKT_DIR_OUTGOING:
			key = (destination_ip, src_port)



			if key in self.partial_requests:
				self.partial_request_indexes[key]+=1 
				self.partial_requests[key] += pkt.http_contents
			else:
				self.partial_request_indexes[key] = pkt.seq_num
				self.partial_requests[key] = pkt.http_contents

			if self.is_complete(self.partial_requests[key]):
				self.promote_request(key)

					


			#see if its in the request builder dictionary
		#if incoming --> response
		elif direction == PKT_DIR_INCOMING:
			key = (source_ip, dest_port)
			if key in self.partial_responses:
				self.partial_responses_indexes[key] += 1
				self.partial_responses[key] += pkt.http_contents
			else:
				self.partial_responses_indexes[key] = pkt.seq_num
				self.partial_responses[key] = pkt.http_contents

			if self.is_complete(self.partial_responses[key]):
				self.write_back(key)
			#check to see if it is the current requests
			#

	#to be called outside log handler to tell whether a response should be passed through or dropped
	def have_request(self, src_ip, src_port):
		key = (source_ip, source_port)
		return key in self.current_requests

	#promote a complete request
	def promote_request(self, key):
		self.current_requests[key] = self.partial_requests.pop(key)
		self.partial_request_indexes.pop(key)

	#to write things back to the log once everthing is done
	def write_back(key):
		self.current_requests.pop(key) 
		self.partial_responses.pop(key)
		self.partial_responses_indexes.pop(key)

	#to be called outside log handler to figure whether the packet should be passed or dropped
	def get_expected_request_index(self, dest_ip, dest_port):
		key = (dest_ip,dest_port)
		return self.partial_request_indexes[key] + 1

	def get_expected_response_index(self, src_ip, src_port):
		key = (src_ip,src_port)
		return self.partial_responses_indexes[key] + 1


	def handle_request(self, key, http_contents):
		pass


	def handle_response():
		pass

	#@param http_string should be the request string and response string concantenated together
	#@return an HTTP Contents instance
	def http_parser(self, http_string):
		lines = http_string.lower().split("\n")
		line_num = 0
		contents = self.Http_Contents()
		for line in lines:
			request_line_contents = line.split(" ")
			if len(request_line_contents) == 0:
				break

			#if payload, continue

			if request_line_contents[0] in ["post","get", "put","drop"]:
				contents.method = request_line_contents[0]
				contents.path = request_line_contents[1]
				contents.version = request_line_contents[2]

			elif request_line_contents[0] == "host:":
				contents.hostname = request_line_contents[1]

			elif request_line_contents[0] == "content-length:":
				contents.object_size = request_line_contents[1]

			elif "http" in request_line_contents[0]:
				contents.statuscode = request_line_contents[1]
		return contents




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

log_handler = Log_Handler()
request = "GET / HTTP/1.1\nHost: google.com\nUser-Agent: Web-sniffer/1.0.46 (+http://web-sniffer.net/\nAccept-Encoding: gzip\nAccept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7\nCache-Control: no-cache\nAccept-Language: de,en;q=0.7,en-us;q=0.3 \n \n"
response = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.google.com/\nContent-Type: text/html; charset=UTF-8\nDate: Mon, 18 Nov 2013 23:58:12 GMT\nExpires: Wed, 18 Dec 2013 23:58:12 GMT\nCache-Control: public, max-age=2 592000\nServer: gws\nContent-Length: 219\nX-XSS-Protection: 1; mode=block\nX-Frame-Options: SAMEORIGIN\nAlternate-Protocol: 80:quic"

log_handler.http_parser(request+response).to_string()
