
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

		if "" in response_lines:
			for response_line in response_lines:
				if self.response_complete:
					pass
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
		request_lines = temp_buff.lower().split("\r\n")

		if "\r\n\r\n" in temp_buff:
			print request_lines
			for request_line in request_lines:
				if self.request_complete:
					pass
				else:
					if request_line == "":
						self.request_complete = True
					else:
						self.current_request.append(request_line)
		else:
			self.request_buffer = temp_buff



buff = Log_Buffer()
buff.handle_request("GET / HTTP/1.1\r\nHost: google.co")
buff.handle_request("m\r\n")
buff.handle_request("User-Agent: Web-sniffer/1.0.46 (+h")
buff.handle_request("ttp://web-sniffer.net/\r")
buff.handle_request("\n")
buff.handle_request("Accept-Encoding: gzip\r\n")
print "is complete?", buff.request_complete
buff.handle_request("Accept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7\r\nCache-Control: no-cache\r\n")
buff.handle_request("\r\n")
print "is complete?", buff.request_complete
print "contents: ", buff.current_request
print "buffer: ", buff.request_buffer

x = "GET / HTTP/1.1\r\nHost: google.co" + "m\r\n"





