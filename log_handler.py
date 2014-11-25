import packet
class log_handler(obj):

	def __init__(self):



	def handle_log(packet, dir):
		source_ip = packet.src_ip
		destination_ip = packet.dest_ip
		source_port = packet.src_port
		destination_ip = packet.dest_port
		protocol = "tcp"

		key = (source_ip, destination_ip, source_port, destination_ip, protocol)



	class http_contents(obj):
		def __init__(self):
			self.hostname = None
			self.method = None
			self.path = None
			self.version = None
			self.statuscode = None
			self.object_size = -1 