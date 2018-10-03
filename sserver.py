import socket, os, ssl, binascii, struct, json, argparse, sys
from CGA import *
from Crypto.Cipher import AES
from Crypto import Random
import base64



IP = "127.0.0.1"
hostname = "manufacturer.com"
PORT = 7890

secret128bit = b'akjds09podakdpoa'

class Server(object):
	def __init__(self, ip, port, mode):
		self.mode = mode
		self.ip = ip
		self.port = port

		self.threads = []
		self.mainLoop()

	def handleTCP(self):
		# Setting up TCP port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((self.ip,self.port))
		self.sock.listen(10)
		
		self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		self.context.options &= ~ssl.OP_SINGLE_ECDH_USE
		self.context.load_cert_chain("keys/" + hostname + '.crt', "keys/" + hostname + '.pem')

		print("[*INFO] TCP Server running on %s:%s" % (self.ip,self.port))
		with self.context.wrap_socket(self.sock, server_side=True) as ssock:
			while True:
				try:
					client_ssock, addr = ssock.accept()
					self.manageClient(client_ssock, addr)
				except KeyboardInterrupt:
					self.shutdown()

	def handleUDP(self):
		#Setting up UDP port
		self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.udp_sock.bind(((self.ip,self.port)))
		print("[*INFO] UDP Server running on %s:%s" % (self.ip,self.port))
		while True:
			try:
				data, addr = self.udp_sock.recvfrom(4092)
				if len(data) == 0:
					return
				data = json.loads(data.decode("utf-8"))
				print("[CLIENT] %s:%s -> %s" % (addr[0], addr[1], data))
				if data[0] == "CGAgen":
						response, iv = self.generateCGA(data, addr, True)
						data_to_encrypt = json.dumps(response[0])
						#ENCRYPTING MESSAGE
						encryption_suite = AES.new(secret128bit, AES.MODE_CFB, iv)
						ciphertext = encryption_suite.encrypt(data_to_encrypt.encode("utf-8"))
						# base64 encoding
						#need a json like { 1 = <encrypted json with params and CGA>, 2 = iv}
						ciphertext = base64.b64encode(ciphertext).decode()
						response = json.dumps([[ciphertext],response[1]])

						self.udp_sock.sendto(response.encode("utf-8"), addr)
			except KeyboardInterrupt:
				self.shutdown()
			except Exception as e:
				print(e)

	def mainLoop(self):
		self.handleTCP() if self.mode == 1 else self.handleUDP()

	def shutdown(self):
		print("[Ctrl+C catched]. Gracefully shutting down..")			
		self.sock.close() if self.mode == 1 else self.udp_sock.close()
		exit(0)

	def shutdown_client_socket(self, client_ssock):
		client_ssock.close()
		print("[*INFO] Client socket closed")

	def manageClient(self, client_ssock, addr):
			print("[*INFO] client %s connected at port %s" % (addr[0], addr[1]))
			while True:
				try:
					#data = client_ssock.recv(int(dlength))
					data = client_ssock.recv(4092)
					if len(data) == 0: 	#connection closed by client
						self.shutdown_client_socket(client_ssock)
						return
					data = json.loads(data.decode("utf-8"))
					print("[CLIENT] %s:%s -> %s" % (addr[0], addr[1], data))
					if data[0] == "CGAgen":
						response = self.generateCGA(data, addr)
						client_ssock.send(response.encode("utf-8"))
				except struct.error as se:
					self.shutdown_client_socket(client_ssock)
					return
				except KeyboardInterrupt as ke:
					client_ssock.close()
					self.shutdown()
	
	# return cga and parameters
	def generateCGA(self, data, addr_info, sym=False):
		public_key = open("keys/devicea.test.pub.der","rb").read()

		#client should send a RouterSolicitation message ?
		#Prefix must be given by a RouterAdvertisement message back..
		#(addr,parameters) = genCGA(1, public_key)  #lets assume extFields = 0 or null
		prefix = data[1]

		(addr,parameters) = genCGA(1, public_key, prefix) if len(prefix)>1 else genCGA(1,public_key)
		print("[CLIENT] %s:%s -> GENERATED CGA: %s" % (addr_info[0], addr_info[1], addr) )
		
		#prepare params for json
		params = unformat_parameters(parameters)
		#TODO maybe separate parameters from addr and iv in json
		params.append(addr)
		#ADD Initialization Vector

		if sym:
			r = Random.new().read(16)
			iv = binascii.hexlify(r).decode("utf-8")
			#print("[*CRYPTO]RANDOM IV: %s" % r)

			response = []
			response.append(params)
			response.append([iv])
			return response, r
		else:
			params = json.dumps(params)

		return params


if __name__ == '__main__':

	parser = argparse.ArgumentParser(usage= sys.argv[0]+ ' -p <u|t> --port <port>',
		description="Server for CGA offloading.\n")
	parser.add_argument("-p", action="store", default='u', help='Protocol to use, t for TCP, u for udp')
	parser.add_argument("--port", type=int, action='store', default=PORT , help='1 = local generation, 2 = offloaded generation')
	parser.add_argument("-i", action='store', default='127.0.0.1', help="Set the ip where the server is listening, default 127.0.0.1")

	args = parser.parse_args()

	proto = args.p
	if proto is not "t" and proto is not "u":
		parser.print_help()
		exit(1)
	port = args.port
	srv_ip = args.i
	#1 tcp, 2 udp
	mode = 1 if proto == "t" else 2
	
	try:
		server = Server(srv_ip, port, mode)
	except socket.error as err:
		print("SocketError: %s" % str(err))
