import socket, os, ssl, binascii, struct, json
from CGA import *

IP = "127.0.0.1"
hostname = "manufacturer.com"
PORT = 7890

class Server(object):
	def __init__(self, ip, port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((ip,port))
		self.sock.listen(10)
		
		self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		self.context.options &= ~ssl.OP_SINGLE_ECDH_USE
		self.context.load_cert_chain("keys/" + hostname + '.crt', "keys/" + hostname + '.pem')

		self.mainLoop()

	def mainLoop(self):
		with self.context.wrap_socket(self.sock, server_side=True) as ssock:
			while True:
				try:
					client_ssock, addr = ssock.accept()
					self.manageClient(client_ssock, addr)
				except KeyboardInterrupt:
					self.shutdown()

	def shutdown(self):
		print("[Ctrl+C catched]. Gracefully shutting down..")			
		self.sock.close()
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
						self.generateCGA(data, client_ssock, addr)
				except struct.error as se:
					self.shutdown_client_socket(client_ssock)
					return
				except KeyboardInterrupt as ke:
					client_ssock.close()
					self.shutdown()
	
	# return cga and parameters
	def generateCGA(self, data, csocket, addr_info):
		public_key = open("keys/devicea.test.pub.der","rb").read()

		#client should send a RouterSolicitation message
		#Prefix must be given by a RouterAdvertisement message back..
		#(addr,parameters) = genCGA(1, public_key)  #lets assume extFields = 0 or null

		prefix = data[1]

		(addr,parameters) = genCGA(1, public_key, prefix)
		
		params = []
		params.append(parameters[0].decode("utf-8"))
		params.append(parameters[1])
		params.append(parameters[2].decode("utf-8"))
		params.append(binascii.hexlify(parameters[3]).decode("utf-8"))
		params.append(parameters[4].decode("utf-8"))
		params.append(addr)
		params = json.dumps(params)
		print("[CLIENT] %s:%s -> GENERATED CGA: %s" % (addr_info[0], addr_info[1], addr) )
		csocket.send(params.encode("utf-8"))


if __name__ == '__main__':
	try:
		server = Server(IP, PORT)
	except socket.error as err:
		print("SocketError: %s" % str(err))
