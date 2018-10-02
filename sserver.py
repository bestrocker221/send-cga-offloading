import socket, os, ssl, struct

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
		#print("[*INFO] Client may has been disconnected..")
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
					data = data.decode("utf-8")
					print("%s:%s -> %s" % (addr[0], addr[1], data))

					#TODO

				except struct.error as se:
					self.shutdown_client_socket(client_ssock)
					return
				except KeyboardInterrupt as ke:
					client_ssock.close()
					self.shutdown()
					

if __name__ == '__main__':
	try:
		server = Server(IP, PORT)
	except socket.error as err:
		print("SocketError: %s" % str(err))
