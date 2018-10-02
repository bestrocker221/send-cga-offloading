import socket, time, struct, ssl, os
from CGA import *

ADDR = ("127.0.0.1", 7890)

hostname = 'manufacturer.com'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE

#TODO
#create argument parser for interface


if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\n\
        Please try again, this time using 'sudo'. Exiting.")


#just create a public-private rsa key pair before , MUST BE in DER format
public_key = open("keys/devicea.test.pub.der","rb").read()

#client should send a RouterSolicitation message
#Prefix must be given by a RouterAdvertisement message back..
(addr,parameters) = genCGA(1, public_key)  #lets assume extFields = 0 or null
print("Verification returns: %s " % verifyCGA(addr,parameters))


#for TLS network connection
'''
with socket.create_connection(ADDR) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print("[*INFO] Protocol used: " + ssock.version())
        print("[*INFO] Connected to %s on port %s" % ADDR)
        while True:
            try:
                data = input("$ ")
            except KeyboardInterrupt:
                print("[*EXCEPTION] [Ctrl+C] detected, gracefully exiting.. ")
                break
            if len(data) == 0:
                continue
            #data = struct.pack(">s", data)
            try:
                ssock.send(data.encode("utf-8"))
            except BrokenPipeError:
                print("[*EXCEPTION] Server closed the connection. Quitting...")
                break
'''
def requestCGAtoServer(prefix):
    return
    #TODO
    #server save CGA and parameters
    #return CGA, parameters

def requestSigningOfMessage(msg, CGA):
    return
    #TODO
    #server sign message
    #return signedMessage

def requestMessageVerification(signedMessage, senderCGA):
    return
    #TODO
    #server verify signature
    #return True,False