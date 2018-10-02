import socket, time, struct, ssl

ADDR = ("127.0.0.1", 7890)

hostname = 'manufacturer.com'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE


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