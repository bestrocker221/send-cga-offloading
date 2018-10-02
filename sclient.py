import socket, time, struct, ssl, os, json, argparse, sys
from CGA import *

ADDR = ("127.0.0.1", 7890)

hostname = 'manufacturer.com'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE

#TODO
#create argument parser for interface, mode (ex, 1=generation locally, 2=generation offloaded)

#
#   Offload CGA generation to a third party
#
#   Return 128bit CGA
#
def requestCGAtoServer(prefix):
    try:
        with socket.create_connection(ADDR) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print("[*NETWORK INFO] Protocol used: " + ssock.version())
                print("[*NETWORK INFO] Connected to %s on port %s" % ADDR)
                
                data = "CGAgen"         #many better ways to pass this
                try:
                    print("[*NETWORK INFO] Sending prefix to Server")
                    ssock.send(json.dumps([data,prefix]).encode("utf-8"))
                except BrokenPipeError:
                    print("[*EXCEPTION] Server closed the connection. Quitting...")
                    ssock.close()
                    exit(1)
                try:
                    data = ssock.recv(5000)
                    data = data.decode("utf-8")
                except Exception as e:
                    print(e)
                    exit(1)
                #strip data into cga,parameters
                ssock.close()
                data = json.loads(data)
                addr = data[5]
                parameters = []
                parameters.append(data[0].encode("utf-8"))
                parameters.append(data[1])
                parameters.append(data[2].encode("utf-8"))
                parameters.append(binascii.unhexlify(data[3].encode("utf-8")))
                parameters.append(data[4].encode("utf-8"))
                print("[*NETWORK INFO] Got CGA from server. Closing connection")
                return addr,parameters
    except ConnectionRefusedError:
        print("[*ERROR] Server is down.")
        exit(0)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(usage= sys.argv[0]+ ' -i <interface> -m <1|2>', \
        description="Generate a CGA from a prefix and a public_key.")
    parser.add_argument("-i", action="store", help='network interface to use', required=True)
    parser.add_argument("-m", type=int, action='store', help='1 = local generation, 2 = offloaded generation', required=True)

    args = parser.parse_args()
    
    mode = args.m
    interface = args.i

    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\n\
            Please try again, this time using 'sudo'. Exiting.")


    #TODO prefix get from RouterAdvertisement
    prefix = "fe80::1111:aaaa"
    
    if mode == 1:
        #just create a public-private rsa key pair before , MUST BE in DER format
        public_key = open("keys/devicea.test.pub.der","rb").read()

        #client should send a RouterSolicitation message
        #Prefix must be given by a RouterAdvertisement message back..
        #(addr,parameters) = genCGA(1, public_key)  #lets assume extFields = 0 or null
        dad_check = True
        while dad_check:
            (addr,parameters) = genCGA(1, public_key, prefix)
            #DAD detection
            dad_check = check_dad(addr, interface)
            print("[*INFO] Performing Duplicate Address Detection... %s --> %s" % \
                (dad_check, "We can't use it..\nRegenerating a new one" if dad_check else "CGA unused, we can use it." ))
            #if already exists -> generate new CGA
        print("[*INFO] Verification returns: %s " % verifyCGA(addr,parameters))

    elif mode == 2:
        dad_check = True
        while dad_check:
            addr,parameters = requestCGAtoServer(prefix)
            
            #DAD detection
            print("[*INFO] CGA: %s" % addr)
            #print(parameters)
            dad_check = check_dad(addr,interface)
            print("[*INFO] Performing Duplicate Address Detection... %s --> %s" % \
                (dad_check, "We can't use it..\nRegenerating a new one" if dad_check else "CGA unused, we can use it." ))
            #if already exists -> generate new CGA
        print("[*INFO] Verification returns: %s " % verifyCGA(addr,parameters))

'''
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
'''