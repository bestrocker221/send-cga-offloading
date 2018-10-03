import socket, time, struct, ssl, os, json, argparse, sys,time
from CGA import *

ADDR = ("127.0.0.1", 7890)

hostname = 'manufacturer.com'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE

#
#   Handle sending and receiving to Server through TCP & TLS
#
#
def send_with_tls(prefix):
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
                parameters = format_parameters(data)
                print("[*NETWORK INFO] Got CGA from server. Closing connection")
                return addr,parameters
    except ConnectionRefusedError:
        print("[*ERROR] Server is down.")
        exit(0)

#
#   Handle send/receive to Server through UDP
#
#
def send_with_udp(prefix):
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("[*NETWORK INFO] Protocol used: UDP")
    print("[*NETWORK INFO] %s on port %s" % ADDR)
    data = "CGAgen"         #many better ways to pass this
    try:
        print("[*NETWORK INFO] Sending prefix to Server")
        csock.sendto(json.dumps([data,prefix]).encode("utf-8"), ADDR)
    except Exception as e:
        print("[*EXCEPTION] %s " % e)
        exit(1)
    try:
        data = csock.recv(5000)
        data = data.decode("utf-8")
    except Exception as e:
        print(e)
        exit(1)
    #strip data into cga,parameters
    csock.close()
    data = json.loads(data)
    addr = data[5]
    parameters = format_parameters(data)
    print("[*NETWORK INFO] Got CGA from server. Closing connection")
    return addr,parameters

#
#   Offload CGA generation to a third party
#
#   Return 128bit CGA
#
def requestCGAtoServer(tls, prefix=""):
    if tls:
        return send_with_tls(prefix)
    else:
        return send_with_udp(prefix)




if __name__ == "__main__":

    parser = argparse.ArgumentParser(usage= sys.argv[0]+ ' -i <interface> -m <1|2>', \
        description="Generate a CGA from a prefix and a public_key.\n" +
        "Default offloading use Symmetric Encryption with UDP sockets, if you want TCP over TLS use -tls")
    parser.add_argument("-i", action="store", help='network interface to use', required=True)
    parser.add_argument("-m", type=int, action='store', help='1 = local generation, 2 = offloaded generation', required=True)
    parser.add_argument("-tls", action="store_true", help="use TLS over TCP for server connection.")

    parser.add_argument("-p", action='store', help='optional, use a different prefix for generating CGA')
    args = parser.parse_args()
    
    mode = args.m
    interface = args.i
    tls = args.tls if args.tls else None

    print(tls)
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\n\
            Please try again, this time using 'sudo'. Exiting.")


    #TODO prefix get from RouterAdvertisement ? no link local has link_local_prefix
    prefix = args.p if args.p else None
    
    if mode == 1:
        #just create a public-private rsa key pair before , MUST BE in DER format
        public_key = open("keys/devicea.test.pub.der","rb").read()

        #client should send a RouterSolicitation message
        #Prefix must be given by a RouterAdvertisement message back..
        #(addr,parameters) = genCGA(1, public_key)  #lets assume extFields = 0 or null
        dad_check = True
        while dad_check:
            (addr,parameters) = genCGA(1, public_key, prefix) if prefix else genCGA(1, public_key)
            #DAD detection
            dad_check = check_dad(addr, interface)
            #print("[*INFO] Performing Duplicate Address Detection... %s --> %s" % \
            #    (dad_check, "We can't use it..\nRegenerating a new one" if dad_check else "CGA unused, we can use it." ))
            #if already exists -> generate new CGA
        #print("[*INFO] Verification returns: %s " % verifyCGA(addr,parameters))
        verifyCGA(addr,parameters)

    elif mode == 2:
        dad_check = True
        while dad_check:
            start_time = time.time()
            addr,parameters = requestCGAtoServer(tls, prefix) if prefix else requestCGAtoServer(tls)
            end_time = time.time() - start_time
            #DAD detection
            print("[*INFO] CGA: %s" % addr)
            dad_check = check_dad(addr,interface)
            print("[*INFO] Performing Duplicate Address Detection... %s --> %s" % \
                (dad_check, "We can't use it..\nRegenerating a new one" if dad_check else "CGA unused, we can use it." ))
            #if already exists -> generate new CGA
        #print("[*INFO] Verification returns: %s " % verifyCGA(addr,parameters))
        verifyCGA(addr,parameters)

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