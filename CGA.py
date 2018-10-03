#!/usr/bin/python
import hashlib, random, binascii, os, time
from ipaddress import IPv6Address
from struct import pack
from scapy.all import ICMPv6ND_NS, IPv6, ICMPv6NDOptSrcLLAddr,sr, get_if_hwaddr


DEBUG = False

link_local_prefix = "FE80:"

def check_iface(interface):
	ifaces = os.listdir('/sys/class/net')
	if interface not in ifaces:
		print("Interface %s does not exists on your machine." % interface)
		print("You have:")
		for i in ifaces:
			print("[ %s ]" % i)
		return True
	return False


#
#	Format parameters in order to send them
#
#
def format_parameters(data):
	parameters = []
	parameters.append(data[0].encode("utf-8"))
	parameters.append(data[1])
	parameters.append(data[2].encode("utf-8"))
	parameters.append(binascii.unhexlify(data[3].encode("utf-8")))
	parameters.append(data[4].encode("utf-8"))
	return parameters


def unformat_parameters(parameters):
	params = []
	params.append(parameters[0].decode("utf-8"))
	params.append(parameters[1])
	params.append(parameters[2].decode("utf-8"))
	params.append(binascii.hexlify(parameters[3]).decode("utf-8"))
	params.append(parameters[4].decode("utf-8"))
	return params

#
#	Function that performs Duplicate Address Detection on a given IPv6 Address
#
#	Send a ICMPv6 NeighborSolicitacion message asking for the LinkLayer address of the specified ipv6 addr
#
#	return True if address is already used, False if not
#
def check_dad(ipv6address, interface, hw_addr="9c:b6:d0:fe:41:43", dst_a="ff02::1"):
	if check_iface(interface):
		exit(1)
	HW_MAC = get_if_hwaddr(interface)
	neigh_sol = IPv6(dst=dst_a)/\
	ICMPv6ND_NS(tgt=ipv6address)/\
	ICMPv6NDOptSrcLLAddr(lladdr=HW_MAC)
	ans,u = sr(neigh_sol, timeout=1, iface=interface, multi=True, verbose=False)
	return True if ans else False


'''
Following CGA creation guidelines and pseudocode by

https://en.wikipedia.org/wiki/Cryptographically_Generated_Address#CGA_generation_method

'''
#
#	CGA Generation Process
#
#	return CGA, parameters
#
def genCGA(sec, public_key, subnetPrefix=link_local_prefix, extFields = b''):
	start_time = time.time()

	modifier = hex(random.randrange(0x00000000000000000000000000000000,
									0xffffffffffffffffffffffffffffffff))[2:]
	modifier = bytes(modifier,"utf-8")
	if DEBUG:
		print("Modifier: (length: %s bits)\n %s" % (len(bin(int(modifier,16))[2:]) , modifier) )
	pubk = binascii.hexlify(public_key)
	#print("Public Key length: %s bits" % len(bin(int(pubk,16))[2:]))
	
	#Label1 1 start
	if DEBUG:
		print("\nStarting phase 1 -> modifier creation..\n")
	hash2 =  b''
	n = 0
	while True:
		if sec == 0 or hash2[0:2*sec] == '00':
			break
		else:
			n += 1
			modifier = bytes(hex( int(modifier,16) + 1 )[2:], "utf-8")
			
			#TODO 
			#how do i format extFields?
			concatenate = modifier + b'00'*9 + pubk + extFields

			digest = hashlib.sha1(concatenate).hexdigest()
			hash2 = digest[0:14]
	if DEBUG:		
		print("\tModifier found: %s" % modifier)
		print("\tHash2 value:      %s" % hash2)
		print("\tRounds made:      %s" % n)

	colCount = b'0' 				#collision count

	#Label2 start
	if DEBUG:
		print("\nStarting phase 2 -> Interface Identifier creation.. \n")

	#formatting ipv6 prefix
	ipv6Prefix = IPv6Address(subnetPrefix + ":0000:0000:0000:0000") 	#add the 64 least significant bits
	subnetPrefix = ipv6Prefix.exploded[0:19]	
	#just take the most 8*8=64 most significant bits of the whole 128bits ipv6 addr
	ipv6Prefix = binascii.hexlify(ipv6Prefix.packed[0:8])
	
	concatenate = modifier + ipv6Prefix + colCount + pubk + extFields

	digest = hashlib.sha1(concatenate).hexdigest()
	hash1 = digest[0:8] 		#8*8=64 most significant bits
	intID = hash1 				#hash1 becomes Interface Identifier
	
	if DEBUG:
		print("\tHash1 value:     %s " % hash1)

	#binary AND --> int
	intID_0 = (ord(intID[0]) & int("0x1c",16) | (sec << 5))
	
	#formatting str to binary	
	intID = "".join(hex(ord(i))[2:] for i in intID[1:])
	intID = hex(intID_0)[2:] + intID
	if DEBUG:
		print("\tHash1 hex value: %s " % intID)

	id1 = "{}:{}:{}:{}".format(intID[0:4],intID[4:8],intID[8:12],intID[12:16])

	CGA = subnetPrefix + ":" + id1
	if DEBUG:
		print("\nCGA -> %s" % CGA)

	print("[*TIME] CGA generation done in   %s" % str(time.time() - start_time))
	return (CGA, (modifier, subnetPrefix, colCount, public_key, extFields))

def verifyCGA(CGA, parameters):
	start_time = time.time()

	modifier = parameters[0]
	subnetPrefix = parameters[1]
	colCount = parameters[2]
	pubk = parameters[3]
	extFields = parameters[4]

	if DEBUG:
		print("\nStarting CGA Verification process... \n")
	if int(colCount) > 2 or CGA[0:19] != subnetPrefix:
		print("first out")
		return False

	pubk = binascii.hexlify(pubk)
	#formatting subnet prefix with zeroes so that the input can be either 0000:0000 or ::
	subnetPrefix = IPv6Address(subnetPrefix + ":0000:0000:0000:0000")
	subnetPrefix = binascii.hexlify(subnetPrefix.packed[0:8])
	
	concat = modifier + subnetPrefix + colCount + pubk + extFields

	digest = hashlib.sha1(concat).hexdigest()
	hash1 = digest[0:8]

	if DEBUG:
		print("\tHash1: \t     %s " % hash1)

	#hash1_0 binary AND -> to integer
	hash1_0 = ord(hash1[0]) & int("0x1c",16)
	#hash1_0 pack data for having fixed length (ex. if res is 0 then we need 0x00 and not 0)
	hash1_0 = pack(">B", hash1_0)  # --> b'\x' format
	#hash1_0 remove the \x part
	hash1_0 = binascii.hexlify(hash1_0)   # --> b''	  format
	
	#hash1 convert from string to binary
	hash1 = bytes("".join(hex(ord(i))[2:] for i in hash1[1:]), "utf-8")
	#recreate the hash1 with the first byte changed
	hash1 = hash1_0 + hash1	
	if DEBUG:
		print("\tFinal Hash1: %s - len %s" % (hash1, len(hash1)))	# fixed length
	#print("CGA: %s " % CGA)
	intID = binascii.hexlify(IPv6Address(CGA).packed)[16:]
	if DEBUG:
		print("\tintID: \t     %s " % intID)
	
	#intID_0 binary AND --> int
	intID_0 = int(intID[0:2],16) & int("0x1c",16)
	#intID_0 pack for having fixed length (if res is 0 -> 0x00 and not 0x0, we need 1 byte)
	intID_0 = pack(">B", intID_0)
	#intID_0 remove \x part
	intID_0 = binascii.hexlify(intID_0)

	#intID recreate intID with the first byte changed (2 exadecimal)
	intID = intID_0 + intID[2:] 
	if DEBUG:
		print("\tFinal intID: %s " % intID)

	if hash1 != intID:
		if DEBUG:
			print("[*ERROR] hash1 != intID  -->\n%s \n--\n%s" % (hash1, intID))
		return False

	sec = int(CGA[18],16) >> 5

	concat = modifier + b'0x000000000' + pubk + extFields
	digest = hashlib.sha1(concat).hexdigest()

	hash2 = digest[0:14]

	if DEBUG:
		print("\nHash1: %s\nintID: %s" % (hash1, intID))
	if sec != 0 and hash2[0:2*sec] != 0:
		if DEBUG:
			print("[*ERROR] hash2 not passed")
		return False
	print("[*TIME] CGA verification done in %s" % str(time.time() - start_time))
	return True

