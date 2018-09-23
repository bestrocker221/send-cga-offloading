#!/usr/bin/python

import hashlib, random, binascii
#from struct import pack
from ipaddress import IPv6Address
# from cert import *
# from scapy import *
# from scapy.all import *

def genCGA(sec, subnetPrefix, pubKey, extFields = b''):

	modifier = hex(random.randrange(0x00000000000000000000000000000000,
									0xffffffffffffffffffffffffffffffff))[2:]
	modifier = bytes(modifier,"utf-8")
	print("Modifier: (length: %s bits)\n %s" % (len(bin(int(modifier,16))[2:]) , modifier) )
	pubk = binascii.hexlify(public_key)
	#print("Public Key length: %s bits" % len(bin(int(pubk,16))[2:]))
	
	#label 1 start
	print("\n Starting phase 1 -> modifier creation..\n")
	hash2, concatenate = "", b''
	n = 0
	while True:
		if sec == 0 or hash2[0:2*sec] == '00':
			break
		else:
			n += 1
			modifier = bytes(hex( int(modifier,16) + 1 )[2:], "utf-8")
			#print(modifier)

			#TODO 
			#how do i format extFields?
			concatenate = modifier + b'00'*9 + pubk + extFields

			digest = hashlib.sha1(concatenate).hexdigest()
			hash2 = digest[0:14]
			
			#print("hash2 %s" % hash2)
			#print("Digest: \n %s" %  digest)	#HEX   .digest() -> BYTES
			#print("Hash2: (length: %s bits)\n %s" % (len(bin(int(hash2,16))[2:])+1, hash2) )
	print("Modifier found: %s" % modifier)
	print("Hash2 value:      %s" % hash2)
	print("Rounds made:      %s" % n)

	colCount = b'0' 				#collision count

	#label2 start
	print("\n Starting phase 2.. \n")
	#how do i format subnet prefix and extfields?
	#formatting ipv6 prefix
	ipv6Prefix = IPv6Address(subnetPrefix + ":0000:0000:0000:0000") 	#add the 64 least significant bits
	#just take the most 8*8=64 most significant bits of the whole 128bits ipv6 addr
	ipv6Prefix = binascii.hexlify(ipv6Prefix.packed[0:8])
	
	concatenate = modifier + ipv6Prefix + colCount + pubk + extFields
	print(concatenate)
	digest = hashlib.sha1(concatenate).hexdigest()
	hash1 = digest[0:8] 		#8*8=64 most significant bits
	intID = hash1 				#hash1 becomes Interface Identifier

	return ("ciao", " stronzo")

#just create a public-private rsa key pair before
public_key = open("/home/bsodps/Dropbox/KTH/Research Methotolody/ResearchProject/test/devicea.test.pub.der","rb").read()

(addr,c) = genCGA(1, "fe80::1111:aaaa", public_key)  #lets assume extFields = 0 or null
print(addr)

