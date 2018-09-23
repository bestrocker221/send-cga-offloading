#!/usr/bin/python

import hashlib,random,binascii
from struct import pack

# from cert import *
# from scapy import *
# from scapy.all import *

def genCGA(sec, subnetPrefix, pubKey, extFields = None):

	modifier = hex(random.randrange(0x00000000000000000000000000000000,
									0xffffffffffffffffffffffffffffffff))[2:]
	modifier = bytes(modifier,"utf-8")
	print("Modifier: (length: %s bits)\n %s" % (len(bin(int(modifier,16))[2:]) , modifier) )
	p2 = binascii.hexlify(public_key)
	#print("Public Key length: %s bits" % len(bin(int(p2,16))[2:]))
	
	print("\n Starting modifier creation..")
	hash2 = ""
	n = 0
	while True:
		if sec == 0 or hash2[0:2*sec] == '00':
			break
		else:
			n += 1
			modifier = bytes(hex( int(modifier,16) + 1 )[2:], "utf-8")
			#print(modifier)
			conc2 = modifier + b'00'*9 + p2
			#print("Concat:\n %s" % conc2)

			#print(bytes(extFields,"utf-8"))

			digest = hashlib.sha1(conc2).hexdigest()
			hash2 = digest[0:14]
			
			#print("hash2 %s" % hash2)
			#print("Digest: \n %s" %  digest)	#HEX   .digest() -> BYTES
			#print("Hash2: (length: %s bits)\n %s" % (len(bin(int(hash2,16))[2:])+1, hash2) )
	print("Modifier found: %s" % modifier)
	print("Hash2 value:      %s" % hash2)
	print("Rounds made:      %s" % n)

	colCount = b'0'

	return ("ciao", " stronzo")


public_key = open("/home/bsodps/Dropbox/KTH/Research Methotolody/ResearchProject/test/devicea.test.pub.der","rb").read()
#public_key = PubKey("devicea.test.pub.der")

(addr,c) = genCGA(1, "fe80:0000:1111:aaaa", public_key)
print(addr)

