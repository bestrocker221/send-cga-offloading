#!/usr/bin/python
import hashlib, random, binascii
from ipaddress import IPv6Address

'''
Following CGA creation guidelines and pseudocode by

https://en.wikipedia.org/wiki/Cryptographically_Generated_Address#CGA_generation_method

'''

def genCGA(sec, subnetPrefix, pubKey, extFields = b''):

	modifier = hex(random.randrange(0x00000000000000000000000000000000,
									0xffffffffffffffffffffffffffffffff))[2:]
	modifier = bytes(modifier,"utf-8")
	print("Modifier: (length: %s bits)\n %s" % (len(bin(int(modifier,16))[2:]) , modifier) )
	pubk = binascii.hexlify(public_key)
	#print("Public Key length: %s bits" % len(bin(int(pubk,16))[2:]))
	
	#Label1 1 start
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
			
	print("Modifier found: %s" % modifier)
	print("Hash2 value:      %s" % hash2)
	print("Rounds made:      %s" % n)

	colCount = b'0' 				#collision count

	#Label2 start
	print("\n Starting phase 2 -> Interface Identifier creation.. \n")

	#formatting ipv6 prefix
	ipv6Prefix = IPv6Address(subnetPrefix + ":0000:0000:0000:0000") 	#add the 64 least significant bits
	#just take the most 8*8=64 most significant bits of the whole 128bits ipv6 addr
	ipv6Prefix = binascii.hexlify(ipv6Prefix.packed[0:8])
	
	concatenate = modifier + ipv6Prefix + colCount + pubk + extFields
	#print(concatenate)
	digest = hashlib.sha1(concatenate).hexdigest()
	hash1 = digest[0:8] 		#8*8=64 most significant bits
	intID = hash1 				#hash1 becomes Interface Identifier
	
	print("Hash1 value:     %s " % hash1)
	#now intID[0] := intID[0] binary and 0x1c binary or (Sec << 5)
	#print("intid pre:  %s" % intID)

	intID_0 = (ord(intID[0]) & int("0x1c",16) | (sec << 5))
	#print("%s -> %s " % (intID[0] ,intID_0))
	#print("%s -> %s " % (intID_0, hex(intID_0)))
	
	intID = "".join(hex(ord(i))[2:] for i in intID[1:])
	intID = hex(intID_0)[2:] + intID
	print("Hash1 hex value: %s " % intID)

	id1 = "{}:{}:{}:{}".format(intID[0:4],intID[4:8],intID[8:12],intID[12:16])

	CGA = subnetPrefix + ":" + id1
	print("\nCGA -> %s" % CGA)
	#concatenate subnet prefix and ID

	#DAD detection (hard part)
	#TODO
	
	return ("", "")

#just create a public-private rsa key pair before
public_key = open("/home/bsodps/Dropbox/KTH/Research Methotolody/ResearchProject/test/devicea.test.pub.der","rb").read()

(addr,c) = genCGA(1, "fe80::1111:aaaa", public_key)  #lets assume extFields = 0 or null
print(addr)

