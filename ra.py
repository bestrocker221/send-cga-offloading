from scapy.all import ICMPv6ND_NS, IPv6, ICMPv6ND_RS, sr, ICMPv6EchoRequest, ICMPv6NDOptSrcLLAddr, ICMPv6MRD_Solicitation

'''
ra_src_addr = ""
hw_addr = "9c:b6:d0:fe:41:43"
router_advertisement = scapy.IPv6(src=ra_src_addr, dst='FF02::1')/
	scapy.ICMPv6ND_RA(routerlifetime=0, reachabletime=0)/
	scapy.ICMPv6NDOptPrefixInfotSrcLLAddr(lladdr=hw_addr)/
	scapy.ICMPv6NDOptPrefixInfo(prefixlen=64, validlifetime=0x6, preferredlifetime=0x6, prefix='dead::')

answer, unanswer = scapy.sr(router_advertisement, timeout=10, multi=True)
'''

interface = "wlp59s0"
HW_addr = "9c:b6:d0:fe:41:43"
router_addr = "fe80::a62b:8cff:fe18:a48d"

ll_a = "fe80::31a8:98f3:573b:5a1b"
dst_a = "ff02::1"


neigh_sol = IPv6(dst=dst_a)/\
	ICMPv6ND_NS(tgt="fe80::31b8:98f3:573b:5a1b")/\
	ICMPv6NDOptSrcLLAddr(lladdr=HW_addr)

neigh_sol.show()
a,u = sr(neigh_sol, timeout=1, iface=interface, multi=True, verbose=False)
print("no hosts") if not a else print("exists")
a.show()


'''
icmpecho = IPv6(src=ll_a, dst=dst_a)/\
	ICMPv6EchoRequest(type=128)
answer, unanswer = sr(icmpecho, timeout=2, multi=True)
answer.show()
'''

'''
router_solicitation = IPv6(dst=router_addr)/\
	ICMPv6ND_RS()
	#ICMPv6NDOptSrcLLAddr(lladdr=ll_a)

router_solicitation.show()

answer, unanswer = sr(router_solicitation, timeout=4, multi=True, iface="wlp59s0")
for a in answer:
	a.show()
'''


'''
router_mcast_sol = IPv6(dst=dst_a)/\
	ICMPv6MRD_Solicitation()

answer, unanswer = sr(router_mcast_sol, timeout=4, multi=True)
for a in answer:
	a.show()
'''