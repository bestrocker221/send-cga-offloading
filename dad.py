from scapy.all import ICMPv6ND_NS, IPv6, ICMPv6NDOptSrcLLAddr,sr

#
#	Function that performs Duplicate Address Detection on a given IPv6 Address
#
#	Send a ICMPv6 NeighborSolicitacion message asking for the LinkLayer address of the specified ipv6 addr
#
#	return True if address is already used, False if not
#
def check_dad(interface, hw_addr, ipv6address, dst_a="ff02::1"):
	neigh_sol = IPv6(dst=dst_a)/\
	ICMPv6ND_NS(tgt=ipv6address)/\
	ICMPv6NDOptSrcLLAddr(lladdr=hw_addr)
	ans,u = sr(neigh_sol, timeout=1, iface=interface, multi=True, verbose=False)
	return True if ans else False