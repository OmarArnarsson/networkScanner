from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import summarize_address_range

#
###########
# Creates a list if user is scanning a netrange
###########
#
def multiIp(low, high):
	x = []
	for r in summarize_address_range(ip_address(low), ip_address(high)):
		nw = ip_network(r)
		for ip in nw:
			x.append(str(ip))
	return x
