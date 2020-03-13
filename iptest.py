from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import summarize_address_range

# Þetta má nota til að smíða lista af IP tölum út frá netrange þ.e. 
# 10.0.20.10 til 10.0.20.50 i þessu dæmi.
#
def multiIp(low, high):
	x = []
	for r in summarize_address_range(ip_address(low), ip_address(high)):
		nw = ip_network(r)
		for ip in nw:
			x.append(str(ip))
	return x

