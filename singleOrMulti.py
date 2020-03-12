import leScanner
import iptest
import random
from datetime import datetime # Other stuff
from time import strftime

wellknown = [7, 9, 13, 17, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 88, 100, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 808,873, 990, 993, 995]

def randomlist(mlist):
	random.shuffle(mlist)
	return mlist

def scanSingle(target, ICMPping, min_port, max_port, randomip, random_ports):
	closed_filtered = []

	if(ICMPping == "Y" or ICMPping == "y"):
		leScanner.checkhost(target)

	if(min_port == "" and max_port == ""):
		ports = wellknown
	else:
		leScanner.validCheck(min_port, max_port)
		ports = buildlist(min_port, max_port)

	if(random_ports == "Y" or random_ports == "y"):
			random.shuffle(ports)

	start_clock = datetime.now() # Start clock for scan time
	print("[*] Scanning Started at " + strftime("%H:%M:%S") + "!\n") # Confirm scan start

	closed_filtered = leScanner.mainscan(target, ports)

	stop_clock = datetime.now() # Stop clock for scan time
	total_time = stop_clock - start_clock # Calculate scan time
	print("\n[*] Scanning Finished!") # Confirm scan stop
	print("[*] Total Scan Duration: " + str(total_time)) # Print scan time

	display_filtered_closed = input("[*] Want to see a list of closed/filtered ports ? [Y/n]: ")
	
	if (display_filtered_closed == "Y" or display_filtered_closed == "y"):
		print("-" * 60)
		for x in range(len(closed_filtered)):
			print(closed_filtered[x])

def scanMulti(target, ICMPping, min_port, max_port, randomip, random_ports, scantype):
	#x = target.split(".")
	#x4 = x[3].split("-")
	#low = x[0] + "." + x[1] + "." + x[2] + "." + x4[0]
	#high = x[0] + "." + x[1] + "." + x[2] + "." + x4[1]
	closed_filtered = []
	iplist = []

	if(ICMPping == "Y" or ICMPping == "y"):
		leScanner.checkhost(target)

	if(min_port == "" and max_port == ""):
		ports = wellknown
	else:
		leScanner.validCheck(min_port, max_port)
		ports = buildlist(min_port, max_port)

	if(scantype == 3):
		x = target.split(".")
		x4 = x[3].split("-")
		low = x[0] + "." + x[1] + "." + x[2] + "." + x4[0]
		high = x[0] + "." + x[1] + "." + x[2] + "." + x4[1]
		iplist = iptest.multiIp(low, high)
	else:
		print(target)
		iplist = iptest.cidrIp(target)

	if(randomip == "Y" or randomip == "y"):
		iplist = randomlist(iplist)

	if(random_ports == "Y" or random_ports == "y"):
			random.shuffle(ports)

	start_clock = datetime.now() # Start clock for scan time
	print("[*] Scanning Started at " + strftime("%H:%M:%S") + "!\n") # Confirm scan start

	for x in range(len(iplist)):
		tmp = leScanner.mainscan(iplist[x], ports)
		closed_filtered.append(iplist[x])
		for x in range(len(tmp)):
			closed_filtered.append(tmp[x])
		closed_filtered.append("-" * 60)

	stop_clock = datetime.now() # Stop clock for scan time
	total_time = stop_clock - start_clock # Calculate scan time
	print("\n[*] Scanning Finished!") # Confirm scan stop
	print("[*] Total Scan Duration: " + str(total_time)) # Print scan time

	display_filtered_closed = input("[*] Want to see a list of closed/filtered ports ? [Y/n]: ")
	
	if (display_filtered_closed == "Y"):
		print("-" * 60)
		for x in range(len(closed_filtered)):
			print(closed_filtered[x])

def buildlist(min_port, max_port):

	ports = []
	for x in range(int(min_port), int(max_port)+1):
		ports.append(x)
	return ports