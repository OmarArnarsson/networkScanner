#! /usr/bin/python
from logging import getLogger, ERROR # Import Logging Things
getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning
from scapy.all import * # The One and Only Scapy
import sys
import random
from datetime import datetime # Other stuff
from time import strftime
target = ""
SYNACK = 0x12 # Set flag values for later reference
RSTACK = 0x14

#
################
# Function that validates the ports from input
################
#
def validCheck(min_port, max_port):
	try:
		if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) >= int(min_port): # Test for valid range of ports
			pass
		else: # If range didn't raise error, but didn't meet criteria
			print("\n[!] Invalid Range of Ports")
			print("[!] Exiting...")
			sys.exit(1)
	except Exception: # If input range raises an error
		print("\n[!] Invalid Range of Ports")
		print("[!] Exiting...")
		sys.exit(1)

#
##################
# checkhost checks if host is up and reports back
# Only activates if user input is "Y" to ICMP ping
##################
#
def checkhost(ip):
	conf.verb = 0 # Hide output
	try:
		ping = sr1(IP(dst = ip)/ICMP()) # Ping the target
		print("\n[*] Target is Up, Beginning Scan...")
	except Exception: # If ping fails
		print("\n[!] Couldn't Resolve Target")
		print("[!] Exiting...")
		sys.exit(1)

#
####################
# Function that scans a given port using SYN scan
# Takes in a single port
####################
#
def scanport(port):
	try:
		srcport = RandShort() # Generate Port Number
		conf.verb = 0 # Hide output
		SYNACKpkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S"),timeout=0.5) # Send SYN and recieve RST-ACK or SYN-ACK
		if SYNACKpkt:
			pktflags = SYNACKpkt.getlayer(TCP).flags # Extract flags of recived packet
			if pktflags == SYNACK: # Cross reference Flags
				return True # If open, return true
			else:
				return False # If closed, return false
		else:
			return None
		RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Construct RST packet
		send(RSTpkt) # Send RST packet
	except KeyboardInterrupt: # In case the user needs to quit
		RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Built RST packet
		send(RSTpkt) # Send RST packet to whatever port is currently being scanned
		print("\n[*] User Requested Shutdown...")
		print("[*] Exiting...")
		sys.exit(1)

#
#################
# The mainscanner function takes in the IP and the ports to scan
# For every single port scanned it calls the scanport function
# IP is the target from input (str)
# ports are the ports from input (list)
#################
#
def mainscan(IP, ports):
	global target
	target = IP
	closed_filtered = []
	ports_scanned = 0

	for port in ports: # Iterate through range of ports
		status = scanport(port) # Feed each port into scanning function
		ports_scanned += 1
		if status == True: # Test result
			print("Port " + str(port) + ": Open") # Print open ports instantly
		elif status == False:
			closed_filtered.append("Port " + str(port) + ": Closed")
		else:
			closed_filtered.append("Port " + str(port) + ": Filtered")

	print("Total number of ports scanned: " + str(ports_scanned))
	return closed_filtered #Returns the list of all closed/filtered ports
