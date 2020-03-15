import sys
import leScanner
import regex
import singleOrMulti

#
####################
# The main function to call to run the Scanner
# Takes inputs and calls other scripts to do the work
####################
#

print("-" * 60)
print("Welcome to Omars & Viktors Port Scanner!")
print("You can scan an IP address with a netrange or a single address")
print("CAUTION : Only scan addresses that you're allowed to scan, we take no responsibility")
print("After scanning you will be prompted to view closed/filtered ports")
print("When prompted for min/max port, hit enter to use well known ports")
print("Example inputs for target : 192.168.0.1 // 192.168.0.1-254 // scanme.nmap.org")
print("-" * 60)
target = input("[*] Enter Target IP Address: ") # Get Target Address
ICMPping = input("[*] Would you like to perform host discovery (ICMP) [Y/n]: ")
FullOrStealth = input("[*] Would you like to perform a SYN-stealth scan or full handshake? [S for stealth, default full handshake]: ")
min_port = input("[*] Enter Minumum Port Number: ") # Get Min. Port Num.
max_port = input("[*] Enter Maximum Port Number: ") # Get Max. Port Num.
random_ips = input("[*] Wanna shuffle IPs? [Y/n]: ")
random_ports = input("[*] Wanna shuffle ports? [Y/n]: ")
scantype = regex.checktype(target) # Check if a single or multi scan will occur

if(scantype == 1 or scantype == 2):
	singleOrMulti.scanSingle(target, ICMPping, min_port, max_port, random_ips, random_ports, FullOrStealth)
else:
	singleOrMulti.scanMulti(target, ICMPping, min_port, max_port, random_ips, random_ports, scantype, FullOrStealth)
