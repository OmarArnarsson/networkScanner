import re

#
##############
# Function that uses regular expressions to decide the input
# If a single ip or a netrange will occur
##############
#
def checktype(ip):
    match = re.search("^[a-zA-Z].*", ip)
    singleip = re.search("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip)
    multiip = re.search("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip)
    CIDR = re.search("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([0-9]|1[0-9]|2[0-4])$", ip)

    if match:
        print("-" * 60)
        print("You have chosen to scan a single address")
        print(ip)
        print("-" * 60)
        return 1
    elif singleip:
        print("-" * 60)
        print("You have chosen to scan a single IP")
        print(ip)
        print("-" * 60)
        return 2
    elif multiip:
        print("-" * 60)
        print("You have chosen to scan a netrange")
        print(ip)
        print("-" * 60)
        return 3
    elif CIDR:
        print("-" * 60)
        print("You have chosen to scan a CIDR")
        print(ip)
        print("-" * 60)
        return 4
