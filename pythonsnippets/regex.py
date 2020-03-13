import argparse
import re

parser = argparse.ArgumentParser()

#segd = input("Gef mér regex.. ")
random = parser.add_argument('-R', "--Random", action='store_true')

def lala(ip):
    match = re.search("^[a-zA-Z].*", ip)
    singleip = re.search("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip)
    multiip = re.search("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip)
    
    if match:
        print(random)
    elif singleip:
        print("Ég er valid ip" + random)
    elif multiip:
        print("electric boogaloo" + random)