# Python Portscanner

## Ómar & Viktors port scanner

## Caution : Only scan addresses you have permission to scan. We take no responsibility for your actions.

#### You can download the repo and we recommend using virtualenv. To do so make sure you have virtualenv installed and follow these steps:
* Setting up virtual env
    * 1. virtualenv -p python3 virtualenv
    * 2. source VENV/bin/activate
    * 3. pip install -r requirements.txt
#### Disclaimer : There is an issue with the scapy module where you may have to run the command "pip uninstall scapy" and then reinstall with "pip install scapy" for it to work correctly. Note this is not on our behalf.

## Usage :
 To use the portscanner after setting up VENV simply run:
 "sudo python main.py"
* Then follow the instructions
    * To scan a single IP or address : 192.168.0.1 or scanme.nmap.org
    * To scan a netrange : 192.168.0.1-30 / will then scan addresses from 192.168.0.1 to 192.168.0.30 and all in between

### Note :
 When prompted for min / max port you can simply press enter and leave it empty and our portscanner will scan for the top 50 ports.
### Note :
 After scanning it will prompt you if you want to display closed/filtered ports.

#### A typical port scanner that can scan a single IP or a netrange and prints open ports!
 This was a school project for "Computer System Security" at the University of Iceland. Reasons for port scanning can be twofold. On one hand as an administrator it's good to verify security policies of their networks and keep an eye on which ports are open and secure them. On the other hand port scanning can be used by attackers to identify network services running on a host and exploit their vulnerabilities.
 A port scan per say is simply a process that sends client requests to a single or a range of server ports / addresses on a host.


## Made by :
Ómar Þór Arnarsson & Viktor Þór Freysson
otha3@hi.is & vthf1@hi.is
