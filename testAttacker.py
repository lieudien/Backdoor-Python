#!/usr/bin/python

import time, os, sys, logging
import config
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

results = ""
targetIP = ""

def checkRootPrivilege():
    if os.getuid() != 0:
        sys.exit("This application have to run with root access. Try again")

def portKnocking():
    global targetIP
    portKnocks = config.portKnocks
    for port in portKnocks:
        packet = IP(dst=targetIP)/UDP(sport=port, dport=8005)
        send(packet)
        time.sleep(1)
def main():
    global targetIP
    checkRootPrivilege()
    portKnocking()

    while True:
        targetIP = input("Enter the target IP: ")
        cmd = input("Enter command: ")
        #sendCommand(cmd)
