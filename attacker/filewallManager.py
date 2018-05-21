import os, time, thread

def open_port(protocol, ip, port, ttl):
    os.system(add_iptables_rule("INPUT", protocol, ip, port))
    os.system(add_iptables_rule("OUTPUT", protocol, ip, port))

    if ttl > 0:
        time.sleep(ttl)
        os.system(remove_iptables_rule("INPUT", protocol, ip, port))
        os.system(remove_iptables_rule("OUTPUT", protocol, ip, port))
        print("Iptables rules removed")

def add_iptables_rule(type, protocol, ip, port):
    if type == "INPUT":
        return "iptables -A INPUT -p {} --dport {} -s {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(protocol, port, ip)
    elif type == "OUTPUT":
        return "iptables -A OUTPUT -p {} --sport {} -d {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(protocol, port, ip)

def remove_iptables_rule(type, protocol, ip, port):
    if type == "INPUT":
        return "iptables -D INPUT -p {} --dport {} -s {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(protocol, port, ip)
    elif type == "OUTPUT":
        return "iptables -D OUTPUT -p {} --sport {} -d {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(protocol, port, ip)
