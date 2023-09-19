import sys, socket
# from scapy.layers.inet import IP, TCP
# from scapy.all import *


# ips = IP(dst="192.168.0.114")
# tcps = TCP(dport=445, flags="S")
# pacote = ips/tcps

# response = sr1(pacote, timeout=1)
# response.show()
from ipwhois import IPWhois
import re

host1 ="inventsoftware.com.br"
#ip = socket.gethostbyname(host1)

for ip in [host1]:
    if bool(re.search(r"[a-zA-Z]", ip)):
        dnsResolver = socket.gethostbyname(ip)
        print(dnsResolver)
    else:
        print(ip)





