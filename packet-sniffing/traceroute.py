import ipaddress
from scapy.all import *
from scapy.layers.inet import IP, ICMP

target = sys.argv[1]

maxops = 30

isvalid = True
isipvalid = True
isdomainvalid = True
try:
    ipaddress.ip_address(target)
except ValueError:
    isipvalid = False

try:
    socket.getaddrinfo(target,None)
except socket.gaierror:
    isdomainvalid = False

isvalid = isdomainvalid | isipvalid

if isvalid is False:
    print('not a valid target host')
    sys.exit(1)

for i in range(maxops):
    pkt = IP(dst=target,ttl=i) / ICMP()
    reply = sr1(pkt,verbose=0,timeout=3)
    if reply is None:
        print('{}\t***'.format(i))
    elif reply.type == 11:
        print('{}\t{}'.format(i,reply.src))
    elif reply.type == 0:
        print('{}\t{}'.format(i,reply.src))
        print("reach target {}".format(target))
        break

