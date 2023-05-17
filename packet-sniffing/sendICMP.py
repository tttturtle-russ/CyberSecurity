from scapy.all import *
from scapy.layers.inet import IP, ICMP

ip = IP(src="127.0.0.1", dst="1.2.3.4")
icmp = ICMP()
raw = Raw(load="this is a test")

f_pkt = ip / icmp / raw

while True:
    send(f_pkt, verbose=0)  # send packet
