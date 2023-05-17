from scapy.all import *
from scapy.layers.inet import IP, ICMP


def sniff_packet(pkt):
    print("got a packet to dst {} from src {}".format(pkt[IP].dst, pkt[IP].src))
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    icmp = ICMP(type=0,seq=pkt[ICMP].seq,id=pkt[ICMP].id)
    fakepkt = ip / icmp
    send(fakepkt, verbose=0)


sniff(filter="icmp and dst host 1.2.3.4", prn=sniff_packet)
