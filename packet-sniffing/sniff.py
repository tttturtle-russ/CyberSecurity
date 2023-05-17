#! /usr/bin/python3
# encoding: utf-8
"""
@author : liuhy
@file name : sniff.py
@date : 2023.4.25
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP


def packet_handler(packet):
    if IP in packet:
        print('src ip {} --> dst ip {}'.format(packet[IP].src, packet[IP].dst))
        print('proto:{}'.format(packet[IP].proto))
    if TCP in packet:
        print('src port {} --> dst port {}'.format(packet[TCP].sport, packet[TCP].dport))


sniff(filter="tcp and dst host 202.114.0.245 and dst port 80", prn=packet_handler)
