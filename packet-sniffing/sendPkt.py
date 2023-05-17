#! /usr/bin/python3
# encoding: utf-8
"""
@author : liuhy
@file name : sendPkt.py
@date : 2023.4.25
"""


import socket

# 创建UDP套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 目标地址和端口
target_address = '127.0.0.1'
target_port = 9091

# 发送的数据
message = 'this is a test'.encode()

# 发送UDP数据包
sock.sendto(message, (target_address,target_port))

