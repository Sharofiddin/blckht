from ctypes import *
import ipaddress
import os
import socket
import struct
import sys

class IP(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos",c_ubyte ,8 ),
        ("len",c_ushort ,16 ),
        ("id",c_ushort ,16),
        ("offset",c_ushort ,16 ),
        ("ttl",c_ubyte , 8),
        ("protocol_num",c_ubyte , 8),
        ("sum",c_ushort , 16),
        ("src",c_uint32 , 32),
        ("dst",c_uint32 , 32) 
    ]
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        self.protocol_map = {1:"ICMP",  6 :"TCP", 17:"UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s %s' % (e,self.protocol_num))
            self.protocol = str(self.protocol)
def sniff(host):
    socket_protocol = socket.IPPROTO_ICMP
    snifferICMP = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    snifferICMP.bind((host, 0))
    snifferICMP.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    socket_protocol = socket.IPPROTO_TCP
    snifferTCP = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    snifferTCP.bind((host, 0))
    snifferTCP.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    socket_protocol = socket.IPPROTO_UDP
    snifferUDP = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    snifferUDP.bind((host, 0))
    snifferUDP.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
      while True:
        raw_buffer = snifferICMP.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                         ip_header.src_address,
                                         ip_header.dst_address))
        raw_buffer = snifferTCP.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                         ip_header.src_address,
                                         ip_header.dst_address))
        raw_buffer = snifferUDP.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                         ip_header.src_address,
                                         ip_header.dst_address))
    except KeyboardInterrupt:
      sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
      host = sys.argv[1]
    else:
      print('Enter host IP')
      host = input()
    sniff(host)

