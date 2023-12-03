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
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host, sniff_prot):
    if sniff_prot == 'TCP':
        socket_protocol = socket.IPPROTO_TCP
    elif sniff_prot == 'UDP':
        socket_protocol = socket.IPPROTO_UDP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
      while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                         ip_header.src_address,
                                         ip_header.dst_address))
        print(f'Version: {ip_header.version}')
        print(f'Header len:{ip_header.ihl}, TTL: {ip_header.ttl}')
        if sniff_prot == 'ICMP':
           offset = ip_header.ihl * 5
           buff = raw_buffer[offset : offset + 8]
           icmp_header = ICMP(buff)
           print('''
         ICMP -> Type: %s
                 Code: %s
                 Sum: %s
                 Id: %s
                 Seq: %s
                 '''%
                 (icmp_header.type,
                  icmp_header.code,
                  # convert endianess of network to host
                  socket.ntohs(icmp_header.sum),
                  socket.ntohs(icmp_header.id),
                  socket.ntohs(icmp_header.seq)
                  ))
    except KeyboardInterrupt:
      sys.exit()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
      host = sys.argv[1]
      if len(sys.argv) > 2:
        protocol = sys.argv[2]
      else:
        protocol = 'ICMP'
    else:
      print('Enter host IP: ')
      host = input()
      print('Protocol: ')
      protocol = input()
    sniff(host, protocol)

